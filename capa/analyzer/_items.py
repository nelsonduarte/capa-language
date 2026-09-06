"""Phase-2 item-checking mixin.

Once :class:`_DeclarationsMixin` has populated the global scope
with every top-level name and its type, this mixin walks the
module again to check each item's body:

- ``_check_item``: top-level dispatcher.
- ``_check_const``: verify the const's RHS matches its declared
  type.
- ``_check_fun``: enter the parameter scope, check the body,
  enforce the "capability parameter must be used" rule.
- ``_check_impl``: validate the impl target / trait references,
  then descend into each method.
- ``_check_function_attributes``: validate ``@security`` /
  ``@deprecated`` / ``@audited`` names and keys against a small
  schema.

The mixin assumes ``self`` has the analyzer state set up and
pulls helpers (``_check_expr``, ``_check_block``,
``_resolve_type``, ``_push_scope``, ``_pop_scope``,
``_push_type_params``, ``_pop_type_params``, ``_substitute_self``,
``_method_type_from_decl``, ``_err``) from the other mixins.
"""

from __future__ import annotations

from .. import capa_ast as A
from .. import _labels as L
from .._borrow import borrow_escapes, is_fun_typed_param
from ..typesys import (
    CAPABILITY_NAMES,
    Ty, TyFun, TyName, TyUnit, TyUnknown, TyVar,
    contains_capability, is_flexible, ty_str,
)


class _ItemsMixin:
    # Attribute schema for ``@security`` / ``@deprecated`` /
    # ``@audited``. v1 ships a fixed catalogue; unknown names
    # and unknown keys are rejected so downstream consumers
    # (``--manifest``, future audit tooling) can rely on a
    # stable shape.
    _ATTRIBUTE_SCHEMA: dict[str, set[str]] = {
        "security":   {"cve", "cwe", "severity", "fixed_in", "description"},
        "deprecated": {"reason", "since", "use", "removed_in"},
        "audited":    {"date", "by", "scope", "notes"},
        "vex":        {"cve", "status", "justification", "detail",
                       "first_issued"},
        # Roadmap S2.4: opt into fail-closed information-flow checking
        # for this function. Without it, a secret-reaches-public-sink
        # flow is a warning (warn-then-enforce); with it, a hard error.
        "strict_ifc": set(),
        # Roadmap S4: require this function to be constant-time. The
        # analyzer rejects any control-flow decision or index that
        # depends on a @secret value (CWE-208 timing leaks).
        "constant_time": set(),
        # Embeddable-component increment: mark this top-level function
        # for the Wasm Component Model export surface. The WIT world
        # advertises it alongside ``main`` (see
        # ``capa.ir._emit_wit._component_export_lines``). Arg-less; an
        # ABI-surface axis orthogonal to ``pub``. Only valid on a
        # top-level function (not an impl method) and not on ``main``
        # (which is exported unconditionally); both are rejected below.
        "export": set(),
    }

    def _check_item(self, item: A.Item) -> None:
        if isinstance(item, A.Import):
            return
        if isinstance(item, A.ConstDecl):
            self._check_const(item)
            return
        if isinstance(item, A.FunDecl):
            self._check_fun(item)
            return
        if isinstance(item, A.ImplBlock):
            self._check_impl(item)
            return
        # TypeStruct, TypeSum, TraitDecl: handled in Phase 1.

    def _check_const(self, c: A.ConstDecl) -> None:
        sym = self.global_scope.lookup(c.name)
        expected = sym.ty if sym is not None else TyUnknown
        actual = self._check_expr(c.value)
        if not self._assignable(expected, actual, c.value):
            self._err(
                f"constant {c.name!r}: expected {ty_str(expected)}, "
                f"got {ty_str(actual)}",
                c.value.pos,
            )
        # Information-flow (roadmap S2, soundness): honour the declared
        # ``@secret``/``@public`` label on a module-level const the same
        # way a ``let``/``var`` binding does. Without this the annotation
        # is silently dropped and a reference to the const comes out
        # PUBLIC, laundering a declared-secret const to any public sink.
        # A const value is usually a public literal, but the annotation
        # DECLARES the intent to treat it as secret; join the declared
        # label with the value's label (never lower) and stamp it on the
        # global symbol so every reference (which binds to this symbol in
        # ``_check_ident``) carries the label.
        if sym is not None:
            decl_label = c.type_expr.label if c.type_expr is not None else None
            sym.label = self._join_decl_and_value_label(decl_label, c.value)

    def _check_function_attributes(self, fn: A.FunDecl) -> None:
        """Validate attribute names and keys against
        :data:`_ATTRIBUTE_SCHEMA`. The parser already guarantees
        argument values are string literals."""
        seen_names: set[str] = set()
        for attr in fn.attributes:
            allowed_keys = self._ATTRIBUTE_SCHEMA.get(attr.name)
            if allowed_keys is None:
                known = ", ".join(sorted(self._ATTRIBUTE_SCHEMA))
                self._err(
                    f"unknown attribute '@{attr.name}'; "
                    f"known attributes are: {known}",
                    attr.pos,
                )
                continue
            if attr.name in seen_names:
                self._err(
                    f"attribute '@{attr.name}' appears more than once on "
                    f"function {fn.name!r}",
                    attr.pos,
                )
                continue
            seen_names.add(attr.name)
            # ``@export`` is only exportable on a top-level function; it
            # is a hard error to mark something that cannot become a
            # component export. An impl method is not a module-level
            # export target (the WIT world only advertises top-level
            # functions), and ``main`` is exported unconditionally, so
            # ``@export main`` would emit a duplicate world export.
            # Fail loud here rather than silently dropping the marker.
            if attr.name == "export":
                if self.self_type is not None:
                    self._err(
                        "@export is only valid on a top-level function, "
                        "not an impl method",
                        attr.pos,
                    )
                elif fn.name == "main":
                    self._err(
                        "main is exported automatically; remove the "
                        "redundant @export",
                        attr.pos,
                    )
            seen_keys: set[str] = set()
            for key, _value in attr.args:
                if key not in allowed_keys:
                    keys_str = ", ".join(sorted(allowed_keys))
                    self._err(
                        f"unknown key '{key}' in '@{attr.name}'; "
                        f"allowed keys are: {keys_str}",
                        attr.pos,
                    )
                    continue
                if key in seen_keys:
                    self._err(
                        f"key '{key}' appears more than once in "
                        f"'@{attr.name}'",
                        attr.pos,
                    )
                seen_keys.add(key)

    def _check_fun(self, fn: A.FunDecl) -> None:
        from . import Symbol, SymbolKind

        # Attribute validation is fast, scope-free, and a
        # precondition for ``--manifest`` to trust the AST.
        if fn.attributes:
            self._check_function_attributes(fn)

        self._push_type_params(fn.type_params)
        self._push_scope(is_function_root=True)

        # Roadmap S2.4: a function opting into ``@strict_ifc`` turns
        # information-flow sink warnings into hard errors for its body.
        # Saved/restored so nested functions don't inherit it.
        prev_strict_ifc = getattr(self, "_strict_ifc", False)
        self._strict_ifc = any(
            a.name == "strict_ifc" for a in fn.attributes
        )

        # Feature #6 (B1): the function a warn-tier un-audited secret->sink
        # flow attributes to. Saved/restored so a nested function does not
        # inherit it, exactly like ``_strict_ifc``.
        prev_cur_fun_id = getattr(self, "_cur_fun_id", 0)
        self._cur_fun_id = id(fn)

        # Roadmap S4: ``@constant_time`` rejects secret-dependent
        # control flow / indexing in this function's body.
        prev_constant_time = getattr(self, "_constant_time", False)
        self._constant_time = any(
            a.name == "constant_time" for a in fn.attributes
        )

        # Roadmap S2.implicit: the pc-label is a per-function quantity.
        # ``_check_block`` raises it monotonically when a statement
        # diverges under a @secret guard (a leaky early-return), and that
        # raise is NOT lowered before the block ends. A body that exits
        # with the pc still raised (``if s > 0: return``) would otherwise
        # carry that elevation into whichever @strict_ifc function is
        # CHECKED NEXT, turning a clean public sink there into an
        # order-dependent false positive (audit 2026-06-17). Save the
        # entry pc and restore it on exit so the raise stays inside this
        # function, exactly as ``_strict_ifc`` / ``_constant_time`` are
        # scoped. Intra-function elevation (the original Finding 5:
        # early-return followed by a sink in the SAME body) is unaffected
        # -- it lives entirely within ``_check_block``.
        prev_pc_label = getattr(self, "_pc_label", L.PUBLIC)
        self._pc_label = L.PUBLIC
        # Fresh per-function branch-scoped container-mutation taint channel
        # (see ``_ifc._container_taint_map``); saved/restored so a nested
        # function / lambda body does not clobber the enclosing one.
        prev_container_taint = getattr(self, "_container_taint", None)
        self._container_taint = {}
        # Flat (NOT branch-scoped) set of bindings that were ever the target
        # of a precisely-tracked field store or container push, i.e. that
        # have a field-KEYED entry on the (branch-scoped) container channel at
        # some point. The capture re-read (``_fresh_capture_label``) consults
        # it to tell a whole-value ``sym.label`` raised by a precise mutation
        # (trust the branch-scoped, field-precise channel) from one raised by
        # a whole reassign / alias / annotation (fall back to ``sym.label``),
        # so a branch-exclusive field store stays branch-sound. Saved /
        # restored per function like the channel itself.
        prev_container_seeded = getattr(self, "_container_seeded_syms", None)
        self._container_seeded_syms = set()
        # Flat set of bindings whose collapsed ``sym.label`` was raised to
        # secret by an IN-PLACE field store that took a whole-value
        # early-return (alias group / escaped / unresolvable path) and so was
        # NOT precisely container-seeded. The capture re-read must re-consult
        # ``sym.label`` for such a binding even if it was ALSO precisely
        # seeded elsewhere, because the field-precise channel does not see the
        # early-returned store (see ``_fresh_capture_label``). Saved / restored
        # per function like the seeded set.
        prev_container_dirty = getattr(self, "_container_whole_dirty_syms", None)
        self._container_whole_dirty_syms = set()

        # Capability parameters: collected so the analyzer can
        # warn at the end of the body if any are declared but
        # never used.
        cap_param_syms: list[Symbol] = []

        for p in fn.params:
            if p.name == "self":
                if self.self_type is None:
                    self._err(
                        "'self' parameter is only valid inside an impl",
                        p.pos,
                    )
                psym = Symbol(
                    name="self", kind=SymbolKind.PARAM, pos=p.pos,
                    ty=self.self_type if self.self_type is not None else TyUnknown,
                )
            else:
                pty = (
                    self._resolve_type(p.type_expr)
                    if p.type_expr else TyUnknown
                )
                psym = Symbol(
                    name=p.name, kind=SymbolKind.PARAM, pos=p.pos, ty=pty,
                    label=p.type_expr.label if p.type_expr else None,
                )
                # A bare capability parameter is the ONE legitimate
                # channel; a capability NESTED inside a container / tuple
                # is not, so reject the parameter up front for a precise
                # message (the resolved-type use-gate would also catch any
                # use of it in the body).
                self._check_no_cap_container(
                    pty, p.pos, f"the type of parameter {p.name!r}",
                )
                # A parameter typed as a container of linear/typestate values
                # (``List<Conn>`` / ``(Conn, Int)`` / ``Map<K, Conn>``) is
                # barred up front; a bare linear/typestate parameter stays
                # legal (that is how single-owner values flow), so this uses
                # the container-scoped predicate.
                self._check_no_linear_container(
                    pty, p.pos, f"the type of parameter {p.name!r}",
                )
                if contains_capability(pty) is not None:
                    cap_param_syms.append(psym)
            if self.scope.lookup_local(p.name) is not None:
                self._err(
                    f"duplicate parameter name {p.name!r}", p.pos,
                )
            self.scope.define(psym)

        # ``borrow`` parameter discipline: a ``borrow`` marker is only
        # meaningful on a ``Fun``-typed parameter, and that parameter may
        # be INVOKED but never retained. Verify both here so the checked
        # contract an auditor reads in the SBOM (the honest ceiling) is
        # actually enforced, and reject any escape naming the exact site.
        # Intra-module forwarding resolver: a ``borrow`` parameter may be
        # forwarded into a same-file callee position that is itself
        # ``borrow`` (see ``_borrow``). Backed by the Phase-1 symbol table,
        # so a callee declared later in the file still resolves; scoped to
        # this function's own source file, since ``borrow``-ness is not
        # carried across the module boundary.
        owner_file = fn.pos.filename or ""

        def _resolve_borrow_params(callee_name: str):
            sym = self.global_scope.lookup(callee_name)
            if sym is None or sym.kind is not SymbolKind.FUNCTION:
                return None
            if (sym.pos.filename or "") != owner_file:
                return None
            return list(zip(sym.param_names, sym.borrowing_params))

        local_names = [q.name for q in fn.params]
        for p in fn.params:
            if not p.borrowing:
                continue
            if not is_fun_typed_param(p.type_expr):
                self._err(
                    "borrow applies only to a function-typed parameter "
                    "(a `Fun(...) -> ...` type); "
                    f"parameter {p.name!r} is not one",
                    p.pos,
                )
                continue
            for esc_pos in borrow_escapes(
                fn.body, p.name,
                resolve_borrow_params=_resolve_borrow_params,
                local_names=local_names,
            ):
                self._err(
                    f"borrow parameter {p.name!r} may only be invoked "
                    f"(called as `{p.name}(...)`); it escapes here. A "
                    "borrow function must not be stored, returned, "
                    "aliased, passed to another function, or captured "
                    "by a lambda.",
                    esc_pos,
                )

        # Snapshot bindings to detect unused capability params.
        bindings_before = set(self.bindings.keys())

        # Fresh ``_consumed`` set for the function body.
        prev_consumed = self._consumed
        self._consumed = set()
        # Fresh linear-name set (which consumed names are linear /
        # typestate values, for the use-after-consume wording).
        prev_linear_names = self._linear_names
        self._linear_names = set()
        # Fresh ``_live_linear`` map for the function body (roadmap
        # S1), saved/restored so a nested function's obligations do
        # not bleed into the enclosing one. Function parameters do NOT
        # seed the live set: a ``consume`` linear param is the
        # terminal owner (the value legitimately ends its life here,
        # e.g. ``close(consume h)`` destroys the handle), and a
        # non-consuming linear param is borrowed (the caller keeps the
        # obligation). Obligations arise only from values *produced*
        # inside the body (``let h = open()``).
        prev_live_linear = self._live_linear
        self._live_linear = {}
        # Per-field discharge accounting (Connection C), reset per function
        # alongside the live map.
        prev_field_moved = self._linear_field_moved
        self._linear_field_moved = set()
        # B: pattern-binding VIEW aliases are function-local, like the live
        # map they resolve into.
        prev_linear_alias = self._linear_alias
        self._linear_alias = {}
        # B-F1: seed the borrowed-linear set. A non-``consume`` parameter
        # of a linear / typestate type is borrowed -- the caller keeps the
        # obligation, so the callee may read and forward it but must not
        # consume, return, alias, or pack it into an aggregate. A
        # ``consume`` param is the terminal owner (not borrowed); a
        # non-linear param carries no obligation. ``self`` (whose declared
        # type is the impl's ``self_type``) is included, so a non-consume
        # ``self`` receiver is borrowed too.
        prev_borrowed_linear = self._borrowed_linear
        self._borrowed_linear = set()
        # LIN-1: seed the consume-owned drop-exempt set (see below).
        prev_drop_exempt_linear = self._drop_exempt_linear
        self._drop_exempt_linear = set()
        for p in fn.params:
            p_ty = (
                self.self_type if p.name == "self"
                else (self._resolve_type(p.type_expr) if p.type_expr else None)
            )
            if p.consuming:
                # LIN-1: a ``consume`` parameter OWNS its value here. Seed a
                # bare linear/typestate one into the SAME ``_live_linear``
                # owned tracker as a let-bound value, so a re-consume or a
                # use-after-consume is poisoned and caught by the single
                # use-after-consume check -- the consume analog of the
                # borrowed seeding below. It is DROP EXEMPT: a consume
                # parameter dropped without re-consuming is the terminal
                # owner (``close(consume h)`` destroys the handle;
                # ``discard`` / ``adopt`` receive and drop it), so the
                # scope-exit leak check skips it. Only a BARE linear/
                # typestate value is tracked here (the same gate as
                # ``_linear_bind``); a carrier struct is seeded too and is
                # exempt transitively (adopting the whole carrier + its
                # linear fields is legal, like ``adopt(consume h)``).
                if self._owned_obligation(p_ty):
                    self._live_linear[p.name] = (p.pos, p_ty)
                    self._drop_exempt_linear.add(p.name)
                continue
            # A non-``consume`` parameter is borrowed when it carries a
            # must-consume obligation -- itself a linear/typestate value OR a
            # struct that transitively OWNS a linear/typestate field (a
            # `Session` / `Settlement` carrier): the caller keeps the
            # obligation, so the callee may read it but must not consume,
            # move, or alias-then-consume it (else it double-frees the
            # caller's field).
            if self._owned_obligation(p_ty):
                self._borrowed_linear.add(p.name)
        # Fresh TyVar substitution universe for the function.
        prev_subs = self._ty_subs
        self._ty_subs = {}
        # Fresh empty-container tracking for the function: the element
        # variables minted for unannotated ``[]`` / ``new_map()`` /
        # ``new_set()`` and the reads that pulled a value out of one at a
        # still-open type. Saved / restored so a nested function does not
        # inherit the enclosing one's containers.
        prev_empty_container_vars = self._empty_container_vars
        self._empty_container_vars = set()
        prev_deferred_elem_reads = self._deferred_elem_reads
        self._deferred_elem_reads = {}

        prev_ret = self.current_return_type
        ret = (
            self._resolve_type(fn.return_type)
            if fn.return_type else TyUnit
        )
        self.current_return_type = ret
        self._check_block(fn.body)
        self.current_return_type = prev_ret

        # Whole-function post-pass (now that the body is analysed and every
        # read is resolved): reject a plain-function shadow of a module
        # const / function that is also read elsewhere in the body -- a
        # backend divergence (Python function-scopes the redeclared name for
        # the whole body; Wasm keeps the lexical module global). Subsumes the
        # plain-function self-ref / read-before / read-after cases; the
        # lambda class is handled per-binding by ``_enclosing_scope_local``.
        self._check_module_shadow_divergence(fn)

        # If the function declares a non-Unit return type, every
        # code path must end in ``return``. A function that just
        # has ``"hello"`` as its last statement when declared
        # ``-> String`` would otherwise compile cleanly and silently
        # return None at runtime, producing a None where a String
        # was promised. Caught here so the user sees a precise
        # message instead of a downstream type confusion.
        if ret is not TyUnit and not _block_always_returns(fn.body):
            # Point at the function's name (or the body's open
            # position when the name span is unavailable) so the
            # caret lands somewhere visible in the editor.
            err_pos = getattr(fn, "name_pos", None) or fn.pos
            self._err(
                f"function {fn.name!r} declares return type but not "
                f"every path ends in `return`; the function will "
                f"fall through and return None at runtime",
                err_pos,
            )

        # Empty-container element-type diagnostic, judged only NOW that the
        # whole body has been analysed and every pin has settled. When a
        # value is read out of a container created empty and unannotated,
        # and that read does NOT itself pin the element type, inference has
        # nothing to fix the type to; the read is reported so the user
        # annotates it. This is a diagnostic-quality aid for the UN-PINNED
        # case, NOT a blanket guarantee that every read-out of an empty
        # container is diagnosed at check time: when the sole read lands
        # directly in a concretely-typed slot, that read pins the element
        # type through the normal assignment-compatibility path, so the
        # variable is already bound by the time we get here and the guard
        # stays silent. Soundness does not depend on catching that residual
        # case -- it fails LOUD at run time on BOTH backends (a trap), with
        # no silent divergence between them. Deferred to here so a
        # legitimate read-before-populate (probe-then-fill, get-or-default,
        # check-then-insert) -- where a LATER populate fixes the type -- is
        # still accepted. Resolution runs against the function's still-live
        # ``_ty_subs``.
        for var_name, read_pos in self._deferred_elem_reads.items():
            resolved_elem = self._resolve_ty(TyVar(var_name))
            # Deferred capability-container recheck. A value read out of a
            # container created empty and unannotated surfaces the bare,
            # still-open element variable, so the ``_check_expr`` use-gate
            # (which is framed on the resolved type) could not see a
            # capability at production time. Now that the whole body has
            # been analysed, the element type may have resolved to a
            # capability -- the inferred-empty-then-populated local, or a
            # capability pushed inside a generic helper that only surfaces
            # as the caller's ``List<capability>``. Reject it here. This
            # keys on a RESOLVED-to-capability element type, whereas the
            # never-determined guard below keys on a STILL-FLEXIBLE one:
            # the two conditions are mutually exclusive, so they compose
            # without double-firing or conflicting.
            cap = self._contains_any_capability(resolved_elem)
            if cap is not None:
                self._err(
                    f"capability {cap.name!r} cannot be read out of a "
                    f"container: this local resolves to a container of "
                    f"capabilities, and a capability may only flow as a "
                    f"bare, top-level value (a direct function parameter), "
                    f"never packed inside a list, set, map, or tuple",
                    read_pos,
                )
                continue
            # Deferred container-of-linear recheck (mirror of the cap case
            # above). The inferred-empty-then-populated local, or a linear
            # value pushed inside a generic helper that only surfaces as the
            # caller's ``List<Conn>``, resolves to a linear/typestate element
            # only now that the whole body has been analysed. Reject the
            # read-out here, since the use-gate could not see it at production
            # time (the element variable was still open).
            if self._owned_obligation(resolved_elem):
                self._err(
                    "a linear/typestate value cannot be read out of a "
                    "container: this local resolves to a container of "
                    "single-owner values, and a linear/typestate value may "
                    "only flow as a bare, top-level value (a direct parameter "
                    "/ return / binding), never packed inside a list, set, "
                    "map, or tuple",
                    read_pos,
                )
                continue
            if is_flexible(resolved_elem):
                if var_name.startswith("?lst"):
                    kind, example = "list", "let xs: List<Int> = []"
                elif var_name.startswith("?map"):
                    kind, example = "map", "let m: Map<String, Int> = new_map()"
                elif var_name.startswith("?set"):
                    kind, example = "set", "let s: Set<Int> = new_set()"
                else:
                    kind, example = "container", "let xs: List<Int> = []"
                self._err(
                    f"cannot determine the element type of this {kind}: it "
                    f"is created empty and its element type is never fixed "
                    f"anywhere in this function, so a value read out of it "
                    f"has no known type. Annotate the element type, e.g. "
                    f"`{example}`.",
                    read_pos,
                )

        # Roadmap S1: any linear obligation still live at function
        # exit was never consumed -- a leak. Report each, then
        # restore the enclosing function's live set.
        self._linear_check_dropped(set(self._live_linear))
        self._live_linear = prev_live_linear
        self._linear_field_moved = prev_field_moved
        self._linear_alias = prev_linear_alias
        self._borrowed_linear = prev_borrowed_linear
        self._drop_exempt_linear = prev_drop_exempt_linear

        self._consumed = prev_consumed
        self._linear_names = prev_linear_names
        self._ty_subs = prev_subs
        self._empty_container_vars = prev_empty_container_vars
        self._deferred_elem_reads = prev_deferred_elem_reads

        new_bindings = {
            k: v for k, v in self.bindings.items()
            if k not in bindings_before
        }
        used_sym_ids = {id(s) for s in new_bindings.values()}

        # Capability params must be referenced in the body
        # (otherwise the function declared an authority it does
        # not exercise, which is a smell). Names starting with
        # ``_`` silence the warning, in the fine tradition of
        # Rust and Haskell.
        for psym in cap_param_syms:
            if id(psym) in used_sym_ids:
                continue
            if psym.name.startswith("_"):
                continue
            self._err(
                f"capability parameter {psym.name!r} is declared but never "
                f"used; prefix the name with '_' to silence this check",
                psym.pos,
            )

        self._strict_ifc = prev_strict_ifc
        self._cur_fun_id = prev_cur_fun_id
        self._constant_time = prev_constant_time
        self._pc_label = prev_pc_label
        self._container_taint = prev_container_taint
        self._container_seeded_syms = prev_container_seeded
        self._container_whole_dirty_syms = prev_container_dirty
        self._pop_scope()
        self._pop_type_params()

    def _check_module_shadow_divergence(self, fn: A.FunDecl) -> None:
        """Reject a PLAIN function whose body BOTH name-shadows a
        module-level CONST / FUNCTION and READS that same symbol elsewhere.

        Such a program compiles differently on the two backends: Python has
        function scope, so a ``let`` / ``var`` / ``for`` / ``match`` bind of
        the name anywhere in the body makes the name a function-local for
        the WHOLE body, and the genuine read then binds to that (possibly
        unassigned or block-local) shadow; the Wasm backend keeps the
        lexical module global. Whichever position the read and the shadow
        sit in, the two disagree, so this whole-function post-pass is
        deliberately position-insensitive and conservative -- it subsumes
        the self-ref, read-before, and read-after (incl. an always-taken
        loop) cases with one rule.

        Binds inside a NESTED LAMBDA are excluded from the shadow set: the
        lambda class is closed by the per-binding check at lambda scope
        (``_enclosing_scope_local``). A read INSIDE a lambda still counts
        for the read side, but only if it RESOLVES to the module symbol (a
        capture that already resolves to an enclosing local does not).
        Built-in symbols are excluded (a shadow of a builtin is a separate,
        pre-existing concern).
        """
        from . import SymbolKind
        from ..builtins import BUILTIN_POS
        binds: dict = {}
        self._collect_plain_shadow_binds(fn.body, binds)
        for name, bind_pos in binds.items():
            sym = self.global_scope.symbols.get(name)
            if (
                sym is None
                or sym.pos == BUILTIN_POS
                or sym.kind not in (SymbolKind.CONSTANT, SymbolKind.FUNCTION)
            ):
                continue
            read = self._first_symbol_read(fn.body, sym)
            if read is None:
                continue
            kind = (
                "constant" if sym.kind == SymbolKind.CONSTANT else "function"
            )
            self._err(
                f"binding {name!r} may not shadow the module-level {kind} "
                f"{name!r} (defined at line {sym.pos.line}, col "
                f"{sym.pos.col}), which is also read at line "
                f"{read.pos.line}, col {read.pos.col} in this function; the "
                f"two runtime backends compile this shadow differently "
                f"(Python function-scopes the whole body while Wasm keeps "
                f"the module {kind}), so rename the inner binding to a "
                f"distinct name",
                bind_pos,
            )

    def _collect_plain_shadow_binds(self, node, out: dict) -> None:
        """Collect every name bound by a ``let`` / ``var`` / ``for`` /
        ``match``-arm pattern reachable from ``node``, EXCLUDING nested
        lambda bodies, mapped to the binding's source position (first
        occurrence wins). Enumerates ALL pattern-bound names -- struct
        shorthand ``Box { k }``, nested, tuple, and variant patterns -- via
        ``_pattern_bound_names``, so a struct-shorthand shadow is not
        missed."""
        from ._ifc_tables import _pattern_bound_names
        import dataclasses
        if node is None or isinstance(node, str):
            return
        if isinstance(node, A.LambdaExpr):
            return
        if isinstance(node, A.LetStmt):
            for nm in _pattern_bound_names(node.pattern):
                out.setdefault(nm, node.pattern.pos)
            self._collect_plain_shadow_binds(node.value, out)
            return
        if isinstance(node, A.VarStmt):
            out.setdefault(node.name, node.pos)
            self._collect_plain_shadow_binds(node.value, out)
            return
        if isinstance(node, A.ForStmt):
            for nm in _pattern_bound_names(node.pattern):
                out.setdefault(nm, node.pattern.pos)
            self._collect_plain_shadow_binds(node.iter, out)
            for st in node.body.stmts:
                self._collect_plain_shadow_binds(st, out)
            return
        if isinstance(node, A.MatchArm):
            for nm in _pattern_bound_names(node.pattern):
                out.setdefault(nm, node.pattern.pos)
            if node.guard is not None:
                self._collect_plain_shadow_binds(node.guard, out)
            self._collect_plain_shadow_binds(node.body, out)
            return
        if dataclasses.is_dataclass(node):
            for f in dataclasses.fields(node):
                self._collect_plain_shadow_binds(getattr(node, f.name), out)
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                self._collect_plain_shadow_binds(x, out)

    def _check_impl(self, impl: A.ImplBlock) -> None:
        from . import SymbolKind
        from . import _signatures_match

        target = self.global_scope.lookup(impl.type_name)
        if target is None or target.kind not in (
            SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM
        ):
            self._err(
                f"impl target {impl.type_name!r} is not a known type",
                impl.pos,
            )
            return

        # ``trait X`` and ``capability X`` are both valid here:
        # they share the ``trait_methods`` / ``trait_method_sigs``
        # shape on the Symbol.
        if impl.trait_name is not None:
            # Audit slice 21 P2 follow-up (2026-05-29): built-in
            # capabilities (Stdio, Fs, Net, ...) are part of the
            # host trust boundary - their inhabitants are the
            # values the host hands the program at startup, not
            # arbitrary user structs. Letting a user write
            # ``impl Stdio for FakeStdio`` lets a non-host value
            # inhabit a host cap type and pollutes the
            # "Stdio is whatever the host hands you" invariant
            # that the discipline relies on for soundness.
            # Method dispatch routes through the user impl so
            # no real I/O happens at runtime, but the model
            # opens the door to future soundness regressions
            # (e.g. when downstream tooling assumes a value of
            # cap type Stdio is host-granted).
            if impl.trait_name in CAPABILITY_NAMES:
                self._err(
                    f"cannot impl built-in capability "
                    f"{impl.trait_name!r}: built-in caps are "
                    f"host-granted and cannot be inhabited by "
                    f"user types. Wrap the cap in a user-defined "
                    f"capability instead.",
                    impl.pos,
                )
                return
            trait = self.global_scope.lookup(impl.trait_name)
            if trait is None or trait.kind not in (
                SymbolKind.TRAIT, SymbolKind.CAPABILITY,
            ):
                self._err(
                    f"trait {impl.trait_name!r} is not defined",
                    impl.pos,
                )
            else:
                impl_method_names = {m.name for m in impl.methods}
                missing = trait.trait_methods - impl_method_names
                if missing:
                    self._err(
                        f"impl of trait {impl.trait_name!r} for "
                        f"{impl.type_name!r} is missing methods: "
                        f"{', '.join(sorted(missing))}",
                        impl.pos,
                    )
                self_args_check = tuple(TyVar(p) for p in target.type_params)
                self_ty_concrete = TyName(impl.type_name, self_args_check)
                for method in impl.methods:
                    if method.name not in trait.trait_method_sigs:
                        continue   # extra (helper) method: allowed
                    expected = trait.trait_method_sigs[method.name]
                    expected_concrete = self._substitute_self(
                        expected, self_ty_concrete,
                    )
                    self._push_type_params(target.type_params)
                    prev_self = self.self_type
                    self.self_type = self_ty_concrete
                    actual = self._method_type_from_decl(method)
                    self.self_type = prev_self
                    self._pop_type_params()
                    if (
                        isinstance(actual, TyFun)
                        and isinstance(expected_concrete, TyFun)
                    ):
                        if not _signatures_match(expected_concrete, actual):
                            self._err(
                                f"impl method {method.name!r} for trait "
                                f"{impl.trait_name!r}: expected signature "
                                f"{ty_str(expected_concrete)}, got "
                                f"{ty_str(actual)}",
                                method.pos,
                            )

        self_args = tuple(TyVar(p) for p in target.type_params)
        prev_self = self.self_type
        # Roadmap S3.5: inside an ``impl Type[State]`` the receiver is
        # in that state, so ``self`` carries it (a transition or a
        # state-method call on ``self`` then type-checks coherently).
        self.self_type = TyName(
            impl.type_name, self_args, state=impl.state,
        )
        self._push_type_params(target.type_params)

        for method in impl.methods:
            self._check_fun(method)

        self._pop_type_params()
        self.self_type = prev_self


def _block_always_returns(block) -> bool:
    """True iff every code path through block ends in a
    return. Used to flag a non-Unit-returning function whose
    body could fall through without producing a value.

    The check is conservative on purpose: a block whose last
    statement is a return is fine; an if whose then and
    else (plus every elif) branches all always-return is
    fine; an exhaustive match whose every arm-body always-
    returns is fine. Anything else returns False even when a
    more sophisticated flow analysis could prove return; the
    fix is to add a trailing return (which is harmless) or
    restructure.
    """
    from .. import capa_ast as A
    if not block.stmts:
        return False
    return _stmt_always_returns(block.stmts[-1])


def _stmt_always_returns(s) -> bool:
    from .. import capa_ast as A
    if isinstance(s, A.ReturnStmt):
        return True
    if isinstance(s, A.IfStmt):
        # Without an else branch, control may fall through.
        if s.else_block is None:
            return False
        for _cond, blk in s.elif_arms:
            if not _block_always_returns(blk):
                return False
        return (
            _block_always_returns(s.then_block)
            and _block_always_returns(s.else_block)
        )
    if isinstance(s, A.ExprStmt) and isinstance(s.expr, A.MatchExpr):
        for arm in s.expr.arms:
            if not _arm_always_returns(arm):
                return False
        # The analyser's exhaustiveness pass runs elsewhere; if it
        # did not flag the match, the arms cover the scrutinee.
        return True
    return False


def _arm_always_returns(arm) -> bool:
    from .. import capa_ast as A
    body = arm.body
    if isinstance(body, A.Block):
        return _block_always_returns(body)
    # Single-expression arm body (no explicit return). Could only
    # satisfy "always returns" via an early-return expression,
    # which Capa does not have. Conservative: False.
    return False

