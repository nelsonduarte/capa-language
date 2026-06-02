"""Information-flow label propagation (roadmap S2.3).

Runs alongside type checking: every expression, after it is typed in
``_check_expr``, is also given a security label stored in
``self._expr_labels[id(e)]``. The label is the join (lattice ⊔) of the
labels of the sub-expressions that flow into it -- so a derived value
is ``secret`` iff some operand it depends on is ``secret``. Variable
references take their label from the binding's ``Symbol.label`` (set
from a ``@secret`` / ``@public`` annotation when the binding was
declared).

Label propagation (S2.3) computes the labels; sink enforcement
(S2.4, ``_check_ifc_sink``) reports when a ``secret`` value reaches a
public-exfiltration sink (Stdio.println, Net.post, Fs.write, ...).
Warn-then-enforce: a non-fatal warning by default, a hard error under
``@strict_ifc``. The source-cap labelling (``env.get`` -> secret),
``declassify`` + SBOM, and implicit (control-flow) leaks land in
later S2 slices.

Children are always visited before their parent (``_check_expr``
recurses into operands first), so when ``_label_of_expr`` runs for a
parent the children's labels are already in ``self._expr_labels``.

Aggregate literals (struct / list / tuple) carry the join of their
element labels, so a secret stashed in one and read back is not
laundered to public; the read rules above already inherit the
receiver's label. The granularity is whole-aggregate (per-field
precision is a follow-up) and the flow is intra-procedural (crossing a
function boundary still relies on an explicit ``@secret`` parameter).
"""

from __future__ import annotations

from .. import capa_ast as A
from .. import _labels as L


# Built-in capability methods that exfiltrate data out of the program
# -- the public sinks. A ``@secret`` value reaching any of these
# argument positions is an information-flow violation unless it was
# declassified. Keyed by ``(CapName, method)`` -> the set of 0-based
# argument indices that are sinks. Roadmap S2.4.
#
# Receiver-only / pure-query methods (allows, exists, read, get from
# Env, now_secs, ...) are NOT sinks: they bring data IN or inspect,
# they don't send it out. ``restrict_to*`` take a config string, not
# user data. The path argument of fs.write is included (a secret
# written to an attacker-chosen path is still disclosure), as is the
# URL of net.get/post (a secret in a URL leaks via the request line /
# server logs).
_PUBLIC_SINKS: dict[tuple[str, str], set[int]] = {
    ("Stdio", "print"):    {0},
    ("Stdio", "println"):  {0},
    ("Stdio", "eprintln"): {0},
    ("Net", "get"):        {0},
    ("Net", "post"):       {0, 1},
    ("Fs", "write"):       {0, 1},
    ("Db", "exec"):        {0, 1},
    ("Db", "query"):       {0, 1},
}

# Built-in capability methods that PRODUCE secret data -- the sources.
# Their result is labelled ``@secret`` regardless of argument labels,
# so a program that reads a secret and routes it to a public sink is
# caught without the programmer annotating anything. Roadmap S2
# (source caps). Keyed ``(CapName, method)``.
#
# Conservative on purpose -- only ``Env.get`` for now. Environment
# variables are where API keys / tokens / credentials live (the
# headline prompt-injection-exfiltration case), so treating them as
# secret-by-default is the safe and accurate call. ``Fs.read`` is
# deliberately NOT a source: a config / data file is usually public,
# and over-labelling it would warn on every legitimate file echo. A
# program that does hold a secret in a file can annotate the binding
# ``@secret`` explicitly. Future levels could make this configurable.
_SECRET_SOURCES: frozenset = frozenset({
    ("Env", "get"),
})

# Mutating methods that can inject tainted data INTO a mutable
# container. When called with a @secret argument in one of the listed
# positions, the receiver container becomes @secret: a later read
# (``get`` / ``contains`` / ``keys`` / iteration) would otherwise
# launder the secret back to public. Keyed ``(TypeName, method)`` ->
# the 0-based argument positions that carry data into the container.
# This is the mutable-container analogue of the aggregate-literal
# rule; together they stop a secret from being hidden in a collection.
_CONTAINER_MUTATORS: dict[tuple[str, str], set[int]] = {
    ("List", "push"): {0},
    ("Set",  "add"):  {0},
    ("Map",  "set"):  {0, 1},
}

# Lookup methods whose index / key argument selects which memory is
# touched. In a ``@constant_time`` function (roadmap S4) a @secret in
# one of these positions is a data-dependent access (the cache-timing
# side channel behind table lookups, e.g. an AES S-box). Keyed
# ``(TypeName, method)`` -> the 0-based argument positions that act as
# the index / key. This is the method-call analogue of ``xs[secret]``.
_CT_INDEX_METHODS: dict[tuple[str, str], set[int]] = {
    ("List",   "get"):          {0},
    ("Map",    "get"):          {0},
    ("Map",    "contains_key"): {0},
    ("Set",    "contains"):     {0},
    ("String", "char_at"):      {0},
}


class _IfcMixin:
    def _label_expr(self, e: A.Expr) -> str:
        """Compute and record the security label of ``e`` from its
        already-labelled children, returning it. Called by
        ``_check_expr`` right after typing, so child labels are
        present. The result is stored in ``self._expr_labels``."""
        label = self._compute_label(e)
        self._expr_labels[id(e)] = label
        return label

    def _label_of(self, e: A.Expr) -> str:
        """The recorded label of an already-visited expression, or
        PUBLIC if it has none (e.g. a node the walk doesn't label)."""
        return self._expr_labels.get(id(e), L.PUBLIC)

    def _join_decl_and_value_label(self, decl_label, value: A.Expr) -> str:
        """The label a binding receives: the join of an explicit
        ``@secret``/``@public`` annotation (``decl_label``, may be
        ``None``) and the label already computed for its RHS value.
        So ``let x: @secret Int = 1`` is secret by annotation, and
        ``let y = secret_x`` is secret by flow -- both surface here."""
        return L.join(decl_label, self._label_of(value))

    def _label_binding(self, name: str, decl_label, value: A.Expr) -> None:
        """Set the IFC label on the in-scope ``Symbol`` for ``name``
        to the join of its annotation and its RHS value's label.
        Used by ``_check_let`` after the pattern is bound."""
        sym = self.scope.lookup_local(name)
        if sym is not None:
            sym.label = self._join_decl_and_value_label(decl_label, value)

    def _label_pattern_binds(self, pat: A.Pattern, scrutinee_label: str) -> None:
        """Propagate a scrutinee's IFC label to every name a pattern
        destructure binds (roadmap S2 source flow). When the matched
        value is ``secret`` -- e.g. the Option from ``env.get(...)`` --
        each name pulled out of it (``Some(key)`` -> ``key``) becomes
        ``secret`` too, so leaking the payload to a public sink is
        caught. Conservative: a sub-payload inherits the whole
        scrutinee's label (no per-field refinement in this slice).

        A ``public`` scrutinee leaves the binds untouched, so an
        explicit ``@secret`` annotation on the bound name (rare in a
        pattern, but possible via the surrounding ``let`` type) is not
        clobbered."""
        if L.normalize(scrutinee_label) != L.SECRET:
            return
        for name in _pattern_bound_names(pat):
            sym = self.scope.lookup_local(name)
            if sym is not None:
                sym.label = L.join(sym.label, L.SECRET)

    def _compute_label(self, e: A.Expr) -> str:
        # Literals are public.
        if isinstance(e, (
            A.IntLit, A.FloatLit, A.StringLit, A.CharLit,
            A.BoolLit, A.UnitLit,
        )):
            return L.PUBLIC

        # A name carries its binding's label.
        if isinstance(e, A.Ident):
            sym = self.bindings.get(id(e))
            if sym is not None and getattr(sym, "label", None):
                return L.normalize(sym.label)
            return L.PUBLIC

        # Derived values join the labels of every operand that flows
        # into them. Interpolation is a flow: ``"${secret}"`` is
        # secret, the classic logging-leak shape.
        if isinstance(e, A.InterpolatedString):
            return L.join_all(
                self._label_of(p) for p in e.parts
                if not isinstance(p, str)
            )
        if isinstance(e, A.BinOp):
            return L.join(self._label_of(e.left), self._label_of(e.right))
        if isinstance(e, A.UnaryOp):
            return self._label_of(e.operand)
        if isinstance(e, A.Try):
            # ``x?`` unwraps; the payload keeps the taint of x.
            return self._label_of(e.expr)
        if isinstance(e, A.Index):
            # An element drawn from a tainted container is tainted.
            return L.join(self._label_of(e.receiver), self._label_of(e.index))
        if isinstance(e, A.FieldAccess):
            # Conservative: a field read inherits the receiver's label.
            # (Per-field labels are a v2 refinement.)
            return self._label_of(e.receiver)

        # Calls / method-calls. A method call on a built-in source
        # cap (``env.get(...)``) yields secret data regardless of its
        # arguments -- this is how secrets enter the program without
        # any annotation (roadmap S2 source caps). Otherwise a call
        # result is the join of its argument (and receiver) labels: a
        # pure function of tainted inputs is tainted -- the safe
        # default. (``declassify`` overrides this at its own call
        # site in a later slice.)
        if isinstance(e, A.Call):
            # declassify is the auditable secret->public bridge: its
            # result is PUBLIC by construction, regardless of the
            # value's label (roadmap S2.5).
            if self._is_declassify_call(e):
                return L.PUBLIC
            return L.join_all(self._label_of(a) for a in e.args)
        if isinstance(e, A.MethodCall):
            recv_ty = self.types.get(id(e.receiver))
            cap_name = getattr(recv_ty, "name", None)
            if cap_name is not None and (cap_name, e.method) in _SECRET_SOURCES:
                return L.SECRET
            return L.join(
                self._label_of(e.receiver),
                L.join_all(self._label_of(a) for a in e.args),
            )

        # Aggregate literals carry the join of the labels of the values
        # they hold, so a secret placed in a struct field / list / tuple
        # element makes the whole aggregate secret. Combined with the
        # field-read / index rules above (a read inherits the receiver's
        # label), this closes the laundering hole where stashing a
        # @secret in an aggregate and reading it back would otherwise
        # come out @public. Conservative (whole-aggregate, not
        # per-field); per-field precision is a later refinement.
        if isinstance(e, A.StructLit):
            return L.join_all(self._label_of(v) for _name, v in e.fields)
        if isinstance(e, (A.ListLit, A.TupleLit)):
            return L.join_all(self._label_of(el) for el in e.elements)

        # Anything else (lambda, match expr, ...) is public by default
        # in this slice. Mutable containers are handled separately: a
        # secret put into one via push / add / set taints the receiver
        # binding (see ``_check_ifc_container_mutation``), so the read
        # rules above inherit the now-secret receiver label.
        return L.PUBLIC

    # ---- implicit flow / pc-label (roadmap S2.implicit) ----------

    def _pc_raise(self, *cond_exprs) -> str:
        """Raise (and return the previous) pc-label by joining in the
        labels of the given condition expressions. The caller stores
        the return value and restores ``self._pc_label`` to it once the
        guarded body is checked. A secret condition makes the pc SECRET
        for the body, so a public sink inside leaks the one bit of
        whether the branch was taken (roadmap S2.implicit)."""
        prev = self._pc_label
        self._pc_label = L.join_all(
            [prev] + [self._label_of(c) for c in cond_exprs]
        )
        return prev

    # ---- constant-time enforcement (roadmap S4) ------------------

    def _ct_reject(self, label: str, pos, what: str) -> None:
        """In a ``@constant_time`` function, a control-flow decision on
        a @secret value leaks the secret through timing (CWE-208).
        Reject it. No-op outside a constant-time function or for a
        public condition."""
        if (
            getattr(self, "_constant_time", False)
            and L.normalize(label) == L.SECRET
        ):
            self._err(
                f"constant-time violation: {what} depends on a @secret "
                f"value, which leaks it through timing. A @constant_time "
                f"function must not branch on secret data; rewrite it "
                f"branchless (e.g. a constant-time select / compare).",
                pos,
            )

    def _check_ct_index(self, e: A.Index) -> None:
        """In a ``@constant_time`` function, indexing with a @secret
        value leaks it through data-dependent memory access (cache
        timing). Reject it."""
        if (
            getattr(self, "_constant_time", False)
            and L.normalize(self._label_of(e.index)) == L.SECRET
        ):
            self._err(
                "constant-time violation: indexing with a @secret value "
                "leaks it through data-dependent memory access. A "
                "@constant_time function must not use a secret as an index.",
                e.pos,
            )

    def _check_ct_method_index(self, e: A.MethodCall, recv_ty) -> None:
        """Method-call form of the index check: ``list.get(secret)`` /
        ``map.get(secret)`` / ``set.contains(secret)`` /
        ``str.char_at(secret)`` in a ``@constant_time`` function is a
        data-dependent lookup (the table-lookup timing side channel)."""
        if not getattr(self, "_constant_time", False):
            return
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        idx_args = _CT_INDEX_METHODS.get((cap_name, e.method))
        if not idx_args:
            return
        for idx in idx_args:
            if idx < len(e.args) and \
                    L.normalize(self._label_of(e.args[idx])) == L.SECRET:
                self._err(
                    f"constant-time violation: {cap_name}.{e.method} with a "
                    f"@secret index / key leaks it through data-dependent "
                    f"memory access (the table-lookup timing side channel). "
                    f"A @constant_time function must not look up by a secret.",
                    e.pos,
                )
                return

    # ---- declassify (roadmap S2.5) -------------------------------

    def _is_declassify_call(self, e: A.Expr) -> bool:
        """True if ``e`` is a call to the built-in ``declassify``.
        Guarded by the binding's built-in position so a user function
        that happens to be named ``declassify`` is not special-cased."""
        from ..builtins import BUILTIN_POS
        if not isinstance(e, A.Call):
            return False
        if not isinstance(e.callee, A.Ident) or e.callee.name != "declassify":
            return False
        sym = self.bindings.get(id(e.callee))
        return sym is not None and sym.pos == BUILTIN_POS

    def _check_declassify(self, e: A.Call, arg_tys: list):
        """Validate a ``declassify(value, reason: "...")`` call and
        return the value's type (declassify is identity on the value;
        only its security label changes -- to PUBLIC, set in
        ``_compute_label``).

        The shape is deliberately rigid so the SBOM can record a
        meaningful audit trail: exactly two arguments, the first the
        value (positional), the second a ``reason:`` named argument
        that must be a plain string literal. A no-op declassify (the
        value is not @secret) is flagged as a warning -- a dead
        security annotation is dangerous noise in a regulated SBOM.

        Args were already type-checked by ``_check_call`` (so their
        labels are in ``self._expr_labels``)."""
        value_ty = arg_tys[0] if arg_tys else None
        names = e.arg_names
        if len(e.args) != 2:
            self._err(
                "declassify takes exactly two arguments: the value and "
                "reason: \"...\" (a string literal recorded in the SBOM)",
                e.pos,
            )
            return value_ty
        if names[0] is not None:
            self._err(
                "declassify: the value is the first (positional) argument",
                e.args[0].pos,
            )
        if names[1] != "reason":
            self._err(
                "declassify: the second argument must be named "
                "reason: \"...\" so the SBOM can record why the "
                "disclosure is intended",
                e.args[1].pos,
            )
        elif not isinstance(e.args[1], A.StringLit):
            self._err(
                "declassify: reason must be a plain string literal (not "
                "an interpolation or a computed value) so it can be "
                "recorded verbatim in the SBOM",
                e.args[1].pos,
            )
        # A declassify of a value that is not secret is a no-op: the
        # annotation claims a disclosure that the data flow does not
        # actually contain. Warn so it does not mislead an auditor.
        if L.normalize(self._label_of(e.args[0])) != L.SECRET:
            self._warn_ifc(
                "declassify of a @public value is a no-op (the value is "
                "not @secret); remove it or re-check the data flow",
                e.pos,
            )
        return value_ty

    # ---- mutable-container taint (roadmap S2) --------------------

    def _check_ifc_container_mutation(self, e: A.MethodCall, recv_ty) -> None:
        """When a mutating method (``List.push`` / ``Set.add`` /
        ``Map.set``) is called with a @secret argument, raise the label
        of the receiver binding so the container is @secret from here
        on. Without this, ``let m = new_map(); m.set(k, secret); m.get(k)``
        would launder the secret back to public on the read.

        Only a plain identifier receiver is handled (the common case);
        a mutation through a more complex receiver expression is not
        tracked in this slice. The raise is monotonic (join), so it is
        sound under conditional / looping mutation: once tainted, the
        binding stays tainted."""
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        taint_args = _CONTAINER_MUTATORS.get((cap_name, e.method))
        if not taint_args:
            return
        if not isinstance(e.receiver, A.Ident):
            return
        incoming = L.join_all(
            self._label_of(e.args[idx])
            for idx in taint_args
            if idx < len(e.args)
        )
        if L.normalize(incoming) != L.SECRET:
            return
        sym = self.bindings.get(id(e.receiver))
        if sym is not None:
            sym.label = L.join(sym.label, L.SECRET)

    # ---- sink enforcement (roadmap S2.4) -------------------------

    def _check_ifc_sink(self, e: A.MethodCall, recv_ty) -> None:
        """If ``e`` calls a public-sink capability method with a
        ``@secret`` argument in a sink position, report a flow
        violation. Warn-then-enforce: a warning by default (so
        existing unlabelled code is unaffected and labelled code
        surfaces the disclosure), a hard error when the enclosing
        function opted into ``@strict_ifc``.

        The arguments were just typed by ``_check_method_call``, so
        their labels are already in ``self._expr_labels``."""
        if not isinstance(recv_ty, A.TypeName) and not _is_ty_name(recv_ty):
            return
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        sink_args = _PUBLIC_SINKS.get((cap_name, e.method))
        if not sink_args:
            return
        for idx in sorted(sink_args):
            if idx >= len(e.args):
                continue
            arg = e.args[idx]
            if L.normalize(self._label_of(arg)) != L.SECRET:
                continue
            msg = (
                f"information-flow: a @secret value reaches "
                f"{cap_name}.{e.method} (argument {idx + 1}), a public "
                f"sink that sends data out of the program. Route it "
                f"through declassify(value, reason: \"...\") if this "
                f"disclosure is intended."
            )
            if getattr(self, "_strict_ifc", False):
                self._err(msg, arg.pos)
            else:
                self._warn_ifc(msg, arg.pos)

        # Implicit control flow (roadmap S2.implicit): the sink fires
        # under a secret pc -- it is inside a branch whose condition is
        # @secret -- so the mere fact that it ran leaks whether that
        # branch was taken, independent of the argument labels.
        #
        # This is checked ONLY under ``@strict_ifc``. Implicit flows are
        # subtle and pervasive (any sink in a branch that matches on a
        # secret source trips one), and flagging them in the default
        # warn tier would be noisy and would undercut declassify: the
        # canonical ``match env.get(...) { Some(k) -> println(
        # declassify(k, ...)) }`` fix still leaks the one existence bit
        # via control flow, which is real but rarely what the user
        # cares about. So the default tier stays focused on the
        # high-value explicit DATA leaks; opting into ``@strict_ifc``
        # turns on full noninterference (explicit + implicit, as hard
        # errors) for code that needs the stronger guarantee.
        if (
            getattr(self, "_strict_ifc", False)
            and L.normalize(getattr(self, "_pc_label", L.PUBLIC)) == L.SECRET
        ):
            self._err(
                f"information-flow (strict): {cap_name}.{e.method} runs "
                f"under secret control flow (inside a branch whose "
                f"condition is @secret), which leaks whether that branch "
                f"was taken. Move the sink outside the secret-conditioned "
                f"branch so its execution does not depend on the secret.",
                e.pos,
            )

    def _warn_ifc(self, message: str, pos) -> None:
        """Record a non-fatal IFC warning (does not affect ``ok``).
        Mirrors ``_err`` but routes to ``self.warnings``."""
        from . import AnalysisError
        src = self.source
        fname = self.filename
        if pos.filename and pos.filename in self.sources:
            src = self.sources[pos.filename]
            fname = pos.filename
        self.warnings.append(AnalysisError(message, pos, src, fname))


def _is_ty_name(ty) -> bool:
    """True if ``ty`` is a TyName (the analyzer's resolved type), not
    the AST TypeName. Kept tolerant so the sink check works whether
    the receiver type is the resolved TyName or anything carrying a
    ``.name``."""
    return type(ty).__name__ == "TyName"


def _pattern_bound_names(pat: A.Pattern):
    """Yield every name a pattern binds, walking nested payloads,
    tuple elements, and struct fields. Wildcard / literal patterns
    bind nothing; or-patterns bind nothing in v0 (the parser forbids
    bindings inside alternatives)."""
    if isinstance(pat, A.IdentPat):
        yield pat.name
    elif isinstance(pat, A.VariantPat):
        for sub in pat.payloads:
            yield from _pattern_bound_names(sub)
    elif isinstance(pat, A.TuplePat):
        for sub in pat.elements:
            yield from _pattern_bound_names(sub)
    elif isinstance(pat, A.StructPat):
        for _field, sub in pat.fields:
            if sub is not None:
                yield from _pattern_bound_names(sub)
            else:
                yield _field
