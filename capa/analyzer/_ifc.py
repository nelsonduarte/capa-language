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
receiver's label. Structs additionally carry a per-field label map so
reading a public field of a struct that also holds a secret field is
not over-tainted (see the per-field section below for the precision
rules and the known pre-existing limitations); lists / tuples / maps
remain whole-aggregate. The flow is intra-procedural (crossing a
function boundary still relies on an explicit ``@secret`` parameter).
"""

from __future__ import annotations

from typing import Optional

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

# Operators whose latency depends on operand values on the targets we
# emit (the variable-latency divider, CWE-208). A @secret operand of any
# of these leaks through timing. Add the next variable-time operator
# here, and ``_check_ct_arith`` picks it up with no further change.
_VARIABLE_TIME_OPS: frozenset[str] = frozenset({"/", "%"})


class _IfcMixin:
    def _label_expr(self, e: A.Expr) -> str:
        """Compute and record the security label of ``e`` from its
        already-labelled children, returning it. Called by
        ``_check_expr`` right after typing, so child labels are
        present. The result is stored in ``self._expr_labels``."""
        label = self._compute_label(e)
        self._expr_labels[id(e)] = label
        self._record_field_map(e)
        self._mark_escapes_for(e)
        return label

    def _mark_escapes_for(self, e: A.Expr) -> None:
        """Mark struct bindings that ESCAPE through ``e`` (roadmap S2
        per-field soundness). A struct passed whole to a call, stored in
        an aggregate / sub-struct, or indexed-through can be mutated or
        aliased beyond what intraprocedural per-field tracking can see,
        so we drop its precise map (reads fall back to the whole-value
        label). Field READS that select a leaf do NOT escape -- handled
        inside ``_mark_struct_escape``."""
        if isinstance(e, A.Call):
            for a in e.args:
                self._mark_struct_escape(a)
        elif isinstance(e, A.MethodCall):
            # A user method takes ``self`` by reference and may MUTATE a
            # field of the receiver (``self.f = secret``); structs are
            # reference types, so that mutation is visible through the
            # binding afterwards. Per-field tracking cannot follow into
            # the callee in this slice, so escape the receiver binding --
            # later field reads through it fall back to the conservative
            # whole-value label. (A FieldAccess receiver that selects a
            # leaf does not escape; ``_mark_struct_escape`` handles the
            # leaf-vs-struct distinction and escapes the root only when
            # the receiver denotes a struct value.)
            self._mark_struct_escape(e.receiver)
            for a in e.args:
                self._mark_struct_escape(a)
        elif isinstance(e, A.StructLit):
            for _name, v in e.fields:
                self._mark_struct_escape(v)
        elif isinstance(e, (A.ListLit, A.TupleLit)):
            for el in e.elements:
                self._mark_struct_escape(el)
        elif isinstance(e, A.Index):
            self._mark_struct_escape(e.receiver)

    def _record_field_map(self, e: A.Expr) -> None:
        """Record the per-field label map for a struct-typed expression
        in ``self._expr_field_labels`` (roadmap S2 per-field precision),
        leaving non-struct expressions untouched. Two sources:

        * a struct LITERAL carries the map of its field values;
        * a field-read CHAIN that lands on a tracked struct sub-value
          carries that sub-value's nested map (so ``outer.inner`` can be
          read field-by-field downstream).

        Only stores a map; the collapsed label is already in
        ``_expr_labels`` and remains the sound fallback."""
        if isinstance(e, A.StructLit):
            self._expr_field_labels[id(e)] = self._struct_lit_field_map(e)
            return
        if isinstance(e, A.FieldAccess):
            node = self._precise_field_label(e)
            if isinstance(node, dict):
                self._expr_field_labels[id(e)] = node

    def _label_of(self, e: A.Expr) -> str:
        """The recorded label of an already-visited expression, or
        PUBLIC if it has none (e.g. a node the walk doesn't label)."""
        return self._expr_labels.get(id(e), L.PUBLIC)

    # ---- per-field IFC precision (roadmap S2) --------------------
    #
    # A struct-typed value carries, besides its collapsed whole-value
    # label, a per-field label map ``{field: label_or_submap}`` (nested
    # for nested structs; leaves are label strings). Construction
    # records it; a field READ on a tracked, non-escaped binding reads
    # the precise field label instead of the conservative whole-value
    # join; a field STORE raises that field's label monotonically. The
    # collapsed label is always kept correct in parallel and is the
    # sound fallback used the moment precision cannot apply (escape /
    # aliasing / unknown shape).
    #
    # KNOWN PRE-EXISTING LIMITATIONS (false negatives). All three are
    # present at HEAD and are NOT introduced by per-field precision;
    # they are recorded here so the field-level reads above are not
    # mistaken for full guarantees:
    #   (a) cross-function self-mutation: a callee that mutates a field
    #       of a struct passed to it as a parameter is tracked only at
    #       whole-value granularity, not propagated back per field (the
    #       deferred cross-function-self-mutation slice).
    #   (b) embed-then-mutate staleness: a bare struct binding embedded
    #       into another struct literal snapshots its field labels at
    #       construction time, so a later mutation of the still-live
    #       source binding is not re-propagated to reads through the
    #       embedding.
    #   (c) implicit flow via a public assignment performed under a
    #       secret pc that escapes the conditioned branch (pre-existing
    #       for scalars too, not specific to structs).

    def _field_map_of(self, e: A.Expr) -> Optional[dict]:
        """The recorded per-field label map of a struct-typed
        expression, or ``None`` if it has none."""
        return self._expr_field_labels.get(id(e))

    def _struct_root_sym(self, e: A.Expr):
        """If ``e`` is an Ident-rooted, statically-resolvable chain of
        struct fields (``b``, ``b.inner``, ...), return its ROOT
        Symbol; else ``None``. Used to find the binding whose per-field
        map governs a field access / escape."""
        if isinstance(e, A.Ident):
            return self.bindings.get(id(e))
        if isinstance(e, A.FieldAccess):
            return self._struct_root_sym(e.receiver)
        return None

    def _field_path_from_root(self, e: A.Expr) -> Optional[list]:
        """The list of field names from the root binding down to ``e``
        (``b`` -> ``[]``, ``b.inner.x`` -> ``["inner", "x"]``), or
        ``None`` if ``e`` is not an Ident-rooted field chain."""
        if isinstance(e, A.Ident):
            return []
        if isinstance(e, A.FieldAccess):
            base = self._field_path_from_root(e.receiver)
            if base is None:
                return None
            return base + [e.field_name]
        return None

    def _precise_field_label(self, e: A.FieldAccess):
        """Try to read the precise per-field label for a field-access
        chain on a TRACKED, NON-ESCAPED binding. Returns the leaf label
        (a string) when the whole chain resolves through the binding's
        field map; a nested SUBMAP when the chain lands on a struct
        field (so the caller can keep tracking the sub-struct); or
        ``None`` when precision does not apply (no map, escaped, unknown
        field, dynamic receiver) and the caller must fall back to the
        conservative whole-value label.

        SOUNDNESS: precision is used only when (1) the receiver chain is
        rooted at a simple binding, (2) that binding has a field map,
        (3) the binding has NOT escaped / been aliased, and (4) every
        field on the path is present in the map. Any failure -> ``None``
        -> whole-value fallback. Because the field map is mutated in
        place with monotonic joins (field store, and the post-if merge
        relies on the same in-place symbol carried across branches), a
        read sees the join over every path that reached it."""
        sym = self._struct_root_sym(e)
        if sym is None:
            return None
        if getattr(sym, "field_labels", None) is None:
            return None
        if id(sym) in self._escaped_struct_syms:
            return None
        path = self._field_path_from_root(e)
        if not path:  # the bare binding itself, or unresolvable
            return None
        node = sym.field_labels
        for name in path:
            if not isinstance(node, dict) or name not in node:
                return None
            node = node[name]
        return node

    def _struct_lit_field_map(self, e: A.StructLit) -> dict:
        """Build the per-field label map for a struct literal: a field
        whose value is itself a struct LITERAL carries that literal's
        nested map (a fresh value with no outside aliases, so precise
        sub-field tracking is sound); any other field -- including a
        bare struct binding embedded whole (``S { inner: b }``), which
        SHARES identity with ``b`` (reference semantics) and could go
        stale on a later mutation of ``b`` -- collapses to the value's
        whole-value label. This keeps nested precision only where it is
        provably alias-free."""
        out: dict = {}
        for name, v in e.fields:
            if isinstance(v, A.StructLit):
                out[name] = self._deep_collapse_or_map(v)
            else:
                out[name] = self._label_of(v)
        return out

    def _deep_collapse_or_map(self, v: A.StructLit) -> dict:
        """The recorded nested map for a struct literal (already built
        when ``v`` was labelled)."""
        sub = self._field_map_of(v)
        return sub if sub is not None else self._struct_lit_field_map(v)

    def _collapse_field_map(self, node) -> str:
        """The collapsed whole-value label of a (possibly nested) field
        map: the join of every leaf label. Used to keep the collapsed
        label in sync with the structured one (e.g. after a store)."""
        if isinstance(node, dict):
            return L.join_all(self._collapse_field_map(v) for v in node.values())
        return L.normalize(node)

    def _mark_struct_escape(self, e: A.Expr) -> None:
        """Mark every tracked struct binding USED AS A WHOLE VALUE
        anywhere inside ``e`` as escaped, so later field reads through it
        fall back to the conservative whole-value label. Call this at
        every escape site: a call/method argument, a return value, an
        aggregate element, a match scrutinee, an index, or an aliasing
        bind (``let y = x``).

        A field READ off a struct that lands on a LEAF (a non-struct
        field) does NOT escape the binding: only that scalar leaves, and
        its own label governs it. But a field chain that denotes a STRUCT
        sub-value used wholesale DOES escape the root binding, because
        the sub-struct shares identity with the parent (structs are
        reference types: a later mutation through the escaped sub-struct
        is visible through the parent). Conservative throughout: when in
        doubt, escape the root."""
        if e is None:
            return
        if isinstance(e, A.Ident):
            sym = self.bindings.get(id(e))
            if sym is not None and getattr(sym, "field_labels", None) is not None:
                self._escaped_struct_syms.add(id(sym))
            return
        if isinstance(e, A.FieldAccess):
            # A field chain in a value position. If it resolves to a
            # struct sub-value (its per-field map is tracked), escape the
            # root binding. If it resolves to a leaf, it does not escape
            # -- but the receiver chain itself must still be walked for
            # other escaping uses nested in it (rare). We only treat the
            # chain as a leaf read when its precise label is a string.
            node = self._precise_field_label(e)
            if isinstance(node, dict):
                root = self._struct_root_sym(e)
                if root is not None:
                    self._escaped_struct_syms.add(id(root))
            elif node is None:
                # Untracked / already-escaped receiver: nothing precise
                # to protect; the whole-value rule already governs it.
                pass
            return
        # Recurse into the sub-expressions that carry struct values in a
        # value position. A struct literal that stores a binding whole
        # into a field escapes that binding.
        if isinstance(e, A.StructLit):
            for _name, v in e.fields:
                self._mark_struct_escape(v)
            return
        if isinstance(e, (A.ListLit, A.TupleLit)):
            for el in e.elements:
                self._mark_struct_escape(el)
            return
        if isinstance(e, A.Call):
            for a in e.args:
                self._mark_struct_escape(a)
            return
        if isinstance(e, A.MethodCall):
            self._mark_struct_escape(e.receiver)
            for a in e.args:
                self._mark_struct_escape(a)
            return
        if isinstance(e, A.Index):
            self._mark_struct_escape(e.receiver)
            self._mark_struct_escape(e.index)
            return
        if isinstance(e, A.Try):
            self._mark_struct_escape(e.expr)
            return

    def _join_decl_and_value_label(self, decl_label, value: A.Expr) -> str:
        """The label a binding receives: the join of an explicit
        ``@secret``/``@public`` annotation (``decl_label``, may be
        ``None``) and the label already computed for its RHS value.
        So ``let x: @secret Int = 1`` is secret by annotation, and
        ``let y = secret_x`` is secret by flow -- both surface here.

        Under ``@strict_ifc`` the current pc-label is also joined in: a
        value assigned under a secret control-flow context (inside a
        secret-conditioned branch / loop) becomes secret, so the classic
        implicit channel ``var x = ...; if secret { x = ... }; sink(x)``
        is caught. The join is monotonic (it can only RAISE a label),
        and it is gated to strict so the default tier's value labels are
        unchanged (the design keeps implicit flows out of the default
        warn tier; see ``_check_ifc_sink``)."""
        return self._join_pc_if_strict(L.join(decl_label, self._label_of(value)))

    def _join_pc_if_strict(self, label: str) -> str:
        """Monotonically join the current pc-label into ``label`` when
        ``@strict_ifc`` is active; return ``label`` unchanged otherwise.
        The single place implicit-flow taint enters an ASSIGNED label, so
        the gating (and the default-tier invariance it guarantees) lives
        in one spot. Never lowers a label -- ``L.join`` is the lattice
        least-upper-bound."""
        if not getattr(self, "_strict_ifc", False):
            return label
        return L.join(label, getattr(self, "_pc_label", L.PUBLIC))

    def _label_binding(self, name: str, decl_label, value: A.Expr) -> None:
        """Set the IFC label on the in-scope ``Symbol`` for ``name``
        to the join of its annotation and its RHS value's label.
        Used by ``_check_let`` after the pattern is bound.

        Per-field precision (roadmap S2): if the RHS is a struct whose
        field map is statically known (a struct literal or a precise
        field-read of a sub-struct), copy that map onto the binding so
        later field reads through ``name`` are precise. A bare-identifier
        RHS (``let y = x``) is an ALIAS: structs are reference types, so
        ``y`` and ``x`` share identity; tracking would go stale on a
        mutation through either, so we DO NOT copy the map and we mark
        the source binding escaped (handled at the let site). The
        binding's field map is also skipped when an explicit @secret
        annotation raises the whole value -- the collapsed label already
        covers it and a per-field map could under-report."""
        sym = self.scope.lookup_local(name)
        if sym is None:
            return
        sym.label = self._join_decl_and_value_label(decl_label, value)
        fmap = self._field_map_of(value)
        if (
            fmap is not None
            and L.normalize(decl_label) != L.SECRET
            and not isinstance(value, A.Ident)
            and not isinstance(value, A.FieldAccess)
        ):
            # Deep-copy so a later store on this binding does not mutate
            # the literal's recorded map (shared dicts would alias).
            sym.field_labels = _deepcopy_field_map(fmap)

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
            # Per-field precision (roadmap S2): when the receiver is a
            # TRACKED, NON-ESCAPED binding whose field map resolves the
            # whole access path, use the precise field label -- which may
            # be narrower than the struct's whole-value join. A leaf
            # resolves to its label; a struct-valued field resolves to a
            # submap, whose collapsed label is the right whole-value for
            # the sub-struct. Any failure (no map, escaped, aliased,
            # unknown field, dynamic receiver) falls back to the
            # conservative receiver label -- the original, sound rule.
            node = self._precise_field_label(e)
            if node is not None:
                if isinstance(node, dict):
                    return self._collapse_field_map(node)
                return L.normalize(node)
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

    def _check_ct_arith(self, e: A.BinOp) -> None:
        """In a ``@constant_time`` function, division and modulo run on
        the CPU's variable-latency divider: their timing depends on the
        operand values (CWE-208), so a @secret operand leaks through
        timing. This holds for both integer (``idiv``) and floating
        (``divsd``) division. Reject ``/`` and ``%`` when either operand
        is secret. (Add / subtract / multiply are fixed-latency on the
        targets we emit, so they stay allowed.)"""
        if not getattr(self, "_constant_time", False):
            return
        if e.op not in _VARIABLE_TIME_OPS:
            return
        if (
            L.normalize(self._label_of(e.left)) == L.SECRET
            or L.normalize(self._label_of(e.right)) == L.SECRET
        ):
            self._err(
                f"constant-time violation: {e.op!r} on a @secret operand "
                f"leaks it through timing (division and modulo run on the "
                f"variable-latency divider). A @constant_time function "
                f"must avoid variable-time arithmetic on secret data.",
                e.pos,
            )

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

    def _ifc_alias_link(self, new_sym, src_expr: A.Expr) -> None:
        """Record that ``new_sym`` aliases the struct binding named by
        ``src_expr`` (a bare Ident or field chain rooted at a struct
        binding), so a later field store through EITHER raises the
        collapsed label of BOTH (structs are reference types). No-op
        unless the source resolves to a struct-typed binding. The two
        bindings join a shared alias group; a store on any member taints
        the whole group (see ``_ifc_field_store``)."""
        if new_sym is None:
            return
        src = self._struct_root_sym(src_expr)
        if src is None:
            return
        from . import SymbolKind
        if new_sym.kind not in (SymbolKind.LOCAL, SymbolKind.LOCAL_VAR):
            return
        # Only link struct-typed bindings (a struct has fields; cheap
        # check via the resolved type name's struct symbol).
        if not self._is_struct_binding(src):
            return
        group = self._struct_aliases.get(id(src))
        if group is None:
            group = [src]
            self._struct_aliases[id(src)] = group
        if new_sym not in group:
            group.append(new_sym)
        self._struct_aliases[id(new_sym)] = group
        # Seed the new binding's collapsed label from the source so an
        # already-secret aliased value stays secret through the alias.
        new_sym.label = L.join(getattr(new_sym, "label", None),
                               getattr(src, "label", None))

    def _is_struct_binding(self, sym) -> bool:
        """True if ``sym``'s type resolves to a user struct type, so it
        is a candidate for per-field tracking / reference-aliasing."""
        from . import SymbolKind
        from ..typesys import TyName
        ty = getattr(sym, "ty", None)
        if not isinstance(ty, TyName):
            return False
        tsym = self.global_scope.lookup(ty.name)
        return tsym is not None and tsym.kind == SymbolKind.TYPE_STRUCT

    def _ifc_field_store(self, target: A.FieldAccess, value: A.Expr) -> None:
        """A field store ``p.f = x`` (or a nested ``p.a.b = x``) raises
        that field's per-field label MONOTONICALLY (join with the
        incoming value's label), and keeps the binding's collapsed
        whole-value label in sync. Monotonic so it is sound under
        conditional / looping stores: once a field is secret it stays
        secret, and a store on one path is not lowered on another (the
        same Symbol object is carried across if/while branches, so the
        post-merge map is the join over all paths).

        Only applies to a tracked, NON-ESCAPED binding whose field map
        already resolves the path's prefix; otherwise the collapsed
        whole-value label still rises (handled below) so the store can
        never make a value LESS secret than the conservative rule."""
        root = self._struct_root_sym(target)
        # Roadmap S2.implicit (strict only): a field stored under a secret
        # pc joins pc into the stored field's label, so a field made
        # secret only by the control-flow context it is written in is
        # tracked too (the struct analogue of the scalar implicit-assign
        # channel). Folding pc into ``incoming`` here applies it uniformly
        # to every store path below (alias group, whole-value fallback,
        # per-field map). Strict-gated and monotonic, so the default
        # tier's field labels are unchanged and a label is never lowered.
        incoming = self._join_pc_if_strict(self._label_of(value))
        if root is None:
            return
        # Aliasing soundness: if this binding is in an alias group
        # (``var b2 = b``), a store through ANY member is visible through
        # all of them (structs are reference types). Per-field tracking
        # cannot model that precisely, so taint the whole group at
        # WHOLE-VALUE granularity and escape every member -- conservative
        # (the aliased-mutation leak stays flagged), never under-reports.
        group = self._struct_aliases.get(id(root))
        if group is not None:
            for member in group:
                member.label = L.join(getattr(member, "label", None), incoming)
                self._escaped_struct_syms.add(id(member))
            return
        # Always keep the collapsed label monotonically correct: a store
        # of a secret into any field of the binding makes the whole value
        # at least that secret. This preserves the pre-existing
        # whole-value soundness even when per-field tracking is absent.
        if getattr(root, "field_labels", None) is None or \
                id(root) in self._escaped_struct_syms:
            root.label = L.join(getattr(root, "label", None), incoming)
            return
        path = self._field_path_from_root(target)
        if not path:
            root.label = L.join(getattr(root, "label", None), incoming)
            return
        node = root.field_labels
        for name in path[:-1]:
            nxt = node.get(name) if isinstance(node, dict) else None
            if not isinstance(nxt, dict):
                # The store reaches into something not tracked as a
                # struct sub-map; fall back to raising the whole value.
                root.label = L.join(getattr(root, "label", None), incoming)
                return
            node = nxt
        leaf = path[-1]
        sub = self._field_map_of(value)
        if sub is not None:
            # Storing a whole struct into a field: keep its sub-map but
            # join it monotonically with any existing tracking.
            old = node.get(leaf)
            node[leaf] = _join_field_map(old, _deepcopy_field_map(sub))
        else:
            old = node.get(leaf)
            node[leaf] = L.join(self._collapse_field_map(old) if old is not None
                                else L.PUBLIC, incoming)
        root.label = L.join(getattr(root, "label", None),
                            self._collapse_field_map(root.field_labels))

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

    # ---- cross-function sink-parameter flow (roadmap S2.6) -------

    def _check_ifc_call_summary(
        self, e: A.Call, sym, perm: list[int],
    ) -> None:
        """At a user free-function call, flag any @secret argument
        bound to a parameter that reaches a public sink inside the
        callee (its sink-reaching parameter set, computed to a
        fixpoint in ``_ifc_summary``). Warn-then-enforce, mirroring
        the intra-procedural sink check.

        ``perm`` is the named-argument permutation: ``e.args[perm[i]]``
        is the argument bound to the callee's i-th explicit parameter
        (the same order ``sym.param_names`` uses, ``self``-stripped for
        free functions). The summary's parameter indices are over the
        full parameter list, which for a free function equals the
        explicit list, so no shift is needed here."""
        key = ("fun", sym.name)
        sink_params = self._ifc_summaries.get(key)
        if not sink_params:
            return
        for param_idx, arg_idx in enumerate(perm):
            if param_idx not in sink_params:
                continue
            if arg_idx >= len(e.args):
                continue
            arg = e.args[arg_idx]
            if L.normalize(self._label_of(arg)) != L.SECRET:
                continue
            pname = (
                sym.param_names[param_idx]
                if param_idx < len(sym.param_names)
                else f"argument {arg_idx + 1}"
            )
            self._emit_ifc_call_leak(repr(sym.name), pname, arg.pos)

    def _check_ifc_method_call_summary(
        self, e: A.MethodCall, type_sym, method_sym,
        recv_ty, perm: list[int],
    ) -> None:
        """At a user method call, flag a @secret receiver or argument
        bound to a sink-reaching parameter of the callee.

        Parameter index 0 in the summary is ``self`` (the receiver);
        the explicit parameters follow. ``perm`` maps the i-th
        explicit parameter to ``e.args[perm[i]]`` (``self``-stripped,
        as ``method_sym.param_names`` is).

        Two receiver shapes:

        * A statically-known CONCRETE receiver type whose exact
          ``("method", T, method)`` summary key is present: use that
          one summary (precise, no over-approximation).

        * A TRAIT- / capability-typed receiver (the call dispatches
          DYNAMICALLY, so the concrete impl is not known statically),
          or a concrete receiver whose exact key is absent: fall back
          to the UNION over every concrete impl type that defines a
          method of this name. A parameter index counts as
          sink-reaching if it is sink-reaching in ANY candidate impl.
          This mirrors the by-name over-approximation the summary
          BUILDER uses for a not-statically-known receiver, so the
          call site never under-reports a leak (sound over-approx)."""
        callee_name = f"{recv_ty.name}.{e.method}"
        exact_key = ("method", recv_ty.name, e.method)

        # A trait/capability-typed receiver dispatches dynamically: the
        # concrete impl is not known statically, so the precise exact
        # key (which is keyed by the IMPL type) does not apply -- it is
        # the TRAIT name. Over-approximate across every impl method of
        # this name. Also fall back when the exact key is simply absent.
        from . import SymbolKind
        recv_is_dynamic = type_sym is not None and getattr(
            type_sym, "kind", None,
        ) in (SymbolKind.TRAIT, SymbolKind.CAPABILITY)

        # Precise path: a statically-known CONCRETE receiver whose exact
        # summary KEY is present. Use that one summary verbatim -- even
        # when it is empty (the method does not sink the param), which
        # is the precision case: another unrelated type's same-named
        # method sinking must NOT taint this concrete call.
        if not recv_is_dynamic and exact_key in self._ifc_summaries:
            sink_params = self._ifc_summaries[exact_key]
        else:
            from ._ifc_summary import methods_by_name
            grouping = methods_by_name(self._ifc_summaries)
            sink_params = set()
            for key in grouping.get(e.method, ()):
                sink_params |= self._ifc_summaries.get(key, frozenset())
        if not sink_params:
            return

        has_self = getattr(method_sym, "has_self", False)
        # Receiver = parameter index 0 when the method takes ``self``.
        if has_self and 0 in sink_params:
            if L.normalize(self._label_of(e.receiver)) == L.SECRET:
                self._emit_ifc_call_leak(
                    repr(callee_name), "self (the receiver)", e.receiver.pos,
                )
        for local_idx, arg_idx in enumerate(perm):
            full_idx = local_idx + 1 if has_self else local_idx
            if full_idx not in sink_params:
                continue
            if arg_idx >= len(e.args):
                continue
            arg = e.args[arg_idx]
            if L.normalize(self._label_of(arg)) != L.SECRET:
                continue
            pname = (
                method_sym.param_names[local_idx]
                if local_idx < len(method_sym.param_names)
                else f"argument {arg_idx + 1}"
            )
            self._emit_ifc_call_leak(repr(callee_name), pname, arg.pos)

    def _emit_ifc_call_leak(self, callee: str, param: str, pos) -> None:
        """Emit the cross-function sink-parameter diagnostic: a @secret
        value passed to a parameter that reaches a public sink inside
        the callee. Warn by default, hard error under ``@strict_ifc``,
        matching the intra-procedural tier."""
        msg = (
            f"information-flow: a @secret value is passed to {callee} as "
            f"{param}, which reaches a public sink inside {callee} (it "
            f"sends data out of the program). Route it through "
            f"declassify(value, reason: \"...\") if this disclosure is "
            f"intended."
        )
        if getattr(self, "_strict_ifc", False):
            self._err(msg, pos)
        else:
            self._warn_ifc(msg, pos)

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


def _deepcopy_field_map(node):
    """Recursively copy a per-field label map so a binding's map is
    independent of the source expression's (later stores must not alias
    back into the literal's recorded map)."""
    if isinstance(node, dict):
        return {k: _deepcopy_field_map(v) for k, v in node.items()}
    return node


def _join_field_map(a, b):
    """Monotonic join of two per-field label maps (or leaf labels):
    field-wise join where both are maps, lattice join where either is a
    leaf. Used when a field store overwrites a struct-valued field --
    the result is never less secret than what was there before."""
    if a is None:
        return b
    if b is None:
        return a
    if isinstance(a, dict) and isinstance(b, dict):
        out = dict(a)
        for k, v in b.items():
            out[k] = _join_field_map(out.get(k), v)
        return out
    # One (or both) is a leaf: collapse both and join.
    def _collapse(n):
        if isinstance(n, dict):
            return L.join_all(_collapse(v) for v in n.values())
        return L.normalize(n)
    return L.join(_collapse(a), _collapse(b))


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
