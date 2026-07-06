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

# Comparison operators that short-circuit byte-by-byte over a String /
# List operand on the targets we emit (CWE-208). ``==`` / ``!=`` on a
# String or List run ``$str_eq`` / element-wise compare with a
# length fast-path and an early exit at the first differing element, so
# the timing reveals the position of the first difference -- the classic
# MAC / token / password compare oracle. The ordering operators
# (``<`` ``<=`` ``>`` ``>=``) on a String are a lexicographic byte scan
# with the same early exit. A @secret operand of any of these in a
# ``@constant_time`` function is rejected (see ``_check_ct_compare``).
# Int / Float scalar comparison is single-cycle and stays allowed.
_SHORT_CIRCUIT_COMPARE_OPS: frozenset[str] = frozenset({
    "==", "!=", "<", "<=", ">", ">=",
})

# String / List methods that short-circuit byte-by-byte against a
# @secret operand, the method-call analogue of the comparison operators
# above. ``starts_with`` / ``ends_with`` / ``contains`` early-exit at the
# first mismatch; ``index_of`` scans for a match. Keyed
# ``(TypeName, method)`` -> the 0-based argument positions whose @secret
# label (or a @secret receiver) makes the call a timing oracle.
_CT_SHORT_CIRCUIT_METHODS: dict[tuple[str, str], set[int]] = {
    ("String", "starts_with"): {0},
    ("String", "ends_with"):   {0},
    ("String", "contains"):    {0},
    ("String", "index_of"):    {0},
    ("List",   "contains"):    {0},
}


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
    # KNOWN LIMITATIONS. Gaps (a) and (b) below were per-field
    # soundness false negatives; both are now CLOSED (recorded here so
    # the closure is documented alongside the precision rules). Gap (c)
    # remains.
    #   (a) cross-function self/param field-write: CLOSED. A callee that
    #       stores a secret-derived value into a field of one of its
    #       parameters (incl ``self``) now taints the caller's binding
    #       whole-value, via a modular FIELD-WRITE EFFECT computed to a
    #       fixpoint in ``_ifc_summary`` and propagated at the call site
    #       (``_check_ifc_call_field_effect`` /
    #       ``_check_ifc_method_call_field_effect``). Conservative:
    #       whole-value on the caller binding (no per-field cross-function
    #       precision), default-warn / strict-error like the other
    #       cross-function check. The field-write effect is recorded for
    #       EVERY store op, not just ``=``: an augmented store
    #       (``box.f += v``) joins the value into the old field and so can
    #       only raise the label, so recording it is sound (FN-1). The
    #       cross-function whole-value taint walks the binding's alias
    #       group, so an embed alias (see (b)) mutated across a function
    #       boundary still taints every aliased binding (FN-2).
    #   (b) embed-then-mutate staleness: CLOSED. A struct EXPRESSION
    #       embedded into another struct literal (``Outer { inner: b }``,
    #       or a field-access chain ``Outer { inner: m.inner }``) names a
    #       live heap object, so the outer binding is linked into the
    #       embedded source's alias group (``_ifc_link_embedded_structs``).
    #       A bare-Ident embed links into that binding's group directly; a
    #       field-chain embed links into the chain ROOT's group (an over-
    #       approximation: the outer is tainted whenever any part of the
    #       root's subtree is, which is sound). A later mutation of either
    #       binding -- intra-procedural (``_ifc_field_store``'s alias-group
    #       path) or cross-function (the field-write effect's alias-group-
    #       aware whole-value taint) -- taints the whole group whole-value.
    #       An embed whose origin cannot be resolved to a tracked binding
    #       escapes the outer binding whole-value rather than dropping it.
    #   (c) implicit flow via a public assignment performed under a
    #       secret pc that escapes the conditioned branch (pre-existing
    #       for scalars too, not specific to structs). Still open;
    #       handled under ``@strict_ifc`` via the pc-label machinery.

    def _declared_field_label(self, e: A.FieldAccess) -> str:
        """The information-flow label DECLARED on the field ``e`` reads,
        resolved from the receiver's struct type (roadmap S2). Returns
        the field's declared label (``secret`` / ``public``) when the
        receiver types to a user struct that declares that field with a
        label, else ``PUBLIC`` (unlabelled field, non-struct receiver,
        or unresolved type). Always a sound contribution: an unlabelled
        field adds the lattice bottom and so never over-taints.

        This is what makes ``type Emp { iban: @secret String }`` /
        ``e.iban`` produce a @secret value: the label travels with the
        struct's TYPE, independent of the receiver binding's per-field
        tracking, so it propagates through both an intra-procedural sink
        and a cross-function return (the summary builder mirrors this in
        ``_ifc_summary``)."""
        from . import SymbolKind
        from ..typesys import TyName
        recv_ty = self.types.get(id(e.receiver))
        if not isinstance(recv_ty, TyName):
            return L.PUBLIC
        sym = self.global_scope.lookup(recv_ty.name)
        if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
            return L.PUBLIC
        return L.normalize(sym.struct_field_labels.get(e.field_name))

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

        A ``public`` scrutinee leaves the whole-value binds untouched,
        so an explicit ``@secret`` annotation on the bound name (rare in
        a pattern, but possible via the surrounding ``let`` type) is not
        clobbered. Independently of the scrutinee label, a name bound to
        a struct field that is DECLARED ``@secret`` is labelled secret
        (``_label_pattern_field_secrets``): destructuring is a field
        read, so it must preserve the declared-field label exactly as a
        direct ``e.field`` access does -- a public scrutinee struct that
        holds a declared-@secret field still taints only the name bound
        to THAT field, never its public siblings."""
        self._label_pattern_field_secrets(pat)
        if L.normalize(scrutinee_label) != L.SECRET:
            return
        for name in _pattern_bound_names(pat):
            sym = self.scope.lookup_local(name)
            if sym is not None:
                sym.label = L.join(sym.label, L.SECRET)

    def _label_pattern_field_secrets(self, pat: A.Pattern) -> None:
        """Label every name bound to a DECLARED-``@secret`` struct field
        as secret, walking nested patterns. This is the pattern-binding
        analogue of ``_declared_field_label`` for a direct field read:
        ``let Emp { id, iban } = e`` (or the ``match`` form) must give
        ``iban`` the same @secret label that ``e.iban`` would, closing
        the destructuring laundering hole.

        Resolution is by the pattern's STRUCT TYPE NAME (``StructPat.
        type_name``), not by bound-name spelling, so a public ``iban``
        field of an UNRELATED struct is never tainted by a same-named
        @secret field elsewhere. Only the field's own name is consulted,
        so a public sibling field stays public. The raise is a monotonic
        join, never lowering an existing label."""
        if isinstance(pat, A.StructPat):
            labels = self._struct_decl_field_labels(pat.type_name)
            for fname, fpat in pat.fields:
                if L.normalize(labels.get(fname)) == L.SECRET:
                    # Shorthand ``{ iban }`` binds the field's own name;
                    # ``{ iban: alias }`` binds the sub-pattern's names.
                    if fpat is None:
                        self._raise_local_secret(fname)
                    else:
                        for name in _pattern_bound_names(fpat):
                            self._raise_local_secret(name)
                if fpat is not None:
                    self._label_pattern_field_secrets(fpat)
            return
        if isinstance(pat, A.VariantPat):
            for sub in pat.payloads:
                self._label_pattern_field_secrets(sub)
        elif isinstance(pat, A.TuplePat):
            for sub in pat.elements:
                self._label_pattern_field_secrets(sub)

    def _struct_decl_field_labels(self, type_name: str) -> dict:
        """``{field name: declared label}`` for the user struct
        ``type_name``, or an empty map when the name does not resolve to
        a struct (the binder reports the bad type separately). Mirrors
        ``_declared_field_label``'s resolution, but keyed by the
        pattern's explicit type name rather than the receiver's type."""
        from . import SymbolKind
        sym = self.global_scope.lookup(type_name)
        if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
            return {}
        return getattr(sym, "struct_field_labels", {}) or {}

    def _raise_local_secret(self, name: str) -> None:
        """Monotonically raise the in-scope local ``name``'s label to
        ``@secret`` (join, never lower)."""
        sym = self.scope.lookup_local(name)
        if sym is not None:
            sym.label = L.join(getattr(sym, "label", None), L.SECRET)

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
            # A field whose TYPE is declared ``@secret`` produces a
            # @secret value when READ (``type Emp { iban: @secret String
            # }``; reading ``e.iban`` yields secret), the struct-type
            # analogue of a ``@secret`` parameter. This declared label is
            # joined into whatever the flow rules below compute, so it is
            # never dropped -- closing the laundering hole where reading a
            # declared-secret field came out public. A field declared
            # @public (or unlabelled) contributes PUBLIC and so does not
            # over-taint a sibling-secret struct's public field.
            decl_label = self._declared_field_label(e)
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
                    return L.join(decl_label, self._collapse_field_map(node))
                return L.join(decl_label, L.normalize(node))
            return L.join(decl_label, self._label_of(e.receiver))

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
            # The callee's own label flows into the result: calling a
            # local binding that holds a @secret-capturing CLOSURE
            # produces a secret value (``let leak = fun () => s; leak()``).
            # A top-level function name carries no label, so this is a
            # no-op for ordinary calls and never over-taints them.
            base = L.join(
                self._callee_label(e.callee),
                L.join_all(self._label_of(a) for a in e.args),
            )
            # A closure passed inline as an argument and invoked inside the
            # callee can leak its captured secret too: a Fun-typed argument
            # contributes its capture label to the result (HOF case, e.g.
            # ``apply(fun () => s)``).
            base = L.join(base, self._call_arg_closure_label(e))
            # A callee that RETURNS a secret-derived value taints the
            # call result even when no argument is whole-value secret --
            # e.g. it reads a declared-@secret field of a struct argument
            # and returns it (cross-function return-secret effect).
            if self._call_returns_secret(e):
                return L.SECRET
            return base
        if isinstance(e, A.MethodCall):
            recv_ty = self.types.get(id(e.receiver))
            cap_name = getattr(recv_ty, "name", None)
            if cap_name is not None and (cap_name, e.method) in _SECRET_SOURCES:
                return L.SECRET
            # The result label follows the method's RETURN-EFFECT (which
            # sources flow into the returned value), NOT the whole-value
            # taint of the receiver: a method whose return derives only
            # from its arguments / a fresh response must NOT inherit the
            # receiver's secret fields (that was the false positive). The
            # receiver label contributes ONLY when ``self`` (param 0) is in
            # the return-effect, and an argument's label ONLY for a param
            # in the return-effect. The unconditional / declared-@secret
            # cases stay covered by ``_method_call_returns_secret`` ->
            # SECRET below, so laundering remains closed.
            if self._method_call_returns_secret(e, recv_ty):
                return L.SECRET
            return self._method_call_return_label(e, recv_ty)

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

        # An if-expression's value is the join of both branch values --
        # ``if c then s else "y"`` is secret iff either branch is. Under
        # ``@strict_ifc`` the condition's label joins in too (an implicit
        # flow: the chosen value reveals which branch ran, hence the
        # condition). A public-branches if stays public (no over-taint).
        if isinstance(e, A.IfExpr):
            branches = L.join(
                self._label_of(e.then_expr), self._label_of(e.else_expr),
            )
            return self._join_pc_if_strict_with(branches, e.cond)

        # A match-expression's value is the join of every arm body's label
        # (the value flows out of whichever arm is selected). Under
        # ``@strict_ifc`` the scrutinee's label joins in as the implicit
        # flow (which arm ran reveals the scrutinee). The pattern binds are
        # already tainted by ``_label_pattern_binds``, so an arm body that
        # uses a bound secret is secret here. All-public arms stay public.
        if isinstance(e, A.MatchExpr):
            arm_label = L.join_all(
                self._match_arm_body_label(arm) for arm in e.arms
            )
            return self._join_pc_if_strict_with(arm_label, e.scrutinee)

        # A lambda VALUE carries the join of the labels of the free
        # variables it captures (computed in ``_check_lambda``). A bare
        # ``fun () => s`` used as a value (assigned, passed, returned) is
        # secret iff it closes over a secret, so the secret is not laundered
        # through the closure boundary. The CALL of such a closure inherits
        # this via ``_callee_label`` / ``_call_arg_closure_label``.
        if isinstance(e, A.LambdaExpr):
            return self._lambda_capture_labels.get(id(e), L.PUBLIC)

        # Anything else is public by default. Mutable containers are
        # handled separately: a secret put into one via push / add / set
        # taints the receiver binding (see ``_check_ifc_container_mutation``),
        # so the read rules above inherit the now-secret receiver label.
        return L.PUBLIC

    def _join_pc_if_strict_with(self, label: str, cond: A.Expr) -> str:
        """Join ``cond``'s label into ``label`` only under ``@strict_ifc``
        -- the implicit-flow contribution for a branch/match selector. The
        default tier keeps value labels free of implicit flow (mirrors
        ``_join_pc_if_strict`` for assignments), so a public-branch
        if/match is never over-tainted by a secret condition in the
        default tier; strict opts into full noninterference."""
        if not getattr(self, "_strict_ifc", False):
            return label
        return L.join(label, self._label_of(cond))

    def _match_arm_body_label(self, arm: A.MatchArm) -> str:
        """The IFC label of a match arm's RESULT value. An expression-
        bodied arm is its expression's label. A block-bodied arm
        evaluates to its trailing bare expression (block-as-expression);
        a block with no trailing value yields Unit (public). A guard does
        not contribute to the produced VALUE (it only selects the arm; its
        implicit flow is covered by the scrutinee join under strict)."""
        body = arm.body
        if isinstance(body, A.Block):
            if body.stmts and isinstance(body.stmts[-1], A.ExprStmt):
                return self._label_of(body.stmts[-1].expr)
            return L.PUBLIC
        return self._label_of(body)

    # ---- closure capture labelling (roadmap S2) ------------------

    def _callee_label(self, callee: A.Expr) -> str:
        """The IFC label of a call's callee. For a bare-identifier callee
        bound to a local that holds a closure (``let leak = fun () => s``),
        this is the binding's label -- which carries the closure's captured
        secret. A top-level function symbol has no label, so this returns
        PUBLIC and ordinary calls are unaffected. A lambda literal callee
        (an immediately-invoked closure) reads its recorded capture label."""
        if isinstance(callee, A.Ident):
            sym = self.bindings.get(id(callee))
            if sym is not None and getattr(sym, "label", None):
                return L.normalize(sym.label)
            return L.PUBLIC
        if isinstance(callee, A.LambdaExpr):
            return self._lambda_capture_labels.get(id(callee), L.PUBLIC)
        return self._label_of(callee)

    def _call_arg_closure_label(self, e: A.Call) -> str:
        """The join of the capture labels of any CLOSURE LITERALS passed
        as arguments to ``e``. A higher-order call ``apply(fun () => s)``
        hands the callee a closure that captures a secret; invoking it
        inside ``apply`` and returning the result would launder ``s``, so
        the secret is reflected into the call result conservatively. A
        non-lambda argument contributes nothing here (its own label is
        already joined via ``base``)."""
        label = L.PUBLIC
        for a in e.args:
            if isinstance(a, A.LambdaExpr):
                label = L.join(
                    label, self._lambda_capture_labels.get(id(a), L.PUBLIC),
                )
        return label

    def _lambda_capture_label(self, e: A.LambdaExpr) -> str:
        """The join of the IFC labels of the FREE variables ``e``'s body
        captures from the enclosing scope. A lambda that closes over a
        @secret binding produces a secret value when CALLED, so the call
        site must inherit this (otherwise ``let leak = fun () => s; leak()``
        would launder a captured secret ``s`` back to public).

        A free variable is an identifier in the body whose name is NOT
        introduced by the lambda itself (its parameters or its inner
        ``let``/``var``/pattern binds). The labels of the free idents are
        already recorded (the body was just checked), so this is a pure
        read. Excluding the lambda's own locals avoids a false positive:
        a @secret PARAMETER taints the result only when the closure is
        CALLED WITH a secret argument, which the ordinary argument-label
        join at the call site already handles -- not a capture."""
        locals_: set[str] = set()
        for p in e.params:
            locals_.add(p.name)
        for stmt in self._lambda_body_stmts(e):
            self._collect_bound_names(stmt, locals_)
        label = L.PUBLIC
        for ident in self._lambda_free_idents(e.body, locals_):
            label = L.join(label, self._label_of(ident))
        return label

    def _lambda_body_result_label(self, e: A.LambdaExpr) -> str:
        """The IFC label of the value an INVOCATION of ``e`` produces --
        its body's result label. An expression-bodied lambda returns its
        expression; a block-bodied one returns its trailing bare
        expression (block-as-expression), or Unit (PUBLIC) when there is
        none. Unlike the capture label, this is what flows out of ``f()``,
        so a body that DECLASSIFIES its captured secret returns PUBLIC
        here -- the precise input to the invoke-sink-reaching boundary
        check, avoiding a false positive on a declassifying closure."""
        body = e.body
        if isinstance(body, A.Block):
            if body.stmts and isinstance(body.stmts[-1], A.ExprStmt):
                return self._label_of(body.stmts[-1].expr)
            return L.PUBLIC
        return self._label_of(body)

    def _sink_param_arg_label(self, arg: A.Expr, ptype):
        """The label to test for an argument bound to a SINK-REACHING
        parameter, or ``None`` when the boundary check does not apply.

        Two parameter shapes reach a sink inside the callee, and they need
        different labels:

        * A DATA parameter whose value flows to a sink: the argument's own
          whole-value label (the original cross-function S2.6 rule).
        * A FUN parameter the callee INVOKES and sinks the result of (the
          invoke-sink-reaching case): the label of what ``f()`` yields.
          For an INLINE closure literal that is its RESULT label (so a
          closure whose body DECLASSIFIES its captured secret is correctly
          public and not flagged). For a closure passed BY NAME whose
          binding denotes ONE CERTAIN lambda LITERAL -- a ``let`` bound to
          a lambda literal, or a ``var`` bound to a lambda literal at its
          declaration and NEVER REASSIGNED (``let f = fun () => secret;
          invoke(f)``) -- that same RESULT label is recovered from the
          binding (``_binding_result_label``), closing the two-hop leak
          while STILL seeing through an in-body declassify: a let-bound
          declassifying closure stays public and is not a false positive.

        KNOWN LIMITATIONS (documented false NEGATIVES that REMAIN). When
        the argument is a Fun-typed name whose PRECISE result label
        cannot be recovered with CERTAINTY, the check is SKIPPED
        (``None``) rather than falling back to the whole-value CAPTURE
        label -- the capture label cannot see through an in-body
        declassify and would raise a FALSE POSITIVE, the worst outcome.
        The skip stands for: a closure borne in a STRUCT FIELD
        (``s.thunk``); a Fun PARAMETER of the enclosing function re-passed
        onward; a binding whose RHS is NOT a lambda literal (e.g. the
        result of a call); and any ``var`` that is EVER REASSIGNED (even
        to another lambda literal) -- reassignment makes the denotation
        ambiguous, so it is skipped rather than joined, deliberately
        trading a residual false negative for ZERO false positive. Only
        the inline and the SINGLE-ASSIGNMENT ``let`` / ``var`` lambda-
        literal shapes -- the common and most dangerous ones -- are
        precise.

        The parameter kind is told apart by its declared TYPE: a ``TyFun``
        parameter is the invoke case, anything else the data case."""
        from ..typesys import TyFun
        if isinstance(ptype, TyFun):
            if isinstance(arg, A.LambdaExpr):
                return self._lambda_result_labels.get(id(arg), L.PUBLIC)
            if isinstance(arg, A.Ident):
                return self._binding_result_label(arg)
            return None
        return self._label_of(arg)

    def _record_binding_lambda(self, sym, value: A.Expr, fresh: bool) -> None:
        """Record, for the closure-by-name boundary check, the SINGLE
        lambda literal a binding denotes WITH CERTAINTY. ``fresh`` marks a
        ``let``/``var`` INTRODUCTION; ``fresh=False`` marks a ``var``
        reassignment.

        Only an introduction bound to a lambda LITERAL is recorded -- the
        binding then denotes exactly that one closure. ANY reassignment,
        of a lambda OR a non-lambda value, makes the denotation ambiguous
        and POISONS the record (stores ``None``): a ``var`` that is ever
        reassigned falls back to the documented skip, because precision
        can no longer be guaranteed and a false positive is the worst
        outcome (a residual false negative is preferred). A fresh
        non-lambda binding records nothing (no lambda to resolve)."""
        if sym is None:
            return
        if fresh:
            if isinstance(value, A.LambdaExpr):
                self._binding_lambdas[id(sym)] = value
            return
        # A reassignment (var only): the name may now denote a DIFFERENT
        # closure, so it is no longer resolvable to a single certain
        # lambda literal. Poison the record regardless of the RHS shape --
        # no join, no over-approximation, hence no false positive.
        self._binding_lambdas[id(sym)] = None

    def _binding_result_label(self, arg: A.Ident):
        """The RESULT label of the single lambda literal the name ``arg``
        denotes with certainty, or ``None`` when it cannot be recovered
        precisely (unknown binding, a reassigned/poisoned ``var``, or a
        binding whose RHS was not a lambda literal). Returning ``None``
        keeps the boundary check's documented skip -- it never falls back
        to a capture label, so a declassifying let-bound closure is not a
        false positive."""
        sym = self.bindings.get(id(arg))
        if sym is None:
            return None
        lam = self._binding_lambdas.get(id(sym))
        if lam is None:  # absent, or the ``None`` poison sentinel
            return None
        return self._lambda_result_labels.get(id(lam), L.PUBLIC)

    def _lambda_body_stmts(self, e: A.LambdaExpr):
        """The statement list of a block-bodied lambda, or empty for an
        expression-bodied one."""
        if isinstance(e.body, A.Block):
            return e.body.stmts
        return ()

    def _collect_bound_names(self, node, out: set) -> None:
        """Add every name a statement introduces into ``out`` (the
        lambda's local names, so they are not counted as captures). Covers
        ``let``/``var`` and the names a destructuring ``let`` binds; a
        nested lambda's own params are handled when that lambda is walked,
        so they are not collected here."""
        if isinstance(node, A.LetStmt):
            out.update(_pattern_bound_names(node.pattern))
        elif isinstance(node, A.VarStmt):
            out.add(node.name)

    def _lambda_free_idents(self, node, locals_: set):
        """Yield every ``A.Ident`` reachable from ``node`` whose name is
        not in ``locals_`` -- the free variables the lambda captures.
        Walks the expression / statement tree generically; does not
        descend into a NESTED lambda's body with the outer locals (a
        nested closure is its own scope and its captures are this
        lambda's captures only transitively, which the recursion below
        still surfaces because the nested body's free idents are walked
        with the SAME ``locals_`` -- sound: an over-approximation never
        under-reports a captured secret)."""
        import dataclasses
        if isinstance(node, A.Ident):
            if node.name not in locals_:
                yield node
            return
        if node is None or isinstance(node, str):
            return
        if dataclasses.is_dataclass(node):
            for f in dataclasses.fields(node):
                yield from self._lambda_free_idents(
                    getattr(node, f.name), locals_,
                )
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                yield from self._lambda_free_idents(x, locals_)

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

    def _check_ct_compare(self, e: A.BinOp) -> None:
        """In a ``@constant_time`` function, comparing a @secret String or
        List with ``==`` / ``!=`` / ``<`` / ``<=`` / ``>`` / ``>=`` leaks
        the secret through timing (CWE-208): the comparison short-circuits
        byte-by-byte (the Wasm ``$str_eq`` even has a length fast-path and
        an early exit), so the running time reveals the position of the
        first differing byte -- the classic MAC / token / password compare
        oracle. Reject it; the fix is a dedicated XOR-accumulate
        constant-time compare (e.g. ``capa_hash.strings_equal``).

        Int / Float scalar comparison is single-cycle on the targets we
        emit and stays allowed, so the check is scoped to String / List
        operands (the receiver-side types of the two operands)."""
        from ..typesys import TyName
        if not getattr(self, "_constant_time", False):
            return
        if e.op not in _SHORT_CIRCUIT_COMPARE_OPS:
            return
        left_secret = L.normalize(self._label_of(e.left)) == L.SECRET
        right_secret = L.normalize(self._label_of(e.right)) == L.SECRET
        if not (left_secret or right_secret):
            return
        # Scope to String / List operands; an Int / Float compare is
        # fixed-latency. Either operand typing to String / List makes the
        # compare a byte-scan (the other operand has the same type by the
        # type-checker's rules for ``==`` / ordering).
        lt = self.types.get(id(e.left))
        rt = self.types.get(id(e.right))
        names = {
            getattr(t, "name", None) for t in (lt, rt) if isinstance(t, TyName)
        }
        if not (names & {"String", "List"}):
            return
        self._err(
            f"constant-time violation: {e.op!r} on a @secret String / List "
            f"operand leaks it through timing -- the comparison "
            f"short-circuits byte-by-byte and reveals the position of the "
            f"first difference (the MAC / token compare oracle, CWE-208). "
            f"Use a dedicated constant-time compare (XOR-accumulate over "
            f"every byte with no early exit) instead of '=='.",
            e.pos,
        )

    def _check_ct_method_compare(self, e: A.MethodCall, recv_ty) -> None:
        """Method-call form of the constant-time compare check:
        ``s.starts_with(secret)`` / ``s.ends_with(secret)`` /
        ``s.contains(secret)`` / ``s.index_of(secret)`` /
        ``list.contains(secret)`` in a ``@constant_time`` function
        short-circuits byte-by-byte against the @secret operand, the same
        timing oracle ``==`` is. A @secret RECEIVER is equally unsafe (the
        scan walks the secret's bytes), so both the receiver and the
        listed argument positions are tested."""
        if not getattr(self, "_constant_time", False):
            return
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        arg_positions = _CT_SHORT_CIRCUIT_METHODS.get((cap_name, e.method))
        if arg_positions is None:
            return
        secret = L.normalize(self._label_of(e.receiver)) == L.SECRET
        if not secret:
            for idx in arg_positions:
                if idx < len(e.args) and \
                        L.normalize(self._label_of(e.args[idx])) == L.SECRET:
                    secret = True
                    break
        if not secret:
            return
        self._err(
            f"constant-time violation: {cap_name}.{e.method} on a @secret "
            f"operand leaks it through timing -- it short-circuits "
            f"byte-by-byte and reveals where the first difference is (the "
            f"compare oracle, CWE-208). Use a dedicated constant-time "
            f"compare (XOR-accumulate over every byte) instead.",
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
            self._warn(
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

    def _ifc_link_embedded_structs(self, new_sym, value: A.Expr) -> None:
        """Closes the embed-then-mutate staleness gap. When a bare
        struct IDENTIFIER ``b`` is embedded into a struct literal field
        (``let o = Outer { inner: b, ... }``), ``o.inner`` and ``b`` are
        the SAME heap object (structs are reference types), so a later
        mutation of the still-live ``b`` must be visible through ``o``.
        Link ``new_sym`` (``o``) into the alias group of every such
        embedded source binding, so a field store through ANY member
        taints the whole group whole-value (handled in
        ``_ifc_field_store``). Whole-value and conservative: tainting
        ``o`` whenever ``b`` is tainted is sound because they share
        identity. Nested struct LITERALS are fresh (no outside alias),
        so they are not linked.

        A non-identifier embed that is a field-access chain rooted at a
        tracked struct binding (``Outer { inner: m.inner }``) names the
        SAME heap object as ``m.inner``, so it must be linked too.
        ``m.inner`` cannot be its own alias-group root (the group keys on
        whole-binding identity, not a sub-path), so link ``new_sym`` into
        the ROOT binding's alias group (here ``m``). This over-
        approximates: ``o`` is tainted whenever ANY part of ``m``'s
        subtree is tainted, which is sound (never under-reports) because
        the embedded sub-object is part of that subtree. If the embedded
        value is some other shape (a call, an index, ...) whose root is
        not a resolvable tracked binding, escape the new binding whole-
        value so a later read of it cannot narrow -- never silently
        drop."""
        if new_sym is None or not isinstance(value, A.StructLit):
            return
        for _name, v in value.fields:
            if isinstance(v, A.Ident):
                src = self._struct_root_sym(v)
                if src is not None and self._is_struct_binding(src):
                    self._ifc_alias_link(new_sym, v)
            elif isinstance(v, A.FieldAccess):
                root = self._struct_root_sym(v)
                if root is not None and self._is_struct_binding(root):
                    # Link into the ROOT binding's group via a bare Ident
                    # for the root (``_ifc_alias_link`` resolves the root
                    # symbol). Over-approximate but sound.
                    self._ifc_alias_link(new_sym, v)
                elif self._is_struct_binding(new_sym):
                    # Embedded sub-struct whose origin we cannot resolve
                    # to a tracked binding: escape the outer binding so a
                    # later per-field read of it falls back to its
                    # (conservative) whole-value label instead of reading
                    # a stale precise label.
                    self._escaped_struct_syms.add(id(new_sym))

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
                self._warn(msg, arg.pos)

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

    def _check_ifc_panic_sink(self, e: A.Call) -> None:
        """``panic(message)`` writes its message to stderr, so it is a
        public sink exactly like ``Stdio.eprintln``: a ``@secret``
        message is a disclosure. Same warn-then-enforce tier as
        ``_check_ifc_sink`` (warning by default, hard error under
        ``@strict_ifc``), and the same implicit-flow rule under
        ``@strict_ifc`` (a panic in a secret-conditioned branch leaks
        whether the branch was taken through the abort itself).

        Called from ``_check_call`` only for the BUILTIN panic (a
        user function named ``panic`` shadows the builtin and is
        covered by the regular cross-function summary instead)."""
        if e.args and L.normalize(self._label_of(e.args[0])) == L.SECRET:
            msg = (
                f"information-flow: a @secret value reaches panic "
                f"(argument 1), a public sink that writes the message "
                f"to stderr. Route it through declassify(value, "
                f"reason: \"...\") if this disclosure is intended."
            )
            if getattr(self, "_strict_ifc", False):
                self._err(msg, e.args[0].pos)
            else:
                self._warn(msg, e.args[0].pos)
        if (
            getattr(self, "_strict_ifc", False)
            and L.normalize(getattr(self, "_pc_label", L.PUBLIC)) == L.SECRET
        ):
            self._err(
                f"information-flow (strict): panic runs under secret "
                f"control flow (inside a branch whose condition is "
                f"@secret), which leaks whether that branch was taken. "
                f"Move the panic outside the secret-conditioned branch "
                f"so its execution does not depend on the secret.",
                e.pos,
            )

    # ---- cross-function sink-parameter flow (roadmap S2.6) -------

    def _call_returns_secret(self, e: A.Call) -> bool:
        """True if the free function ``e`` calls returns a secret-derived
        value (cross-function return-secret effect): an unconditional
        internal secret (``INTERNAL_SECRET`` -- e.g. a declared-@secret
        field read returned, or ``env.get`` returned), or a return
        derived from a parameter whose bound argument here is @secret.
        Used to taint the call RESULT label so the secret is not
        laundered through a function boundary on return."""
        if not isinstance(e.callee, A.Ident):
            return False
        sources = self._ifc_return_effects.get(("fun", e.callee.name))
        if not sources:
            return False
        sym = self.bindings.get(id(e.callee))
        param_names = getattr(sym, "param_names", []) if sym is not None else []
        from ._ifc_summary import _bind
        perm = _bind(e.args, e.arg_names, param_names)
        return self._return_sources_fire(sources, perm, e.args)

    def _method_call_returns_secret(self, e: A.MethodCall, recv_ty) -> bool:
        """Method-call form of the return-secret check. Parameter index 0
        is ``self`` (the receiver); explicit parameters follow. Uses the
        same by-name over-approximation as the summary (a dynamic-dispatch
        receiver matches every impl method of this name), so a secret
        return is never missed across the boundary."""
        recv_name = getattr(recv_ty, "name", None)
        if recv_name is None:
            return False
        from ._ifc_summary import methods_by_name
        exact_key = ("method", recv_name, e.method)
        keys = ([exact_key] if exact_key in self._ifc_return_effects
                else methods_by_name(self._ifc_return_effects).get(e.method, ()))
        # Full-order arg list: receiver is index 0, explicit args follow.
        # ``self`` (param 0) maps to the receiver; explicit param i+1 maps
        # to explicit argument i (positional; the common case). The
        # dominant return-secret source for the field-read case is the
        # unconditional INTERNAL_SECRET sentinel, which fires regardless
        # of this mapping, so a positional approximation is sound.
        full_args = [e.receiver] + list(e.args)
        perm: dict = {0: 0}
        for i in range(len(e.args)):
            perm[i + 1] = i + 1
        for key in keys:
            sources = self._ifc_return_effects.get(key)
            if sources and self._return_sources_fire(sources, perm, full_args):
                return True
        return False

    def _is_trait_type(self, type_name: str) -> bool:
        """True if ``type_name`` resolves to a TRAIT (a dynamic-dispatch
        receiver). Only a trait receiver justifies the by-name union over
        every impl method of this name for the result label: a concrete
        receiver type (including a built-in container modelled as a
        struct, e.g. ``List``) must match an EXACT user-method key or it
        falls back to the conservative whole-value join, so a same-named
        user method cannot under-taint a built-in receiver's result."""
        from . import SymbolKind
        sym = self.global_scope.lookup(type_name)
        return sym is not None and sym.kind == SymbolKind.TRAIT

    def _method_call_return_label(self, e: A.MethodCall, recv_ty) -> str:
        """The result label of a USER method call, following the method's
        RETURN-EFFECT instead of the whole-value taint of the receiver.

        For each candidate method (by-name over-approximation, the same
        set ``_method_call_returns_secret`` consults) the result carries:
        the RECEIVER's label when ``self`` (param index 0) is in the
        return-effect, and an ARGUMENT's label when that argument's
        parameter index is in the return-effect. The unconditional /
        declared-@secret (``INTERNAL_SECRET``) case is handled by
        ``_method_call_returns_secret`` -> SECRET at the call site, so it
        is not re-tested here. UNION over every candidate.

        When the call resolves to NO user-method candidate (a built-in /
        stdlib method on a resolved type, or an unknown receiver), fall
        back to the conservative whole-value join of the receiver and all
        argument labels -- the original, sound rule -- so e.g. a read off
        a @secret container is still @secret."""
        from ._ifc_summary import methods_by_name
        conservative = L.join(
            self._label_of(e.receiver),
            L.join_all(self._label_of(a) for a in e.args),
        )
        recv_name = getattr(recv_ty, "name", None)
        keys: tuple = ()
        if recv_name is not None:
            exact_key = ("method", recv_name, e.method)
            if exact_key in self._ifc_return_effects:
                # Resolved to a concrete user method: use its effect.
                keys = (exact_key,)
            elif self._is_trait_type(recv_name):
                # A trait-typed (dynamic-dispatch) receiver: by-name union
                # over every impl method of this name, the sound
                # over-approximation. A concrete type WITHOUT an exact key
                # (a built-in container / a struct with no such impl
                # method) falls through to the conservative join below.
                keys = tuple(
                    methods_by_name(self._ifc_return_effects).get(
                        e.method, (),
                    )
                )
        # When the receiver is a BUILT-IN / non-user type (List, Map, Set,
        # String, a capability, ...), a same-named user method must NOT
        # narrow its result: the conservative whole-value join governs, so
        # a read off a @secret built-in receiver stays @secret. Narrowing
        # is applied only for a genuine user-method dispatch.
        if not keys:
            return conservative
        # Full-order arg labels: index 0 is the receiver, explicit args
        # follow (positional; the same approximation the return-secret
        # check uses). ``self`` (param 0) -> receiver, param i+1 -> arg i.
        full_labels = [self._label_of(e.receiver)] + [
            self._label_of(a) for a in e.args
        ]
        label = L.PUBLIC
        for key in keys:
            sources = self._ifc_return_effects.get(key)
            if not sources:
                continue
            for s in sources:
                # INTERNAL_SECRET is already handled (-> SECRET) above.
                if 0 <= s < len(full_labels):
                    label = L.join(label, full_labels[s])
        return label

    def _return_sources_fire(self, sources, perm, args) -> bool:
        """True if any return-secret source fires: the unconditional
        internal-secret sentinel, or a real parameter index whose bound
        argument is @secret. ``perm`` maps a parameter index to an index
        into ``args`` (a list for free calls, a dict for method calls)."""
        from ._ifc_summary import INTERNAL_SECRET
        def arg_for(pidx):
            if isinstance(perm, dict):
                idx = perm.get(pidx)
            else:
                idx = perm[pidx] if pidx < len(perm) else None
            if idx is None or idx >= len(args):
                return None
            return args[idx]
        for s in sources:
            if s == INTERNAL_SECRET:
                return True
            a = arg_for(s)
            if a is not None and L.normalize(self._label_of(a)) == L.SECRET:
                return True
        return False

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
        param_tys = getattr(getattr(sym, "ty", None), "params", ())
        for param_idx, arg_idx in enumerate(perm):
            if param_idx not in sink_params:
                continue
            if arg_idx >= len(e.args):
                continue
            arg = e.args[arg_idx]
            ptype = param_tys[param_idx] if param_idx < len(param_tys) else None
            label = self._sink_param_arg_label(arg, ptype)
            if label is None or L.normalize(label) != L.SECRET:
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
        param_tys = getattr(getattr(method_sym, "ty", None), "params", ())
        for local_idx, arg_idx in enumerate(perm):
            full_idx = local_idx + 1 if has_self else local_idx
            if full_idx not in sink_params:
                continue
            if arg_idx >= len(e.args):
                continue
            arg = e.args[arg_idx]
            ptype = param_tys[local_idx] if local_idx < len(param_tys) else None
            label = self._sink_param_arg_label(arg, ptype)
            if label is None or L.normalize(label) != L.SECRET:
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
            self._warn(msg, pos)

    # ---- higher-order closure return-label flow (roadmap S2) -----

    def _closure_ret_label_leak(self, expected, actual) -> bool:
        """True when ``actual`` carries a function type whose RETURN label
        is @secret in a position where ``expected`` declares it public --
        i.e. a secret-returning closure flowing into a public-returning
        slot. Covariant in the return label: ``secret`` must flow to a
        ``secret`` (or looser) slot only. Recurses through the return
        chain and through aggregate positions (tuple elements, generic
        type arguments) so a closure nested one level deep (a struct field
        typed ``List<Fun() -> String>``, a tuple of closures) is covered.

        Parameter labels are intentionally NOT walked here: in Phase A a
        lambda stamps public parameter labels and an unannotated ``Fun``
        parameter type is public, so the return label is the only channel
        that carries taint, and skipping the (contravariant) parameter
        positions avoids a spurious report."""
        from ..typesys import TyFun, TyTuple, TyName
        from .. import _labels as L
        if isinstance(expected, TyFun) and isinstance(actual, TyFun):
            if not L.flows_to(actual.ret_label, expected.ret_label):
                return True
            return self._closure_ret_label_leak(expected.ret, actual.ret)
        if (
            isinstance(expected, TyTuple) and isinstance(actual, TyTuple)
            and len(expected.elements) == len(actual.elements)
        ):
            return any(
                self._closure_ret_label_leak(e, a)
                for e, a in zip(expected.elements, actual.elements)
            )
        if (
            isinstance(expected, TyName) and isinstance(actual, TyName)
            and len(expected.args) == len(actual.args)
        ):
            return any(
                self._closure_ret_label_leak(e, a)
                for e, a in zip(expected.args, actual.args)
            )
        return False

    def _check_closure_ret_flow(
        self, expected, actual, pos, where: str,
    ) -> None:
        """Store-site higher-order IFC check. When a secret-returning
        closure is stored where a public-returning function type is
        declared -- a struct field, a typed ``let`` / ``var``, a ``var``
        reassignment, or a function ``return`` -- the secret can leak the
        moment that stored closure is invoked at a public sink, even
        though the leak surfaces cross-function and by-name. Flag it here,
        where the declared slot's public return label and the closure's
        secret return label are both in hand. Warn by default, hard error
        under ``@strict_ifc`` -- the same two-tier discipline as the
        intra-procedural and cross-function sink checks."""
        if expected is None or actual is None:
            return
        if not self._closure_ret_label_leak(expected, actual):
            return
        msg = (
            "information-flow: a closure that returns a @secret value is "
            f"{where} where a public-returning function type is declared; "
            "it can leak the secret when the closure is later invoked at a "
            "public sink. Declare the slot 'Fun(...) -> @secret ...', or "
            "route the closure's result through declassify(value, reason: "
            "\"...\") if the disclosure is intended."
        )
        if getattr(self, "_strict_ifc", False):
            self._err(msg, pos)
        else:
            self._warn(msg, pos)

    # ---- cross-function field-write effect (closes gap 1) --------

    def _check_ifc_call_field_effect(
        self, e: A.Call, sym, perm: list[int],
    ) -> None:
        """At a user free-function call, apply the callee's field-write
        effects to the CALLER's bindings. ``perm`` is in parameter
        order: ``e.args[perm[i]]`` is the argument bound to parameter
        ``i``. The effect ``{j -> sources}`` means the callee writes a
        field of the object passed as parameter ``j`` from those
        sources; when a source fires (a @secret real-param argument, or
        the unconditional internal-secret sentinel), the caller's
        binding for parameter ``j`` is tainted whole-value secret."""
        effects = self._ifc_field_effects.get(("fun", sym.name))
        if not effects:
            return
        self._apply_field_effects(effects, perm, e.args)

    def _check_ifc_method_call_field_effect(
        self, e: A.MethodCall, method_sym, recv_ty, perm: list[int],
    ) -> None:
        """Method-call form of the field-write-effect propagation.
        Parameter index 0 is ``self`` (the receiver); the explicit
        parameters follow. Builds the full-order argument list
        (receiver first) and the full-order ``param_idx -> arg_idx``
        map, then applies every candidate impl's effects (the same
        by-name over-approximation the summary uses) -- whole-value and
        conservative, so a dynamic-dispatch receiver never drops the
        taint."""
        from ._ifc_summary import methods_by_name
        exact_key = ("method", recv_ty.name, e.method)
        keys = [exact_key] if exact_key in self._ifc_field_effects else \
            methods_by_name(self._ifc_field_effects).get(e.method, ())
        if not keys:
            return
        has_self = getattr(method_sym, "has_self", False)
        full_args = [e.receiver] + list(e.args)
        full_perm: dict[int, int] = {}
        if has_self:
            full_perm[0] = 0
        for local_idx, arg_idx in enumerate(perm):
            full_idx = local_idx + 1 if has_self else local_idx
            full_perm[full_idx] = arg_idx + 1
        for key in keys:
            effects = self._ifc_field_effects.get(key)
            if effects:
                self._apply_field_effects(effects, full_perm, full_args)

    def _apply_field_effects(self, effects: dict, perm, args: list) -> None:
        """Shared effect application: ``perm`` maps a callee parameter
        index to an index into ``args``. For each target param whose
        effect fires, taint the caller's binding for that target's
        argument whole-value secret. ``perm`` may be a list (free call,
        parameter-ordered) or a dict (method call, full order)."""
        def arg_for(pidx):
            if isinstance(perm, dict):
                idx = perm.get(pidx)
            else:
                idx = perm[pidx] if pidx < len(perm) else None
            if idx is None or idx >= len(args):
                return None
            return args[idx]

        from ._ifc_summary import INTERNAL_SECRET
        for target_pidx, sources in effects.items():
            fires = False
            for s in sources:
                if s == INTERNAL_SECRET:
                    fires = True
                    break
                src_arg = arg_for(s)
                if src_arg is not None and \
                        L.normalize(self._label_of(src_arg)) == L.SECRET:
                    fires = True
                    break
            if not fires:
                continue
            target_arg = arg_for(target_pidx)
            if target_arg is None:
                continue
            self._taint_binding_whole_value(target_arg)

    def _taint_binding_whole_value(self, e: A.Expr) -> None:
        """Raise the binding rooted at ``e`` to whole-value @secret and
        escape it, so a later read of ANY field of it is caught. The
        conservative, sound granularity for a cross-function field-write
        effect (per-field precision across the boundary is not
        attempted). No-op when ``e`` is not rooted at a binding.

        Aliasing soundness: if the binding is in an alias group (an embed
        alias ``Outer { inner: b }`` links ``o`` and ``b``, or ``var
        b2 = b``), every member names the SAME heap object, so the
        cross-function whole-value taint must reach all of them. Mirror
        ``_ifc_field_store``'s alias-group path exactly: taint AND escape
        every member, so a later read of any field of any aliased binding
        is caught."""
        sym = self._struct_root_sym(e)
        if sym is None:
            return
        group = self._struct_aliases.get(id(sym))
        members = group if group is not None else [sym]
        for member in members:
            member.label = L.join(getattr(member, "label", None), L.SECRET)
            if getattr(member, "field_labels", None) is not None:
                self._escaped_struct_syms.add(id(member))

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
