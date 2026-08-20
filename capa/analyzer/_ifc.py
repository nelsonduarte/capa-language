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
    # Serve.send writes bytes to whoever is on the other end of an
    # inbound connection -- exfiltration exactly like Net.post. Only
    # argument 1 (the payload) is a sink; argument 0 is the connection
    # id the runtime handed out, not program data, so gating it would
    # be noise.
    #
    # It is spelled ``send`` and not ``write`` because the summary pass
    # in ``_ifc_summary`` attributes a sink to a capability BY METHOD
    # NAME (it has no receiver type at that point), which is sound only
    # while each sink method name belongs to exactly one capability.
    # ``Fs.write`` already owns "write", so a ``Serve.write`` made every
    # ``fs.write`` report Serve as a reached capability too -- caught by
    # tests/test_unaudited_secret_sink_fact.py when this landed.
    ("Serve", "send"):     {1},
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
#
# ``Serve.read`` is deliberately NOT a source either, and this is the
# one entry whose ABSENCE is a decision worth spelling out. Serve
# (2026-07) is the language's first INBOUND data source, so it is the
# first time the question "is data arriving from outside secret?" has
# an answer to give. It is ``@public``.
#
# The reason is that this lattice models CONFIDENTIALITY -- who is
# allowed to LEARN a value -- and not integrity or taint. An inbound
# request is untrusted, but "untrusted" is an integrity property, and
# labelling it ``@secret`` would encode it in the wrong lattice: the
# immediate consequence is that echoing a request back to the client
# that sent it (the single most ordinary thing a server does) becomes
# a reported violation. The useful signal would drown in that noise.
#
# ``Serve.read`` being ``@public`` therefore asserts only "these bytes
# are not a secret whose disclosure this analysis must prevent". It
# asserts NOTHING about whether they can be trusted. Integrity /
# taint tracking would be a second lattice, not a relabelling of this
# one.
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

# Higher-order IFC precision (Phase B1). Built-in combinators whose
# result is element-granular: the closure's return label taints the
# result's ELEMENTS / payload, not its SHAPE. Keyed ``(owner, method)``
# -> ``(rule, closure_index, init_index)`` where ``closure_index`` is
# the parameter position of the transforming closure and ``init_index``
# is the position of a seed value (``fold`` only, else ``None``). The
# ``rule`` selects how the result's (structure, element) labels are
# derived at the call-site seam (see ``_record_combinator_split``):
#   "transform" -- element = join(input element, closure ret_label);
#                  structure = input structure. Covers map / map_err (the
#                  closure's returned value becomes the new element /
#                  payload without changing presence / cardinality).
#   "bind"      -- a CONTAINER-RETURNING closure (and_then / flat_map):
#                  the closure returns the result container itself, so it
#                  decides BOTH the payload (element = join(input element,
#                  closure ret_label)) AND presence / cardinality
#                  (structure = join(input structure, closure ret_label)).
#                  Folding ret_label into the STRUCTURE closes the strict-
#                  tier presence leak where ``and_then(x => if s then
#                  Some(x) else None).is_some()`` read public (Phase B2').
#   "filter"    -- element = input element; structure = input structure.
#                  The predicate's label is dropped: the elements that
#                  pass through are exactly (a subset of) the input's.
#   "fold"      -- a SCALAR result: whole-value =
#                  join(init, input element, closure ret_label).
_COMBINATOR_SPECS: dict[tuple[str, str], tuple[str, int, "int | None"]] = {
    ("List",   "map"):      ("transform", 0, None),
    ("List",   "filter"):   ("filter",    0, None),
    ("List",   "fold"):     ("fold",      1, 0),
    ("List",   "flat_map"): ("bind",      0, None),
    ("Range",  "map"):      ("transform", 0, None),
    ("Range",  "filter"):   ("filter",    0, None),
    ("Range",  "fold"):     ("fold",      1, 0),
    ("Option", "map"):      ("transform", 0, None),
    ("Option", "and_then"): ("bind",      0, None),
    ("Option", "filter"):   ("filter",    0, None),
    ("Result", "map"):      ("transform", 0, None),
    ("Result", "and_then"): ("bind",      0, None),
    ("Result", "map_err"):  ("transform", 0, None),
}

# Structure / shape queries that read only a container's STRUCTURE
# label, never its element / payload label. Over an element-granular
# combinator result (``xs.map(secretClosure)``) these stay PUBLIC while
# an element read stays tainted. Keyed ``(owner, method)``. Restricted
# to the owners a combinator split can attach to; for every other
# receiver the query falls back to the whole-value label unchanged.
_STRUCTURE_OPS: frozenset[tuple[str, str]] = frozenset({
    ("List",   "length"),   ("List",   "is_empty"),
    ("Range",  "length"),   ("Range",  "is_empty"),
    ("Option", "is_some"),  ("Option", "is_none"),
    ("Result", "is_ok"),    ("Result", "is_err"),
})


class _IfcMixin:
    def _label_expr(self, e: A.Expr) -> str:
        """Compute and record the security label of ``e`` from its
        already-labelled children, returning it. Called by
        ``_check_expr`` right after typing, so child labels are
        present.

        ``_compute_label`` yields the BASE label (data-flow / field-store /
        declared-field, EXCLUDING the branch-scoped container-mutation
        channel), cached in ``_expr_base_labels`` so the escaped field-read
        fallback can read a receiver's base without its container taint.
        The container-mutation channel is joined in ONCE here as a prefix
        scan at ``e``'s own access path (``_container_read_taint``): a WHOLE
        read of a struct sees every field taint of its root (the length-0
        access-path query ``x.f^0 = x``), a FIELD read only the taints at
        or below its own path. The full label is stored in
        ``self._expr_labels``."""
        base = self._compute_label(e)
        self._expr_base_labels[id(e)] = base
        extra = self._container_read_taint(e)
        label = L.join(base, extra) if extra else base
        self._expr_labels[id(e)] = label
        self._record_field_map(e)
        self._mark_escapes_for(e)
        return label

    def _base_label_of(self, e: A.Expr) -> str:
        """The recorded BASE label of ``e``: its data-flow / field-store /
        declared-field label EXCLUDING the branch-scoped container-mutation
        channel. Consulted only by the escaped field-read fallback in
        ``_compute_label``, so a field read that cannot resolve a precise
        per-field label does NOT inherit the receiver's WHOLE-subtree
        container taint (which would re-taint a clean sibling field); the
        container channel is instead consulted precisely at the field's own
        access path via ``_container_read_taint``."""
        return self._expr_base_labels.get(id(e), L.PUBLIC)

    def _container_read_taint(self, e: A.Expr):
        """The branch-scoped container-mutation taint OBSERVED by reading
        ``e``, as a prefix scan over the ``(root-binding, *)`` access-path
        channel, or ``None`` when ``e`` is not rooted at a binding.

        A WHOLE read of a struct binding (a bare Ident, or a
        getter / interpolation / pass-whole read routed through it, all of
        which take the Ident's label) observes EVERY field taint of that
        root: the length-0 access-path query ``x.f^0 = x`` from the
        FlowDroid access-path semantics. A FIELD read (``bag.other``)
        observes only the taints at or below its own path, so a public
        sibling field stays clean and a bare whole read of the same root
        that was container-pushed into a field is now caught (closing the
        cross-function whole / getter read-back that the field-keyed
        channel introduced). The scan is per ROOT SYMBOL, so a
        different-root alias / rename / embedding stays a disclosed
        residual (only a points-to analysis could close it)."""
        if isinstance(e, A.Ident):
            sym = self.bindings.get(id(e))
            if sym is not None:
                return self._container_taint_at(sym, ())
            return None
        if isinstance(e, A.FieldAccess):
            root = self._struct_root_sym(e)
            path = self._field_path_from_root(e)
            if root is not None and path is not None:
                return self._container_taint_at(root, tuple(path))
        return None

    def _arg_container_paths(self, arg: A.Expr):
        """The PARAMETER-RELATIVE container-mutation access paths that are
        @secret for ``arg`` (a struct passed to a sink-reaching parameter),
        or ``None`` when ``arg`` is not an Ident-rooted chain (so its paths
        cannot be determined and the caller must fall back to the
        conservative whole-value check).

        ``arg``'s root binding and the caller's field prefix to it are
        resolved, then every ``(root, kpath)`` @secret container-taint key
        whose ``kpath`` extends the prefix is returned with the prefix
        STRIPPED, so the paths are relative to the callee's PARAMETER (the
        same frame the callee's sunk paths are in). Passing ``bag`` (prefix
        ``()``) tainted at ``("secret_items",)`` yields ``{("secret_items",)}``;
        passing ``outer.bag`` yields the paths under ``("bag",)`` stripped."""
        root = self._struct_root_sym(arg)
        prefix = self._field_path_from_root(arg)
        if root is None or prefix is None:
            return None
        prefix = tuple(prefix)
        plen = len(prefix)
        out: set = set()
        for (kid, kpath), lbl in self._container_taint_map().items():
            if (
                kid == id(root)
                and kpath[:plen] == prefix
                and L.normalize(lbl) == L.SECRET
            ):
                out.add(kpath[plen:])
        return out

    def _sink_arg_field_cleared(self, arg: A.Expr, sunk_paths) -> bool:
        """Stage 2 read-side field-qualified check. Return True (SKIP the
        cross-function sink flag) ONLY when it is provably safe: the
        argument's @secret label comes PURELY from the container-mutation
        channel (its BASE label is public), its tainted access paths are
        determinable, and NONE of them is prefix-compatible with any path
        the callee actually SINKS for this parameter. Then passing a struct
        tainted at ``("items",)`` to a callee that sinks only ``("note",)``
        is clean.

        Conservative on any uncertainty (returns False -> keep flagging),
        which is the soundness floor: no leak may reopen. Never skips when
        the callee's sunk paths are unknown/empty, when the whole-value
        BASE label is @secret (a genuinely secret struct, or the disclosed
        field-store sibling over-report), when the argument is not
        Ident-rooted, or when a tainted path is on the same root-to-leaf
        line as a sunk path (the mirror leak ``m_whole_callee`` etc.). A
        callee that sinks the WHOLE parameter records the sentinel ``()``,
        which is prefix-compatible with every tainted path, so it always
        flags."""
        if not sunk_paths:
            return False
        if L.normalize(self._base_label_of(arg)) == L.SECRET:
            return False
        tainted = self._arg_container_paths(arg)
        if not tainted:
            return False
        for t in tainted:
            for s in sunk_paths:
                if _prefix_compatible(t, s):
                    return False
        return True

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

    # ---- element-granular container labels (roadmap S2, Phase B1) ----
    #
    # A built-in combinator result carries, besides its collapsed
    # whole-value label, a ``(structure, element)`` split so a SHAPE
    # query (``length`` / ``is_empty`` / ``is_some`` / ...) reads the
    # structure label while an ELEMENT read (indexing, iteration, a
    # payload unwrap, ``first`` / ``last`` / ``get``) reads the element
    # label. The whole-value label is always kept as the join of the two
    # -- so a container passed / sunk WHOLE is caught -- and is the sound
    # fallback the moment no split is recorded. The split for an
    # expression lives in ``_container_split`` (keyed by id); the split
    # for a binding lives on ``Symbol.container_split``.

    def _split_of(self, e: A.Expr):
        """The recorded ``(structure, element)`` split of ``e`` -- from
        the binding's Symbol when ``e`` is a name, else from the
        per-expression side table -- or ``None`` when ``e`` carries no
        split (a plain value, whose structure and element labels both
        equal its whole-value label)."""
        if isinstance(e, A.Ident):
            sym = self.bindings.get(id(e))
            split = getattr(sym, "container_split", None) if sym else None
            if split is not None:
                return split
        return self._container_split.get(id(e))

    def _structure_label_of(self, e: A.Expr) -> str:
        """The STRUCTURE (shape) label of ``e``: the structure part of a
        combinator split, else the whole-value label (a plain container's
        shape is as tainted as the container)."""
        split = self._split_of(e)
        return split[0] if split is not None else self._label_of(e)

    def _element_label_of(self, e: A.Expr) -> str:
        """The ELEMENT / payload label of ``e``: the element part of a
        combinator split, else the whole-value label (a plain container's
        elements are as tainted as the container)."""
        split = self._split_of(e)
        return split[1] if split is not None else self._label_of(e)

    def _copy_container_split(self, sym, value: A.Expr) -> None:
        """Copy a combinator-result split from a binding's RHS ``value``
        onto its ``Symbol`` (``let ys = xs.map(f)``), so later reads
        through the name stay element-granular. A RHS with no split (a
        plain value, or a ``declassify`` that cleared the taint) leaves
        the binding with ``container_split = None`` -- every read then
        uses the whole-value label."""
        if sym is None:
            return
        sym.container_split = self._split_of(value)

    def _record_combinator_split(
        self, e: A.MethodCall, owner: str, args: list, arg_tys: list,
    ) -> None:
        """Publish the element-granular ``(structure, element)`` split of
        a built-in combinator call into the IFC channel (Phase B1). Runs
        at the call-site seam, AFTER inferred-lambda re-checking has fixed
        every closure argument's ``TyFun.ret_label`` and BEFORE the
        result label is computed for ``e``. Overrides the conservative
        whole-value join for the specific ``(owner, method)`` keys in
        ``_COMBINATOR_SPECS`` and is a no-op for every other method.

        ``args`` and ``arg_tys`` are the argument expressions and types in
        PARAMETER order (so the closure / seed indices from the spec
        address them directly, independent of named-argument order)."""
        from ..typesys import TyFun
        spec = _COMBINATOR_SPECS.get((owner, e.method))
        if spec is None:
            return
        rule, closure_idx, init_idx = spec
        recv = e.receiver
        struct_in = self._structure_label_of(recv)
        elem_in = self._element_label_of(recv)
        ret_label = L.PUBLIC
        if 0 <= closure_idx < len(arg_tys):
            closure_ty = arg_tys[closure_idx]
            if isinstance(closure_ty, TyFun):
                ret_label = L.normalize(getattr(closure_ty, "ret_label", None))
        if rule == "fold":
            init_label = L.PUBLIC
            if init_idx is not None and init_idx < len(args):
                init_label = self._label_of(args[init_idx])
            whole = L.join(init_label, L.join(elem_in, ret_label))
            self._container_split[id(e)] = (whole, whole)
            return
        if rule == "filter":
            # The surviving ELEMENTS are exactly (a subset of) the
            # input's, so the element label is the input's unchanged. The
            # CARDINALITY, however, is decided by the predicate: how many
            # elements pass -- and hence the result's length / is_empty /
            # is_some -- is a function of the predicate, so a
            # secret-dependent predicate makes the STRUCTURE secret-
            # derived (``xs.filter(fun (n) => n == s).length()`` discloses
            # membership). Fold the predicate's ret_label into the
            # structure component; a public predicate contributes PUBLIC
            # and so keeps the shape query clean.
            self._container_split[id(e)] = (
                L.join(struct_in, ret_label), elem_in,
            )
            return
        if rule == "bind":
            # A CONTAINER-RETURNING closure (and_then / flat_map): the
            # closure returns the result container itself, so its label
            # decides BOTH the payload (element) AND presence /
            # cardinality (structure). Folding ret_label into the
            # STRUCTURE closes the strict-tier presence leak where
            # ``and_then(x => if s then Some(x) else None).is_some()``
            # read public (a container-returning closure choosing
            # Some/None on a secret makes the shape query secret-derived).
            self._container_split[id(e)] = (
                L.join(struct_in, ret_label), L.join(elem_in, ret_label),
            )
            return
        # "transform": the closure's returned value becomes the new
        # element / payload. Join the input element label in as well --
        # a closure PARAMETER is labelled public (Phase A), so an
        # identity / element-derived transform would otherwise drop a
        # secret input element; joining ``elem_in`` keeps it sound.
        elem_out = L.join(elem_in, ret_label)
        self._container_split[id(e)] = (struct_in, elem_out)

    def _record_call_split(
        self, e: A.Call, fun_ty, mapping: dict, args: list, arg_tys: list,
    ) -> None:
        """Publish the element-granular ``(structure, element)`` split of
        a USER-DEFINED generic higher-order call into the IFC channel
        (Phase B2'). Runs at the FREE-CALL seam, AFTER inferred-lambda
        re-checking has fixed every closure argument's ``TyFun.ret_label``
        and BEFORE ``instantiate`` (so ``fun_ty`` still carries its
        ``TyVar``s and ``mapping`` records which were inferred).

        By parametricity the SIGNATURE is a sound per-call summary for the
        split: a rigid type-var in the body can only originate from a
        matching-typed input or a matching-typed closure result, so where
        each parameter's type-var lands in ``fun_ty.ret`` classifies its
        contribution. ``args`` / ``arg_tys`` are in PARAMETER order.

        The ELEMENT (and hence whole-value) label is the declassify-aware
        whole-value label the return-effect summary computes
        (``_call_return_label``): a generic body's internal ``declassify``
        wins (element / whole stay public), and a secret that genuinely
        flows out on return -- whether captured by a closure or sourced
        INSIDE its body (an ``env.get`` in a transform closure, seen via
        the closure's ``ret_label``) -- taints every element read and
        whole-container sink, exactly as the built-in ``map`` does.

        The STRUCTURE stands on its OWN channel: the join of the
        STRUCTURE-affecting contributions, NEVER capped at the element /
        whole-value floor. A container's cardinality / presence can depend
        on a secret that never becomes an element value (``for x in xs: if
        s > 0: out.push(...)``), so lowering the structure to the floor
        would DROP a real structure-channel leak. A shape query (``length``
        / ``is_empty`` / ``is_some`` / ...) reads this independent
        structure label. Residual structure FALSE POSITIVES (a secret
        non-passthrough input that does not actually affect cardinality, or
        a body that declassifies the structure) are disclosed and sound --
        soundness wins over that precision."""
        from ..typesys import TyName
        ret = fun_ty.ret
        if not isinstance(ret, TyName):
            return
        elem_var = _result_payload_var(ret)
        # Parametric only: the result must be a container whose payload is
        # a type-var that this call actually inferred. A concrete result
        # (``List<Int>``) or an un-inferred payload carries no parametric
        # split and falls back to the conservative whole-value label.
        if elem_var is None or elem_var not in mapping:
            return
        element = self._call_return_label(e)
        structure = self._callee_label(e.callee)
        for i, param_ty in enumerate(fun_ty.params):
            if i >= len(args):
                break
            kind = _classify_call_param(param_ty, elem_var, ret)
            if kind == "transform":
                # A transform closure (its return type-var IS the result
                # payload var) affects only the ELEMENT -- map preserves
                # presence / cardinality -- and the element floor already
                # carries its taint (via the return-effect + ret_label).
                # It contributes nothing to the STRUCTURE.
                continue
            if kind == "passthrough":
                # A passthrough container input (its element type-var IS
                # the result payload var) contributes its STRUCTURE label
                # to the result structure; its element flows via the floor.
                structure = L.join(
                    structure, self._structure_label_of(args[i]),
                )
                continue
            # "bind" (a container-RETURNING closure, which decides
            # presence) and "other" (a predicate / seed / non-passthrough
            # input, conservatively structure-affecting): fold the
            # structure-deciding label in. A closure contributes its
            # return label (tier-aware, matching the built-in specs); any
            # other argument its whole-value label.
            arg_ty = arg_tys[i] if i < len(arg_tys) else None
            structure = L.join(
                structure, self._structure_contribution(args[i], arg_ty),
            )
        self._container_split[id(e)] = (structure, element)

    def _structure_contribution(self, arg: A.Expr, arg_ty) -> str:
        """The STRUCTURE-affecting label of a non-passthrough argument: a
        closure contributes its (tier-aware) return label -- what a
        container-returning closure yields decides presence -- while any
        other value contributes its whole-value label."""
        from ..typesys import TyFun
        if isinstance(arg_ty, TyFun):
            return L.normalize(getattr(arg_ty, "ret_label", None))
        return self._label_of(arg)

    def _call_return_label(self, e: A.Call) -> str:
        """The declassify-aware whole-value label of a free-function call,
        following its RETURN-EFFECT summary rather than the crude argument
        join -- the free-function analogue of ``_method_call_return_label``,
        and the SOUND FLOOR for a generic HO split.

        A summarised callee's result carries source ``s`` iff ``s`` is in
        its ``return_effects``: ``INTERNAL_SECRET`` -> secret
        unconditionally (a declared-@secret field read / ``env.get``
        returned); a real param ``s`` -> the label the argument bound to it
        CONTRIBUTES to the callee's return. For a Fun-typed parameter the
        callee INVOKES and returns the result of, that is the closure's
        RETURN label (``TyFun.ret_label``), NOT its capture label: a
        transform / bind closure whose body sources a secret internally
        (``env.get`` inside ``fun (n) => ...``) has ``ret_label = secret``
        even with an empty capture set, so its result taints the return
        exactly as the built-in ``map`` sees it. A body that ``declassify``s
        the returned value has an empty return-effect and so is PUBLIC here
        even when a closure captured a secret. When the callee is not a
        summarised free function, fall back to the conservative callee +
        argument + closure-capture join (unchanged from the pre-split
        whole-value rule)."""
        conservative = L.join(
            self._callee_label(e.callee),
            L.join(
                L.join_all(self._label_of(a) for a in e.args),
                self._call_arg_closure_label(e),
            ),
        )
        if not isinstance(e.callee, A.Ident):
            return conservative
        sources = self._ifc_return_effects.get(("fun", e.callee.name))
        if sources is None:
            return conservative
        from ._ifc_summary import INTERNAL_SECRET, _bind
        sym = self.bindings.get(id(e.callee))
        param_names = getattr(sym, "param_names", []) if sym is not None else []
        perm = _bind(e.args, e.arg_names, param_names)
        label = L.PUBLIC
        # ``sources`` is a per-path return map ``{field-path -> sources}``;
        # the whole-value call-result label joins over EVERY path.
        for _rpath, srcs in sources.items():
            for s in srcs:
                if s == INTERNAL_SECRET:
                    label = L.SECRET
                    continue
                arg_idx = perm.get(s)
                if arg_idx is not None and arg_idx < len(e.args):
                    label = L.join(
                        label,
                        self._return_arg_contribution(e.args[arg_idx]),
                    )
        return label

    def _return_arg_contribution(self, arg: A.Expr) -> str:
        """The label an argument CONTRIBUTES when it flows into the
        callee's return. For a Fun-typed argument (a closure the callee
        invokes and returns the result of) that is its RETURN label -- what
        the closure yields, which sees a body-internal secret (``env.get``)
        and sees THROUGH an in-body declassify -- mirroring the built-in
        combinator element rule. For any other argument it is the
        argument's own whole-value label."""
        from ..typesys import TyFun
        arg_ty = self.types.get(id(arg))
        if isinstance(arg_ty, TyFun):
            return L.normalize(getattr(arg_ty, "ret_label", None))
        return self._label_of(arg)

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
    #       The same effect carries a CONTAINER mutated by a callee
    #       (``xs.push(v)`` and every other ``_CONTAINER_MUTATORS``
    #       entry, the single source of truth for the mutator set):
    #       before, a struct field written by a callee was caught but a
    #       container mutated by one escaped the analysis entirely, even
    #       though the identical push written inline was caught (FN-3).
    #       SCOPE (FN-3 was not fully closed): the caller-binding
    #       whole-value taint above fires only when the secret is already
    #       @secret IN THE CALLER (it owns the local and, e.g., reads it
    #       from ``env``). When the secret instead arrives as a PARAMETER
    #       of the caller, which pushes it through a callee into a FRESH
    #       LOCAL, reads it back and sinks it, no caller-side @secret label
    #       exists, so only the caller's cross-function SUMMARY can see the
    #       leak. The summary recorded the callee's write against the
    #       caller's own parameters (the mutation-TARGET channel) but did
    #       NOT reflect it on the local's READ-BACK, so the parameter was
    #       never marked sink-reaching and that param-carried read-back
    #       leaked unflagged. It is now CLOSED for the FRESH, UNALIASED
    #       local shape by a distinct, additive content channel in
    #       ``_ifc_summary`` (the callee's translated write raises the
    #       local's read-back label, applied regardless of whether the
    #       local is itself a writable mutation target). The closure holds
    #       across CONTROL-FLOW positions uniformly: the mutation and the
    #       read-back may sit straight-line or inside / after any branching
    #       construct -- the ``if`` / ``elif`` / ``else`` and ``match``
    #       STATEMENT forms, the ``if ... then ... else`` and ``match``
    #       EXPRESSION forms, and ``while`` / ``for`` loop bodies -- in any
    #       position (mid-body, tail / implicit return, a let-binding, or
    #       nested). A branch CONDITION and a match-arm GUARD run on the
    #       path to later branches / arms, so a side-effecting one's
    #       mutation propagates (evaluated in the enclosing content scope,
    #       not isolated). The content channel is scoped so a mutation in
    #       one mutually-exclusive branch BODY does not contaminate a
    #       sibling branch's read (no false positive) yet still reaches a
    #       read AFTER the construct (no false negative). GENERAL aliasing
    #       residual stays OPEN: a local that escapes, is aliased to a
    #       second name, is stored into another structure, is returned and
    #       re-entered, is mutated by a deeper untracked path, or is mutated
    #       by an INVOKED lambda that captured it, is not tracked without a
    #       points-to analysis, which Capa does not have. A LOOP-CARRIED
    #       read-before-write inside a ``while`` / ``for`` (a read textually
    #       before the push that a later iteration would feed) is also OUT
    #       of scope -- there is no iteration fixpoint. This closes the
    #       fresh-unaliased-local shape, not "all cross-function false
    #       negatives".
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
        # Higher-order IFC precision (Phase B1): carry a combinator-result
        # element/structure split from the RHS onto the binding. An
        # explicit @secret annotation raises the whole value, so the
        # collapsed label already governs -- do not keep a split that
        # could read narrower than the annotation.
        if L.normalize(decl_label) != L.SECRET:
            self._copy_container_split(sym, value)
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

        # A name carries its binding's BASE label. The branch-scoped
        # container-mutation taint is joined in by ``_label_expr`` via
        # ``_container_read_taint`` (a whole read of a struct binding
        # observes every field taint of its root), so it is NOT consulted
        # here -- keeping ``_compute_label`` the container-free base that
        # the escaped field-read fallback can read without over-tainting a
        # clean sibling.
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
            # An element drawn from a tainted container is tainted. An
            # element read observes BOTH the element VALUE and its
            # PRESENCE / position, so it reads the WHOLE-VALUE join
            # (structure AND element): over a ``filter`` on a secret
            # predicate the structure is secret (which / how many elements
            # are present discloses the predicate) even when the surviving
            # elements are individually public. Only a STRUCTURE query
            # (length / is_empty / ...) reads the lower structure label.
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
            # Escaped / unresolvable: fall back to the receiver's BASE label
            # (its data-flow / field-store label WITHOUT the container
            # channel), NOT its full label. A field read must not inherit
            # the receiver's WHOLE-subtree container taint -- that would
            # re-taint a clean sibling field (``bag.other`` after a push into
            # ``bag.items``); the container channel is consulted precisely at
            # THIS field's own access path by ``_container_read_taint`` in
            # ``_label_expr``. The receiver's field-store / whole-value label
            # is still inherited (so a struct raised whole-value, e.g. by a
            # cross-function field-store carrier, still taints a field read).
            return L.join(decl_label, self._base_label_of(e.receiver))

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
            # Higher-order IFC precision (Phase B2'): a user-defined
            # generic combinator whose element-granular split was derived
            # from its signature at the free-call seam. Mirrors the
            # MethodCall branch -- the whole-value label is the join of the
            # structure and element labels, so a structure op reads the
            # (refined) structure while an element / whole read reads the
            # join. Absent a split this is a no-op and the base join below
            # governs, so ordinary calls are unchanged.
            split = self._container_split.get(id(e))
            if split is not None:
                return L.join(split[0], split[1])
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
            # Higher-order IFC precision (Phase B1). A SHAPE query on a
            # container (``length`` / ``is_empty`` / ``is_some`` / ...)
            # reads only the receiver's STRUCTURE label, so a
            # ``map``-of-secret-closure result whose ELEMENTS are secret
            # still answers a PUBLIC count. For a receiver with no split
            # this is exactly the whole-value label (unchanged behavior).
            if cap_name is not None and (cap_name, e.method) in _STRUCTURE_OPS:
                return self._structure_label_of(e.receiver)
            # A built-in combinator whose element-granular split was
            # recorded at the call-site seam: the whole-value label is the
            # join of its structure and element labels (overriding the
            # conservative receiver+args join for these specific keys).
            split = self._container_split.get(id(e))
            if split is not None:
                return L.join(split[0], split[1])
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

        # A range ``a..b`` (or ``a..=b``) carries the JOIN of its endpoint
        # labels: a range with a @secret bound (``0..secret``) is @secret,
        # so a later ``.length()`` or a loop over it that reveals the bound
        # cannot launder the secret to public. Mirrors the aggregate join --
        # the range is a value derived from its endpoints.
        if isinstance(e, A.RangeExpr):
            return L.join(self._label_of(e.start), self._label_of(e.end))

        # ``become(value, State)`` re-types a typestate value in place; the
        # value it carries keeps its label (identity is preserved, only the
        # state changes). Reached by legitimate typestate programs, so it
        # needs a real case rather than the terminal default below.
        if isinstance(e, A.Become):
            return self._label_of(e.value)

        # The label function is TOTAL over the expression node kinds: every
        # ``A.Expr`` subclass has a real case above. A node that reaches here
        # is a compiler bug -- a new expression form added without a label
        # rule -- and must fail LOUD rather than silently default to PUBLIC,
        # which would let a future unhandled node launder a secret to a
        # public sink (the range-expression hole this guard replaced).
        # Mutable containers are NOT this fallthrough: a secret put into one
        # via push / add / set taints the receiver binding (see
        # ``_check_ifc_container_mutation``), so the read rules above inherit
        # the now-secret receiver label.
        raise AssertionError(
            "IFC label function is not total: no rule for expression node "
            f"{type(e).__name__}"
        )

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
        (an immediately-invoked closure) reads its recorded capture label.

        Stage B (capture-side lambda-flow): when the callee resolves through
        ``_binding_lambdas`` to ONE certain lambda literal, its captured free
        bindings are RE-READ LIVE at THIS invocation site
        (``_fresh_capture_label``) and joined in, so a container captured
        BEFORE a later mutation and read through the closure AFTER is caught
        (``let f = fun () => bag.reveal(); bag.items.push(secret); f()``). The
        binding's cached ``sym.label`` was stamped at the lambda's DEFINITION
        (before the mutation), so it alone would miss the leak. Only a locally
        resolved lambda is re-read; an escaping / HOF-invoked closure stays the
        disclosed residual.

        Candidate A (result face): for the SAME locally-resolved lambda (the
        Ident-to-one-certain-lambda and the IIFE ``LambdaExpr``-callee sites)
        the closure's DEF-TIME RESULT label is ALSO joined in
        (``_lambda_static_result_label``), so a one-line wrapper whose RESULT
        is a statically @secret value -- a declared-@secret field read
        (``fun () => o.f2.f3.v``), a method / free-function call that returns
        one (``o.reveal()`` / ``peek(o)``) -- cannot launder it past the sink.
        This is the RESULT-FACE mirror of the named-return field channel; it
        complements the live capture re-read (delivered-after-definition taint)
        with the static-at-definition secrecy. The ceiling is exact: it is as
        strong as the DIRECT-call verdict through a one-certain lambda, never
        weaker, never stronger. A NESTED local lambda in RESULT POSITION is
        caught for free: the outer lambda's cached result label recurses
        through the inner call (``let g = fun () => o.reveal(); return g()``,
        the bound-then-returned ``let x = g(); return x``, or the inner closure
        RETURNED and then invoked all flag). The disclosed residuals are
        unchanged -- an escaping alias (``let g = f; g()``), a HOF-invoked
        closure (``apply(f)``, including an inner lambda passed to a HOF inside
        the outer body), a returned / struct-stored / reassigned-``var``
        closure, and the different-root points-to family all stay
        unflagged."""
        if isinstance(callee, A.Ident):
            sym = self.bindings.get(id(callee))
            base = (
                L.normalize(sym.label)
                if sym is not None and getattr(sym, "label", None)
                else L.PUBLIC
            )
            if sym is not None:
                lam = self._binding_lambdas.get(id(sym))
                if isinstance(lam, A.LambdaExpr):
                    return L.join(
                        base,
                        L.join(
                            self._fresh_capture_label(lam),
                            self._lambda_static_result_label(lam),
                        ),
                    )
            return base
        if isinstance(callee, A.LambdaExpr):
            return L.join(
                self._lambda_capture_labels.get(id(callee), L.PUBLIC),
                self._lambda_static_result_label(callee),
            )
        return self._label_of(callee)

    def _lambda_static_result_label(self, lam: A.LambdaExpr) -> str:
        """The DEF-TIME result label of a locally-resolved lambda -- the
        return-effect-aware, method-return-precise, declassify-aware label of
        the value an invocation of ``lam`` produces, as the analyzer already
        computed it when the body was checked
        (``_lambda_result_labels`` / ``_lambda_body_result_label``). Joined
        into the call-result label at a locally-resolved invocation
        (Candidate A, result face).

        Closes the result-face laundering where the body's result is a read or
        a CALL that produces a STATICALLY @secret value: a declared-@secret
        field read (``o.f2.f3.v``), a method whose return is declared-@secret /
        self-in-return (``o.reveal()``), or a free function whose return effect
        carries a secret (``peek(o)``). It is the same label that flags the
        DIRECT ``o.reveal()`` / ``peek(o)`` / ``o.f2.f3.v`` at the sink, now
        reflected through the one-certain lambda so a one-line wrapper cannot
        launder it. The ceiling is exact: as strong as the direct-call verdict
        through a one-certain lambda, never weaker, never stronger.

        Complements ``_fresh_capture_label`` (which carries taint DELIVERED
        AFTER definition by a mutation, field-precisely): this term carries the
        STATIC secrecy fixed at definition. It is declassify-aware (an in-body
        ``declassify`` of the returned value makes ``_lambda_body_result_label``
        PUBLIC), so the call-site escape hatch is preserved; and it does NOT
        re-introduce the field-precise mutation over-reports, because the
        def-time label reflects only the structure present at definition (an
        empty captured container reads PUBLIC). It touches neither the
        branch-scoped container channel nor the capture-INTERNAL-sink face
        (which reads ``_capture_live_label``), nor the return-effects summary.
        The residuals stay disclosed: an escaping alias, a HOF-invoked closure,
        a returned / struct-stored / reassigned-``var`` closure, and the
        different-root points-to family remain unflagged. A nested local lambda
        in RESULT POSITION is NOT a residual: the outer lambda's cached result
        label recurses through the inner call, so ``return g()`` (and the
        bound-then-returned form) flag. Only a nested case that ALSO escapes or
        goes through a HOF stays open, by the escaping / HOF residual above.

        MISS HANDLING. The recorded label is looked up by the lambda's
        identity. A miss is reachable in exactly ONE benign way: a lambda with
        an OMITTED parameter type and NO inference context is checked LAZILY
        (``_check_lambda`` returns early, before recording its result label,
        and leaves it in ``_pending_inferred_lambdas``), yet the ``let`` / IIFE
        still records the node in ``_binding_lambdas``. Such a lambda is ALREADY
        a reported type error (``_flush_pending_inferred_lambdas`` emits the
        ``cannot infer the type of this lambda`` diagnostic), so the program is
        rejected (exit 1) and NEVER runs. For that case the missing label is
        PUBLIC-for-now: it cannot hide a leak (the program does not compile),
        and returning it keeps the clean type-error diagnostic instead of
        turning it into a panic.

        Any OTHER miss -- a fully type-checked, NON-pending locally-resolved
        lambda with no recorded result label -- is genuinely unexpected and
        fails CLOSED: rather than fall open to PUBLIC (a future refactor routing
        a checked lambda into ``_binding_lambdas`` without recording its result
        label would then silently launder a @secret result), it raises,
        compilation stops, nothing leaks. The explicit raise is deliberate over
        an ``assert`` so ``python -O`` cannot strip the soundness gate."""
        label = self._lambda_result_labels.get(id(lam))
        if label is None:
            if id(lam) in self._pending_inferred_lambdas:
                # Benign, reachable miss: an un-inferrable-parameter lambda
                # already rejected by a type error; never runs, cannot leak.
                return L.PUBLIC
            raise AssertionError(
                "IFC invariant violated: a fully checked locally-resolved "
                "lambda has no recorded result label. Refusing to fall open "
                "to PUBLIC."
            )
        return label

    def _fresh_capture_label(self, lam: A.LambdaExpr) -> str:
        """Re-read the CURRENT LIVE label of each free binding ``lam``
        captures and join them -- the capture-side lambda-flow re-read
        (Stage B), evaluated at the INVOCATION site. It carries a captured
        value's later taint into the closure's RESULT label, so a caller that
        sinks that result is caught; a sink INTERNAL to the closure body (a
        side effect, not the result) is a disclosed residual (Stage B closes
        the RESULT-sink case only).

        CRITICAL: it consults the LIVE channels DIRECTLY -- the branch-scoped
        container-mutation taint (``_container_taint_at(sym, ())``) and, for a
        REFERENCE-typed capture, the binding's current ``sym.label`` -- and
        NEVER the cached ``_lambda_capture_labels`` / ``_label_of`` /
        ``_expr_labels``, which were stamped when the lambda body was checked
        at its DEFINITION (the captured container still empty), so re-serving
        them would silently no-op. Re-reading the live container-taint map is
        what surfaces a push that happened AFTER the closure was defined.

        FIELD-PRECISE (the R2 fix). How the body READS each capture decides
        the granularity (``_capture_read_paths``). A WHOLE / undeterminable
        read (a bare use, a method receiver ``bag.reveal()``, an argument)
        observes EVERY container taint on the root (``_container_taint_at(sym,
        ())``) plus -- for a reference type -- the whole-value ``sym.label``. A
        read at determinable FIELD PATHS only (``box.note``) observes only the
        branch-scoped container taints PREFIX-COMPATIBLE with those paths
        (``_capture_container_taint``), so a closure reading a CLEAN SIBLING of
        a field stored / pushed after its definition is no longer over-tainted,
        while reading the STORED path (``s_struct_fieldstore_result``,
        ``r2ctl_capture_samefield``) stays flagged. An in-place field store now
        SEEDS that branch-scoped channel (``_seed_container_taint``), so it is
        observed exactly like a push.

        REFTYPE. The whole-value ``sym.label`` is re-read only for a
        REFERENCE-typed capture, and only when the binding was NOT precisely
        container-seeded (``_container_seeded``) OR is whole-value-DIRTY
        (``_container_whole_dirty``). Not seeded: its secrecy is a whole
        reassign / alias / annotation the field-precise channel cannot see, so
        re-reading it keeps the disclosed whole-reassign over-report and the
        aliasing catch. Dirty: a precisely-seeded binding that ALSO took an
        IN-PLACE field store through a whole-value early-return -- an escaped /
        aliased / unresolvable-path store raising ``sym.label`` WITHOUT a
        precise seed -- which the field-precise channel would miss, so its
        whole-value label must be re-consulted. When the binding was precisely
        seeded AND is not dirty, the branch-scoped field-precise channel
        governs and the collapsed whole-value label is deliberately NOT re-read
        (that removes the R2 sibling over-report while staying branch-sound).
        ``sym.label`` is always SKIPPED for a VALUE-typed capture -- a built-in
        immutable primitive (String / Int / Float / Bool / Char), told apart by
        ``_capture_is_value_typed`` -- because a primitive is captured BY VALUE,
        so a later REASSIGNMENT is not observed (``l_a_scalar_reassign``).

        Branch-soundness is BY CONSTRUCTION: ``_container_taint`` is the live,
        branch-scoped map (``_container_isolate`` / ``_container_merge``), so a
        push / store in a mutually-exclusive ``then`` branch is simply not in
        the map at an ``else`` branch's invocation point; the ``_container_
        seeded`` flat mark gates only the whole-value ``sym.label`` re-read, so
        a branch-exclusive field store stays clean at the sibling branch.

        DISCLOSED SAFE over-reports (sound, never a missed leak):
        * WHOLE-VALUE on a WHOLE-read capture: a closure reading a captured
          container through a getter / whole read whose OTHER field was pushed
          flags (the read is whole, so the length-0 query observes the push),
          at parity with the ``ALIAS_COPY_AFTER`` over-report;
        * DECLASSIFY-BLIND: the re-read reads the RAW taint (unlike
          ``_lambda_result_labels``), so a closure that ``declassify``s its
          captured value IN-BODY still flags -- ``declassify(f(), reason: ...)``
          at the CALL SITE silences it;
        * REF-TYPE WHOLE-REASSIGN: a captured STRUCT whole-reassigned to a
          secret after definition (``bag = Bag { data: secret }``) flags though
          a struct is captured by value here and nothing leaks -- the reassign
          leaves no precise container seed, so ``sym.label`` is re-read and
          cannot tell it from an in-place field store. A strict-tier
          over-rejection, with precedent in the reassigned-``var`` sink
          recovery that also fails closed under strict.

        The lambda's own parameters / inner binds are excluded (they are not
        captures), mirroring ``_lambda_capture_label``."""
        label = L.PUBLIC
        for sym, paths, whole in self._capture_read_paths(lam).values():
            label = L.join(label, self._capture_live_label(sym, paths, whole))
        return label

    def _capture_live_label(self, sym, paths, whole) -> str:
        """The CURRENT LIVE label a single capture ``sym`` contributes, given
        how the closure body accesses it: ``whole`` (or an empty ``paths``
        set) for a WHOLE / undeterminable read, else the determinable field
        ``paths``. A pure function of ``sym`` + ``paths`` + ``whole`` and the
        live channels (the branch-scoped container-taint map, the flat
        container-seeded / whole-value-dirty marks, and ``sym.label``); it
        consults NO cached def-time label. Factored out of
        ``_fresh_capture_label`` so BOTH the RESULT re-read (which joins it
        over the closure's READ paths) and the capture-INTERNAL-sink check
        (``_apply_lambda_capture_sink_summary``, which passes the SUNK paths)
        share one gate. See ``_fresh_capture_label`` for the full rationale of
        each arm (WHOLE vs FIELD-PRECISE, the REFTYPE ``sym.label`` re-read,
        the value-typed capture-by-value skip, branch-soundness by
        construction)."""
        value_typed = self._capture_is_value_typed(sym)
        label = L.PUBLIC
        if whole or not paths:
            # WHOLE / undeterminable read of the capture (a bare use, a
            # method receiver, an argument): observe EVERY container taint
            # on the root (the length-0 query), plus -- for a reference
            # type -- the flat whole-value ``sym.label``. A value-typed
            # (built-in immutable primitive) capture is captured by value,
            # so its later reassignment is not observed and ``sym.label``
            # is skipped.
            ct = self._container_taint_at(sym, ())
            if ct:
                label = L.join(label, ct)
            if not value_typed:
                label = L.join(
                    label,
                    L.normalize(getattr(sym, "label", None) or L.PUBLIC),
                )
        else:
            # FIELD-PRECISE read: the closure reads the capture only at
            # determinable field paths, so observe only the branch-scoped
            # container taints PREFIX-COMPATIBLE with a read path (an
            # in-place field store / push at, above, or below a read path
            # is seen; a disjoint CLEAN SIBLING is not -- the R2 fix).
            ct = self._capture_container_taint(sym, paths)
            if ct:
                label = L.join(label, ct)
            # A reference type's whole-value ``sym.label`` is re-read when
            # the binding is NOT precisely container-seeded (its secrecy is
            # a whole reassign / alias / annotation the field-precise
            # channel cannot see -- keeping the disclosed whole-reassign
            # over-report and the aliasing catch) OR when it is
            # whole-value-DIRTY (a precisely-seeded binding that ALSO took
            # an in-place field store through a whole-value early-return:
            # an escaped / aliased / unresolvable-path store that raised
            # sym.label without a precise seed, so the field-precise
            # channel would miss it). When it was precisely seeded AND is
            # not dirty, the branch-scoped field-precise channel governs
            # (so a branch-exclusive store stays branch-sound), and the
            # collapsed whole-value label is deliberately NOT re-read.
            if not value_typed and (
                id(sym) not in self._container_seeded()
                or id(sym) in self._container_whole_dirty()
            ):
                label = L.join(
                    label,
                    L.normalize(getattr(sym, "label", None) or L.PUBLIC),
                )
        return label

    def _capture_container_taint(self, sym, paths):
        """Join every branch-scoped container-mutation taint on ``sym`` whose
        access path is PREFIX-COMPATIBLE with any read path in ``paths`` (one
        is a prefix of the other), or ``None``. A whole / sub-struct read
        observes a nested field store / push, and a read INTO a stored secret
        sub-struct observes it too, while a disjoint sibling path matches
        nothing. The field-precise analogue of ``_container_taint_at(sym, ())``
        used by the capture re-read."""
        ct = self._container_taint_map()
        if not ct:
            return None
        root = id(sym)
        out = None
        for (kid, kpath), lbl in ct.items():
            if kid != root:
                continue
            if any(_prefix_compatible(kpath, tuple(p)) for p in paths):
                out = L.join(out, lbl)
        return out

    def _capture_read_paths(self, lam: A.LambdaExpr) -> dict:
        """For each free binding ``lam`` captures, how its body READS it:
        ``{id(sym): (sym, {field-path, ...}, whole)}``. A maximal
        Ident-rooted field chain (``box.a.b``) contributes its parameter-
        relative path; a BARE use of the root -- a method receiver
        (``box.reveal()``), an argument, a scrutinee, a whole value -- sets
        ``whole`` (an undeterminable / whole read that falls back to the
        whole-value re-read). Binding identity (not name) matches the root, so
        a nested lambda's same-named parameter is not confused with the
        capture. The lambda's own params / inner binds are excluded."""
        locals_: set[str] = {p.name for p in lam.params}
        for stmt in self._lambda_body_stmts(lam):
            self._collect_bound_names(stmt, locals_)
        out: dict = {}
        self._walk_capture_reads(lam.body, locals_, out)
        return {k: (v[0], v[1], v[2]) for k, v in out.items()}

    def _walk_capture_reads(self, node, locals_: set, out: dict) -> None:
        """Recursive walk backing ``_capture_read_paths``. A maximal
        Ident-rooted field chain rooted at a NON-local binding records its
        path and is not descended into; a bare captured Ident records a whole
        read; everything else recurses generically (so a capture nested in a
        call receiver / index / argument is still found)."""
        import dataclasses
        if isinstance(node, A.FieldAccess):
            root_ident = node
            while isinstance(root_ident, A.FieldAccess):
                root_ident = root_ident.receiver
            path = self._field_path_from_root(node)
            if (
                isinstance(root_ident, A.Ident)
                and root_ident.name not in locals_
                and path
            ):
                sym = self.bindings.get(id(root_ident))
                if sym is not None:
                    entry = out.setdefault(id(sym), [sym, set(), False])
                    entry[1].add(tuple(path))
                    return
            self._walk_capture_reads(node.receiver, locals_, out)
            return
        if isinstance(node, A.Ident):
            if node.name not in locals_:
                sym = self.bindings.get(id(node))
                if sym is not None:
                    entry = out.setdefault(id(sym), [sym, set(), False])
                    entry[2] = True
            return
        if node is None or isinstance(node, str):
            return
        if dataclasses.is_dataclass(node):
            for f in dataclasses.fields(node):
                self._walk_capture_reads(getattr(node, f.name), locals_, out)
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                self._walk_capture_reads(x, locals_, out)

    def _capture_is_value_typed(self, sym) -> bool:
        """True when ``sym``'s resolved type is a built-in immutable PRIMITIVE
        (String / Int / Float / Bool / Char) -- captured BY VALUE, so a later
        REASSIGNMENT of the binding is not observed through a closure that
        captured it. Consulted by the capture re-read (``_fresh_capture_label``,
        Finding 2) to skip the whole-value ``sym.label`` re-read for such a
        capture while keeping it for a reference type.

        Reuses ``PRIMITIVE_NAMES`` and the built-in-origin (``BUILTIN_POS``)
        test of the mutation-effect precision predicate
        (``_name_is_builtin_immutable`` in :mod:`._ifc_summary`): the resolved
        type must be a bare ``TyName`` whose name is a primitive AND resolves to
        the ACTUAL built-in symbol, so a user ``type String { ... }`` (a mutable
        struct shadowing the name) is NOT treated as value-typed and keeps its
        sound whole-value re-read. Conservative: any non-primitive, generic /
        argument-bearing, unresolved, or user-shadowed type is reference-typed
        (returns False), so the re-read is never dropped where a leak could
        hide."""
        from ..typesys import TyName, PRIMITIVE_NAMES
        from ..builtins import BUILTIN_POS
        ty = getattr(sym, "ty", None)
        if not isinstance(ty, TyName) or getattr(ty, "args", None):
            return False
        if ty.name not in PRIMITIVE_NAMES:
            return False
        tsym = self.global_scope.lookup(ty.name)
        return tsym is not None and tsym.pos == BUILTIN_POS

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
        the JOIN of the labels of every value the closure can return along
        ANY path. An expression-bodied lambda returns its expression; a
        block-bodied one can return via its trailing bare expression
        (block-as-expression) AND via any ``return <expr>`` statement,
        including returns nested inside ``if`` / ``match`` / loop branches.
        If a secret is returned on any path the result label is secret;
        Unit (no returnable value) is PUBLIC.

        Unlike the capture label, this is what flows out of ``f()``, so a
        path that DECLASSIFIES its captured secret contributes PUBLIC --
        the precise input to the store-site and boundary checks, avoiding a
        false positive on a closure that only ever returns public /
        declassified values."""
        body = e.body
        if not isinstance(body, A.Block):
            return self._label_of(body)
        labels = [self._block_tail_value_label(body)]
        for rexpr in self._lambda_return_exprs(body.stmts):
            labels.append(self._label_of(rexpr))
        return L.join_all(labels)

    def _block_tail_value_label(self, block) -> str:
        """The IFC label of the value a BLOCK yields as an expression
        (block-as-value). Handles every trailing statement form the parser
        admits as a block's tail value, anchored to the SAME node set the
        block-value TYPE derivation uses so the label channel cannot
        diverge from the type channel:

        * a trailing bare expression (``ExprStmt``) -- which already covers
          an ``if`` EXPRESSION (``if c then a else b``) and a ``match``
          expression, since those are expressions labelled by ``_label_of``;
        * a trailing statement-form ``if`` whose branches are blocks (join
          every branch's tail-value label; a missing ``else`` yields Unit
          on that path, contributing PUBLIC);
        * a trailing nested ``Block`` (recurse).

        Any other trailing statement yields no block value (PUBLIC); values
        produced via ``return`` are joined separately by the caller. A
        secret on ANY yielding path makes the whole result secret."""
        if not isinstance(block, A.Block) or not block.stmts:
            return L.PUBLIC
        last = block.stmts[-1]
        if isinstance(last, A.ExprStmt):
            return self._label_of(last.expr)
        if isinstance(last, A.IfStmt):
            labels = [self._block_tail_value_label(last.then_block)]
            for _cond, blk in last.elif_arms:
                labels.append(self._block_tail_value_label(blk))
            if last.else_block is not None:
                labels.append(self._block_tail_value_label(last.else_block))
            return L.join_all(labels)
        if isinstance(last, A.Block):
            return self._block_tail_value_label(last)
        return L.PUBLIC

    def _lambda_return_exprs(self, node):
        """Yield the value expression of every ``return <expr>`` reachable
        from ``node`` along any control-flow path (``if`` / ``match`` /
        loop branches), WITHOUT descending into a nested lambda's body (a
        nested closure's ``return`` produces that closure's value, not
        this one's). ``return`` with no value yields nothing (Unit)."""
        import dataclasses
        if isinstance(node, A.LambdaExpr):
            return
        if isinstance(node, A.ReturnStmt):
            if node.value is not None:
                yield node.value
            return
        if node is None or isinstance(node, str):
            return
        if dataclasses.is_dataclass(node):
            for f in dataclasses.fields(node):
                yield from self._lambda_return_exprs(getattr(node, f.name))
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                yield from self._lambda_return_exprs(x)

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
          binding (``_binding_result_label``), closing the two-hop leak for
          these single-denotation bindings while STILL seeing through an
          in-body declassify: a let-bound declassifying closure stays public
          and is not a false positive. A REASSIGNED / mixed ``var`` has no
          single denotation, so it is not resolved here: it is closed in the
          STRICT tier but only best-effort in the warn tier, which SKIPS an
          ever-public ``var`` to stay free of false positives (see
          ``_fun_arg_ret_label``).

        For any OTHER Fun argument -- one whose binding RHS is a call
        result (``let f = make(env); invoke(f)``), a by-name alias, a fresh
        ``var`` bound to a non-lambda, a struct field (``b.thunk``), a
        re-passed Fun parameter, or a call result passed inline
        (``invoke(make(env))``) -- the argument's declassify-aware RETURN
        label is recovered from its RESOLVED ``TyFun`` type
        (``_fun_arg_ret_label``). This is sound precisely because it runs on
        the SINK path (it only matters when the callee actually sinks the
        argument's result), and ``TyFun.ret_label`` already sees THROUGH an
        in-body declassify: a factory that declassifies internally has a
        public return type, so its result binding is not flagged. It closes
        the call-result-binding false negative (a honestly-secret-returning
        factory whose result is later sunk by a public-``Fun`` callee).

        A REASSIGNED ``var`` has an ambiguous denotation, and the two tiers
        resolve it differently (``_fun_arg_ret_label``). In the DEFAULT
        (warn) tier the check is precise: it flags the ``var`` only when
        EVERY closure ever assigned to it is secret-returning, and SKIPS an
        ever-public / mixed ``var`` (its current closure may be public), a
        best-effort documented limitation that keeps the warn tier free of
        false positives. In the STRICT tier the check FAILS CLOSED: any
        reassigned Fun argument whose resolved ``TyFun.ret_label`` is secret
        is flagged, regardless of ever-public -- the mixed ``var`` whose last
        assignment is secret is a real leak, so the strict tier over-rejects
        (a public-only-final ``var`` becomes an accepted strict-tier false
        positive, consistent with the strict tier's reject-first posture).

        The parameter kind is told apart by its declared TYPE: a ``TyFun``
        parameter is the invoke case, anything else the data case."""
        from ..typesys import TyFun
        if isinstance(ptype, TyFun):
            if isinstance(arg, A.LambdaExpr):
                return self._lambda_result_labels.get(id(arg), L.PUBLIC)
            if isinstance(arg, A.Ident):
                precise = self._binding_result_label(arg)
                if precise is not None:
                    return precise
            return self._fun_arg_ret_label(arg)
        return self._label_of(arg)

    def _fun_arg_ret_label(self, arg: A.Expr):
        """The declassify-aware RETURN label of a Fun argument that does not
        resolve to a single certain lambda literal, recovered from its
        resolved ``TyFun`` type for the sink-path boundary check. ``None``
        when the type is not a resolved ``TyFun`` (nothing to test).

        A REASSIGNED ``var`` has an ambiguous denotation -- its joined
        resolved type can read ``secret`` even when the name currently holds
        a PUBLIC closure -- so the two tiers resolve it differently:

        * DEFAULT (warn): recover the resolved label only when EVERY closure
          ever assigned to the ``var`` is secret-returning
          (``_var_ever_public_fun`` does not hold its id); the ``var`` then
          holds a secret closure on every path and at every point, so
          flagging is never a false positive. Once a public-returning
          closure has been assigned, the current value MAY be public, so the
          warn tier SKIPS (``None``) -- a best-effort documented limitation
          that keeps the warn tier free of false positives.
        * STRICT: FAIL CLOSED. Drop the ever-public exception and return the
          resolved ``TyFun.ret_label`` for any reassigned ``var`` -- a mixed
          ``var`` whose last assignment is secret is a real leak the strict
          tier must reject, and the strict tier accepts the resulting
          over-rejection on a public-only-final ``var`` (its reject-first
          posture). A public-then-secret reassignment into a PUBLIC slot is
          in any case already caught at the store site
          (``_check_closure_ret_flow`` at ``_check_assign``)."""
        from ..typesys import TyFun
        if isinstance(arg, A.Ident):
            sym = self.bindings.get(id(arg))
            if (
                sym is not None
                and self._binding_reassigned(sym)
                and id(sym) in self._var_ever_public_fun
                and not getattr(self, "_strict_ifc", False)
            ):
                return None
        arg_ty = self.types.get(id(arg))
        if isinstance(arg_ty, TyFun):
            return L.normalize(getattr(arg_ty, "ret_label", None))
        return None

    def _binding_reassigned(self, sym) -> bool:
        """True when ``sym`` names a ``var`` that was REASSIGNED after its
        introduction -- recorded by ``_record_binding_lambda`` poisoning the
        binding-lambda record to the ``None`` sentinel. Distinguished from a
        binding that was simply never a lambda literal (absent from the
        record), which is NOT ambiguous and does carry a sound resolved
        type."""
        return (
            id(sym) in self._binding_lambdas
            and self._binding_lambdas[id(sym)] is None
        )

    def _note_fun_var_assignment(self, sym, value: A.Expr) -> None:
        """Record that a ``var`` was assigned a PUBLIC-returning closure, at
        its introduction or a reassignment (``_var_ever_public_fun``). Once
        set, the reassigned-var sink recovery skips the binding (its current
        closure may be public); a ``var`` all of whose assigned closures are
        secret-returning is never marked and stays flaggable. A non-Fun RHS
        contributes nothing. Monotonic: only ever adds."""
        if sym is None:
            return
        ret = self._closure_value_ret_label(value)
        if ret is not None and L.normalize(ret) == L.PUBLIC:
            self._var_ever_public_fun.add(id(sym))

    def _closure_value_ret_label(self, value: A.Expr):
        """The RETURN label of a Fun-valued RHS: a lambda literal's own
        RESULT label (declassify-aware, so an in-body declassify reads
        public), else the resolved ``TyFun`` type's ``ret_label``. ``None``
        when the value is not a Fun (nothing to contribute)."""
        from ..typesys import TyFun
        if isinstance(value, A.LambdaExpr):
            return self._lambda_result_labels.get(id(value))
        t = self.types.get(id(value))
        if isinstance(t, TyFun):
            return getattr(t, "ret_label", None)
        return None

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
        binding whose RHS was not a lambda literal). Precise by
        construction: it reads the recorded lambda's own RESULT label, so a
        declassifying let-bound closure stays public. ``None`` is the caller
        of this helper (``_sink_param_arg_label``) then handing off to
        ``_fun_arg_ret_label``, which recovers the argument's declassify-
        aware ``TyFun.ret_label`` for every non-lambda-literal shape except
        the ambiguous reassigned ``var``."""
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

    # ---- branch-scoped container-mutation taint channel ----------
    #
    # A per-binding channel (``id(Symbol) -> label``) recording the taint
    # a container binding acquired from an in-body mutation
    # (``xs.push(secret)``). It is kept SEPARATE from the shared
    # ``Symbol.label`` (which stays flat / monotone, coupled to field / alias
    # / escape reasoning) and is branch-scoped exactly like the summary's
    # cross-function content channel: each branch is analyzed from a common
    # snapshot in isolation, then every branch's delta is unioned back
    # (``_container_isolate`` / ``_container_merge``). Joined into a binding's
    # effective label only on a READ (``_compute_label``). ``while`` / ``for``
    # have a single body and merge naturally (the body mutates the channel in
    # place); only ``if`` / ``elif`` / ``else`` and ``match`` arms need the
    # explicit isolate-then-merge.

    def _container_taint_map(self) -> dict:
        ct = getattr(self, "_container_taint", None)
        if ct is None:
            ct = {}
            self._container_taint = ct
        return ct

    def _container_seeded(self) -> set:
        """The flat (NOT branch-scoped) set of bindings ever field-KEYED on
        the container channel by a precise field store / container push.
        Reset per function in ``_check_fn``; lazily created for a context
        (a nested lambda check) that runs before the reset."""
        seeded = getattr(self, "_container_seeded_syms", None)
        if seeded is None:
            seeded = set()
            self._container_seeded_syms = seeded
        return seeded

    def _container_whole_dirty(self) -> set:
        """The flat set of bindings whose ``sym.label`` was raised to secret
        by an IN-PLACE field store that took a whole-value early-return
        (alias group / escaped / unresolvable path), so was NOT precisely
        seeded. The capture re-read re-consults ``sym.label`` for these even
        if they were precisely seeded elsewhere. Reset per function."""
        dirty = getattr(self, "_container_whole_dirty_syms", None)
        if dirty is None:
            dirty = set()
            self._container_whole_dirty_syms = dirty
        return dirty

    def _mark_whole_value_dirty(self, sym, incoming) -> None:
        """Flag ``sym`` whole-value-dirty when an in-place field store raising
        its collapsed label took a whole-value early-return without a precise
        seed. SECRET-only: a public early-returned store leaves the binding's
        field-precise channel authoritative, so it does not dirty it."""
        if sym is not None and L.normalize(incoming) == L.SECRET:
            self._container_whole_dirty().add(id(sym))

    def _raise_whole_value_label(self, sym, incoming) -> None:
        """The single CHOKE-POINT for raising a struct binding's COLLAPSED
        whole-value label OUTSIDE the precise field-store leaf path: an
        aliased / escaped / unresolvable-path field store, or a cross-function
        whole-value mutation effect. It raises the label AND marks the binding
        whole-value-DIRTY, because such a raise is NOT backed by a precise
        ``(root, field-path)`` seed, so the field-precise capture channel
        cannot see it and the capture gate (``_fresh_capture_label``) must
        re-consult ``sym.label`` for it.

        Routing EVERY non-seed whole-value raise here is what keeps the capture
        gate SOUND BY CONSTRUCTION: a whole-value taint added through this
        helper cannot silently suppress the re-read (which was the CRITICAL-2
        / CRITICAL-3 leak class). The two whole-value raises that deliberately
        do NOT go through here are (a) the precise field-store LEAF path, whose
        secrecy IS seeded (``_seed_container_taint`` / ``_seed_container_leaves``),
        and (b) a whole REASSIGN ``box = <secret>`` (an Ident-target assign in
        ``_check_assign``), which rebinds the variable to a NEW object the
        closure -- holding the OLD one -- cannot observe, so it is captured by
        value and must NOT dirty the binding (else the disclosed
        whole-reassign over-report would flip to a false negative's opposite).
        The remaining ``sym.label`` raises are on FRESH, not-yet-seeded
        bindings (a ``let`` / ``var`` / const introduction, a pattern-bound
        local, a fresh alias target), which the gate already re-consults via
        the NOT-seeded arm, so dirtying them is unnecessary."""
        sym.label = L.join(getattr(sym, "label", None), incoming)
        self._mark_whole_value_dirty(sym, incoming)

    def _seed_container_taint(self, sym, path: tuple, incoming) -> None:
        """Record a field-KEYED container-mutation taint on ``sym`` at
        ``path`` (a precise field store or container push), monotone and
        SECRET-only, and flat-mark ``sym`` as container-seeded. The taint
        goes on the branch-scoped ``(root, field-path)`` channel; the flat
        mark is a separate, non-branch-scoped record the capture re-read
        consults for branch-soundness (see ``_container_seeded``)."""
        if L.normalize(incoming) != L.SECRET:
            return
        ct = self._container_taint_map()
        key = (id(sym), tuple(path))
        ct[key] = L.join(ct.get(key), incoming)
        self._container_seeded().add(id(sym))

    def _seed_container_leaves(self, sym, base_path: tuple, node) -> None:
        """Seed the container channel at the SECRET LEAVES of ``node`` (a
        per-field label map or a leaf label) under ``base_path``. A whole-
        struct field store (``o.inner = Inner { x: secret }``) seeds the exact
        leaf ``(o, ("inner", "x"))`` rather than the collapsed interior node,
        so a public sub-leaf of the stored struct is NOT over-tainted by the
        prefix-compatible ancestor direction of ``_container_taint_at`` while
        the secret leaf is still observed by a read at, above, or below it."""
        if isinstance(node, dict):
            for name, child in node.items():
                self._seed_container_leaves(sym, base_path + (name,), child)
        else:
            self._seed_container_taint(sym, base_path, node)

    def _container_taint_at(self, sym, path: tuple):
        """Join of every branch-scoped container-mutation taint recorded on
        ``sym`` at a PREFIX-COMPATIBLE path (one path is a prefix of the
        other), or ``None``. Reading a value observes a taint AT or BELOW its
        path (reading ``bag.items`` observes a push into ``bag.items``;
        reading the sub-struct ``bag.a`` observes a push into ``bag.a.b``)
        AND a taint at an ANCESTOR of its path (reading ``o.inner.x`` observes
        a whole-value store into ``o.inner`` -- the cross-function
        field-store effect keyed at the interior node), while a DISJOINT
        sibling path (``bag.other``) matches nothing and stays public.
        A field store seeds at LEAF granularity (``_seed_container_leaves``),
        so a whole-struct store's public sub-leaf is NOT over-tainted by the
        ancestor direction; a cross-function effect seeds at its (coarser)
        interior path, a sound over-approximation of the callee's unknown
        sub-structure."""
        ct = self._container_taint_map()
        if not ct:
            return None
        root = id(sym)
        out = None
        for (kid, kpath), lbl in ct.items():
            if kid == root and _prefix_compatible(kpath, path):
                out = L.join(out, lbl)
        return out

    def _container_isolate(self, baseline: dict) -> dict:
        """Start a branch from a copy of ``baseline`` and return the map the
        branch ends with (its own additions), leaving ``baseline`` intact so
        the next sibling starts clean too."""
        self._container_taint = dict(baseline)
        return self._container_taint

    def _container_merge(self, baseline: dict, posts: list) -> None:
        """Union every branch's container-taint map (from
        ``_container_isolate``) back into the enclosing scope, so a read
        AFTER the construct reflects any branch's push while a sibling read
        did not."""
        merged = dict(baseline)
        for post in posts:
            for key, lbl in post.items():
                merged[key] = L.join(merged.get(key), lbl)
        self._container_taint = merged

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
        that happens to be named ``declassify`` is not special-cased.

        Delegates to :func:`capa._declassify.is_declassify_call`, the
        SINGLE source of truth this predicate shares with the artifact
        pipeline: the manifest collector asks the same function, so the
        analyzer and the SBOM can no longer disagree about which calls
        are declassifications."""
        from .._declassify import is_declassify_call
        return is_declassify_call(e, self.bindings)

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

    def _container_mutation_key(self, recv: A.Expr):
        """The ``(id(root-binding), field-path-tuple)`` the mutated
        container lives at, or ``None`` when the receiver is not rooted at
        a binding. A plain identifier (``xs``) yields path ``()``; an
        Ident-rooted field chain (``bag.items``, nested ``bag.a.b``) yields
        its field names. A receiver rooted at a call / index / any other
        expression (``foo().items``, ``arr[0].items``) is out of reach and
        left untracked, exactly as the plain-Ident slice left field chains
        untracked before."""
        if isinstance(recv, A.Ident):
            sym = self.bindings.get(id(recv))
            return (id(sym), ()) if sym is not None else None
        if isinstance(recv, A.FieldAccess):
            sym = self._struct_root_sym(recv)
            path = self._field_path_from_root(recv)
            if sym is None or path is None:
                return None
            return (id(sym), tuple(path))
        return None

    def _check_ifc_container_mutation(self, e: A.MethodCall, recv_ty) -> None:
        """When a mutating method (``List.push`` / ``Set.add`` /
        ``Map.set``) is called with a @secret argument, record that the
        mutated container is @secret from here on, keyed on the
        ``(root-binding, field-path)`` it lives at, so a later read of that
        path does not launder the secret back to public. Without this,
        ``let m = new_map(); m.set(k, secret); m.get(k)`` (or the
        field-chain form ``bag.items.push(secret); bag.items.get(0)``)
        would come out public on the read.

        The receiver may be a plain identifier (``xs.push(secret)`` -> path
        ``()``) or an Ident-rooted field chain (``bag.items.push(secret)``
        -> path ``("items",)``; nested ``bag.a.b`` -> ``("a", "b")``). A
        receiver not rooted at a binding is left untracked (a disclosed
        residual, as before). The record is monotonic (join) and
        branch-scoped, so it is sound under conditional / looping mutation."""
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        taint_args = _CONTAINER_MUTATORS.get((cap_name, e.method))
        if not taint_args:
            return
        target = self._container_mutation_key(e.receiver)
        if target is None:
            return
        incoming = L.join_all(
            self._label_of(e.args[idx])
            for idx in taint_args
            if idx < len(e.args)
        )
        if L.normalize(incoming) != L.SECRET:
            return
        # Record the taint in a SEPARATE, per-(binding, field-path),
        # BRANCH-SCOPED channel rather than raising the shared ``sym.label``
        # / the per-field ``field_labels`` / the struct-alias groups / the
        # escaped-struct set. Raising any of those over-taints a public
        # sibling field and leaks a branch-local push into a
        # mutually-exclusive sibling branch's read -- the false positives
        # commits b895ca6 / 4c69a02 removed for the plain-Ident case. This
        # channel is isolated per branch and deferred-unioned out (see
        # ``_check_if`` / ``_check_match_expr``), and joined into the
        # effective label only when the path is READ (``_compute_label``),
        # so a sibling read stays clean while a read AFTER the construct
        # still reflects the push. The shared label / field labels / alias
        # groups / escape tracking are left flat and untouched. The binding
        # is also flat-marked container-seeded (``_container_seeded``) so the
        # capture re-read trusts this branch-scoped, field-precise channel.
        ct = self._container_taint_map()
        ct[target] = L.join(ct.get(target), L.SECRET)
        self._container_seeded().add(target[0])

    def _check_no_cap_into_container(self, e: A.MethodCall, recv_ty) -> None:
        """Reject inserting a capability into a container via a
        mutator (``List.push`` / ``Set.add`` / ``Map.set``). This is an
        entry gate for a precise, early diagnostic at the insertion
        site; the resolved-type use-gate and the deferred recheck would
        catch a later read of the populated container regardless.

        The element / value argument positions are exactly the ones the
        IFC taint check already keys on (``_CONTAINER_MUTATORS``). A
        capability -- bare or itself nested -- in any of those positions
        is packed into the container, which the discipline forbids."""
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        positions = _CONTAINER_MUTATORS.get((cap_name, e.method))
        if not positions:
            return
        for idx in positions:
            if idx >= len(e.args):
                continue
            arg_ty = self.types.get(id(e.args[idx]))
            if arg_ty is None:
                continue
            cap = self._contains_any_capability(self._resolve_ty(arg_ty))
            if cap is not None:
                self._err(
                    f"capability {cap.name!r} cannot be inserted into a "
                    f"container: a capability may only flow as a bare, "
                    f"top-level value (a direct function parameter), never "
                    f"packed inside a list, set, map, or tuple",
                    e.args[idx].pos,
                )
                return

    def _check_container_closure_store(self, e: A.MethodCall, recv_ty) -> None:
        """Higher-order IFC: inserting a secret-returning closure into a
        public-declared container (``List.push`` / ``Set.add`` /
        ``Map.set``) launders the secret through the container's declared
        element / value type, so a later read-and-invoke at a public sink
        would leak it. Flag it at the insertion -- the container analogue
        of the struct-field store check. Argument position ``i`` binds to
        the container's ``i``-th type argument (List / Set element, Map key
        then value), so the declared slot type and the closure's actual
        return label are both in hand."""
        cap_name = getattr(recv_ty, "name", None)
        if cap_name is None:
            return
        positions = _CONTAINER_MUTATORS.get((cap_name, e.method))
        if not positions:
            return
        args = getattr(recv_ty, "args", ())
        for i in positions:
            if i < len(e.args) and i < len(args):
                self._check_closure_ret_flow(
                    args[i], self.types.get(id(e.args[i])),
                    e.args[i].pos, f"stored into a {cap_name}",
                )

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
                # Whole-value CHOKE-POINT: an aliased store is not
                # field-keyable, so it raises the member's whole-value label
                # WITHOUT a precise seed and marks it whole-value-dirty (the
                # capture re-read re-consults sym.label). Also escape it.
                self._raise_whole_value_label(member, incoming)
                self._escaped_struct_syms.add(id(member))
            return
        # Always keep the collapsed label monotonically correct: a store
        # of a secret into any field of the binding makes the whole value
        # at least that secret. This preserves the pre-existing
        # whole-value soundness even when per-field tracking is absent. Each
        # of these early-returns raises the whole-value label without a
        # precise seed, so it routes through the CHOKE-POINT (dirtying the
        # binding) rather than assigning ``root.label`` directly.
        if getattr(root, "field_labels", None) is None or \
                id(root) in self._escaped_struct_syms:
            self._raise_whole_value_label(root, incoming)
            return
        path = self._field_path_from_root(target)
        if not path:
            self._raise_whole_value_label(root, incoming)
            return
        node = root.field_labels
        for name in path[:-1]:
            nxt = node.get(name) if isinstance(node, dict) else None
            if not isinstance(nxt, dict):
                # The store reaches into something not tracked as a
                # struct sub-map; fall back to raising the whole value.
                self._raise_whole_value_label(root, incoming)
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
        # Also seed the branch-scoped ``(root, field-path)`` container channel
        # for this precise, non-aliased, non-escaped, resolvable-path store,
        # mirroring a container push. It is REDUNDANT for same-body reads --
        # the per-field map above already governs them field-precisely -- but
        # the per-field map is FLAT while the container channel is
        # BRANCH-SCOPED (``_container_isolate`` / ``_container_merge``), so
        # this is what gives the field-precise capture re-read
        # (``_fresh_capture_label``) and the cross-function apply a
        # branch-isolated, access-path source: a closure re-reading a CLEAN
        # SIBLING of a field stored after its definition is no longer
        # over-tainted, while a read of the stored path stays caught. Seeded at
        # LEAF granularity for a whole-struct store (``_seed_container_leaves``
        # walks the stored sub-map), so a public sub-leaf is not over-tainted
        # by the prefix-compatible ancestor scan; a scalar store seeds its own
        # leaf. Monotone and SECRET-only.
        if isinstance(sub, dict):
            self._seed_container_leaves(root, tuple(path), sub)
        else:
            self._seed_container_taint(root, tuple(path), incoming)

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
                # Feature #6 (B1): materialize the un-audited leak. The
                # sink capability is the receiver capability reached.
                self._record_unaudited_secret_sink(cap_name, arg.pos)

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
                # Feature #6 (B1): panic writes its message to stderr -- the
                # analyzer frames it as a public sink "exactly like
                # Stdio.eprintln" -- so the un-audited egress is via Stdio.
                # (panic itself needs no capability, but the secret still
                # leaves the program through the stderr stream Stdio owns.)
                self._record_unaudited_secret_sink("Stdio", e.args[0].pos)
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
            # ``sources`` is a per-path return map ``{field-path -> sources}``;
            # iterate the SOURCE sets (a path key is a tuple, so the old
            # ``0 <= s`` scalar test would raise ``TypeError`` on it). Join
            # over every path (whole-value). INTERNAL_SECRET (-1) is handled
            # (-> SECRET) above, so ``0 <= s`` skips it here.
            for _rpath, srcs in sources.items():
                for s in srcs:
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
        # ``sources`` is a per-path return map ``{field-path -> sources}``;
        # any source on ANY path firing taints the whole-value result.
        for _rpath, srcs in sources.items():
            for s in srcs:
                if s == INTERNAL_SECRET:
                    return True
                a = arg_for(s)
                if a is not None and                         L.normalize(self._label_of(a)) == L.SECRET:
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
        # Feature #6 (B1): the egress capabilities the routed secret
        # reaches inside the callee, PER PARAMETER (precise: a
        # free-function name resolves to exactly one callable). Tagging the
        # leak with only the sink-reaching parameter's own caps -- not the
        # whole-callable union -- keeps a secret routed to a Net-only param
        # from being fabricated as reaching a sibling param's Fs.
        callee_sink_caps = self._ifc_sink_caps.get(key, {})
        callee_sink_paths = self._ifc_sink_paths.get(key, {})
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
            # Stage 2 (read-side field precision): a whole struct tainted
            # only in the container channel is a leak ONLY if the callee
            # actually sinks a tainted access path -- intersect against the
            # callee's field-qualified sunk paths for this parameter.
            if self._sink_arg_field_cleared(
                arg, callee_sink_paths.get(param_idx),
            ):
                continue
            pname = (
                sym.param_names[param_idx]
                if param_idx < len(sym.param_names)
                else f"argument {arg_idx + 1}"
            )
            self._emit_ifc_call_leak(
                repr(sym.name), pname, arg.pos,
                callee_sink_caps.get(param_idx, frozenset()),
            )

    def _check_ifc_call_pc(self, e: A.Call, sym) -> None:
        """IFC-1 (strict implicit-flow across a call): under ``@strict_ifc``,
        calling a free function that can EXECUTE a public sink under its own
        control flow while the caller's pc is SECRET (the call sits inside a
        branch whose condition is @secret) leaks whether that branch was
        taken -- exactly the intra-procedural implicit-flow rule
        (``_check_ifc_sink``), now composed across the function boundary.

        The callee's ``sink_reaching_pc`` bit is a STATIC property from the
        summary pre-pass (whether the body reaches a real built-in sink or
        ``panic``, directly or transitively), so no live pc / label of the
        callee is consulted here. A free-function name resolves to exactly
        one callable, so the lookup is precise. Hard error under
        ``@strict_ifc`` ONLY (no default-tier warning), matching the inline
        rule's tier."""
        if not getattr(self, "_strict_ifc", False):
            return
        if L.normalize(getattr(self, "_pc_label", L.PUBLIC)) != L.SECRET:
            return
        if self._ifc_sink_pc.get(("fun", sym.name), False):
            self._emit_ifc_call_pc(repr(sym.name), e.pos)

    def _check_ifc_method_call_pc(
        self, e: A.MethodCall, type_sym, recv_ty,
    ) -> None:
        """IFC-1 (strict implicit-flow), method-call form. Resolves the
        callee's ``sink_reaching_pc`` bit:

        * a USER-DEFINED dynamic receiver (a user trait or user capability,
          dispatched at runtime) ORs the bit over every impl method of this
          name -- the sound by-name over-approximation, since the concrete
          user impl is not known statically;
        * a CONCRETE user-typed receiver whose exact ``("method", T,
          method)`` key is present uses that one bit precisely;
        * ANY BUILT-IN receiver contributes NO bit. A built-in container /
          primitive (``List`` / ``Map`` / ``String`` ...) and a built-in
          CAPABILITY (``Env`` / ``Stdio`` / ``Net`` / ``Fs`` / ``Db`` /
          ``Serve`` / ``Clock`` / ``Proc``) both have no user-defined method
          that could transitively reach a user sink, and a built-in
          capability's OWN direct sink call is already caught by the inline
          ``_check_ifc_sink`` -- so a built-in receiver must never import an
          unrelated same-named user method's bit through the union.

        The built-in-vs-user distinction is by SYMBOL ORIGIN
        (``_receiver_type_is_user_defined``, the ``BUILTIN_POS`` test the
        summary's ``_name_is_builtin_immutable`` also uses), NOT by the kind
        alone: a built-in capability lands as ``SymbolKind.CAPABILITY`` just
        like a user capability, so keying the union on ``recv_is_dynamic``
        alone would still widen ``env.get(...)`` to a user ``Logger.get``.

        Note the DIFFERENCE from ``_check_ifc_method_call_summary``: the pc
        bit does NOT fall to the by-name union for a built-in receiver. The
        data channel there gates its by-name union on a SECRET argument, but
        the pc channel fires on ANY argument, so widening a built-in getter
        (``xs.get(i)`` / ``env.get(k)``) to a same-named user sink method
        (``Logger.get``) would be a false positive on a plain
        ``if secret: xs.get(0)``. Keeping the union only for a user-defined
        dynamic receiver closes that without weakening any real rejection: a
        user method reached via its exact key or a user trait / capability
        dynamic receiver still bites. Hard error under ``@strict_ifc`` ONLY,
        as with the free form."""
        if not getattr(self, "_strict_ifc", False):
            return
        if L.normalize(getattr(self, "_pc_label", L.PUBLIC)) != L.SECRET:
            return
        exact_key = ("method", recv_ty.name, e.method)
        from . import SymbolKind
        recv_is_dynamic = type_sym is not None and getattr(
            type_sym, "kind", None,
        ) in (SymbolKind.TRAIT, SymbolKind.CAPABILITY)
        if recv_is_dynamic and self._receiver_type_is_user_defined(
            recv_ty.name,
        ):
            # OR the bit over the receiver's ACTUAL dispatch targets only,
            # not every module-wide same-named method: a dynamic call to
            # ``R.m`` can land on a concrete type implementing ``R`` (or,
            # for a capability / self-implemented trait, on ``R`` itself),
            # never on an unrelated type that merely has a same-named method
            # under a DIFFERENT trait. Widening to all ``methods_by_name``
            # false-positived a clean ``q.say()`` because an unrelated
            # ``Loud.say`` (implementing another trait) sank.
            reaches = any(
                self._ifc_sink_pc.get(k, False)
                for k in self._dispatch_target_keys(recv_ty.name, e.method)
            )
        else:
            # A concrete user-typed receiver -> its precise exact-key bit;
            # ANY built-in receiver (container / primitive / capability) ->
            # NONE, since its exact key is absent (no user method body to
            # summarise) so the lookup yields False.
            reaches = self._ifc_sink_pc.get(exact_key, False)
        if reaches:
            self._emit_ifc_call_pc(
                repr(f"{recv_ty.name}.{e.method}"), e.pos,
            )

    def _receiver_type_is_user_defined(self, name: str) -> bool:
        """True when the receiver type ``name`` resolves to a USER-defined
        symbol (its ``pos`` is not the built-in source position), so its
        by-name union of user impl methods is meaningful. A built-in type
        (a container / primitive OR a built-in capability such as ``Env`` /
        ``Stdio`` / ``Net``) sits at ``BUILTIN_POS`` and returns False, so
        the IFC-1 pc check never imports a same-named user method's bit for
        it. Mirrors the origin test the summary's
        ``_name_is_builtin_immutable`` uses."""
        from ..builtins import BUILTIN_POS
        sym = self.global_scope.lookup(name)
        return sym is not None and sym.pos != BUILTIN_POS

    def _dispatch_target_keys(self, recv_name: str, method: str) -> set:
        """The summary keys a dynamic call ``recv.method(...)`` on a
        USER-defined trait / capability ``recv_name`` can actually dispatch
        to -- the set the IFC-1 pc-union must OR over (NOT every module-wide
        same-named method). It is:

        * ``("method", T, method)`` for every concrete type ``T`` that
          implements ``recv_name`` (from the ``impl recv_name for T``
          reverse index); PLUS
        * ``("method", recv_name, method)`` -- the receiver's OWN key. This
          is the COMPLETENESS clause: a user capability with a direct
          ``impl recv_name`` (or a trait with a direct impl on itself) keys
          its methods under ``recv_name`` and lists nothing in any type's
          ``implements``, so the reverse index alone would be empty and a
          capability-own-impl sink would be UNDER-reported. An absent key is
          a harmless no-op (``.get`` yields False), so always including it is
          sound and never widens to an unrelated type."""
        keys = {("method", recv_name, method)}
        for tname in self._impl_reverse_index().get(recv_name, ()):
            keys.add(("method", tname, method))
        return keys

    def _impl_reverse_index(self) -> dict:
        """``trait / capability name -> {concrete type names implementing
        it}``, built once (memoised) from the populated global scope's
        ``Symbol.implements`` sets (populated at ``impl Trait for T``). The
        reverse of each type's ``implements``, used to restrict the IFC-1
        pc-union to a dynamic receiver's real dispatch targets."""
        if self._ifc_impl_index is None:
            index: dict = {}
            for sym in self.global_scope.symbols.values():
                for r in getattr(sym, "implements", ()) or ():
                    index.setdefault(r, set()).add(sym.name)
            self._ifc_impl_index = index
        return self._ifc_impl_index

    def _emit_ifc_call_pc(self, callee: str, pos) -> None:
        """Emit the IFC-1 cross-call implicit-flow diagnostic. Mirrors the
        inline strict implicit-flow error (``_check_ifc_sink``) reworded for
        the call site."""
        self._err(
            f"information-flow (strict): calling {callee} runs a public "
            f"sink under secret control flow (inside a branch whose "
            f"condition is @secret), which leaks whether that branch was "
            f"taken. Move the call outside the secret-conditioned branch "
            f"so its execution does not depend on the secret.",
            pos,
        )

    def _check_ifc_local_lambda_call(self, e: A.Call, sym) -> None:
        """Sink-side lambda-flow check at a call ``g(args)`` whose callee
        ``g`` is a LOCAL / parameter / constant that resolves to ONE certain
        lambda literal. The lambda body carries its own sink-reaching
        summary (keyed by ``("lambda", id)`` in :mod:`._ifc_summary`), so a
        @secret argument bound to a lambda parameter that reaches a public
        sink inside the body is flagged at the call, mirroring the named-call
        check (``_check_ifc_call_summary``).

        The lambda is recovered from ``_binding_lambdas`` -- the SAME
        resolution the higher-order sink boundary already uses -- which
        records the single literal a ``let`` / fresh ``var`` introduces and
        POISONS to ``None`` on any reassignment. So a reassigned ``var``, an
        alias, or a call-result binding resolves to ``None`` here and is a
        conservative MISS (a disclosed escaping residual), never a
        wrong-target guess: the check only ever runs against the exact lambda
        the binding certainly denotes."""
        lam = self._binding_lambdas.get(id(sym))
        if isinstance(lam, A.LambdaExpr):
            self._apply_lambda_sink_summary(e, lam, repr(sym.name))
            self._apply_lambda_capture_sink_summary(e, lam, repr(sym.name))

    def _check_ifc_iife_call(self, e: A.Call) -> None:
        """Sink-side lambda-flow check at an immediately-invoked lambda
        literal ``(fun(s) => sink_str(s, stdio))(args)``. The callee IS the
        lambda literal, so its ``("lambda", id)`` summary is recovered
        directly with no binding resolution. Keeps the boundary consistent
        with the named-local case (``let g = fun...; g(x)`` caught, but
        ``(fun...)(x)`` not caught, would be inconsistent)."""
        if isinstance(e.callee, A.LambdaExpr):
            self._apply_lambda_sink_summary(e, e.callee, "the closure")
            self._apply_lambda_capture_sink_summary(e, e.callee, "the closure")

    def _apply_lambda_sink_summary(
        self, e: A.Call, lam: A.LambdaExpr, callee_label: str,
    ) -> None:
        """Apply lambda ``lam``'s sink-reaching summary to the actual
        arguments of call ``e``, verbatim with the named-call path
        (``_check_ifc_call_summary``): a @secret argument bound to a
        sink-reaching lambda parameter is flagged, threading the argument
        label through ``_sink_param_arg_label``, the read-side field-qualified
        clear-gate through ``_sink_arg_field_cleared``, and the warn/strict
        emitter through ``_emit_ifc_call_leak``. Argument binding is POSITIONAL
        -- a lambda ``Fun`` type carries no parameter names. Never applies a
        summary to a target that was not resolved: an absent summary (the
        lambda sinks no parameter) is a no-op."""
        from ..typesys import TyFun
        key = ("lambda", id(lam))
        sink_params = self._ifc_summaries.get(key)
        if not sink_params:
            return
        sink_caps = self._ifc_sink_caps.get(key, {})
        sink_paths = self._ifc_sink_paths.get(key, {})
        fun_ty = self.types.get(id(lam))
        param_tys = fun_ty.params if isinstance(fun_ty, TyFun) else ()
        for pidx, arg in enumerate(e.args):
            if pidx not in sink_params:
                continue
            ptype = param_tys[pidx] if pidx < len(param_tys) else None
            label = self._sink_param_arg_label(arg, ptype)
            if label is None or L.normalize(label) != L.SECRET:
                continue
            # Stage 2 read-side field precision (see the named free-call path).
            if self._sink_arg_field_cleared(arg, sink_paths.get(pidx)):
                continue
            pname = (
                lam.params[pidx].name
                if pidx < len(lam.params)
                else f"argument {pidx + 1}"
            )
            self._emit_ifc_call_leak(
                callee_label, pname, arg.pos,
                sink_caps.get(pidx, frozenset()),
            )

    def _apply_lambda_capture_sink_summary(
        self, e: A.Call, lam: A.LambdaExpr, callee_label: str,
    ) -> None:
        """Apply lambda ``lam``'s CAPTURE-sink summary at the invocation ``e``
        (the R1 fix): a captured value whose LIVE label is @secret AND that
        reaches a public sink INSIDE the body is flagged at the invocation
        position. Orthogonal / additive to ``_apply_lambda_sink_summary`` (the
        parameter check) -- neither removes the other's flag.

        The lambda's captures are resolved by IDENTITY (``_capture_read_paths``,
        the same resolution the RESULT re-read uses), then matched by NAME to
        the per-lambda ``capture_sink_paths`` summary (a name resolves to one
        binding inside a lambda body, so name -> sym is 1:1 here). For each
        summarised capture the LIVE label at its SUNK paths is taken with the
        SHARED ``_capture_live_label`` gate (whole vs field-precise, the
        REFTYPE re-read, the value-typed capture-by-value skip -- so a
        value-typed scalar reassigned after definition stays clean, and a
        disjoint clean-sibling read is not over-tainted). Only a live @secret
        capture is flagged; the label re-read is declassify-blind exactly like
        the RESULT re-read, but the SUMMARY already dropped an in-body
        declassify (no sunk path recorded), so a closure that declassifies the
        value it sinks carries no summary entry and stays clean.

        Warn by default, hard error under ``@strict_ifc`` -- the same two-tier
        discipline as the parameter check, via ``_emit_ifc_call_leak``."""
        summary = self._ifc_capture_sink_paths.get(("lambda", id(lam)))
        if not summary:
            return
        by_name = {
            sym.name: sym
            for sym, _paths, _whole in self._capture_read_paths(lam).values()
        }
        for name, sink_paths in summary.items():
            sym = by_name.get(name)
            if sym is None:
                continue
            whole = () in sink_paths
            field_paths = {p for p in sink_paths if p}
            live = self._capture_live_label(sym, field_paths, whole)
            if L.normalize(live) != L.SECRET:
                continue
            self._emit_ifc_call_leak(
                callee_label, f"the captured {name!r}", e.pos, frozenset(),
            )

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
        # Feature #6 (B1): alongside the sink-reaching parameter set, take
        # the callee's egress sink capabilities under the SAME derivation
        # (precise exact key, else the by-name union), so a cross-function
        # un-audited leak is tagged with the capability actually reached.
        if not recv_is_dynamic and exact_key in self._ifc_summaries:
            sink_params = self._ifc_summaries[exact_key]
            sink_caps = self._ifc_sink_caps.get(exact_key, {})
            sink_paths = self._ifc_sink_paths.get(exact_key, {})
        else:
            from ._ifc_summary import methods_by_name
            grouping = methods_by_name(self._ifc_summaries)
            sink_params = set()
            # PER-PARAMETER caps map (full param idx -> caps), unioned over
            # the candidate impls under the SAME by-name over-approximation
            # ``sink_params`` uses -- so the leak is tagged with only the
            # routed parameter's caps, never a sibling parameter's.
            sink_caps: dict = {}
            # Field-qualified SUNK PATHS, unioned over candidates under the
            # SAME by-name over-approximation (a dynamic-dispatch receiver
            # may sink ANY candidate impl's paths, so the union is the sound
            # over-report: a tainted path compatible with ANY candidate's
            # sunk path flags).
            sink_paths: dict = {}
            for key in grouping.get(e.method, ()):
                sink_params |= self._ifc_summaries.get(key, frozenset())
                for pidx, caps in self._ifc_sink_caps.get(key, {}).items():
                    sink_caps.setdefault(pidx, set()).update(caps)
                for pidx, paths in self._ifc_sink_paths.get(key, {}).items():
                    sink_paths.setdefault(pidx, set()).update(paths)
        if not sink_params:
            return

        has_self = getattr(method_sym, "has_self", False)
        # Receiver = parameter index 0 when the method takes ``self``.
        if has_self and 0 in sink_params:
            if (
                L.normalize(self._label_of(e.receiver)) == L.SECRET
                and not self._sink_arg_field_cleared(
                    e.receiver, sink_paths.get(0),
                )
            ):
                self._emit_ifc_call_leak(
                    repr(callee_name), "self (the receiver)", e.receiver.pos,
                    sink_caps.get(0, frozenset()),
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
            # Stage 2 read-side field precision (see the free-call path).
            if self._sink_arg_field_cleared(arg, sink_paths.get(full_idx)):
                continue
            pname = (
                method_sym.param_names[local_idx]
                if local_idx < len(method_sym.param_names)
                else f"argument {arg_idx + 1}"
            )
            self._emit_ifc_call_leak(
                repr(callee_name), pname, arg.pos,
                sink_caps.get(full_idx, frozenset()),
            )

    def _emit_ifc_call_leak(
        self, callee: str, param: str, pos, sink_caps=(),
    ) -> None:
        """Emit the cross-function sink-parameter diagnostic: a @secret
        value passed to a parameter that reaches a public sink inside
        the callee. Warn by default, hard error under ``@strict_ifc``,
        matching the intra-procedural tier.

        ``sink_caps`` is the set of built-in sink CAPABILITIES that the
        SPECIFIC sink-reaching parameter the secret was routed to reaches
        inside the callee (feature #6, B1) -- the callee's per-parameter
        IFC summary looked up at that parameter, NOT the whole-callable
        union, so a secret that reaches only Net is never tagged with a
        sibling parameter's Fs. On the warn tier the un-audited leak is
        recorded against the CALLER (the function at this warn site) with
        each of those capabilities as the egress reached."""
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
            # Feature #6 (B1): attribute the un-audited leak to the caller
            # (the enclosing function at this warn site), tagged with each
            # egress capability the secret reaches inside the callee.
            for cap in sink_caps:
                self._record_unaudited_secret_sink(cap, pos)

    def _record_unaudited_secret_sink(self, cap_name, pos) -> None:
        """Record (feature #6, B1) a WARN-tier un-audited secret->public
        -sink flow for the function currently being checked: the sink
        CAPABILITY reached and the source position, keyed by the enclosing
        ``FunDecl``'s identity. Purely observational -- it never changes a
        warn-or-error decision. Only called on the warn tier, so a recorded
        flow is by construction un-audited (a strict-IFC flow is an error,
        and a declassified value is public and never reaches here)."""
        if not cap_name:
            return
        fid = getattr(self, "_cur_fun_id", 0)
        if not fid:
            return
        self._unaudited_secret_sinks.setdefault(fid, []).append(
            (cap_name, pos),
        )

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

    def _raise_fun_labels(self, template, actuals):
        """Build a type with ``template``'s STRUCTURE but its function-type
        return labels RAISED to the join of the corresponding actual types'
        return labels. Used when an aggregate literal (a ``List`` literal,
        ...) is inferred against a DECLARED element type: the declared
        element carries the type structure (so a heterogeneous annotated
        list still type-checks), but the actual elements' ret_labels must
        survive, otherwise a secret-returning closure stored in a public-
        declared container is laundered and the store-site check misses it.

        Recurses through the function return chain, tuple elements and
        generic type arguments (List / Option / Result / Map value ...),
        which is where a closure element can hide."""
        from ..typesys import TyFun, TyTuple, TyName
        from .. import _labels as L
        if isinstance(template, TyFun):
            funs = [a for a in actuals if isinstance(a, TyFun)]
            if not funs:
                return template
            ret_label = L.join_all(
                [template.ret_label] + [a.ret_label for a in funs]
            )
            new_ret = self._raise_fun_labels(
                template.ret, [a.ret for a in funs],
            )
            return TyFun(
                template.params, new_ret,
                param_labels=template.param_labels, ret_label=ret_label,
            )
        if isinstance(template, TyTuple):
            tups = [
                a for a in actuals
                if isinstance(a, TyTuple)
                and len(a.elements) == len(template.elements)
            ]
            if not tups:
                return template
            elems = tuple(
                self._raise_fun_labels(te, [t.elements[i] for t in tups])
                for i, te in enumerate(template.elements)
            )
            return TyTuple(elems)
        if isinstance(template, TyName) and template.args:
            names = [
                a for a in actuals
                if isinstance(a, TyName) and len(a.args) == len(template.args)
            ]
            if not names:
                return template
            args = tuple(
                self._raise_fun_labels(ta, [n.args[i] for n in names])
                for i, ta in enumerate(template.args)
            )
            return TyName(template.name, args, state=template.state)
        return template

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

    # ---- cross-function mutation effect (closes gap 1) -----------

    def _check_ifc_call_field_effect(
        self, e: A.Call, sym, perm: list[int],
    ) -> None:
        """At a user free-function call, apply the callee's mutation
        effects to the CALLER's bindings. ``perm`` is in parameter
        order: ``e.args[perm[i]]`` is the argument bound to parameter
        ``i``. The effect ``{(j, field_path) -> sources}`` means the
        callee writes into the object passed as parameter ``j`` at
        ``field_path`` -- storing a field of it, or mutating it through a
        ``_CONTAINER_MUTATORS`` method -- from those sources; when a
        source fires (a @secret real-param argument, or the unconditional
        internal-secret sentinel), the caller's binding for parameter
        ``j`` is tainted at ``field_path`` (field-keyed on the
        container-mutation channel) or whole-value (the carrier)."""
        effects = self._ifc_field_effects.get(("fun", sym.name))
        if not effects:
            return
        self._apply_field_effects(effects, perm, e.args)

    def _check_ifc_method_call_field_effect(
        self, e: A.MethodCall, method_sym, recv_ty, perm: list[int],
    ) -> None:
        """Method-call form of the mutation-effect propagation.
        Parameter index 0 is ``self`` (the receiver); the explicit
        parameters follow. Builds the full-order argument list
        (receiver first) and the full-order ``param_idx -> arg_idx``
        map, then applies every candidate impl's effects (the same
        by-name over-approximation the summary uses) -- field-keyed on the
        container-mutation channel where the effect is keyable, else the
        whole-value carrier, so a dynamic-dispatch receiver never drops
        the taint."""
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
        index to an index into ``args``. Each effect is keyed by
        ``(target_param_idx, field_path)``; for a target whose effect
        fires, taint the caller's binding for that target's argument --
        field-keyed at ``field_path`` on the branch-scoped
        container-mutation channel, or whole-value via the carrier (see
        ``_apply_one_field_effect``). ``perm`` may be a list (free call,
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
        for (target_pidx, field_path), sources in effects.items():
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
            self._apply_one_field_effect(target_arg, field_path)

    def _apply_one_field_effect(self, target_arg: A.Expr, field_path) -> None:
        """Apply one fired cross-function mutation effect to the caller's
        binding rooted at ``target_arg``.

        FIELD-KEYED (``field_path`` a tuple): taint the branch-scoped
        container-mutation channel at ``(root-binding, caller-prefix +
        field_path)`` -- the SAME ``(root, field-path)`` access-path
        channel the intra-procedural container mutation uses -- so a later
        read of that path is caught (``_container_taint_at`` in
        ``_compute_label``) while a public sibling field
        (``bag.other``) and a mutually-exclusive branch's read stay clean.
        The caller's prefix is composed with the callee's field path, so
        an argument that is itself a field chain (``fill(outer.bag)``) is
        keyed at the full path.

        WHOLE-VALUE carrier (the sound fallback that keeps a leak caught
        with less precision): used when the effect is itself whole-value
        (``field_path`` is ``None``), when ``target_arg`` is not an
        Ident-rooted field chain (a call- / index-rooted argument has no
        keyable access path), or when the target binding is ALIASED (an
        embed / rename group in ``_struct_aliases``) -- there a read
        through a DIFFERENT root would miss a field-keyed taint, so the
        whole-value carrier's alias-group taint is required for
        soundness."""
        if field_path is None:
            self._taint_binding_whole_value(target_arg)
            return
        root_sym = self._struct_root_sym(target_arg)
        caller_prefix = self._field_path_from_root(target_arg)
        if (
            root_sym is None
            or caller_prefix is None
            or id(root_sym) in self._struct_aliases
        ):
            self._taint_binding_whole_value(target_arg)
            return
        full_path = tuple(caller_prefix) + tuple(field_path)
        self._seed_container_taint(root_sym, full_path, L.SECRET)

    def _taint_binding_whole_value(self, e: A.Expr) -> None:
        """Raise the binding rooted at ``e`` to whole-value @secret and
        escape it, so a later read of ANY field / element of it is
        caught. The conservative, sound granularity for a cross-function
        mutation effect (per-field / per-element precision across the
        boundary is not attempted). No-op when ``e`` is not rooted at a
        binding.

        Aliasing soundness: if the binding is in an alias group (an embed
        alias ``Outer { inner: b }`` links ``o`` and ``b``, or ``var
        b2 = b``), every member names the SAME heap object, so the
        cross-function whole-value taint must reach all of them. Mirror
        ``_ifc_field_store``'s alias-group path exactly: taint AND escape
        every member, so a later read of any field of any aliased binding
        is caught.

        The label raise goes through ``_raise_whole_value_label`` (the
        whole-value CHOKE-POINT), so each member is marked whole-value-DIRTY:
        this cross-function taint is NOT backed by a precise field seed at the
        affected path, so a closure that captured the binding and reads the
        tainted FIELD must re-consult ``sym.label`` rather than the
        field-precise channel that cannot see it (the CRITICAL-3 leak)."""
        sym = self._struct_root_sym(e)
        if sym is None:
            return
        group = self._struct_aliases.get(id(sym))
        members = group if group is not None else [sym]
        for member in members:
            self._raise_whole_value_label(member, L.SECRET)
            if getattr(member, "field_labels", None) is not None:
                self._escaped_struct_syms.add(id(member))

def _prefix_compatible(a: tuple, b: tuple) -> bool:
    """True when access paths ``a`` and ``b`` lie on the same root-to-leaf
    line: one is a prefix of the other. Used by the Stage 2 read-side check
    to decide whether a TAINTED access path is actually SUNK. ``a`` sunk at
    ``b``: the container taint at ``a`` reaches a sink iff the sunk path
    ``b`` is at or under ``a`` (``b`` reads into the tainted container) or
    ``a`` is at or under ``b`` (the tainted sub-path is inside what the
    callee sinks). The sentinel ``()`` (whole struct / param) is a prefix
    of everything, so it is compatible with any path -- the conservative
    catch-all."""
    n = min(len(a), len(b))
    return a[:n] == b[:n]


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


def _result_payload_var(ty) -> "str | None":
    """The name of the element / payload TYPE-VAR of a container result
    type, or ``None`` when the result is not a container-with-type-var.
    The payload is the FIRST type argument -- ``List<U>`` / ``Option<U>``
    / ``Result<U, E>`` / ``Range<U>`` / ``Set<U>`` all carry it there. A
    concrete payload (``List<Int>``) or a bare type name yields ``None``,
    so no parametric split is derived for it."""
    from ..typesys import TyName, TyVar
    if not isinstance(ty, TyName) or not ty.args:
        return None
    first = ty.args[0]
    return first.name if isinstance(first, TyVar) else None


def _classify_call_param(param_ty, elem_var: str, result) -> str:
    """Classify a generic function parameter by WHERE its type-var lands
    in the result, for the free-call split derivation (Phase B2'):

    * ``"transform"`` -- a closure whose RETURN type-var IS the result
      payload var (``f: Fun(T) -> U`` for a ``List<U>`` result). Its
      value becomes the new element; it does not change presence.
    * ``"bind"`` -- a closure whose RETURN TYPE is the result container
      itself (``f: Fun(T) -> Option<U>`` for an ``Option<U>`` result).
      It decides presence / cardinality (and the payload), so it is
      STRUCTURE-affecting.
    * ``"passthrough"`` -- a container input whose element type-var IS the
      result payload var (``xs: List<T>`` for a ``List<T>`` result). Its
      structure flows to the result structure, its element to the element.
    * ``"other"`` -- anything else (a predicate ``Fun(T) -> Bool``, a
      scalar seed, a non-passthrough container): conservatively
      STRUCTURE-affecting via its whole-value / return label."""
    from ..typesys import TyFun, TyName, TyVar
    if isinstance(param_ty, TyFun):
        cret = param_ty.ret
        if isinstance(cret, TyVar) and cret.name == elem_var:
            return "transform"
        if (
            isinstance(cret, TyName) and isinstance(result, TyName)
            and cret.name == result.name
        ):
            return "bind"
        return "other"
    pvar = _result_payload_var(param_ty)
    if pvar is not None and pvar == elem_var:
        return "passthrough"
    return "other"


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
