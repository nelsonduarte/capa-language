"""Cross-function information-flow summaries (roadmap S2.6).

The intra-procedural IFC pass in :mod:`._ifc` propagates labels and
catches a ``@secret`` value reaching a public sink *within one
function body*. Crossing a function boundary relied on an explicit
``@secret`` parameter: a secret passed to an un-annotated parameter
that then reaches a sink *inside the callee* was silently missed.

This module closes that gap with a modular, additive, sound slice:
for every user-defined function and impl/trait method it computes a
**sink-reaching parameter set** -- the 0-based indices of value
parameters whose value, by the existing intra-procedural flow rules,
reaches a public-sink argument position inside the body, either
directly (the parameter, or a value derived from it, reaches a
``_PUBLIC_SINKS`` position) or transitively (the parameter is passed
into a position that is itself a sink-reaching parameter of the called
user function). A flow that passes through ``declassify(...)`` before
the sink does NOT count -- declassify breaks the chain, mirroring the
PUBLIC relabel in ``_compute_label``.

Summaries are computed to a least fixpoint over the call graph
(monotone: start empty, grow until stable), so mutual and self
recursion terminate.

The analyzer's main walk then consults these summaries at each user
call / method-call site (see ``_check_ifc_call_summary`` in
:mod:`._ifc`): an argument that is ``@secret`` and binds to a
sink-reaching parameter of the callee is flagged at the call site --
a warning by default, a hard error under ``@strict_ifc``, matching
the intra-procedural tier.

This is whole-value granularity (no per-field precision) and a sound
over-approximation: a method call whose receiver type is not known
statically is matched against every user method of that name, so the
analysis never under-reports a leak. It never RELAXES (loosens) a label
or check: every effect is in the tightening direction. It is not
invisible to already-accepted code, though: adding detection can TIGHTEN
the outcome, so a program whose genuine cross-function leak was previously
missed now warns and is rejected under ``@strict_ifc``. Being a sound
over-approximation, the tightening can in principle over-report on a
non-leak too (a false positive), so the control-flow scoping that decides
when a cross-function mutation is visible to a later read is applied
uniformly across every branching construct (see the content channel in
``_analyze_body``). The direction is never more permissive.

MUTATION EFFECTS (closes the cross-function self/param field-write
false negative, and the container one). Alongside the sink-reaching
set, every callable also gets a **mutation effect**: a map
``(target_param_idx, field_path) -> set of sources`` recording that the
callee writes INTO the object bound to ``target_param_idx`` (``self`` is
index 0) at the access path ``field_path`` from a value tainted by
either another parameter (the source's index) or an internal secret
source within the body (the sentinel ``INTERNAL_SECRET``), directly or
transitively (the write happens from a value passed to a further call
that itself has the effect). It is computed to the SAME fixpoint.

FIELD-PATH GRANULARITY (Stage 1). ``field_path`` gives a CONTAINER
mutation effect access-path (field-sensitive) precision, so a callee that
pushes a secret into ``bag.items`` records ``(bag_slot, ("items",))``
rather than a whole-value taint of ``bag``. A ``field_path`` is either the
tuple of field names from the target PARAMETER down to the mutated
container -- ``()`` when the parameter IS the container (``xs.push(v)``),
``("items",)`` for ``self.items.push(v)`` -- or the sentinel ``None`` for
the WHOLE-VALUE carrier. The field-keyed form is recorded only when the
write chain is rooted DIRECTLY at the parameter, so the path is exactly
parameter-relative; otherwise (an aliased / renamed root, a chain that
cannot be keyed, or a path longer than ``_MAX_FIELD_PATH``) the
whole-value carrier ``(j, None)`` is kept so the leak stays caught.

The two kinds of write take the channel that MIRRORS the intra-procedural
pass, because they are observed differently there and the soundness floor
is that no cross-function leak regresses:

* a FIELD STORE, ``obj.f = v`` (any store op, including the augmented
  ``obj.f += v``), takes the WHOLE-VALUE carrier (``field_path`` is
  ``None``). The intra field store (``_ifc_field_store``) raises the
  struct's COLLAPSED whole-value label, so a later whole / getter read of
  the struct observes it; keeping the whole-value carrier keeps that
  coverage. De-collapsing a field store to a per-field caller taint is
  Stage 2, out of scope here.
* a CONTAINER MUTATION, ``xs.push(v)`` and every other entry of the
  ``_CONTAINER_MUTATORS`` registry in :mod:`._ifc` (its single source of
  truth), is FIELD-KEYED onto the branch-scoped ``(root, field-path)``
  container channel the intra container mutation
  (``_check_ifc_container_mutation``) uses. A FIELD read of the path
  observes it precisely (a public sibling field stays clean), and a WHOLE
  read of the root observes it too: ``_compute_label`` prefix-scans the
  ``(root, *)`` channel for a whole / getter / interpolation / pass-whole
  read (the length-0 access-path query ``x.f^0 = x``), so a same-root
  whole read-back is caught without re-tainting a clean sibling. The
  receiver may be a parameter (``xs.push(v)`` -> path ``()``) or a field
  chain rooted at one (``self.items.push(v)`` -> path ``("items",)``); the
  effect is recorded against the ROOT parameter at that field path. Without
  the effect, a secret pushed onto a list / set / map by a CALLEE escaped
  the analysis entirely while the identical push written inline was caught.

The call site (see ``_check_ifc_call_field_effect`` /
``_check_ifc_method_call_field_effect`` in :mod:`._ifc`) propagates it
CONSERVATIVELY: when the callee writes into param ``j`` at ``field_path``
from param ``i`` and the caller's argument for ``i`` is @secret, the
caller's binding bound to ``j`` is tainted -- a field-keyed CONTAINER
effect on the SAME ``(root, field-path)`` branch-scoped container-mutation
channel the intra-procedural pass uses (so a later read of that path, AND a
same-root whole / getter / interpolation / pass-whole read-back, is caught
while a public sibling field stays clean), a whole-value FIELD-STORE effect
via the whole-value carrier (a later read of any field / element, whole or
getter, is caught). An internal-secret source taints the caller's
binding-``j`` unconditionally. This is an explicit data-flow taint,
default-warn / strict-error like the sink-reaching check.

READ-SIDE FIELD PRECISION (Stage 2, ``sink_paths``). Passing a whole
struct to a callee no longer over-reports when the callee sinks only a
CLEAN sibling: the callee's field-qualified SUNK paths (``sink_paths``) are
intersected against the argument's container-tainted access paths at the
call site, so ``show_note(bag)`` reading ``bag.note`` is clean while
``bag`` is tainted at ``bag.secret_items``. The MIRROR leak stays caught:
a callee that sinks the tainted field, or the whole struct (the
conservative sentinel ``()`` sunk path), still flags.

CLOSED vs RESIDUAL. A same-root read-back (direct field read, whole read,
getter, interpolation, or passing the whole struct to a callee that sinks
the tainted path) is caught; passing a whole struct to a callee that sinks
only a clean sibling is precise (clean). What genuinely REMAINS disclosed:

* DIFFERENT-ROOT points-to: a container reached through a root the taint is
  not keyed on -- an INLINE push through a struct alias, a whole-struct
  value copy ``var b2 = bag`` made AFTER the push then a sibling read
  through the copy (a SAFE over-report, flags but leaks nothing), a
  field-chain rename ``var lst = bag.items``, or an embed-then-mutate; and
  a mutator whose receiver is not rooted at a binding (a call- / index-
  rooted receiver). Only a points-to analysis, which Capa lacks, closes
  these.
* CLOSURE-CAPTURE flow: a container captured by a closure defined BEFORE
  the push and read through the closure AFTER is unflagged (a deferred
  lambda-flow item; a closure defined AFTER the push is caught).
* A cross-function FIELD STORE keeps the whole-value carrier, so its
  sibling read is conservatively flagged (the disclosed field-store
  sibling over-report); only CONTAINER mutations get sibling precision.
"""

from __future__ import annotations

from .. import capa_ast as A
from ._ifc import (
    _PUBLIC_SINKS, _CONTAINER_MUTATORS, _SECRET_SOURCES,
    _pattern_bound_names,
)


# Sentinel source for a field written from an internal secret source
# (``env.get(...)``) rather than from another parameter. Distinct from
# any real 0-based parameter index.
INTERNAL_SECRET = -1

# Access-path length bound for a field-qualified mutation effect (Stage
# 1). A mutation effect is keyed by ``(target_param_idx, field_path)``,
# where ``field_path`` is the tuple of field names from the target
# PARAMETER down to the mutated container / field, or ``None`` for the
# whole-value carrier. Because ``_propagate_callee_effects`` COMPOSES a
# caller's access-path prefix with a callee's field path, a recursive
# call graph could otherwise grow the path without bound and the monotone
# summary fixpoint would not terminate. Bounding the length -- FlowDroid's
# k-bound (its default is 5) -- keeps the key space finite: a path longer
# than the bound collapses to the whole-value carrier (``None``), a sound
# over-approximation. So the effect map ranges over the FINITE key set
# ``param_idx x ({None} + field-name-tuples of length <= k)`` and the
# ascending chain stabilises.
_MAX_FIELD_PATH = 5

# Capability type names whose source methods (``_SECRET_SOURCES``)
# produce secret data. Used to recognise an internal secret source at
# summary time (no resolved types here) by matching a method call whose
# receiver is a parameter of that capability type. Keeps the source
# recognition precise (so e.g. ``List.get`` / ``Map.get`` are not
# mistaken for the ``Env.get`` source).
_SECRET_SOURCE_CAPS: frozenset = frozenset(cap for cap, _m in _SECRET_SOURCES)
_SECRET_SOURCE_METHODS: frozenset = frozenset(m for _c, m in _SECRET_SOURCES)


# A callable's parameters, in the canonical order the analyzer uses:
# for a method, index 0 is ``self`` and the explicit parameters follow
# (matching ``has_self`` + ``param_names``); for a free function, the
# explicit parameters in declaration order.
#
# Keys into the summary table:
#   ("fun", name)                  -- a free function
#   ("method", type_name, method)  -- an impl / trait method


def compute_ifc_summaries(
    module: A.Module, global_scope,
) -> tuple[dict, dict, dict, dict, dict]:
    """Return ``(sink_summaries, field_effects, return_effects,
    sink_caps, sink_paths)``:

    * ``sink_summaries``: ``{callable_key: frozenset(sink_reaching
      param indices)}`` -- a value parameter whose value reaches a
      public sink inside the body.
    * ``field_effects``: ``{callable_key: {(target_param_idx,
      field_path): frozenset(source_param_idx | INTERNAL_SECRET)}}`` --
      the callee writes INTO the object at ``target_param_idx`` at the
      access path ``field_path`` from the named source(s), either by
      storing a field of it or by mutating it through a
      ``_CONTAINER_MUTATORS`` method. ``field_path`` is the tuple of
      field names from the parameter down to the mutated location
      (``()`` when the parameter itself is the container), or ``None``
      for the whole-value carrier (an aliased / renamed / unkeyable
      root, or a path beyond ``_MAX_FIELD_PATH``).
    * ``return_effects``: ``{callable_key: frozenset(source_param_idx |
      INTERNAL_SECRET)}`` -- the callee returns a value derived from the
      named source(s); the call result is @secret when one fires (a real
      param whose argument is @secret, or the unconditional internal
      secret, which includes a declared-@secret field read).
    * ``sink_caps``: ``{callable_key: {param_idx: frozenset(sink
      capability name)}}`` -- PER PARAMETER, the built-in sink
      CAPABILITIES (Stdio / Net / Fs / Db) that THAT parameter's value
      reaches inside the body, directly or transitively. Parallel to
      ``sink_summaries`` (only a parameter present in the sink-reaching
      set has an entry) and computed on the SAME fixpoint. Purely
      observational (feature #6, B1): it lets a cross-function
      un-audited-leak recording tag the leak with the concrete egress
      capability the SPECIFIC sink-reaching parameter the secret was
      routed to reaches -- not the whole-callable union -- so a secret
      that reaches only Net is never tagged with a sibling parameter's
      Fs. It never affects a sink-reaching / warn-or-error decision.
    * ``sink_paths``: ``{callable_key: {param_idx: frozenset(field_path)}}``
      -- PER PARAMETER, the ACCESS PATHS of that parameter that actually
      reach a public sink inside the body, directly or transitively. The
      read-side field-qualified mirror of ``field_effects``: when a whole
      struct is passed to a callee, the caller (``_check_ifc_call_summary``
      in :mod:`._ifc`) INTERSECTS the argument's container-tainted access
      paths against these SUNK paths and flags only when a tainted path is
      prefix-compatible with a sunk one, so passing a struct tainted at
      ``("items",)`` to a callee that sinks only ``("note",)`` is clean.
      ``field_path`` is the parameter-relative tuple of field names sunk;
      the sentinel ``()`` means the WHOLE parameter reaches a sink (a bare
      param sunk, a value derived through a local, an escape, or a k-bound
      overflow) -- the conservative default, prefix-compatible with every
      tainted path, so soundness never depends on the precision. Parallel
      to ``sink_summaries`` and computed on the SAME fixpoint.

    ``global_scope`` is the analyzer's populated global scope, used to
    tell user functions / variants / capabilities apart at call sites.
    All results are the least fixpoint of the monotone summary operator,
    so recursion (self or mutual) terminates.
    """
    builder = _SummaryBuilder(module, global_scope)
    return builder.run()


def methods_by_name(summaries: dict) -> dict[str, list]:
    """Group method summary keys by method name:
    ``method_name -> [("method", type_name, method_name), ...]``.

    Derived from the summary table's keys so the same by-name
    over-approximation the builder uses at a receiver-type-unknown
    method call (``_taint_of_method_call``) is available to the
    call-site checker (``_check_ifc_method_call_summary``) without
    duplicating the grouping logic. A trait-typed (dynamic-dispatch)
    receiver, or a missing exact key, falls back to the UNION over
    every concrete impl type that defines a method of that name -- a
    sound over-approximation (never misses a leak)."""
    out: dict[str, list] = {}
    for key in summaries:
        if isinstance(key, tuple) and len(key) == 3 and key[0] == "method":
            out.setdefault(key[2], []).append(key)
    return out


class _SummaryBuilder:
    def __init__(self, module: A.Module, global_scope) -> None:
        self.module = module
        self.global_scope = global_scope
        # callable_key -> set of sink-reaching param indices.
        self.summaries: dict = {}
        # callable_key -> {param idx -> set of built-in sink CAPABILITY
        # names (Stdio / Net / Fs / Db) that THAT PARAMETER's value reaches
        # inside the body, directly or transitively}. PER PARAMETER, parallel
        # to ``summaries`` (only a sink-reaching parameter gets an entry) and
        # computed on the SAME fixpoint, but PURELY OBSERVATIONAL: it never
        # feeds a sink-reaching / warn-or-error decision. Consulted only by
        # the cross-function un-audited-leak RECORDING (feature #6, B1) so
        # the caller warn site can tag the leak with the concrete egress
        # capability the SPECIFIC sink-reaching parameter the routed secret
        # was bound to reaches inside the callee -- never a sibling
        # parameter's capability. A method name in ``_PUBLIC_SINKS`` maps to
        # exactly one capability, so the by-method-name over-approximation
        # the summary already uses yields a determinate (sound, may
        # over-approx) capability here.
        self.sink_caps: dict = {}
        # callable_key -> {param idx -> set of parameter-relative field
        # PATHS that actually reach a public sink inside the body, directly
        # or transitively}. The read-side field-qualified mirror of
        # ``field_effects``: the call site intersects a whole-struct
        # argument's container-tainted paths against these SUNK paths, so a
        # struct tainted at one field passed to a callee that sinks only a
        # sibling is clean. The sentinel ``()`` means the WHOLE parameter
        # reaches a sink (conservative default, prefix-compatible with every
        # tainted path). Parallel to ``summaries`` and on the SAME fixpoint.
        self.sink_paths: dict = {}
        # callable_key -> {target param idx -> set of source param idx /
        # INTERNAL_SECRET}: the mutation effect -- a field store OR a
        # container mutation (see module docstring).
        self.field_effects: dict = {}
        # callable_key -> set of source param idx / INTERNAL_SECRET that
        # flow into a RETURNED value -- the return-secret effect. The
        # call result is @secret when one of these sources fires (a real
        # param whose argument is @secret, or the unconditional internal
        # secret, which includes a declared-@secret field read). This is
        # what carries a callee's secret-derived return across the
        # boundary to the caller's call-result label, mirroring the
        # intra-procedural rule and closing the field-return laundering.
        self.return_effects: dict = {}
        # callable_key -> (param_names_in_order, A.FunDecl, is_method).
        # ``param_names_in_order`` includes ``self`` at index 0 for a
        # method, so a positional / named argument binds to the right
        # index uniformly with the call-site logic.
        self.callables: dict = {}
        # callable_key -> set of parameter names that are typed as a
        # secret-source capability (e.g. ``Env``). Used to recognise an
        # internal secret source (``env.get(...)``) at summary time.
        self.secret_source_params: dict = {}
        # callable_key -> {param name: struct type name}. The declared
        # struct type of each struct-typed parameter (``self`` resolves
        # to the impl's owner type), so a field read off it can be
        # resolved to the field's declared label precisely.
        self.param_struct_types: dict = {}
        # callable_key -> {param name: declared type name} for EVERY typed
        # parameter (``self`` -> the impl owner type), regardless of
        # whether the type has labelled fields. Used to tell, at a method
        # call, whether the receiver is a USER-defined type (so the
        # return-effect narrowing is applied) or a built-in container /
        # primitive (so the conservative whole-value join governs and a
        # same-named user method cannot under-taint the result).
        self.param_type_names: dict = {}
        # callable_key -> frozenset of parameter indices whose declared
        # type PROVABLY has no writable interior (a built-in capability, a
        # built-in primitive / String, or the built-in Unit). A parameter
        # in this set is DROPPED from a mutation-effect TARGET set: a fresh
        # local that merely carries such a parameter's data-flow taint
        # cannot, by being mutated, write back into the parameter's object
        # (it has none). Everything else is kept -- keep-by-default on any
        # uncertainty -- so a user-defined capability, a user type that
        # shadows a built-in name, a struct / sum / tuple / Fun / generic,
        # or an unresolved name is never dropped. Consulted at the two
        # sites that conflate a value's TAINT set with its mutation-TARGET
        # set (``_record_mutation_effect`` and ``_propagate_callee_effects``,
        # both via ``_writable_targets``).
        self.immutable_params: dict = {}
        # method name -> list of method callable_keys (for the
        # receiver-type-unknown over-approximation at method calls).
        self.methods_by_name: dict[str, list] = {}
        # struct type name -> {field name: declared label}. Records
        # which struct fields are DECLARED ``@secret`` (roadmap S2), so a
        # field read off a parameter of that struct type is recognised as
        # an internal secret source at summary time -- the cross-function
        # analogue of the intra-procedural declared-field-label rule.
        self.struct_field_labels: dict[str, dict[str, str]] = {}
        # Names of module-level consts DECLARED ``@secret`` (roadmap S2).
        # A reference to one is an internal secret source in the summary
        # walk, the cross-function analogue of the intra-procedural
        # ``sym.label`` on the const's global symbol. Pre-computed once so
        # each identifier costs a set membership test, not a lookup.
        self.secret_consts: set[str] = set()
        self._collect_secret_fields()
        self._collect_secret_consts()
        self._collect_callables()

    def _collect_secret_fields(self) -> None:
        """Populate ``struct_field_labels`` from every struct (and
        typestate) declaration's field labels, so the body walk can
        recognise a declared-@secret field read off a parameter of that
        struct type (``_field_read_is_secret``)."""
        from .. import _labels as L
        for item in self.module.items:
            fields = getattr(item, "fields", None)
            name = getattr(item, "name", None)
            if not fields or name is None:
                continue
            for fld in fields:
                te = getattr(fld, "type_expr", None)
                label = getattr(te, "label", None) if te is not None else None
                if label in L.VALID_LABELS:
                    self.struct_field_labels.setdefault(name, {})[fld.name] = \
                        label

    def _collect_secret_consts(self) -> None:
        """Populate ``secret_consts`` from every module-level ``const``
        whose declared type carries the ``@secret`` label, so the body
        walk recognises a reference to it as an internal secret source
        (``_taint_of`` of an ``A.Ident``). The cross-function analogue of
        the intra-procedural label stamped on the const's global symbol;
        without it a secret const that crosses a free-function return or
        field-write to a public sink is missed (fail-open)."""
        from .. import _labels as L
        for item in self.module.items:
            if isinstance(item, A.ConstDecl):
                te = getattr(item, "type_expr", None)
                label = getattr(te, "label", None) if te is not None else None
                if label == L.SECRET:
                    self.secret_consts.add(item.name)

    # ---- collection -------------------------------------------------

    def _collect_callables(self) -> None:
        for item in self.module.items:
            if isinstance(item, A.FunDecl):
                key = ("fun", item.name)
                names = [p.name for p in item.params]
                self.callables[key] = (names, item, False)
                self.summaries[key] = set()
                self.sink_caps[key] = {}
                self.sink_paths[key] = {}
                self.field_effects[key] = {}
                self.return_effects[key] = set()
                self.secret_source_params[key] = self._secret_source_params(
                    item.params,
                )
                self.param_struct_types[key] = self._param_struct_types(
                    item.params,
                )
                self.param_type_names[key] = self._param_type_names(
                    item.params,
                )
                self.immutable_params[key] = self._immutable_param_idxs(
                    item.params,
                )
            elif isinstance(item, A.ImplBlock):
                for method in item.methods:
                    key = ("method", item.type_name, method.name)
                    # Methods are keyed by (type, name); a name unique
                    # across states is guaranteed by the analyzer.
                    if key in self.callables:
                        continue
                    names = [p.name for p in method.params]
                    self.callables[key] = (names, method, True)
                    self.summaries[key] = set()
                    self.sink_caps[key] = {}
                    self.sink_paths[key] = {}
                    self.field_effects[key] = {}
                    self.return_effects[key] = set()
                    self.secret_source_params[key] = (
                        self._secret_source_params(method.params)
                    )
                    self.param_struct_types[key] = self._param_struct_types(
                        method.params, owner=item.type_name,
                    )
                    self.param_type_names[key] = self._param_type_names(
                        method.params, owner=item.type_name,
                    )
                    self.immutable_params[key] = self._immutable_param_idxs(
                        method.params,
                    )
                    self.methods_by_name.setdefault(
                        method.name, []
                    ).append(key)

    def _param_struct_types(self, params, owner: str = None) -> dict:
        """``{param name: struct type name}`` for parameters whose
        declared type names a struct that has at least one declared-label
        field. ``self`` (no ``type_expr``) resolves to the impl ``owner``
        type. Restricting to structs we actually track keeps the map
        small and the field-read recognition precise."""
        out: dict = {}
        for p in params:
            te = getattr(p, "type_expr", None)
            if p.name == "self" and te is None and owner is not None:
                tyname = owner
            else:
                tyname = getattr(te, "name", None) if te is not None else None
            if tyname is not None and tyname in self.struct_field_labels:
                out[p.name] = tyname
        return out

    def _param_type_names(self, params, owner: str = None) -> dict:
        """``{param name: declared type name}`` for every parameter with
        a named type (``self`` -> the impl ``owner``). Unlike
        ``_param_struct_types`` this is NOT restricted to labelled-field
        structs: it is the general signal used to tell a user-typed
        receiver from a built-in one at a method call."""
        out: dict = {}
        for p in params:
            te = getattr(p, "type_expr", None)
            if p.name == "self" and te is None and owner is not None:
                tyname = owner
            else:
                tyname = getattr(te, "name", None) if te is not None else None
            if tyname is not None:
                out[p.name] = tyname
        return out

    def _immutable_param_idxs(self, params) -> frozenset:
        """The 0-based indices of ``params`` whose declared type PROVABLY
        has no writable interior, so a fresh local that merely carries the
        parameter's data-flow taint cannot, by being mutated, write back
        into the parameter's object. These are the ONLY parameters dropped
        from a mutation-effect TARGET set; everything else is kept
        (keep-by-default on any uncertainty), so no real write-back channel
        is silently lost. Index alignment matches ``param_names`` (``self``
        at index 0 for a method), so a dropped index lines up with the
        summary's parameter order.

        ``self`` (no ``type_expr``) is an impl OWNER type -- always a
        user-defined struct / sum / capability, never a built-in immutable
        -- so it is kept unconditionally."""
        out: set = set()
        for idx, p in enumerate(params):
            te = getattr(p, "type_expr", None)
            if p.name == "self" and te is None:
                continue
            if self._type_expr_is_builtin_immutable(te):
                out.add(idx)
        return frozenset(out)

    def _type_expr_is_builtin_immutable(self, te) -> bool:
        """True when ``te`` names a type that PROVABLY has no writable
        interior: the built-in Unit (``()``), or a BARE named type that
        resolves to a built-in capability or a built-in primitive /
        String. A generic application (``List<T>``, ``Option<T>``), a
        ``Fun`` / tuple type, a typestate handle (``Socket[Open]``), an
        unannotated parameter, or anything unresolved is NOT provably
        immutable and is kept."""
        if te is None:
            return False
        # ``()`` -- the Unit type node. The parser only ever produces
        # ``UnitType`` from ``()`` and a user cannot redeclare it, so the
        # node itself is proof of the immutable built-in Unit (sourced from
        # the AST shape, never a name a user could shadow). Unit has no
        # interior at all.
        if isinstance(te, A.UnitType):
            return True
        # Only a bare named type can be a built-in primitive / capability.
        # A Fun or tuple type has a callable / writable interior.
        if not isinstance(te, A.TypeName):
            return False
        # A generic application (``List<Int>``, ``Option<Emp>``) carries an
        # interior element / payload, and a typestate handle is a mutable
        # linear type: keep both.
        if getattr(te, "args", None):
            return False
        if getattr(te, "state", None) is not None:
            return False
        return self._name_is_builtin_immutable(te.name)

    def _name_is_builtin_immutable(self, name: str) -> bool:
        """True when ``name`` resolves to the ACTUAL BUILT-IN capability or
        primitive / String SYMBOL, not a user redeclaration of the same
        name. Soundness rests on two distinctions the design review proved
        must not be skipped:

        * A parameter is dropped only when the name resolves to a symbol at
          the built-in source position (``BUILTIN_POS``). A user
          ``type Int { ... }`` shadows the built-in name with a MUTABLE
          struct that carries a real source position, so it is kept -- the
          check is by SYMBOL ORIGIN, never by the name alone.
        * The built-in capability set is matched by NAME within the
          built-in-position CAPABILITY symbols, so a USER-defined
          ``capability Store`` (whose methods are a genuine mutable data
          channel, and which also lands as ``SymbolKind.CAPABILITY``) is
          kept -- the drop is decided by BUILT-IN-vs-user origin, never by
          the symbol kind alone.

        ``TYPE_STRUCT`` at the built-in position also covers the mutable
        built-in containers (``List`` / ``Map`` / ``Set`` / ``IoError``),
        so the primitive drop additionally requires the name to be in
        ``PRIMITIVE_NAMES`` -- ``Int`` / ``Float`` / ``String`` / ``Char``
        / ``Bool`` only."""
        from .. import typesys as _typesys
        from ..builtins import BUILTIN_POS
        from . import SymbolKind
        sym = self.global_scope.lookup(name)
        if sym is None or sym.pos != BUILTIN_POS:
            return False
        if sym.kind == SymbolKind.CAPABILITY and \
                name in _typesys.CAPABILITY_NAMES:
            return True
        if sym.kind == SymbolKind.TYPE_STRUCT and \
                name in _typesys.PRIMITIVE_NAMES:
            return True
        return False

    def _writable_targets(self, targets: set) -> set:
        """Drop from a mutation-effect TARGET set every parameter whose
        type is provably a built-in immutable (``_cur_immutable_params``),
        leaving only the parameters that can hold a writable interior. The
        SHARED guard called at BOTH sites that use a value's data-flow taint
        set as an alias / mutation-target set (``_record_mutation_effect``
        and ``_propagate_callee_effects``), so a fresh local whose elements
        derive from an immutable-typed parameter no longer mis-records a
        mutation of that parameter. The sentinel ``INTERNAL_SECRET`` (a
        negative index) is never in the drop set, so it passes through
        unchanged (both call sites skip it separately)."""
        immutable = self._cur_immutable_params
        if not immutable:
            return targets
        return {j for j in targets if j not in immutable}

    @staticmethod
    def _secret_source_params(params) -> set:
        """The names of parameters whose declared type is a
        secret-source capability (``Env``), so a ``param.get(...)`` on
        them is an internal secret source."""
        out: set = set()
        for p in params:
            te = getattr(p, "type_expr", None)
            if te is not None and getattr(te, "name", None) in \
                    _SECRET_SOURCE_CAPS:
                out.add(p.name)
        return out

    # ---- fixpoint ---------------------------------------------------

    def run(self) -> tuple[dict, dict]:
        changed = True
        # The summary operator is monotone over a finite lattice (each
        # sink summary is a subset of parameter indices; each field
        # effect maps a finite set of target indices to a finite set of
        # source indices), so the ascending chain stabilises and the
        # loop is bounded.
        while changed:
            changed = False
            for key in self.callables:
                names, decl, _is_method = self.callables[key]
                reaching, effects, returns, scaps, spaths = self._analyze_body(
                    names, decl, key,
                )
                if not reaching <= self.summaries[key]:
                    self.summaries[key] |= reaching
                    changed = True
                # ``scaps`` is a per-parameter map (param idx -> set of
                # sink caps), merged monotonically exactly like the
                # field-write effect map so the same fixpoint carries it.
                if self._merge_effects(self.sink_caps[key], scaps):
                    changed = True
                # ``spaths`` (param idx -> set of sunk field paths) is the
                # read-side mirror, merged on the SAME fixpoint.
                if self._merge_effects(self.sink_paths[key], spaths):
                    changed = True
                if self._merge_effects(self.field_effects[key], effects):
                    changed = True
                if not returns <= self.return_effects[key]:
                    self.return_effects[key] |= returns
                    changed = True
        sinks = {k: frozenset(v) for k, v in self.summaries.items()}
        feffects = {
            k: {t: frozenset(s) for t, s in v.items()}
            for k, v in self.field_effects.items()
        }
        reffects = {k: frozenset(v) for k, v in self.return_effects.items()}
        sink_caps = {
            k: {p: frozenset(c) for p, c in v.items()}
            for k, v in self.sink_caps.items()
        }
        sink_paths = {
            k: {p: frozenset(paths) for p, paths in v.items()}
            for k, v in self.sink_paths.items()
        }
        return sinks, feffects, reffects, sink_caps, sink_paths

    @staticmethod
    def _merge_effects(acc: dict, new: dict) -> bool:
        """Monotonically merge field-write effect map ``new`` into
        ``acc`` (target idx -> set of sources). Return True if ``acc``
        grew (drives the fixpoint)."""
        grew = False
        for target, sources in new.items():
            cur = acc.get(target)
            if cur is None:
                acc[target] = set(sources)
                grew = grew or bool(sources)
            elif not sources <= cur:
                cur |= sources
                grew = True
        return grew

    # ---- per-body taint analysis ------------------------------------

    def _analyze_body(
        self, param_names: list[str], decl: A.FunDecl, key,
    ) -> tuple[set, dict, set, dict, dict]:
        """Compute (a) which parameter indices of ``decl`` reach a sink,
        (b) the field-write effects, and (c) the return-secret sources,
        using the summaries computed so far for transitive calls.

        Taint is tracked as ``name -> set(param indices)``: the set of
        source parameters (or ``INTERNAL_SECRET``) whose value flows
        into that name. A sink position taints those source params
        (adds them to ``reaching``); a field store on a param-rooted
        object records a field-write effect. ``declassify(...)`` yields
        the empty source set, breaking the chain. The set of names that
        ALIAS a parameter's object (for the field-store target) is the
        same taint set, since a struct binding carries its source
        params' indices by reference.
        """
        env: dict[str, set] = {}
        for idx, pname in enumerate(param_names):
            # ``self`` and every explicit parameter is a potential
            # carrier; a capability-typed parameter never holds secret
            # data, but it also never appears as a sink ARGUMENT, so
            # seeding it is harmless and keeps the index alignment.
            env[pname] = {idx}
        reaching: set = set()
        effects: dict = {}
        returns: set = set()
        # The additive CONTENT channel: ``name -> set of source-param /
        # INTERNAL_SECRET`` that a CALLEE wrote INTO the object bound to
        # ``name`` (a container mutation / field store recorded as the
        # callee's mutation effect and inherited here). It is joined into
        # the ``_taint_of`` result on a READ of the name, so a read-back of
        # a caller-local the callee mutated reflects the injected taint --
        # WITHOUT feeding the alias / mutation-TARGET derivation, which
        # stays ``env``-only (the two channels are kept distinct on
        # purpose). Reset per body; only ever unioned into (never
        # overwritten).
        #
        # Scoping across the branching constructs is UNIFORM: the ``if`` /
        # ``elif`` / ``else`` and ``match`` STATEMENT forms, the ``if ...
        # then ... else`` and ``match`` EXPRESSION forms, and the ``while``
        # / ``for`` loop bodies. Each branch is analyzed from a common
        # pre-construct content snapshot in isolation, then every branch's
        # delta is unioned into the enclosing scope AFTER all branches are
        # walked (``_content_isolated`` / ``_content_merge``). So a mutation
        # in one branch does NOT reach a sibling branch's read, and the
        # delta DOES propagate out to a read AFTER the construct. A branch
        # CONDITION (an ``if`` / ``elif`` guard) and a match-arm GUARD are
        # NOT isolated: they run on the path to later branches / arms, so
        # they are evaluated in the enclosing content scope and their
        # mutation propagates (see the ``MatchExpr`` handler). The trailing
        # / implicit-return expression of a value block is walked EXACTLY
        # ONCE (``_walk_value_block``), never walk-then-re-walk, so a
        # branching tail expression's branches are not re-isolated from an
        # already-merged baseline (which would leak a sibling's mutation
        # into another sibling's read). A LAMBDA body is
        # isolated-and-discarded instead: its mutation of a captured local
        # is a side effect that only happens on invocation, which the
        # summary does not model, so not propagating it keeps an un-invoked
        # lambda from raising a false positive.
        #
        # RESIDUALS (out of scope): (1) a LOOP-CARRIED read-before-write
        # inside a ``while`` / ``for`` -- a read textually BEFORE the
        # cross-function push that, on a later iteration, would see the
        # earlier iteration's push -- is not caught, since the body is
        # walked once in source order with no iteration fixpoint ("closed
        # uniformly inside while / for" means within a single pass, not
        # across loop-carried ordering); and (2) an INVOKED lambda's
        # mutation of a captured local (the aliasing / escape residual: the
        # side effect happens at an invocation site the summary does not
        # model). Both need machinery this pass deliberately omits.
        content: dict = {}
        self._cur_content = content
        # Observational (feature #6, B1): PER PARAMETER, the sink
        # capabilities that parameter's value reaches in this body,
        # accumulated by the walk in parallel with ``reaching`` (a source
        # param that flows into a sink gets the reached cap attributed to
        # IT, not to the whole callable).
        sink_caps_local: dict = {}
        self._cur_sink_caps = sink_caps_local
        # Read-side mirror (Stage 2): PER PARAMETER, the parameter-relative
        # field PATHS that reach a public sink in this body, accumulated by
        # the walk in parallel with ``reaching``. ``()`` records the WHOLE
        # parameter reaching a sink (the conservative default).
        sink_paths_local: dict = {}
        self._cur_sink_paths = sink_paths_local
        # Per-callable analysis state consulted inside the walk (which
        # threads only ``env`` / ``reaching`` through its signatures):
        # the names of secret-source-capability params, the accumulating
        # field-write effect map, and the return-secret source set.
        self._cur_secret_source_params = self.secret_source_params.get(
            key, set(),
        )
        self._cur_param_struct_types = self.param_struct_types.get(key, {})
        self._cur_param_type_names = self.param_type_names.get(key, {})
        # The parameter indices of THIS callable whose type is provably a
        # built-in immutable, so ``_writable_targets`` can drop them from a
        # mutation-effect TARGET set (see ``immutable_params``).
        self._cur_immutable_params = self.immutable_params.get(
            key, frozenset(),
        )
        self._cur_effects = effects
        self._cur_returns = returns
        # ``param name -> 0-based index`` for THIS callable, so a mutation
        # chain whose ROOT identifier is a parameter can be keyed at a
        # parameter-relative field path (Stage 1). A chain rooted at a
        # local that merely ALIASES a parameter is absent here, so it takes
        # the whole-value carrier (its field path is not parameter-relative).
        self._cur_param_index = {
            pname: idx for idx, pname in enumerate(param_names)
        }
        # Names of secret consts currently shadowed by a LEXICALLY IN-SCOPE
        # local binding. Consulted (not ``env``) by the const-vs-local
        # decision in ``_taint_of``: ``env`` is a flat, monotonically
        # grown, per-body map, so a ``let K = ...`` in a closed sub-scope
        # would suppress a GENUINE reference to the secret const ``K`` in a
        # sibling / later block (fail-open). This set is saved/restored per
        # sub-block (mirroring the ``dict(env)`` isolation match arms
        # already get), so a local shadow only masks the const within its
        # real lexical extent. A PARAMETER named like a const shadows it
        # for the whole body (Capa forbids shadowing a param with a local,
        # so the whole-body extent is correct).
        self._shadowed_consts: set[str] = {
            pname for pname in param_names if pname in self.secret_consts
        }
        # A function body's trailing bare expression is an implicit
        # return (unit / expression-bodied functions), so its taint is a
        # return source too. ``_walk_value_block`` walks that trailing
        # expression EXACTLY ONCE (not walk-then-re-walk), so a branching
        # tail expression's per-branch content isolation is not defeated by
        # a second walk over an already-merged baseline.
        returns |= self._walk_value_block(decl.body, env, reaching)
        return reaching, effects, returns, sink_caps_local, sink_paths_local

    def _walk_block(self, block: A.Block, env: dict, reaching: set) -> None:
        for stmt in block.stmts:
            self._walk_stmt(stmt, env, reaching)

    def _walk_scoped_block(
        self, block: A.Block, env: dict, reaching: set,
    ) -> None:
        """Walk a nested block (an ``if`` branch or loop body) under its
        OWN const-shadow scope: a ``let K = ...`` inside it masks the
        secret const ``K`` only within the block, not in sibling / later
        blocks. ``env`` stays flat (its monotone taint accumulation across
        blocks is intentional and unchanged); only the lexical const-vs-
        local decision is scoped, mirroring the ``dict(env)`` isolation
        that match arms already use."""
        saved = self._shadowed_consts
        self._shadowed_consts = set(saved)
        self._walk_block(block, env, reaching)
        self._shadowed_consts = saved

    def _register_shadowing_binds(self, names) -> None:
        """Record every bound ``name`` that equals a secret const as
        shadowing it in the CURRENT scope (added to ``_shadowed_consts``,
        which the enclosing ``_walk_scoped_block`` unwinds on exit)."""
        for name in names:
            if name in self.secret_consts:
                self._shadowed_consts.add(name)

    # ---- content-channel scoping across branching constructs --------

    def _content_isolated(self, walk) -> dict:
        """Run ``walk`` with the content channel isolated from a snapshot
        of the CURRENT content, and RETURN the resulting content map (the
        snapshot plus whatever the branch added) while RESTORING the
        pre-call content.

        The snapshot is taken NOW, so it includes anything already
        evaluated on the enclosing path (e.g. a preceding branch's
        condition). Restoring the pre-call content means a sibling branch
        analyzed next does NOT see this branch's cross-function mutation
        (fixes the cross-branch false positive). The caller collects the
        returned maps and unions them once ALL branches are walked (see
        ``_content_merge``) -- the union is DEFERRED so no branch sees an
        earlier sibling's delta. ``env`` scoping is the caller's job and
        is unchanged (flat for ``if`` / ``while`` / ``for``, copied per
        ``match`` arm)."""
        saved = self._cur_content
        self._cur_content = {k: set(v) for k, v in saved.items()}
        walk()
        post = self._cur_content
        self._cur_content = saved
        return post

    def _content_merge(self, posts) -> None:
        """Union each branch's content map (from ``_content_isolated``)
        into the enclosing content, so a read AFTER the construct reflects
        any branch's cross-function mutation (a fresh local mutated in one
        arm and read past the construct is caught). Deferred to after all
        branches, so it never contaminates a sibling branch's read."""
        for post in posts:
            for name, srcs in post.items():
                self._cur_content.setdefault(name, set()).update(srcs)

    def _walk_stmt(self, stmt: A.Stmt, env: dict, reaching: set) -> None:
        if isinstance(stmt, A.LetStmt):
            src = self._taint_of(stmt.value, env, reaching)
            self._bind_pattern_taint(stmt.pattern, src, env)
            # A ``let`` binding a name equal to a secret const shadows it
            # for the REST OF THIS BLOCK (and its sub-blocks); it is
            # unwound when the enclosing block's scope is restored.
            self._register_shadowing_binds(_pattern_bound_names(stmt.pattern))
        elif isinstance(stmt, A.VarStmt):
            env[stmt.name] = self._taint_of(stmt.value, env, reaching)
            self._register_shadowing_binds((stmt.name,))
        elif isinstance(stmt, A.AssignStmt):
            src = self._taint_of(stmt.value, env, reaching)
            self._taint_of(stmt.target, env, reaching)
            if isinstance(stmt.target, A.Ident):
                # Monotone over loops / branches: join, never clear.
                env[stmt.target.name] = (
                    env.get(stmt.target.name, set()) | src
                )
            elif isinstance(stmt.target, A.FieldAccess):
                # A field store ``obj.f = value`` (or ``obj.a.b = ...``):
                # if the written object is rooted at a parameter (or a
                # binding that aliases one), record a mutation effect from
                # each source flowing into ``value`` onto each target param
                # the object aliases. NOT field-keyed (``field_keyable=
                # False``): the whole-value carrier mirrors the intra field
                # store, which raises the struct's collapsed whole-value
                # label, so a later whole / getter read of the struct
                # observes it (keeping that coverage). ANY store op is
                # recorded: an augmented store (``box.f += v``) reads the
                # old field and joins ``value`` into it, so it can only
                # RAISE the field's label, never lower it -- recording the
                # effect for every op is sound and closes the augmented-
                # store cross-function leak.
                self._record_mutation_effect(
                    stmt.target, src, env, field_keyable=False,
                )
        elif isinstance(stmt, A.IfStmt):
            # ``env`` (and each condition) is evaluated in the ORIGINAL
            # interleaved order (cond, body, cond, body ...) so its flat,
            # monotone propagation is unchanged. Only the CONTENT channel is
            # scoped: each branch is isolated from a snapshot of the content
            # at that point, and every branch's delta is unioned into the
            # enclosing scope after ALL branches are walked (deferred union).
            self._taint_of(stmt.cond, env, reaching)
            posts = [self._content_isolated(
                lambda: self._walk_scoped_block(
                    stmt.then_block, env, reaching,
                ),
            )]
            for cond, blk in stmt.elif_arms:
                self._taint_of(cond, env, reaching)
                posts.append(self._content_isolated(
                    lambda b=blk: self._walk_scoped_block(b, env, reaching),
                ))
            if stmt.else_block is not None:
                posts.append(self._content_isolated(
                    lambda: self._walk_scoped_block(
                        stmt.else_block, env, reaching,
                    ),
                ))
            self._content_merge(posts)
        elif isinstance(stmt, A.WhileStmt):
            self._taint_of(stmt.cond, env, reaching)
            # A single body, but routed through the same rule so a read
            # AFTER the loop reflects a cross-function mutation in the body.
            self._content_merge([self._content_isolated(
                lambda: self._walk_scoped_block(stmt.body, env, reaching),
            )])
        elif isinstance(stmt, A.ForStmt):
            iter_src = self._taint_of(stmt.iter, env, reaching)
            self._bind_pattern_taint(stmt.pattern, iter_src, env)

            def _for_body():
                # The loop variable is scoped to the body; a loop var named
                # like a secret const shadows it there only.
                saved = self._shadowed_consts
                self._shadowed_consts = set(saved)
                self._register_shadowing_binds(
                    _pattern_bound_names(stmt.pattern),
                )
                self._walk_block(stmt.body, env, reaching)
                self._shadowed_consts = saved

            self._content_merge([self._content_isolated(_for_body)])
        elif isinstance(stmt, A.ReturnStmt):
            if stmt.value is not None:
                # The returned value's source set is a return-secret
                # effect: it carries the callee's secret-derived result
                # to the caller's call-result label cross-function.
                self._cur_returns |= self._taint_of(stmt.value, env, reaching)
        elif isinstance(stmt, A.ExprStmt):
            self._taint_of(stmt.expr, env, reaching)
        # break / continue carry no value.

    def _bind_pattern_taint(self, pat: A.Pattern, src: set, env: dict) -> None:
        """Propagate a scrutinee / value's source-param set to every
        name the pattern binds (whole-value granularity, matching
        ``_label_pattern_binds``).

        A name bound to a struct field DECLARED ``@secret`` additionally
        carries the ``INTERNAL_SECRET`` sentinel, independent of the
        scrutinee's own taint -- the cross-function analogue of
        ``_field_read_is_secret`` for a pattern bind. So a callee that
        destructures a declared-@secret field of a struct parameter and
        sinks / returns the bound name is caught across the boundary,
        exactly like one that reads ``param.iban`` directly. Resolved by
        the pattern's STRUCT TYPE NAME (never by bound-name spelling), so
        a same-named public field of an unrelated struct is not tainted."""
        if isinstance(pat, A.IdentPat):
            env[pat.name] = env.get(pat.name, set()) | src
            return
        for name in _pattern_bound_names(pat):
            env[name] = env.get(name, set()) | src
        self._bind_pattern_field_secrets(pat, env)

    def _bind_pattern_field_secrets(self, pat: A.Pattern, env: dict) -> None:
        """Taint every name bound to a DECLARED-``@secret`` struct field
        with ``INTERNAL_SECRET``, walking nested patterns. Mirrors the
        intra-procedural ``_label_pattern_field_secrets``; see
        ``_bind_pattern_taint`` for why resolution is by the pattern's
        struct type name."""
        from .. import _labels as L
        if isinstance(pat, A.StructPat):
            labels = self.struct_field_labels.get(pat.type_name, {})
            for fname, fpat in pat.fields:
                if labels.get(fname) == L.SECRET:
                    if fpat is None:
                        env[fname] = env.get(fname, set()) | {INTERNAL_SECRET}
                    else:
                        for name in _pattern_bound_names(fpat):
                            env[name] = (
                                env.get(name, set()) | {INTERNAL_SECRET}
                            )
                if fpat is not None:
                    self._bind_pattern_field_secrets(fpat, env)
            return
        if isinstance(pat, A.VariantPat):
            for sub in pat.payloads:
                self._bind_pattern_field_secrets(sub, env)
        elif isinstance(pat, A.TuplePat):
            for sub in pat.elements:
                self._bind_pattern_field_secrets(sub, env)

    def _record_mutation_effect(
        self, target: A.Expr, value_src: set, env: dict,
        field_keyable: bool,
    ) -> None:
        """Record a mutation effect for a write into ``target`` -- a
        field store (``target.f = value``) or a container mutation
        (``target.push(value)`` and every other entry of
        ``_CONTAINER_MUTATORS``). The written object's identity is the
        env taint set of the chain's ROOT name (a struct / container
        binding carries the param indices of every param it aliases by
        reference). For each such target param ``j``, every source
        flowing into the value becomes a mutation effect ``(j, path) <-
        source``. A source that is itself a parameter index (or
        ``INTERNAL_SECRET``) is recorded; transitive sources already
        collapsed into ``value_src`` by ``_taint_of``.

        ``field_keyable`` follows the intra-procedural two-channel split:
        a CONTAINER MUTATION (``True``) is field-keyed, so ``path`` is the
        parameter-relative field path when the chain is rooted directly at
        param ``j`` (else the whole-value carrier) and the caller taints
        only that ``(root, field-path)`` on the branch-scoped container
        channel. A public SIBLING field stays clean (a field read scans
        only its own path), while a same-root WHOLE read-back is still
        caught: ``_compute_label`` prefix-scans the ``(root, *)`` channel
        for a whole / getter / interpolation / pass-whole read (the
        length-0 access-path query). A FIELD STORE (``False``) is NOT
        field-keyed: it takes the whole-value carrier (``path`` is
        ``None``), because the intra field store raises the struct's
        COLLAPSED whole-value label -- keeping the whole-value carrier
        keeps that coverage. De-collapsing a field store to a per-field
        caller taint (so its sibling gains the same precision) is a later
        refinement, not needed for soundness."""
        root = self._chain_root_name(target)
        if root is None:
            return
        # ``env.get(root)`` is the root binding's data-flow TAINT set, used
        # here as its alias / mutation-TARGET set. Drop any parameter whose
        # type is provably a built-in immutable: a fresh local whose
        # elements derive from such a parameter carries its taint but
        # writing into the local can never write back into the parameter's
        # (non-existent) interior. Keeps a real write-back channel (a user
        # struct / capability, a List param, ...) untouched.
        target_params = self._writable_targets(env.get(root, set()))
        if not target_params or not value_src:
            return
        field_path = self._chain_field_path(target) if field_keyable else None
        for j in target_params:
            if j == INTERNAL_SECRET:
                continue
            key = self._mutation_effect_key(j, root, field_path)
            self._cur_effects.setdefault(key, set()).update(value_src)

    def _mutation_effect_key(self, j: int, root_name: str, field_path):
        """The effect-map key for a write into target param ``j`` whose
        chain root is named ``root_name`` at ``field_path`` (a tuple of
        field names, or ``None``). FIELD-KEYED ``(j, field_path)`` only
        when the chain is rooted DIRECTLY at param ``j`` -- so
        ``field_path`` is exactly parameter-relative -- and the path is
        within the ``_MAX_FIELD_PATH`` bound; otherwise the WHOLE-VALUE
        carrier ``(j, None)``, the sound fallback for an aliased / renamed
        root (whose path is not parameter-relative), an unkeyable chain,
        or an over-long path (kept finite so the fixpoint terminates)."""
        if (
            field_path is not None
            and self._cur_param_index.get(root_name) == j
            and len(field_path) <= _MAX_FIELD_PATH
        ):
            return (j, field_path)
        return (j, None)

    @staticmethod
    def _compose_paths(prefix, suffix):
        """Compose a caller's access-path ``prefix`` (its field path down
        to the argument) with a callee's ``suffix`` field path, for the
        transitive effect. A ``None`` (whole-value) on either side
        collapses the result to whole-value."""
        if prefix is None or suffix is None:
            return None
        return prefix + suffix

    def _field_read_is_secret(self, e: A.FieldAccess) -> bool:
        """True if reading field ``e`` yields a value declared
        ``@secret``, resolved PRECISELY: the receiver must be a parameter
        whose struct type we know (``param_struct_types``), and that
        struct must declare this exact field ``@secret``. Deliberately
        precise (no by-name over-approximation): a same-named field that
        is @secret in some UNRELATED struct must NOT taint a public field
        read here, so the cross-function summary never raises a false
        positive on a public field. The intra-procedural pass (resolved
        types) is the precise primary check; this only adds the
        cross-function carry for the common parameter-struct shape that
        the required facets use (a callee that reads a declared-@secret
        field of a struct PARAMETER and sinks / returns it).

        PARITY (field-read / field-pattern): the SAME declared-@secret
        field reached by DESTRUCTURING (``let Emp { iban } = e`` / a
        ``match`` arm) is covered too -- see
        ``_bind_pattern_field_secrets``, the pattern-bind analogue of
        this read rule -- so a field cannot launder its label through a
        pattern bind any more than through a direct ``e.iban`` read."""
        from .. import _labels as L
        recv = e.receiver
        if isinstance(recv, A.Ident):
            tyname = self._cur_param_struct_types.get(recv.name)
            if tyname is not None:
                labels = self.struct_field_labels.get(tyname, {})
                return labels.get(e.field_name) == L.SECRET
        return False

    @staticmethod
    def _chain_root_name(e: A.Expr):
        """The root identifier name of a field-access chain
        (``b`` -> ``"b"``, ``b.inner.x`` -> ``"b"``), or ``None`` if the
        chain is not rooted at a plain identifier."""
        while isinstance(e, A.FieldAccess):
            e = e.receiver
        return e.name if isinstance(e, A.Ident) else None

    @staticmethod
    def _chain_field_path(e: A.Expr):
        """The tuple of field names from the chain ROOT down to ``e``
        (``xs`` -> ``()``, ``bag.items`` -> ``("items",)``, ``b.a.b`` ->
        ``("a", "b")``), or ``None`` when ``e`` is not an Ident-rooted
        field chain (a call- / index-rooted receiver has no keyable
        access path). Mirrors ``_field_path_from_root`` in :mod:`._ifc`,
        the intra-procedural channel this effect routes onto."""
        names = []
        while isinstance(e, A.FieldAccess):
            names.append(e.field_name)
            e = e.receiver
        if not isinstance(e, A.Ident):
            return None
        names.reverse()
        return tuple(names)

    # ---- taint of an expression ------------------------------------

    def _taint_of(self, e: A.Expr, env: dict, reaching: set) -> set:
        """Return the set of source-param indices that flow into the
        value of ``e``. Side effect: when ``e`` (or a sub-expression)
        places a param-derived value into a sink argument position,
        those source params are added to ``reaching``.
        """
        if isinstance(e, A.Ident):
            # A reference to a module-level ``@secret`` const is an
            # internal secret source, symmetric to a declared-@secret
            # field read: it carries the INTERNAL_SECRET sentinel so a
            # free function returning it / writing it to a field taints
            # its return / field-write effect and the leak is caught at
            # the call site. Suppressed only when a LEXICALLY IN-SCOPE
            # local shadows the const name (``_shadowed_consts``, scoped
            # per sub-block) -- NOT when it merely appears in the flat
            # ``env`` (a sibling / later-block shadow must not mask a
            # genuine const reference).
            if (
                e.name in self.secret_consts
                and e.name not in self._shadowed_consts
            ):
                return {INTERNAL_SECRET}
            # Join the ADDITIVE content channel: a callee that mutated this
            # local's interior (recorded cross-function in
            # ``_propagate_callee_effects``) raised its content label, and a
            # read-back must reflect it. Additive only -- ``env`` alone
            # remains the alias / mutation-target set consulted elsewhere.
            return (
                set(env.get(e.name, set()))
                | self._cur_content.get(e.name, set())
            )
        if isinstance(e, (
            A.IntLit, A.FloatLit, A.StringLit, A.CharLit,
            A.BoolLit, A.UnitLit,
        )):
            return set()
        if isinstance(e, A.InterpolatedString):
            out: set = set()
            for p in e.parts:
                if not isinstance(p, str):
                    out |= self._taint_of(p, env, reaching)
            return out
        if isinstance(e, A.BinOp):
            return (
                self._taint_of(e.left, env, reaching)
                | self._taint_of(e.right, env, reaching)
            )
        if isinstance(e, A.UnaryOp):
            return self._taint_of(e.operand, env, reaching)
        if isinstance(e, A.Try):
            return self._taint_of(e.expr, env, reaching)
        if isinstance(e, A.Index):
            return (
                self._taint_of(e.receiver, env, reaching)
                | self._taint_of(e.index, env, reaching)
            )
        if isinstance(e, A.FieldAccess):
            recv_src = self._taint_of(e.receiver, env, reaching)
            # A field whose declared type is ``@secret`` (``type Emp {
            # iban: @secret String }``) is an internal secret source when
            # READ: the value carries the INTERNAL_SECRET sentinel so it
            # reaches a sink / return cross-function, mirroring the
            # intra-procedural declared-field-label rule. Precise when the
            # receiver is a parameter whose struct type we resolved; a
            # by-name over-approximation (any struct declares this field
            # @secret) otherwise -- sound, never under-reports.
            if self._field_read_is_secret(e):
                return recv_src | {INTERNAL_SECRET}
            return recv_src
        if isinstance(e, A.RangeExpr):
            return (
                self._taint_of(e.start, env, reaching)
                | self._taint_of(e.end, env, reaching)
            )
        if isinstance(e, A.StructLit):
            out = set()
            for _name, v in e.fields:
                out |= self._taint_of(v, env, reaching)
            return out
        if isinstance(e, (A.ListLit, A.TupleLit)):
            out = set()
            for el in e.elements:
                out |= self._taint_of(el, env, reaching)
            return out
        if isinstance(e, A.IfExpr):
            # Same uniform content-channel rule as the if / match STATEMENT
            # forms: the two branch expressions are isolated from a common
            # snapshot and their deltas unioned afterwards, so a
            # cross-function mutation in the ``then`` branch is not seen by
            # the ``else`` branch's read (no false positive), while the
            # value taint is the union over both branches.
            self._taint_of(e.cond, env, reaching)
            results: list = []
            posts = [
                self._content_isolated(
                    lambda: results.append(
                        self._taint_of(e.then_expr, env, reaching),
                    ),
                ),
                self._content_isolated(
                    lambda: results.append(
                        self._taint_of(e.else_expr, env, reaching),
                    ),
                ),
            ]
            self._content_merge(posts)
            return results[0] | results[1]
        if isinstance(e, A.MatchExpr):
            scrut = self._taint_of(e.scrutinee, env, reaching)
            out = set()
            # Uniform content-channel rule: each arm BODY is mutually
            # exclusive, so it is isolated from a snapshot of the content and
            # every body's delta is unioned into the enclosing scope after
            # ALL arms are walked (deferred union). A cross-function mutation
            # in one arm's body therefore does NOT reach a sibling arm's
            # read, yet a read AFTER the match reflects any arm's mutation.
            # ``env`` is a fresh ``dict(env)`` per arm.
            #
            # An arm GUARD is NOT isolated: it is tested on the path to
            # LATER arms (if it fails, control proceeds to the next arm), so
            # -- exactly like an ``if`` / ``elif`` CONDITION -- it is
            # evaluated in the ENCLOSING content scope, so a cross-function
            # mutation it performs is visible to later arms and to code after
            # the match. Only the mutually-exclusive BODY is isolated.
            posts = []
            for arm in e.arms:
                # Each arm sees a sub-env where the pattern binds carry the
                # scrutinee's taint (whole-value), and its OWN const-shadow
                # scope: a pattern binding a name equal to a secret const
                # shadows it within the arm only.
                arm_env = dict(env)
                self._bind_pattern_taint(arm.pattern, scrut, arm_env)
                saved = self._shadowed_consts
                self._shadowed_consts = set(saved)
                self._register_shadowing_binds(
                    _pattern_bound_names(arm.pattern),
                )
                if arm.guard is not None:
                    self._taint_of(arm.guard, arm_env, reaching)

                def _walk_body(arm=arm, arm_env=arm_env):
                    if isinstance(arm.body, A.Block):
                        out.update(
                            self._walk_value_block(
                                arm.body, arm_env, reaching,
                            ),
                        )
                    else:
                        out.update(self._taint_of(arm.body, arm_env, reaching))

                posts.append(self._content_isolated(_walk_body))
                self._shadowed_consts = saved
            self._content_merge(posts)
            return out
        if isinstance(e, A.Become):
            return self._taint_of(e.value, env, reaching)
        if isinstance(e, A.Call):
            return self._taint_of_call(e, env, reaching)
        if isinstance(e, A.MethodCall):
            return self._taint_of_method_call(e, env, reaching)
        if isinstance(e, A.LambdaExpr):
            return self._taint_of_lambda(e, env, reaching)
        # Any other expression carries no source taint.
        return set()

    def _taint_of_lambda(
        self, e: A.LambdaExpr, env: dict, reaching: set,
    ) -> set:
        """The taint the VALUE of a lambda carries: the taint its
        INVOCATION would produce -- the source-param / internal-secret set
        of the value the body returns (its ``return`` statements plus its
        trailing bare expression / expression body). So a free function
        ``return fun () => K`` (``K`` a @secret const) or ``return fun () =>
        e.iban`` (a declared-@secret field of a struct param it captures)
        makes the function's return-effect record the captured secret, and
        the existing call-site rules taint the caller's closure binding, so
        invoking it and sinking the result is caught -- closing the
        lambda-capture laundering. A lambda that captures a secret but
        returns a PUBLIC value, or ``declassify(...)`` inside the body,
        carries no taint (no false positive).

        The lambda's own PARAMETERS are fresh locals, not captures: they
        are masked in an ISOLATED copy of ``env`` (a param named like a
        captured local does NOT inherit the enclosing taint) and registered
        as const shadows (a param named like a secret const suppresses it
        inside the body). The copy is throwaway so a body mutation never
        leaks back into the enclosing function's flat, monotone env;
        ``_shadowed_consts`` and the return accumulator are saved/restored
        so nested lambdas compose. A sink INSIDE the body is left to the
        intra-procedural pass; walking it here only ever ADDS to
        ``reaching`` (sound over-approximation)."""
        body_env = dict(env)
        for p in e.params:
            body_env[p.name] = set()
        saved_shadowed = self._shadowed_consts
        self._shadowed_consts = set(saved_shadowed)
        self._register_shadowing_binds(p.name for p in e.params)
        saved_returns = self._cur_returns
        lambda_returns: set = set()
        self._cur_returns = lambda_returns
        # Isolate the content channel like ``body_env``: a cross-function
        # mutation of a CAPTURED local inside the lambda body must not
        # escape into the enclosing body's content map (whether the lambda
        # is ever invoked is unknown), mirroring the env copy above.
        saved_content = self._cur_content
        self._cur_content = {k: set(v) for k, v in saved_content.items()}
        try:
            if isinstance(e.body, A.Block):
                lambda_returns |= self._walk_value_block(
                    e.body, body_env, reaching,
                )
            else:
                lambda_returns |= self._taint_of(e.body, body_env, reaching)
        finally:
            self._cur_returns = saved_returns
            self._shadowed_consts = saved_shadowed
            self._cur_content = saved_content
        return lambda_returns

    def _walk_value_block(
        self, block: A.Block, env: dict, reaching: set,
    ) -> set:
        """Walk a block used as a VALUE (a function / lambda body, or a
        ``match`` arm body) and return the taint of its implicit-return
        value: the taint of its trailing bare expression.

        The trailing expression is walked EXACTLY ONCE. Walking the whole
        block and then RE-walking the trailing expression (the previous
        shape) is unsound for the content channel: the first walk merges a
        branching tail expression's per-branch deltas into the block's
        content, and the second walk then re-isolates those same branches
        from the now-merged baseline, so a sibling read arm sees another
        arm's cross-function mutation (a false positive). Walking once
        keeps each branch isolated from the pre-tail baseline. The trailing
        expression's own content delta still merges into the block content,
        which is harmless because nothing follows it."""
        stmts = block.stmts
        if stmts and isinstance(stmts[-1], A.ExprStmt):
            for stmt in stmts[:-1]:
                self._walk_stmt(stmt, env, reaching)
            return self._taint_of(stmts[-1].expr, env, reaching)
        self._walk_block(block, env, reaching)
        return set()

    def _attribute_sink_caps(self, sources: set, caps) -> None:
        """Observational (feature #6, B1): attribute each sink capability
        in ``caps`` to EVERY source param (or ``INTERNAL_SECRET``) in
        ``sources`` -- the params whose value just reached that sink. Runs
        at every point ``reaching |= sources`` records a sink hit, so the
        per-parameter map grows in lockstep with the sink-reaching set:
        a param that reaches only Net never inherits a sibling's Fs. A
        source key that is not a real parameter (``INTERNAL_SECRET``) is
        recorded harmlessly -- the call site only ever looks the map up by
        a real parameter index."""
        if not caps:
            return
        for s in sources:
            self._cur_sink_caps.setdefault(s, set()).update(caps)

    def _record_sink_paths(self, arg: A.Expr, sources: set) -> None:
        """Read-side mirror of ``_record_mutation_effect`` for a DIRECT
        sink on ``arg`` (a built-in sink / panic). For each source param
        ``p`` in ``sources``, record the PARAMETER-RELATIVE field path of
        the sunk value: the syntactic field path when ``arg`` is a chain
        rooted DIRECTLY at param ``p`` (so ``println(bag.note)`` records
        ``p=bag`` sunk at ``("note",)``), else the sentinel ``()`` meaning
        the WHOLE param reaches the sink (a bare param, a value derived
        through a local, or an over-long path -- the conservative default,
        prefix-compatible with every tainted path)."""
        root = self._chain_root_name(arg)
        root_param = self._cur_param_index.get(root) if root is not None \
            else None
        fpath = self._chain_field_path(arg)
        for p in sources:
            if p == INTERNAL_SECRET:
                continue
            if p == root_param and fpath is not None \
                    and len(fpath) <= _MAX_FIELD_PATH:
                path = fpath
            else:
                path = ()
            self._cur_sink_paths.setdefault(p, set()).add(path)

    def _propagate_sink_paths(
        self, arg: A.Expr, sources: set, callee_paths,
    ) -> None:
        """Read-side mirror of ``_propagate_callee_effects``: a callee's
        param sinks at ``callee_paths``; when ``arg`` (bound to it) is
        rooted at one of MY params, MY param sinks at the COMPOSED path
        (my access-path prefix to ``arg`` + the callee's sunk path). Falls
        back to ``()`` (whole param sunk) when the argument is not rooted
        directly at the param, when a callee path is unkeyable, or when the
        composed path overflows the k-bound -- always conservative (a
        wider sunk path flags at least as much)."""
        if not callee_paths:
            callee_paths = {()}
        root = self._chain_root_name(arg)
        root_param = self._cur_param_index.get(root) if root is not None \
            else None
        arg_path = self._chain_field_path(arg)
        for p in sources:
            if p == INTERNAL_SECRET:
                continue
            if p == root_param and arg_path is not None:
                for cp in callee_paths:
                    composed = self._compose_paths(arg_path, cp)
                    if composed is not None and \
                            len(composed) <= _MAX_FIELD_PATH:
                        path = composed
                    else:
                        path = ()
                    self._cur_sink_paths.setdefault(p, set()).add(path)
            else:
                self._cur_sink_paths.setdefault(p, set()).add(())

    # ---- calls ------------------------------------------------------

    def _taint_of_call(self, e: A.Call, env: dict, reaching: set) -> set:
        # declassify breaks the chain: its arguments are still walked
        # (so a sink *inside* an argument is still seen), but the value
        # it yields carries no source taint.
        if self._is_declassify(e):
            for a in e.args:
                self._taint_of(a, env, reaching)
            return set()

        arg_srcs = [self._taint_of(a, env, reaching) for a in e.args]

        # The builtin ``panic(message)`` is a public sink (the message
        # goes to stderr, like Stdio.eprintln): a parameter flowing
        # into its argument is sink-reaching, so a caller passing a
        # @secret to a function that panics with it is flagged at the
        # boundary. A user function named ``panic`` shadows the
        # builtin and takes the regular summary path below instead.
        if (
            isinstance(e.callee, A.Ident)
            and e.callee.name == "panic"
            and ("fun", "panic") not in self.callables
            and arg_srcs
        ):
            reaching |= arg_srcs[0]
            # Observational (feature #6, B1): ``panic`` writes its message
            # to stderr, treated as Stdio egress (matching the
            # intra-procedural panic sink). Attribute Stdio to each param
            # flowing into the message, so a cross-function or transitive
            # @secret-through-panic leak records ``Stdio`` -- keeping the
            # completeness invariant that every reaching-growth site pairs
            # with a capability attribution.
            self._attribute_sink_caps(arg_srcs[0], ("Stdio",))
            # Read-side (Stage 2): record the sunk access path of the
            # panicked message, so a whole-struct arg is intersected
            # field-precisely at the call site.
            self._record_sink_paths(e.args[0], arg_srcs[0])

        if not isinstance(e.callee, A.Ident):
            # Non-Ident callee (lambda result, etc.): conservatively
            # join the argument taints into the result; no summary.
            self._taint_of(e.callee, env, reaching)
            out = set()
            for s in arg_srcs:
                out |= s
            return out

        key = ("fun", e.callee.name)
        # Invoking a Fun-typed PARAMETER: ``f()`` where ``f`` is parameter
        # ``idx``. The result carries ``f``'s taint, so if it reaches a
        # sink the parameter ``idx`` becomes sink-reaching -- the
        # INVOKE-SINK-REACHING parameter (a Fun parameter the callee
        # invokes and whose result it sinks). The call site disambiguates
        # by the parameter's declared TYPE: a Fun-typed sink-reaching
        # parameter consults a closure argument's RESULT label (so a
        # declassifying closure is not flagged), a data-typed one its
        # whole-value label. Only fires for a callee name that is NOT a
        # known free function (those take the summary path) and that
        # carries parameter taint in ``env`` (an ordinary public local
        # does not).
        invoke_src: set = set()
        if key not in self.callables:
            invoke_src = set(env.get(e.callee.name, set()))
        if key in self.callables:
            names, _decl, _is_method = self.callables[key]
            perm = self._bind_args(e, names)
            sink_params = self.summaries.get(key, set())
            callee_caps = self.sink_caps.get(key, {})
            callee_sink_paths = self.sink_paths.get(key, {})
            for pidx, arg_idx in perm.items():
                if (
                    pidx in sink_params
                    and arg_idx < len(arg_srcs)
                    and arg_srcs[arg_idx]
                ):
                    reaching |= arg_srcs[arg_idx]
                    # Observational (B1): the params flowing into this
                    # argument reach exactly the sinks the callee's param
                    # ``pidx`` reaches -- inherit ITS caps, not the union.
                    self._attribute_sink_caps(
                        arg_srcs[arg_idx], callee_caps.get(pidx, ()),
                    )
                    # Read-side (Stage 2): compose the callee's sunk paths
                    # for ``pidx`` with my access path to the argument.
                    self._propagate_sink_paths(
                        e.args[arg_idx], arg_srcs[arg_idx],
                        callee_sink_paths.get(pidx),
                    )
            # Transitive mutation effect: ``g`` writes into its param
            # ``j`` (a field store or a container mutation) from sources
            # ``S``; if the argument bound to ``j`` here is rooted at one
            # of MY params, that object is written, so I inherit the
            # effect (with ``S`` translated from g's params to my taint).
            # This is what gives the container case its DEPTH: a callee
            # that calls a callee that pushes reaches me too.
            self._propagate_callee_effects(
                self.field_effects.get(key, {}), perm, e.args, arg_srcs, env,
            )
            # The call RESULT follows the callee's RETURN-EFFECT, mapped
            # back to this call's taint -- the same rule the method path
            # uses (``_return_taint_of_method_call``), and the key fix for
            # the free-function return-laundering false negative. A free
            # function name resolves to EXACTLY ONE callable, so its
            # ``return_effects`` is precise (no by-name over-approximation):
            # ``INTERNAL_SECRET`` -> the sentinel (the result is secret
            # unconditionally, e.g. the callee reads a declared-@secret
            # field of a struct param and returns it, which the plain
            # argument join dropped); a real param ``s`` -> the taint of
            # the argument bound to ``s``. This both CLOSES the laundering
            # (INTERNAL_SECRET now propagates) and is more precise than the
            # old unconditional argument join (a param whose value does not
            # flow into the return no longer taints the result), mirroring
            # the method-path narrowing. The invoked Fun-typed-parameter
            # taint still joins in (it is not a summarised callee).
            out = set(invoke_src)
            for s in self.return_effects.get(key, set()):
                if s == INTERNAL_SECRET:
                    out.add(INTERNAL_SECRET)
                    continue
                arg_idx = perm.get(s)
                if arg_idx is not None and arg_idx < len(arg_srcs):
                    out |= arg_srcs[arg_idx]
            return out
        # Non-summarised callee (a Fun-typed parameter invocation, or a
        # name that is not a known free function): conservatively join the
        # argument taints into the result plus the invoked value's taint.
        out = set(invoke_src)
        for s in arg_srcs:
            out |= s
        return out

    def _taint_of_method_call(
        self, e: A.MethodCall, env: dict, reaching: set,
    ) -> set:
        recv_src = self._taint_of(e.receiver, env, reaching)
        arg_srcs = [self._taint_of(a, env, reaching) for a in e.args]

        # Internal secret source (``env.get(...)``): a method named in
        # ``_SECRET_SOURCE_METHODS`` called on a parameter typed as a
        # secret-source capability yields a value carrying the
        # INTERNAL_SECRET sentinel, so a field stored from it records an
        # unconditional field-write effect. Matched precisely (the
        # receiver is a known Env-typed parameter) so List/Map ``get``
        # are not misread as a source.
        if (
            e.method in _SECRET_SOURCE_METHODS
            and isinstance(e.receiver, A.Ident)
            and e.receiver.name in self._cur_secret_source_params
        ):
            return {INTERNAL_SECRET}

        # Built-in public sink (Stdio.println, Net.post, ...): a
        # param-derived value in a sink argument position reaches a
        # sink. The receiver-type name is the capability name; we only
        # know it syntactically when the receiver is a plain Ident
        # whose name matches a capability, but built-in sinks are
        # keyed by capability TYPE name, not value name. The
        # intra-procedural pass (which has resolved types) already
        # catches the in-body case; here we over-approximate by
        # matching the METHOD name against any sink signature, so a
        # secret routed to a parameter that the callee sinks via a
        # built-in cap is still caught at the boundary.
        for (_cap, meth), positions in _PUBLIC_SINKS.items():
            if meth != e.method:
                continue
            for pos in positions:
                if pos < len(arg_srcs) and arg_srcs[pos]:
                    reaching |= arg_srcs[pos]
                    # Observational (feature #6, B1): the params flowing into
                    # this argument reach this built-in sink, so record its
                    # capability against EACH of them. A sink method name is
                    # unique to one capability in ``_PUBLIC_SINKS``, so
                    # ``_cap`` is determinate. That uniqueness is not a
                    # happy accident to be relied on quietly: it is now
                    # pinned by
                    # ``test_sink_method_names_are_unique_per_capability``
                    # in tests/test_serve_capability.py, which fired when
                    # Serve was first given a ``write``.
                    self._attribute_sink_caps(arg_srcs[pos], (_cap,))
                    # Read-side (Stage 2): the sunk access path of the
                    # argument in the built-in sink position.
                    self._record_sink_paths(e.args[pos], arg_srcs[pos])

        # A mutating container method (every entry of the
        # ``_CONTAINER_MUTATORS`` registry -- push / add / set -- so a
        # mutator added there is covered here without a further change)
        # routes the argument taint into the receiver, so a later read
        # of the receiver does not launder it. Reflect that in ``env``
        # when the receiver is a plain name, AND record it as a
        # CONTAINER-MUTATION EFFECT when the receiver is rooted at one
        # of this callable's parameters: the container is a reference,
        # so the CALLER's binding holds the injected secret after the
        # call returns. This is the container analogue of the
        # field-write effect and shares its map, its fixpoint and its
        # call-site propagation, which is what makes it transitive (a
        # callee that calls a callee that pushes) and what carries it
        # through a parameter that was merely passed along.
        #
        # The ``_CONTAINER_MUTATORS`` match is BY METHOD NAME, so the
        # by-name shortcut fires ONLY when the receiver is a built-in
        # container, never a user type that defines its OWN
        # push/add/set: a by-name collision must not taint a user-typed
        # receiver whole-value across the boundary (that was a precision
        # regression -- a spurious warning, a hard error under
        # ``@strict_ifc``, widening through the fixpoint). Skipping the
        # shortcut loses no leak: a user type's real mutation is a field
        # store in that method's body, carried by its OWN summary and
        # propagated below by ``_propagate_callee_effects``. The rest of
        # this method (the user-method sink-reaching path, the transitive
        # field-write propagation, the return taint) still runs. The gate
        # mirrors the type-aware intra-procedural check
        # (``_check_ifc_container_mutation``).
        receiver_is_user_owner = self._receiver_is_user_method_owner(e)
        for (_ty, meth), positions in _CONTAINER_MUTATORS.items():
            if meth != e.method or receiver_is_user_owner:
                continue
            injected = set()
            for pos in positions:
                if pos < len(arg_srcs):
                    injected |= arg_srcs[pos]
            if not injected:
                continue
            if isinstance(e.receiver, A.Ident):
                # Reflect the pushed value on a later READ of the receiver
                # via the branch-scoped CONTENT channel, NOT ``env``. ``env``
                # is flat/monotone across branches and doubles as the alias /
                # mutation-TARGET set, so raising it here made a direct push
                # in one branch leak into a mutually-exclusive sibling
                # branch's read (a false positive), and it polluted the alias
                # set with the pushed VALUE's taint (a spurious self-effect:
                # the pushed value's param index became a mutation target of
                # the receiver). The content channel is isolated per branch
                # and deferred-unioned out (``_content_isolated`` /
                # ``_content_merge``), so a sibling read stays clean while a
                # read AFTER the construct still reflects the push -- the
                # exact separation the cross-function content channel already
                # uses. ``env``'s alias role is left untouched.
                self._cur_content.setdefault(
                    e.receiver.name, set(),
                ).update(injected)
            # The receiver may be a plain parameter (``xs.push(v)`` -> path
            # ``()``) or a field chain rooted at one (``self.items.push(v)``
            # -> path ``("items",)``); the effect is FIELD-KEYED
            # (``field_keyable=True``) against the ROOT parameter at that
            # path, routed by the caller onto the SAME branch-scoped
            # ``(root, field-path)`` container-mutation channel the
            # intra-procedural push uses -- so a public sibling field stays
            # clean, and a bare whole read stays the disclosed residual. It
            # reads ``env`` (the un-polluted alias set), so the target set
            # is derived exactly as before.
            self._record_mutation_effect(
                e.receiver, injected, env, field_keyable=True,
            )

        # User method call: receiver-type may be unknown at summary
        # time, so over-approximate across every user method of this
        # name. ``self`` is parameter index 0, the explicit args
        # follow (positional / named).
        candidate_keys = self.methods_by_name.get(e.method, [])
        for key in candidate_keys:
            names, _decl, _is_method = self.callables[key]
            sink_params = self.summaries.get(key, set())
            if not sink_params:
                continue
            callee_caps = self.sink_caps.get(key, {})
            callee_sink_paths = self.sink_paths.get(key, {})
            # Index 0 is ``self`` -> the receiver.
            if 0 in sink_params and recv_src:
                reaching |= recv_src
                # Observational (B1): the params flowing into the receiver
                # reach exactly the sinks the callee's ``self`` (param 0)
                # reaches -- inherit param 0's caps, not the union.
                self._attribute_sink_caps(recv_src, callee_caps.get(0, ()))
                # Read-side (Stage 2): compose the callee's ``self`` sunk
                # paths with my access path to the receiver.
                self._propagate_sink_paths(
                    e.receiver, recv_src, callee_sink_paths.get(0),
                )
            # Explicit parameters are names[1:]; bind the call's
            # positional / named args to them.
            explicit = names[1:] if names and names[0] == "self" else names
            perm = self._bind_explicit_args(e, explicit)
            for local_pidx, arg_idx in perm.items():
                # local_pidx indexes ``explicit``; the summary uses the
                # full param order, so shift by 1 when ``self`` leads.
                full_pidx = (
                    local_pidx + 1
                    if names and names[0] == "self" else local_pidx
                )
                if (
                    full_pidx in sink_params
                    and arg_idx < len(arg_srcs)
                    and arg_srcs[arg_idx]
                ):
                    reaching |= arg_srcs[arg_idx]
                    # Observational (B1): inherit only the caps the callee's
                    # param ``full_pidx`` reaches, attributed to the params
                    # flowing into this argument.
                    self._attribute_sink_caps(
                        arg_srcs[arg_idx], callee_caps.get(full_pidx, ()),
                    )
                    # Read-side (Stage 2): compose the callee's sunk paths
                    # for ``full_pidx`` with my access path to the argument.
                    self._propagate_sink_paths(
                        e.args[arg_idx], arg_srcs[arg_idx],
                        callee_sink_paths.get(full_pidx),
                    )

        # Transitive mutation effect across the (possibly
        # over-approximated) candidate methods. The full-order argument
        # map binds ``self`` (param 0) to the receiver and the explicit
        # params to their call arguments.
        for key in candidate_keys:
            names, _decl, _is_method = self.callables[key]
            effects = self.field_effects.get(key, {})
            if not effects:
                continue
            full_perm, full_args = self._method_full_perm(e, names)
            full_srcs = [recv_src] + arg_srcs
            self._propagate_callee_effects(
                effects, full_perm, full_args, full_srcs, env,
            )

        # Result label follows the RETURN-EFFECT of the candidate
        # methods, not the whole-value taint of the receiver: the result
        # carries source ``s`` iff ``s`` is in some candidate's
        # ``return_effects``, mapped back to this call's taint. So a
        # method whose return derives only from its arguments / a response
        # does NOT inherit the receiver's secret fields (kills the
        # false positive), while a method that returns a secret-derived
        # value (a real param echoed back, ``self``, or an internal
        # secret) still taints the result (laundering stays closed).
        #
        # UNION BY-NAME over every candidate impl (the same
        # over-approximation ``_method_call_returns_secret`` uses): a
        # receiver whose concrete type is unknown / dynamically dispatched
        # contributes the union of every matching method's effect, so the
        # result is never under-tainted.
        return self._return_taint_of_method_call(
            e, candidate_keys, recv_src, arg_srcs,
        )

    def _return_taint_of_method_call(
        self, e: A.MethodCall, candidate_keys: list,
        recv_src: set, arg_srcs: list,
    ) -> set:
        """The taint the RESULT of ``recv.m(args)`` carries, derived from
        the candidate methods' return-effects (full param order: index 0
        is ``self``, explicit params follow). For each source ``s`` in a
        candidate's return-effect: ``INTERNAL_SECRET`` -> the sentinel
        (result tainted unconditionally); ``0`` -> the receiver taint;
        a real param ``s`` -> the taint of the argument bound to ``s``.
        Union over every candidate (by-name over-approximation).

        The narrowing is applied ONLY when the receiver's declared type
        is provably a USER method owner: a parameter whose type has an
        EXACT impl-method key for this call, or a parameter typed as a
        TRAIT (dynamic dispatch, where the by-name union is sound). When
        the receiver is a built-in container / primitive (``list.get`` /
        ``str.to_upper``), a non-parameter local, or its type cannot be
        resolved here, fall back to the conservative whole-value join of
        the receiver + argument taints -- the original, sound rule -- so a
        same-named user method cannot under-taint a built-in receiver's
        result and a read off a secret-derived receiver stays tainted."""
        full_srcs = [recv_src] + arg_srcs
        conservative: set = set(recv_src)
        for s in arg_srcs:
            conservative |= s
        keys = self._result_candidate_keys(e, candidate_keys)
        if not keys:
            return conservative
        out: set = set()
        for key in keys:
            sources = self.return_effects.get(key)
            if not sources:
                continue
            names, _decl, _is_method = self.callables[key]
            full_perm, _full_args = self._method_full_perm(e, names)
            for s in sources:
                if s == INTERNAL_SECRET:
                    out.add(INTERNAL_SECRET)
                    continue
                full_arg_idx = full_perm.get(s)
                if full_arg_idx is not None and full_arg_idx < len(full_srcs):
                    out |= full_srcs[full_arg_idx]
        return out

    def _result_candidate_keys(self, e: A.MethodCall, by_name: list) -> tuple:
        """The method keys whose return-effect may NARROW the result label
        of ``e``, or ``()`` to fall back to the conservative whole-value
        join. Narrowing requires the receiver's declared type to be a
        provable user method owner in the current body:

        * a parameter whose declared type has an EXACT impl-method key for
          this call (``("method", tyname, e.method)``) -> that key; or
        * a parameter typed as a TRAIT (dynamic dispatch) -> the by-name
          union over every impl method of this name.

        Any other receiver (a built-in container modelled as a struct such
        as ``List``, a non-parameter local, an unresolved chain) yields
        ``()`` so the conservative join governs -- so a same-named user
        method cannot under-taint a built-in receiver's result."""
        if not isinstance(e.receiver, A.Ident):
            return ()
        tyname = self._cur_param_type_names.get(e.receiver.name)
        if tyname is None:
            return ()
        exact_key = ("method", tyname, e.method)
        if exact_key in self.return_effects:
            return (exact_key,)
        if self._is_trait_type(tyname):
            return tuple(by_name)
        return ()

    def _receiver_is_user_method_owner(self, e: A.MethodCall) -> bool:
        """True when the method-call receiver PROVABLY resolves to a
        USER-defined type that declares its own method ``e.method`` -- a
        parameter whose declared type has an exact impl-method key, or a
        parameter typed as a trait (dynamic dispatch). Reuses the exact
        receiver-vs-built-in distinction the return-effect narrowing uses
        (``_result_candidate_keys``).

        Used to gate the cross-function CONTAINER-MUTATION effect: the
        ``_CONTAINER_MUTATORS`` match is BY METHOD NAME, so without this
        a user type that merely shares a mutator's name
        (``push`` / ``add`` / ``set``) would have its receiver tainted
        whole-value across a call boundary -- a false positive that
        escapes to every caller and widens through the fixpoint, and a
        hard error under ``@strict_ifc``. The intra-procedural check
        (``_check_ifc_container_mutation``) is already type-aware, keying
        ``_CONTAINER_MUTATORS.get((cap_name, method))``; this keeps the
        summary path from being laxer. Only a BUILT-IN container (whose
        method has no user body to summarise) records the effect; a user
        type's genuine mutation is carried by that method's OWN summary,
        propagated at the call site by ``_propagate_callee_effects``, so
        gating the by-name shortcut out never loses a real leak."""
        candidate_keys = self.methods_by_name.get(e.method, [])
        return bool(self._result_candidate_keys(e, candidate_keys))

    def _is_trait_type(self, type_name: str) -> bool:
        """True if ``type_name`` resolves to a TRAIT (dynamic dispatch),
        the only concrete case where the by-name union over impl methods
        is justified for the result label; a built-in container modelled
        as a struct (``List``) is NOT a trait, so it falls back to the
        conservative join."""
        from . import SymbolKind
        sym = self.global_scope.lookup(type_name)
        return sym is not None and sym.kind == SymbolKind.TRAIT

    def _method_full_perm(self, e: A.MethodCall, names: list[str]):
        """Full-order ``{param_idx: full_arg_idx}`` map and the matching
        argument list for a method call, where index 0 is ``self`` (the
        receiver) and the explicit params follow. ``full_arg_idx`` 0 is
        the receiver; explicit args are shifted by 1 so they line up
        with the ``[recv] + args`` source list."""
        has_self = bool(names) and names[0] == "self"
        explicit = names[1:] if has_self else names
        explicit_perm = _bind(e.args, e.arg_names, explicit)
        full_perm: dict = {}
        if has_self:
            full_perm[0] = 0
        for local_pidx, arg_idx in explicit_perm.items():
            full_pidx = local_pidx + 1 if has_self else local_pidx
            full_perm[full_pidx] = arg_idx + 1
        full_args = [e.receiver] + list(e.args)
        return full_perm, full_args

    def _propagate_callee_effects(
        self, effects: dict, perm: dict, args: list,
        arg_srcs: list, env: dict,
    ) -> None:
        """Inherit a callee's mutation effects at a call site. For
        each callee target ``(j, callee_path)`` with sources ``S``: the
        argument bound to ``j`` is the written object; if it is rooted at
        one of MY bindings, record a mutation effect on every param that
        object aliases, with ``S`` translated from the callee's params
        to my taint (a real source param ``i`` -> the taint of my
        argument bound to ``i``; ``INTERNAL_SECRET`` stays itself). The
        effect stays FIELD-KEYED by COMPOSING my access-path prefix to
        the argument with ``callee_path`` (so ``inner`` writing
        ``bag.items`` reached through my own ``bag`` param keeps the
        ``("items",)`` path), collapsing to the whole-value carrier when
        either half is unkeyable (see ``_compose_paths`` /
        ``_mutation_effect_key``)."""
        for (target_pidx, callee_path), sources in effects.items():
            arg_idx = perm.get(target_pidx)
            if arg_idx is None or arg_idx >= len(args):
                continue
            arg = args[arg_idx]
            root = self._chain_root_name(arg)
            if root is None:
                continue
            translated: set = set()
            for s in sources:
                if s == INTERNAL_SECRET:
                    translated.add(INTERNAL_SECRET)
                else:
                    src_arg = perm.get(s)
                    if src_arg is not None and src_arg < len(arg_srcs):
                        translated |= arg_srcs[src_arg]
            if not translated:
                continue
            composed = self._compose_paths(
                self._chain_field_path(arg), callee_path,
            )
            # CONTENT channel (additive, distinct from the alias set): the
            # callee wrote ``translated`` INTO the object bound to
            # ``target_pidx`` -- this caller-local -- so a read-back of the
            # local must reflect it. Applied REGARDLESS of whether the local
            # is itself a writable mutation TARGET of this body: a fresh or
            # immutable-seeded local has an empty writable-target set (its
            # taint derives only from a built-in-immutable param the
            # precision fix drops), yet the callee still mutated its
            # interior. Gating this on the target set would reopen the
            # false negative. Keyed by the chain ROOT name; JOINED (never
            # overwritten) so it both accumulates straight-line and composes
            # with the deferred per-branch merge (``_content_merge``).
            self._cur_content.setdefault(root, set()).update(translated)
            # MUTATION-TARGET channel: the argument's root binding taint
            # set doubles as its alias / mutation-TARGET set; drop
            # provably-immutable parameters so inheriting a callee's write
            # effect through an immutable-typed argument (a built-in
            # capability, an ``Int``, ...) does not mis-record a mutation of
            # that parameter. The effect stays field-keyed on the composed
            # access path when the argument is rooted directly at param
            # ``j``, else the whole-value carrier (``_mutation_effect_key``).
            for j in self._writable_targets(env.get(root, set())):
                if j == INTERNAL_SECRET:
                    continue
                key = self._mutation_effect_key(j, root, composed)
                self._cur_effects.setdefault(key, set()).update(translated)

    # ---- argument binding ------------------------------------------

    def _bind_args(self, e: A.Call, param_names: list[str]) -> dict:
        """Map ``{param_index: arg_index}`` for a free-function call,
        honouring positional and named arguments. Permissive: an
        ill-formed call (the analyzer reports it separately) just maps
        what it can."""
        return _bind(e.args, e.arg_names, param_names)

    def _bind_explicit_args(
        self, e: A.MethodCall, explicit_names: list[str],
    ) -> dict:
        """Map ``{explicit_param_index: arg_index}`` for a method
        call's explicit arguments (receiver handled separately)."""
        return _bind(e.args, e.arg_names, explicit_names)

    # ---- helpers ----------------------------------------------------

    def _is_declassify(self, e: A.Call) -> bool:
        """True when ``e`` is a call to the BUILT-IN ``declassify``.

        Delegates to :func:`capa._declassify.is_declassify_call`, the
        single source of truth the intra-procedural walk and the artifact
        pipeline also consult. This pass runs BEFORE the body walk fills
        ``Analyzer.bindings``, so identity comes from the global scope
        (the module-scope floor): a user-declared ``declassify`` of ANY
        item kind -- not just a ``fun``, which is all the previous
        hand-rolled check looked at -- displaces the built-in."""
        from .._declassify import is_declassify_call
        return is_declassify_call(e, module_scope=self.global_scope)


def _bind(args: list, arg_names: list, param_names: list[str]) -> dict:
    """Return ``{param_index: arg_index}`` resolving positional and
    named arguments against ``param_names``. Mirrors the analyzer's
    ``_resolve_named_args`` shape but is permissive about errors (a
    malformed call is diagnosed by the main walk; here we only need a
    best-effort binding for taint flow)."""
    name_to_param = {p: i for i, p in enumerate(param_names)}
    out: dict = {}
    names = arg_names if arg_names else [None] * len(args)
    for arg_idx, n in enumerate(names):
        if n is None:
            if arg_idx < len(param_names):
                out[arg_idx] = arg_idx
        else:
            pidx = name_to_param.get(n)
            if pidx is not None:
                out[pidx] = arg_idx
    return out
