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

Both kinds of write route onto the SAME field-keyed ``(root, field-path)``
branch-scoped container channel the intra-procedural pass uses, because the
soundness floor is that no cross-function leak regresses while a clean
sibling is not over-tainted:

* a FIELD STORE, ``obj.f = v`` (any store op, including the augmented
  ``obj.f += v``), is FIELD-KEYED at the STORED field's path
  (``bag.secret_field = v`` -> ``("secret_field",)``). A FIELD read of that
  path, a WHOLE / getter / interpolation / pass-whole read (the length-0
  prefix scan over ``(root, *)``), or passing the whole struct to a callee
  that sinks the stored path all observe it, while a public SIBLING field
  (``bag.note``) stays clean. The intra field store (``_ifc_field_store``)
  still raises the struct's COLLAPSED whole-value label for the same-body
  reads, so no same-body coverage is lost.
* a CONTAINER MUTATION, ``xs.push(v)`` and every other entry of the
  ``_CONTAINER_MUTATORS`` registry in :mod:`._ifc_tables` (its single source of
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
* LAMBDA-FLOW sensitivity. The SINK-SIDE face -- a bare @secret passed to a
  LOCALLY-RESOLVABLE lambda (or an IIFE) whose body sinks its parameter,
  ``let g = fun(s) => sink_str(s, stdio); g(secret)`` -- is now CLOSED
  (Stage A): every lambda literal is registered as a synthetic callable
  ``("lambda", id)`` and summarised on this same fixpoint, and the call site
  (``_check_ifc_local_lambda_call`` / ``_check_ifc_iife_call`` in
  :mod:`._ifc`) applies that summary to the actual arguments exactly as the
  named-call check does. "Sinks its parameter" here means the parameter
  reaches a sink DIRECTLY or via a NAMED callee: a sink reached ONLY through a
  nested LOCAL-lambda invocation inside the body (``let inner = fun(t) =>
  sink_str(t, stdio); let g = fun(s) => inner(s); g(secret)``) is opaque to
  the summary walk (which resolves calls to NAMED callees only, the same
  limitation named callables have) and stays unflagged. What STAYS disclosed:
  - ESCAPING lambdas the caller cannot resolve to one certain literal: a
    reassigned ``var`` (poisoned to ``None`` by ``_record_binding_lambda``),
    an alias ``let g2 = g``, a call-result binding ``let g = mk()``, a
    lambda passed to a higher-order function and invoked there, returned then
    invoked, stored in a struct / list then invoked, recursive, or
    conditionally selected. On any ambiguity the call site falls back to NO
    check (a conservative MISS, never a wrong-target guess); closing these
    needs higher-order CFA / points-to Capa lacks.
  - the CAPTURE-SIDE RESULT-SINK face is CLOSED (Stage B) for a
    locally-resolved lambda (let-bound / IIFE): a container captured by a
    closure defined BEFORE a push and read through the closure AFTER, where the
    CALLER SINKS THE CLOSURE'S RESULT -- ``let f = fun() => bag.reveal();
    bag.items.push(secret); stdio.println(f())`` -- is now flagged. The fix is
    in the label path (``_callee_label`` / ``_fresh_capture_label`` in
    :mod:`._ifc`, NOT this summary): at a locally-resolved lambda invocation
    each captured free binding's CURRENT LIVE label is re-read from the
    branch-scoped container-taint map (and, for a REFERENCE-typed capture, the
    live ``sym.label``), never the label cached at the lambda's DEFINITION. What
    STAYS disclosed on the capture side: (a) a sink INTERNAL to the closure body
    (a side effect, not the result -- ``let f = fun() => stdio.println(
    bag.reveal()); bag.items.push(secret); f()``), which a future
    field-store / access-path channel slice would close, not this label re-read;
    (b) a closure that ESCAPES to a higher-order callee (``apply(f)``), whose
    invocation is not locally resolvable; and (c) a captured STRUCT whole-
    reassigned to a secret after definition (a SAFE strict-tier over-rejection:
    REFTYPE keeps ``sym.label`` for a reference type and cannot tell a whole
    reassign from an in-place field store).
* A cross-function FIELD STORE is field-keyed at the stored field's path,
  so a clean sibling of it stays clean, at parity with a container
  mutation; only an ALIASED / renamed / unkeyable field-store root keeps
  the whole-value carrier (the sibling is then conservatively flagged), the
  same points-to residual container mutations already have.
"""

from __future__ import annotations

import dataclasses

from .. import capa_ast as A
from ._ifc_tables import (
    _PUBLIC_SINKS, _CONTAINER_MUTATORS, _SECRET_SOURCES,
    _VARIABLE_TIME_OPS, _SHORT_CIRCUIT_COMPARE_OPS,
    _CT_INDEX_METHODS, _CT_SHORT_CIRCUIT_METHODS,
    _pattern_bound_names, _prefix_compatible,
    INTERNAL_SECRET, _bind, methods_by_name, result_effect_keys,
    build_impl_reverse_index, trait_destructure_field_label,
)


class _LambdaCallable:
    """A lambda literal presented to the per-body summary walk as a
    callable. ``body`` is a value BLOCK: an expression-bodied lambda's
    single expression is wrapped in a one-statement block, so the shared
    ``_walk_value_block`` walker treats it exactly like a named function's
    trailing implicit-return expression, and an in-body sink is walked the
    same way. Only ``body`` is consulted by ``_analyze_body`` (the parameter
    facts are pre-computed from the lambda's own ``params`` at registration),
    so a minimal carrier is all that is needed."""

    __slots__ = ("body",)

    def __init__(self, body: A.Block) -> None:
        self.body = body


class _TraitMethodCallable:
    """A trait-block method SIGNATURE presented to the summary tables as a
    callable, so the compositional scrutinee resolver can read its declared
    return type for a TRAIT-typed receiver (``s.clone()`` where ``s: Shape``,
    keyed ``("method", TraitName, method)``). A trait signature has NO body,
    so ``body`` is an empty block: the fixpoint summarises it to the empty
    summary. That is correct -- a trait method is abstract; the real
    per-implementor sink / return behaviour is carried by each concrete impl
    method's OWN summary, keyed by the concrete type, and a dynamic-dispatch
    call over-approximates across those concrete keys (``methods_by_name``,
    which a trait signature is deliberately NOT indexed in). Only ``body`` (by
    ``_analyze_body``) and ``return_type`` (by ``_method_return_type_expr``)
    are consulted."""

    __slots__ = ("body", "return_type")

    def __init__(self, return_type, body: A.Block) -> None:
        self.body = body
        self.return_type = return_type


# Absent-marker for the body-scoped for-loop binder seed: distinguishes a
# name that was ABSENT from ``_cur_value_types`` / ``_cur_elem_types`` before
# the loop from one that was present, so the save/restore reinstates the
# prior state exactly (reinsert if present, delete if absent). A plain
# ``None`` cannot serve because the maps never store ``None`` (an absent key
# and a ``None`` value would be indistinguishable), and the restore must be
# exact for the body-scoping to hold.
_ABSENT = object()

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

# The built-in sink CAPABILITY type names (Stdio / Net / Fs / Db / Serve),
# derived from ``_PUBLIC_SINKS``. Used by the strict implicit-flow
# (sink-reaching-pc) recognition to decide, TYPE-AWARELY, whether a
# method-call receiver is a real built-in sink capability -- so
# ``xs.get(i)`` on a ``List`` receiver is never mistaken for ``Net.get``,
# the by-name collision the pc bit must not over-report on.
_SINK_CAPS: frozenset = frozenset(cap for cap, _m in _PUBLIC_SINKS)


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
) -> tuple[dict, dict, dict, dict, dict, dict, dict, dict]:
    """Return ``(sink_summaries, field_effects, return_effects,
    sink_caps, sink_paths, capture_sink_paths, sink_reaching_pc,
    ct_sensitive)``:

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
    * ``return_effects``: ``{callable_key: {field_path -> frozenset(
      source_param_idx | INTERNAL_SECRET)}}`` -- PER RETURNED-VALUE field
      path, the sources that flow into that path of the returned value; the
      call result is @secret when one fires (a real param whose argument is
      @secret, or the unconditional internal secret, which includes a
      declared-@secret field read). In this cut every source is recorded at
      the whole-value sentinel ``()`` and the readers union over every path
      (whole-value granularity); the per-path keying is the schema Part 3
      migrates to, bounded by ``_MAX_FIELD_PATH`` so the fixpoint stays
      finite.
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
    * ``capture_sink_paths``: ``{("lambda", id): {capture_name:
      frozenset(field_path)}}`` -- PER LAMBDA, the access paths of each
      CAPTURED free binding that reach a public sink INSIDE the body (``()``
      = the whole capture). The capture-side mirror of ``sink_paths``: the
      call site (``_apply_lambda_capture_sink_summary`` in :mod:`._ifc`)
      checks the LIVE label of each summarised capture path at a
      locally-resolved lambda invocation, catching a captured value whose
      label ROSE AFTER the closure was defined and is sunk inside the body.
      Computed ONCE after the fixpoint (it only reads the final named
      summaries), by seeding each lambda's captures as sources in the SAME
      declassify-aware body walk.
    * ``sink_reaching_pc``: ``{callable_key: bool}`` -- the STRICT
      implicit-flow (IFC-1) bit: True iff the body can EXECUTE a real
      built-in public sink (a ``_PUBLIC_SINKS`` method whose receiver
      resolves type-awarely to a built-in sink capability, or builtin
      ``panic``) on SOME path under its own control flow, directly or
      transitively through a resolved call. NOT parameter-indexed and NOT
      data-taint gated: it records only "invoking this function is
      observable at a public sink", which the call site
      (``_check_ifc_call_pc``) hard-errors on when the invocation sits
      under a secret pc.
    * ``ct_sensitive``: ``{callable_key: frozenset(param_idx)}`` -- the
      CONSTANT-TIME (IFC-2) data channel: the 0-based indices of value
      parameters whose value flows (directly or transitively, on the SAME
      monotone fixpoint) into a VARIABLE-TIME operation inside the body --
      division / modulo, a data-dependent branch condition / scrutinee, a
      variable-time String / List compare, or a data-dependent index /
      lookup. Annotation-BLIND (computed for every callable, not just
      ``@constant_time`` ones): a compiling ``@constant_time`` callee has a
      ct-sensitive parameter only if that parameter is un-annotated (public
      inside), which is exactly the leaking case a caller must be stopped
      from routing a secret into. Parameter-indexed like ``sink_summaries``
      (index 0 = ``self`` for a method), the timing-side-channel twin of it.
      The call site (``_check_ct_call`` / ``_check_ct_method_call``)
      hard-errors, inside a ``@constant_time`` function, on a @secret
      argument bound to a ct-sensitive parameter -- closing the cross-call
      blind spot the inline CT checks (``_check_ct_arith`` etc.) miss.

    ``global_scope`` is the analyzer's populated global scope, used to
    tell user functions / variants / capabilities apart at call sites.
    All results are the least fixpoint of the monotone summary operator,
    so recursion (self or mutual) terminates.
    """
    builder = _SummaryBuilder(module, global_scope)
    return builder.run()


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
        # callable_key -> bool: the STRICT IMPLICIT-FLOW (sink-reaching-pc)
        # bit (IFC-1). True iff the body, on SOME path under its own control
        # flow, can EXECUTE a real built-in public sink -- a ``_PUBLIC_SINKS``
        # method whose RECEIVER resolves (type-awarely, via ``_cur_value_types``)
        # to a built-in sink capability, or builtin ``panic`` -- directly or
        # transitively through a call to another user callable. NOT
        # parameter-indexed, NOT data-taint gated, NOT declassify-sensitive:
        # it records only "invoking this function is observable at a public
        # sink". The call site (``_check_ifc_call_pc`` in :mod:`._ifc`) hard-
        # errors under ``@strict_ifc`` when such a callee is invoked under a
        # secret pc, closing the cross-call implicit-flow noninterference hole.
        # Computed to the SAME monotone fixpoint (a single bool per callable,
        # a finite lattice), so self / mutual recursion converge.
        self.sink_reaching_pc: dict = {}
        # callable_key -> set of CT-SENSITIVE param indices (IFC-2): a value
        # parameter whose value flows, directly or transitively, into a
        # VARIABLE-TIME operation inside the body (division / modulo, a
        # data-dependent branch condition / scrutinee, a variable-time String
        # / List compare, or a data-dependent index / lookup). Parameter-
        # indexed, ANNOTATION-BLIND (computed for every callable), the
        # timing-side-channel twin of ``summaries``: it never affects the
        # sink-reaching data decision, and the call site
        # (``_check_ct_call`` / ``_check_ct_method_call``) hard-errors, inside
        # a ``@constant_time`` function, on a @secret argument bound to one of
        # these parameters -- closing the cross-call blind spot the inline CT
        # checks miss. Computed to the SAME monotone finite-subset fixpoint as
        # ``summaries`` (grows until stable), so self / mutual recursion
        # converge.
        self.ct_sensitive: dict = {}
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
        # callable_key -> {param name: element struct type NAME} for every
        # parameter whose declared type is a generic container (``List<Outer>``
        # -> ``"Outer"``, the first generic argument's name). The minimal
        # element-type source the for-loop binder seed resolves against: an
        # ``Ident`` iterable (``for u in secs``) resolves ``u``'s element
        # struct type from this map (``_iter_element_struct_type``). Parallel
        # to ``param_type_names`` and populated at the same collection sites.
        self.param_elem_type_names: dict = {}
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
        # ``trait / capability name -> {implementor type names}``, built once
        # (memoised) via the SAME ``build_impl_reverse_index`` the intra pass
        # uses, so the trait-destructure join (``_raise_trait_destructure_taint``)
        # never hand-rolls a second trait walk.
        self._ifc_impl_index: dict = None
        # ``struct type -> {field name -> declared type NAME}`` for every
        # struct / typestate field with a NAMED type, built from the SAME
        # ``fld.type_expr.name`` the label walk reads. Lets a deep field-read
        # chain (``t.f2.f3.v``) be walked type-precisely hop by hop to the
        # leaf's owning struct, so a declared-@secret nested field read is
        # recognised as an internal secret source (``_field_read_is_secret``).
        self.struct_field_type_names: dict[str, dict[str, str]] = {}
        # ``struct type -> {field name -> element struct type NAME}`` for every
        # struct / typestate field whose declared type is a generic container
        # (``items: List<Outer>`` -> ``"Outer"``, the first generic argument's
        # name), built alongside ``struct_field_type_names``. Lets a for-loop
        # over a CONTAINER FIELD (``for u in bag.items``) resolve the binder's
        # element struct type: ``_iter_element_struct_type`` resolves the
        # receiver's struct type via ``_cur_value_types``, then reads this map.
        self.struct_field_elem_type_names: dict[str, dict[str, str]] = {}
        # Names of module-level consts DECLARED ``@secret`` (roadmap S2).
        # A reference to one is an internal secret source in the summary
        # walk, the cross-function analogue of the intra-procedural
        # ``sym.label`` on the const's global symbol. Pre-computed once so
        # each identifier costs a set membership test, not a lookup.
        self.secret_consts: set[str] = set()
        # ("lambda", id) -> the original ``A.LambdaExpr`` node, kept so the
        # post-fixpoint capture pass can recover the lambda's parameters and
        # unwrapped body to compute its FREE identifiers (its captures).
        self._lambda_nodes: dict = {}
        # ("lambda", id) -> {capture NAME -> frozenset of capture-relative
        # field PATHS that reach a public sink INSIDE the body} (``()`` = the
        # whole capture reaches a sink). The capture-side mirror of the
        # parameter ``sink_paths``: computed AFTER the parameter fixpoint by
        # seeding each lambda's captures as sources and running the SAME
        # declassify-aware body walk. Consulted at a locally-resolved lambda
        # invocation to catch a captured value whose label ROSE AFTER the
        # closure was defined and is SUNK inside the body.
        self.capture_sink_paths: dict = {}
        self._collect_secret_fields()
        self._collect_secret_consts()
        self._collect_callables()
        self._collect_lambda_callables()

    def _collect_secret_fields(self) -> None:
        """Populate ``struct_field_labels`` from every struct (and
        typestate) declaration's field labels, so the body walk can
        recognise a declared-@secret field read off a parameter of that
        struct type (``_field_read_is_secret``).

        Also populates ``struct_field_type_names`` from the SAME
        ``fld.type_expr.name``, so a deep field-read chain can be walked
        hop by hop to the leaf field's owning struct type."""
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
                tyname = getattr(te, "name", None) if te is not None else None
                if tyname is not None:
                    self.struct_field_type_names.setdefault(
                        name, {},
                    )[fld.name] = tyname
                # A generic container field (``items: List<Outer>``) records
                # its ELEMENT struct type (the first generic argument's name),
                # so a for-loop over the field resolves the binder's type.
                targs = getattr(te, "args", None) if te is not None else None
                if targs:
                    elem = getattr(targs[0], "name", None)
                    if elem is not None:
                        self.struct_field_elem_type_names.setdefault(
                            name, {},
                        )[fld.name] = elem

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

    def _register_callable(
        self, key, decl, params, *, is_method, owner=None, by_name=False,
    ) -> None:
        """Register ONE callable -- a free function, an impl method, a
        trait-method signature, or a lambda -- in the shared summary tables
        under ``key``. The SINGLE per-callable initialisation site: every
        branch of ``_collect_callables`` / ``_collect_lambda_callables`` routes
        through here, so the seven effect tables and the four parameter-fact
        tables can never be seeded for one kind of callable but not another.

        ``by_name`` additionally indexes an impl method in ``methods_by_name``
        (the by-name over-approximation set a receiver-unknown method call
        joins over); a trait signature is deliberately NOT indexed there, so
        its abstract empty summary never dilutes a dynamic-dispatch call's
        candidate set, which stays the concrete impl keys."""
        self.callables[key] = ([p.name for p in params], decl, is_method)
        self.summaries[key] = set()
        self.sink_caps[key] = {}
        self.sink_paths[key] = {}
        self.sink_reaching_pc[key] = False
        self.ct_sensitive[key] = set()
        self.field_effects[key] = {}
        self.return_effects[key] = {}
        self.secret_source_params[key] = self._secret_source_params(params)
        self.param_struct_types[key] = self._param_struct_types(
            params, owner=owner,
        )
        self.param_type_names[key] = self._param_type_names(
            params, owner=owner,
        )
        self.param_elem_type_names[key] = self._param_elem_type_names(params)
        self.immutable_params[key] = self._immutable_param_idxs(params)
        if by_name:
            self.methods_by_name.setdefault(key[2], []).append(key)

    def _collect_callables(self) -> None:
        for item in self.module.items:
            if isinstance(item, A.FunDecl):
                self._register_callable(
                    ("fun", item.name), item, item.params, is_method=False,
                )
            elif isinstance(item, A.ImplBlock):
                for method in item.methods:
                    key = ("method", item.type_name, method.name)
                    # Methods are keyed by (type, name); a name unique
                    # across states is guaranteed by the analyzer.
                    if key in self.callables:
                        continue
                    self._register_callable(
                        key, method, method.params, is_method=True,
                        owner=item.type_name, by_name=True,
                    )
            elif isinstance(item, A.TraitDecl):
                # A trait-block method signature is registered under the SAME
                # ``("method", type, name)`` scheme, keyed by the TRAIT name, so
                # ``_method_return_type_expr`` can read its declared return type
                # for a trait-typed receiver (RC2: closes the whole
                # trait-typed-receiver-method scrutinee family, e.g. ``let
                # OtherCircle { r } = s.clone()`` where ``s: Shape``). The
                # signature has no body, so it carries an empty one and
                # summarises to the empty summary; it is NOT added to
                # ``methods_by_name``, so dynamic dispatch still joins over the
                # concrete impls.
                for sig in item.methods:
                    key = ("method", item.name, sig.name)
                    if key in self.callables:
                        continue
                    self._register_callable(
                        key,
                        _TraitMethodCallable(
                            sig.return_type, A.Block(pos=item.pos, stmts=[]),
                        ),
                        sig.params, is_method=True, owner=item.name,
                    )

    def _collect_lambda_callables(self) -> None:
        """Register every lambda literal anywhere in the module as a
        SYNTHETIC callable keyed by ``("lambda", id(lambda_expr))``, so the
        SAME sink-reaching / sink-path fixpoint that summarises a named
        function also summarises a lambda body. The sink-side lambda-flow
        check (``_check_ifc_local_lambda_call`` / ``_check_ifc_iife_call`` in
        :mod:`._ifc`) then consults this summary at a locally-resolvable or
        IIFE lambda invocation, exactly as the named-call path consults a
        function's summary -- closing the leak where a bare @secret passed to
        a local lambda that sinks its parameter escaped the analysis while the
        direct named call was caught.

        Keyed by the AST node's ``id``, which is stable for the single parsed
        module both this builder and the analyzer's main walk share, so the
        call site recovers the exact per-lambda summary. Registered AFTER the
        named callables so the ``("lambda", id)`` keys never collide with a
        ``("fun", name)`` / ``("method", ...)`` key, and they are inert to
        every existing consumer (the named-call checks look summaries up by
        their own keys; ``methods_by_name`` filters to method keys), so no
        named-function summary changes. The parameter facts are computed from
        the lambda's OWN ``params`` exactly as for a named function; the body
        is wrapped in a value block (``_LambdaCallable``) so an
        expression-bodied lambda is walked by the same block walker.

        OPACITY (disclosed residual): the body walk resolves a call only to a
        NAMED (``fun`` / method) callee, never to a LOCAL-lambda binding -- the
        SAME limitation named callables have -- so a sink reached ONLY through
        a nested LOCAL-lambda invocation inside the body (``let inner = fun(t)
        => sink_str(t, stdio); let g = fun(s) => inner(s); g(secret)``) is
        opaque to this summary and stays unflagged (it leaks on both backends,
        as on main). So the sink-reaching a lambda summary captures is a sink
        the parameter reaches DIRECTLY or via a NAMED callee, not one reached
        only through another LOCAL lambda."""
        for lam in self._iter_lambdas(self.module):
            key = ("lambda", id(lam))
            self._lambda_nodes[key] = lam
            body = lam.body if isinstance(lam.body, A.Block) else A.Block(
                pos=lam.pos,
                stmts=[A.ExprStmt(pos=lam.pos, expr=lam.body)],
            )
            self._register_callable(
                key, _LambdaCallable(body), lam.params, is_method=False,
            )

    @staticmethod
    def _iter_lambdas(node):
        """Yield every ``LambdaExpr`` reachable from ``node`` (a nested
        lambda inside another lambda's body is yielded too, so each gets its
        own summary keyed by its own id). A dataclass walk mirroring
        ``_lambda_return_exprs`` in :mod:`._ifc`."""
        if isinstance(node, A.LambdaExpr):
            yield node
        if dataclasses.is_dataclass(node):
            for f in dataclasses.fields(node):
                yield from _SummaryBuilder._iter_lambdas(getattr(node, f.name))
        elif isinstance(node, (list, tuple)):
            for x in node:
                yield from _SummaryBuilder._iter_lambdas(x)

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

    def _param_elem_type_names(self, params) -> dict:
        """``{param name: element struct type name}`` for every parameter
        whose declared type is a generic container (``List<Outer>`` ->
        ``"Outer"``, the first generic argument's name). The minimal
        element-type source the for-loop binder seed resolves against
        (``_iter_element_struct_type`` for an ``Ident`` iterable); a NESTED
        container element (``List<List<Outer>>`` -> ``"List"``) records only
        the outer name, so a for over such a param leaves the binder
        unresolved -- the disclosed nested-generic residual. ``self`` (no
        ``type_expr``) is never a generic container, so it never appears."""
        out: dict = {}
        for p in params:
            te = getattr(p, "type_expr", None)
            args = getattr(te, "args", None) if te is not None else None
            if args:
                elem = getattr(args[0], "name", None)
                if elem is not None:
                    out[p.name] = elem
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
                (
                    reaching, effects, returns, scaps, spaths, reaches_pc,
                    ct_new,
                ) = self._analyze_body(names, decl, key)
                if not reaching <= self.summaries[key]:
                    self.summaries[key] |= reaching
                    changed = True
                # The sink-reaching-pc bit is monotone (once True it stays
                # True); grow it on the SAME fixpoint as the sink summaries.
                if reaches_pc and not self.sink_reaching_pc[key]:
                    self.sink_reaching_pc[key] = True
                    changed = True
                # The CT-sensitive param set (IFC-2) is a monotone finite
                # subset, grown on the SAME fixpoint exactly like the sink
                # summaries.
                if not ct_new <= self.ct_sensitive[key]:
                    self.ct_sensitive[key] |= ct_new
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
                # ``returns`` is a per-path map ``{field-path -> sources}``
                # (everything recorded at ``()`` in this cut), merged on the
                # SAME monotone fixpoint as the field-write effect map.
                if self._merge_effects(self.return_effects[key], returns):
                    changed = True
        sinks = {k: frozenset(v) for k, v in self.summaries.items()}
        feffects = {
            k: {t: frozenset(s) for t, s in v.items()}
            for k, v in self.field_effects.items()
        }
        reffects = {
            k: {p: frozenset(srcs) for p, srcs in v.items()}
            for k, v in self.return_effects.items()
        }
        sink_caps = {
            k: {p: frozenset(c) for p, c in v.items()}
            for k, v in self.sink_caps.items()
        }
        sink_paths = {
            k: {p: frozenset(paths) for p, paths in v.items()}
            for k, v in self.sink_paths.items()
        }
        # Capture-side sink paths (the R1 fix). Computed ONCE here, after the
        # parameter fixpoint has stabilised: the capture pass only READS the
        # (now final) named summaries -- composing a named helper's
        # ``sink_paths`` through ``_propagate_sink_paths`` -- and feeds no
        # other summary, so it needs no fixpoint of its own.
        capture_sink_paths: dict = {}
        for key, lam in self._lambda_nodes.items():
            cp = self._capture_sink_paths_of(key, lam)
            if cp:
                capture_sink_paths[key] = {
                    name: frozenset(paths) for name, paths in cp.items()
                }
        self.capture_sink_paths = capture_sink_paths
        sink_reaching_pc = dict(self.sink_reaching_pc)
        ct_sensitive = {k: frozenset(v) for k, v in self.ct_sensitive.items()}
        return sinks, feffects, reffects, sink_caps, sink_paths, \
            capture_sink_paths, sink_reaching_pc, ct_sensitive

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
    ) -> tuple[set, dict, set, dict, dict, bool, set]:
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
        returns: dict = {}
        # The additive, FIELD-KEYED CONTENT channel: ``name -> {field-path
        # -> set of source-param / INTERNAL_SECRET}`` that a CALLEE wrote
        # INTO the object bound to ``name`` at that access path (a container
        # mutation / field store recorded as the callee's field-keyed
        # mutation effect and inherited here), plus the ``None`` key for the
        # whole-value carrier (an aliased / unkeyable effect). It is joined
        # into the ``_taint_of`` result on a READ, FIELD-PRECISELY: a WHOLE
        # read of the name (a bare Ident) observes every field-path (the
        # length-0 access-path query ``x.f^0 = x``), while a FIELD read
        # (``bag.note``) observes the taints on any PREFIX-COMPATIBLE path
        # (its own, an ancestor whose secret sub-struct it reads into, or a
        # descendant nested under it) plus the whole-value ``None`` carrier,
        # so a read-back of the mutated path (and a store at an interior
        # ancestor of it) is caught while a DISJOINT public sibling of a
        # mutated field stays clean (see ``_content_at`` /
        # ``_content_contribution``, the same prefix-compatible relation the
        # sink summary and the capture side use). The
        # channel does NOT feed the alias / mutation-TARGET derivation, which
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
        # Strict implicit-flow (IFC-1): whether THIS body can execute a real
        # built-in public sink (or ``panic``) under its own control flow,
        # directly or transitively. Set True at the direct-sink recognition
        # (a receiver typed as a built-in sink capability) and at every
        # resolved call to a callee whose own bit is already True. Read back
        # in ``run()`` and merged onto the monotone fixpoint.
        self._cur_reaches_sink_pc = False
        # Constant-time (IFC-2): the source-param / internal-secret set whose
        # value flows into a VARIABLE-TIME operation in THIS body -- a
        # division / modulo, a branch condition / scrutinee, a variable-time
        # String / List compare, or a data-dependent index / lookup.
        # Accumulated by the walk in parallel with ``reaching`` at the five
        # recognition sites, and grown transitively at a resolved call over
        # the callee's own ct-sensitive set. Read back in ``run()`` and merged
        # onto the SAME monotone fixpoint.
        self._cur_ct_sensitive: set = set()
        # Per-callable analysis state consulted inside the walk (which
        # threads only ``env`` / ``reaching`` through its signatures):
        # the names of secret-source-capability params, the accumulating
        # field-write effect map, and the return-secret source set.
        self._cur_secret_source_params = self.secret_source_params.get(
            key, set(),
        )
        self._cur_param_struct_types = self.param_struct_types.get(key, {})
        self._cur_param_type_names = self.param_type_names.get(key, {})
        # ``value name -> static struct TYPE name`` for THIS callable: seeded
        # with the parameter types (unrestricted, so a param whose own fields
        # are unlabelled still resolves) and grown by ``let`` / ``var``
        # bindings whose RHS statically denotes a struct. Consulted by
        # ``_field_read_is_secret`` to resolve a deep field-read chain's ROOT
        # type. FP-safe because Capa REJECTS same-function local shadowing, so
        # a local name is single-valued per callable and this flat map cannot
        # conflate two struct types under one name.
        self._cur_value_types = dict(self._cur_param_type_names)
        # ``value name -> element struct TYPE name`` for THIS callable: seeded
        # with the parameter element types (``secs: List<Outer>`` -> ``secs ->
        # "Outer"``) so a for-loop over an ``Ident`` iterable resolves the
        # binder's element struct type (``_iter_element_struct_type``). Grown
        # by NOTHING outside the parameter seed: a ``let``-bound container does
        # NOT propagate its element type here (the local-bound-list residual),
        # so ``let xs = secs; for u in xs`` stays open, matching the design.
        self._cur_elem_types = dict(
            self.param_elem_type_names.get(key, {}),
        )
        # Names in ``_cur_value_types`` / ``_cur_elem_types`` whose recorded
        # type was re-derived COMPOSITIONALLY from a CALL / METHOD / INDEX
        # result rather than a struct-literal / copy / field-chain shape (RC1:
        # ``let s = get()``). Such an entry is visible ONLY to the trait-
        # destructure scrutinee resolver (``_resolve_static_type`` /
        # ``_resolve_element_type``, raw reads); every DEEP-READ / capability /
        # ct reader consults the gated ``_struct_prov_type`` /
        # ``_struct_prov_elem`` view instead, which HIDES a call-derived entry,
        # so those readers keep their exact pre-RC1 behaviour and the
        # ``RESTORE_BITES`` deep-read residual is preserved (a call-result root
        # stays a whole-value fallback). Written only by ``_seed_call_derived``;
        # the sole structural pop of these maps (the for-loop binder restore)
        # discards its binder names from this set too, so it cannot drift.
        self._cur_call_derived: set[str] = set()
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
        # The trailing bare expression of the body is an implicit return,
        # recorded PER PATH exactly like an explicit ``return`` (a returned
        # LOCAL carries its content channel field-keyed; every other shape
        # falls back to the whole-value carrier). Walked EXACTLY ONCE, so a
        # branching tail expression's per-branch content isolation is not
        # defeated by a second walk over an already-merged baseline.
        body_stmts = decl.body.stmts
        if body_stmts and isinstance(body_stmts[-1], A.ExprStmt):
            for st in body_stmts[:-1]:
                self._walk_stmt(st, env, reaching)
            self._record_return(body_stmts[-1].expr, env, reaching)
        else:
            self._walk_block(decl.body, env, reaching)
        return reaching, effects, returns, sink_caps_local, \
            sink_paths_local, self._cur_reaches_sink_pc, \
            self._cur_ct_sensitive

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
        self._cur_content = self._content_copy(saved)
        walk()
        post = self._cur_content
        self._cur_content = saved
        return post

    def _content_merge(self, posts) -> None:
        """Union each branch's content map (from ``_content_isolated``)
        into the enclosing content, so a read AFTER the construct reflects
        any branch's cross-function mutation (a fresh local mutated in one
        arm and read past the construct is caught). Deferred to after all
        branches, so it never contaminates a sibling branch's read. The
        union is per ``(name, field-path)`` bucket (the channel is
        field-keyed)."""
        for post in posts:
            for name, bucket in post.items():
                dst = self._cur_content.setdefault(name, {})
                for path, srcs in bucket.items():
                    dst.setdefault(path, set()).update(srcs)

    @staticmethod
    def _content_copy(m: dict) -> dict:
        """A deep copy of the field-keyed content map ``{name -> {path ->
        set}}`` down to fresh source sets, so a branch's isolated content
        can grow without mutating the enclosing snapshot."""
        return {
            name: {path: set(srcs) for path, srcs in bucket.items()}
            for name, bucket in m.items()
        }

    def _content_write(self, root: str, path, srcs: set) -> None:
        """Add ``srcs`` to the content channel for ``root`` at access
        ``path`` (a field-path tuple, or ``None`` for the whole-value
        carrier). Joined, never overwritten, so it accumulates straight-line
        and composes with the deferred per-branch merge."""
        self._cur_content.setdefault(root, {}).setdefault(path, set()).update(
            srcs,
        )

    def _content_at(self, root: str, path: tuple) -> set:
        """The content-channel taint OBSERVED by reading ``root`` at
        ``path``: the union of the sources recorded at any PREFIX-COMPATIBLE
        path (``_prefix_compatible`` -- one path is a prefix of the other),
        plus the whole-value ``None`` carrier which EVERY read observes. Two
        directions matter and both are sound: a WHOLE / sub-struct read at a
        SHORTER path observes a store NESTED under it (a read at ``()``
        observes every field -- the length-0 query), and a read at a LONGER
        path observes a store at an ANCESTOR (a callee that stores a whole
        secret sub-struct at ``o.inner`` is observed by a read of
        ``o.inner.x``). A DISJOINT sibling (``("note",)`` vs
        ``("secret_field",)``) is prefix-INcompatible and stays clean, so
        field precision is kept. Mirrors the sink-summary / capture-side
        prefix-compatible relation."""
        bucket = self._cur_content.get(root)
        if not bucket:
            return set()
        out: set = set()
        for kpath, srcs in bucket.items():
            if kpath is None or _prefix_compatible(kpath, path):
                out |= srcs
        return out

    def _content_contribution(self, e: A.Expr) -> set:
        """The content-channel taint a read of the field-access chain ``e``
        observes, scanned at ``e``'s OWN access path (``_content_at``), or
        the empty set when ``e`` is not an Ident-rooted chain (so its path
        cannot be determined). Used by the FIELD-read taint so a clean
        sibling of a cross-function-mutated field is not over-tainted."""
        root = self._chain_root_name(e)
        path = self._chain_field_path(e)
        if root is None or path is None:
            return set()
        return self._content_at(root, tuple(path))

    def _base_taint_of(self, e: A.Expr, env: dict, reaching: set) -> set:
        """The data-flow taint of ``e`` EXCLUDING the content channel. The
        content channel is folded in ONCE at the access path of the READ (by
        ``_taint_of``), so an intermediate field-chain receiver does not
        contribute the whole-root content to a field read of a clean
        sibling. Differs from ``_taint_of`` only for an Ident / FieldAccess
        base (it drops the content join); every other shape (a call, an
        index, ...) has no content entry of its own, so it delegates to
        ``_taint_of`` unchanged (preserving that shape's ``reaching`` side
        effects)."""
        if isinstance(e, A.Ident):
            if (
                e.name in self.secret_consts
                and e.name not in self._shadowed_consts
            ):
                return {INTERNAL_SECRET}
            return set(env.get(e.name, set()))
        if isinstance(e, A.FieldAccess):
            recv_src = self._base_taint_of(e.receiver, env, reaching)
            if self._field_read_is_secret(e):
                return recv_src | {INTERNAL_SECRET}
            return recv_src
        return self._taint_of(e, env, reaching)

    def _content_path_key(self, path):
        """Clamp a field path for the CONTENT channel: an unkeyable ``None``
        or a path beyond ``_MAX_FIELD_PATH`` becomes the whole-value carrier
        ``None`` (the content channel's whole-value key), so the content-map
        key space stays finite and a read of the whole root still observes
        it (mirror ``_mutation_effect_key``)."""
        if path is not None and len(path) <= _MAX_FIELD_PATH:
            return path
        return None

    def _return_path_key(self, path):
        """Clamp a field path for the RETURN-effect map: an unkeyable ``None``
        or a path beyond ``_MAX_FIELD_PATH`` collapses to the whole-value
        sentinel ``()`` (which every caller read observes), so the return-map
        key space stays finite and the summary fixpoint terminates (mirror
        ``_mutation_effect_key``)."""
        if path is not None and len(path) <= _MAX_FIELD_PATH:
            return path
        return ()

    def _seed_content_value(
        self, root, base_path, value, src, env, reaching,
    ) -> None:
        """Content-write a field store into ``root`` at ``base_path`` from
        ``value``. A struct-literal RHS is LEAF-SEEDED at each leaf's FULL
        path (mirror ``_struct_lit_field_map`` in :mod:`._ifc`), so a later
        read of a CLEAN leaf of the stored sub-struct stays clean; any other
        RHS writes its whole taint ``src`` at ``base_path``. An unkeyable
        ``None`` root (a call- / index-rooted store target) has no channel and
        is skipped; an over-``_MAX_FIELD_PATH`` / ``None`` path collapses to
        the whole-value carrier. Additive and field-keyed exactly like the
        container-mutation and propagated-effect content, so a read-back of
        the stored path -- and a whole / return read of the root -- observes
        it while a disjoint public sibling stays clean."""
        if root is None:
            return
        if isinstance(value, A.StructLit):
            for name, v in value.fields:
                leaf = base_path + (name,) if base_path is not None else None
                self._seed_content_value(root, leaf, v, None, env, reaching)
            return
        if src is None:
            src = self._taint_of(value, env, reaching)
        if src:
            self._content_write(root, self._content_path_key(base_path), src)

    def _record_return(self, value: A.Expr, env: dict, reaching: set) -> None:
        """Record ``value`` as a return-effect, per path. A bare-Ident LOCAL
        carries its CONTENT channel per path (a field store / container write
        the body made into it) plus its whole-value BASE at ``()``, so the
        caller observes the returned struct's field-keyed taint. Every other
        return shape -- a field-access sub-return (``return o.sub``), a call,
        a literal, an unwrap, a param -- records the whole-value taint at
        ``()``: recording a SOURCE-relative path there would misplace the
        taint relative to the caller's view of the result and drop it (the
        G_subreturn false negative). A bare Ident that is an un-shadowed
        secret const has no env / content entry, so it too takes the
        whole-value branch."""
        if isinstance(value, A.Ident):
            root = value.name
            is_const = (
                root in self.secret_consts
                and root not in self._shadowed_consts
            )
            if not is_const:
                bucket = self._cur_content.get(root)
                if bucket:
                    for path, srcs in bucket.items():
                        self._cur_returns.setdefault(
                            self._return_path_key(path), set(),
                        ).update(srcs)
                base = env.get(root, set())
                if base:
                    self._cur_returns.setdefault((), set()).update(base)
                return
        self._cur_returns.setdefault((), set()).update(
            self._taint_of(value, env, reaching),
        )

    def _walk_stmt(self, stmt: A.Stmt, env: dict, reaching: set) -> None:
        if isinstance(stmt, A.LetStmt):
            src = self._taint_of(stmt.value, env, reaching)
            self._bind_pattern_taint(
                stmt.pattern, src, env,
                self._scrutinee_static_type(stmt.value),
            )
            # Record a single-ident binding's static struct type so a deep
            # field read rooted at it (``let u = t; return u.f2.f3.v``)
            # resolves its root type. Only a bare ``IdentPat`` denotes one
            # value; a destructuring pattern binds field names handled by
            # the pattern-secret rule instead.
            if isinstance(stmt.pattern, A.IdentPat):
                self._record_value_type(
                    stmt.pattern.name, stmt.type_expr, stmt.value,
                )
            else:
                # A DESTRUCTURING ``let`` (``let Outer { f2 } = t``) seeds each
                # destructured field binder's static struct type from the
                # pattern's DECLARED struct type, so a deep read off the binder
                # (``return f2.f3.v``) resolves its root type. Not save/restored:
                # a ``let`` binding is scoped to the rest of the block and Capa
                # rejects same-block re-binding, so the flat map is correct.
                self._record_pattern_value_types(stmt.pattern)
            # A ``let`` binding a name equal to a secret const shadows it
            # for the REST OF THIS BLOCK (and its sub-blocks); it is
            # unwound when the enclosing block's scope is restored.
            self._register_shadowing_binds(_pattern_bound_names(stmt.pattern))
        elif isinstance(stmt, A.VarStmt):
            env[stmt.name] = self._taint_of(stmt.value, env, reaching)
            self._record_value_type(stmt.name, stmt.type_expr, stmt.value)
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
                # the object aliases. FIELD-KEYED (``field_keyable=True``),
                # exactly like a container mutation: the effect is recorded
                # against the ROOT parameter at the STORED field's path
                # (``bag.secret_field = v`` -> ``("secret_field",)``), routed
                # by the caller onto the SAME ``(root, field-path)``
                # branch-scoped container channel. So a later read of a CLEAN
                # SIBLING field (``bag.note``) stays clean, while a read of the
                # stored path, a whole / getter read (the length-0 prefix
                # scan), or passing the whole struct to a callee that sinks the
                # stored path still flags. The keying is applied ONLY when the
                # chain is rooted DIRECTLY at the param within ``_MAX_FIELD_PATH``
                # (``_mutation_effect_key``); an aliased / renamed / over-long
                # root keeps the whole-value carrier, so the cross-function
                # whole-value leak never regresses. ANY store op is recorded: an
                # augmented store (``box.f += v``) reads the old field and joins
                # ``value`` into it, so it can only RAISE the field's label,
                # never lower it -- recording the effect for every op is sound
                # and closes the augmented-store cross-function leak.
                self._record_mutation_effect(
                    stmt.target, src, env, field_keyable=True,
                )
                # Same-body CONTENT: raise the root's field-keyed content at
                # the STORED path (a struct-literal RHS is leaf-seeded per
                # leaf), so a later read-back of the path, a whole read, or a
                # return of a LOCAL observes it while a disjoint public sibling
                # stays clean. The pass-to-callee gate is field-qualified
                # (Commit 1), so passing the whole struct to a callee that
                # sinks only a clean sibling is not over-flagged.
                self._seed_content_value(
                    self._chain_root_name(stmt.target),
                    self._chain_field_path(stmt.target),
                    stmt.value, src, env, reaching,
                )
        elif isinstance(stmt, A.IfStmt):
            # ``env`` (and each condition) is evaluated in the ORIGINAL
            # interleaved order (cond, body, cond, body ...) so its flat,
            # monotone propagation is unchanged. Only the CONTENT channel is
            # scoped: each branch is isolated from a snapshot of the content
            # at that point, and every branch's delta is unioned into the
            # enclosing scope after ALL branches are walked (deferred union).
            # CT (IFC-2) recognition site 3: the ``if`` / ``elif`` CONDITION
            # is a data-dependent branch, so its taint is ct-sensitive.
            self._cur_ct_sensitive |= self._taint_of(stmt.cond, env, reaching)
            posts = [self._content_isolated(
                lambda: self._walk_scoped_block(
                    stmt.then_block, env, reaching,
                ),
            )]
            for cond, blk in stmt.elif_arms:
                self._cur_ct_sensitive |= self._taint_of(cond, env, reaching)
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
            # CT (IFC-2) recognition site 3: the ``while`` CONDITION is a
            # data-dependent branch (it decides whether to iterate), so its
            # taint is ct-sensitive.
            self._cur_ct_sensitive |= self._taint_of(stmt.cond, env, reaching)
            # A single body, but routed through the same rule so a read
            # AFTER the loop reflects a cross-function mutation in the body.
            self._content_merge([self._content_isolated(
                lambda: self._walk_scoped_block(stmt.body, env, reaching),
            )])
        elif isinstance(stmt, A.ForStmt):
            iter_src = self._taint_of(stmt.iter, env, reaching)
            self._bind_pattern_taint(
                stmt.pattern, iter_src, env,
                self._iter_element_struct_type(stmt.iter),
            )

            def _for_body():
                # The loop variable is scoped to the body; a loop var named
                # like a secret const shadows it there only.
                saved = self._shadowed_consts
                self._shadowed_consts = set(saved)
                bound = list(_pattern_bound_names(stmt.pattern))
                self._register_shadowing_binds(bound)
                # BODY-SCOPED struct-type seed for the loop binder(s). The seed
                # resolves the ELEMENT struct type of the iterable and records
                # it for the binder, so a deep read off it (``return
                # u.f2.f3.v``) resolves its root type -- but ONLY within this
                # body. Save each binder's prior entry in BOTH type maps (with
                # ``_ABSENT`` when absent), CLEAR them so no stale type from a
                # sibling / sequential loop that reused the name leaks in, seed
                # for the body, walk, then RESTORE. Restoring is what keeps the
                # seed genuinely body-scoped: a later loop reusing the binder
                # over a different (or unresolvable) element type cannot resolve
                # against this loop's type, and a same-named binding AFTER the
                # loop is unaffected.
                saved_value = {
                    n: self._cur_value_types.get(n, _ABSENT) for n in bound
                }
                saved_elem = {
                    n: self._cur_elem_types.get(n, _ABSENT) for n in bound
                }
                # A for-loop binder is seeded from a STRUCT-provenance element
                # type (``_iter_element_struct_type`` reads the gated view), so
                # it is never call-derived; drop it from the provenance set on
                # clear so this map moves in lockstep with the two type maps and
                # cannot drift (a binder can never shadow an outer call-derived
                # ``let`` -- the analyzer rejects that shadow).
                for n in bound:
                    self._cur_call_derived.discard(n)
                if isinstance(stmt.pattern, A.IdentPat):
                    elem_ty = self._iter_element_struct_type(stmt.iter)
                    self._cur_value_types.pop(stmt.pattern.name, None)
                    self._cur_elem_types.pop(stmt.pattern.name, None)
                    # Leave the entry CLEARED when the element type is
                    # unresolvable (a call- / index-rooted iterable, a
                    # nested-generic element, a local-bound list), so a
                    # residual deep-return stays a whole-value fallback rather
                    # than resolving against a stale type.
                    if elem_ty is not None:
                        self._cur_value_types[stmt.pattern.name] = elem_ty
                else:
                    for n in bound:
                        self._cur_value_types.pop(n, None)
                        self._cur_elem_types.pop(n, None)
                    # A DESTRUCTURING for-pattern (``for Outer { f2 } in secs``)
                    # binds field names by the pattern's DECLARED struct type,
                    # exactly like a destructuring ``let``.
                    self._record_pattern_value_types(stmt.pattern)
                self._walk_block(stmt.body, env, reaching)
                for n in bound:
                    self._cur_call_derived.discard(n)
                    v = saved_value[n]
                    if v is _ABSENT:
                        self._cur_value_types.pop(n, None)
                    else:
                        self._cur_value_types[n] = v
                    e = saved_elem[n]
                    if e is _ABSENT:
                        self._cur_elem_types.pop(n, None)
                    else:
                        self._cur_elem_types[n] = e
                self._shadowed_consts = saved

            self._content_merge([self._content_isolated(_for_body)])
        elif isinstance(stmt, A.ReturnStmt):
            if stmt.value is not None:
                # The returned value is a return-secret effect, recorded PER
                # PATH: a returned LOCAL carries its content channel field-
                # keyed, so the caller observes the returned struct's per-field
                # taint; every other shape falls back to the whole-value
                # carrier (see ``_record_return``).
                self._record_return(stmt.value, env, reaching)
        elif isinstance(stmt, A.ExprStmt):
            self._taint_of(stmt.expr, env, reaching)
        # break / continue carry no value.

    def _impl_reverse_index(self) -> dict:
        """``trait / capability name -> {implementor type names}``, built once
        (memoised) via the shared ``build_impl_reverse_index`` -- the SAME
        single source the intra-procedural pass uses -- so the trait-destructure
        join here cannot drift from the intra one."""
        if self._ifc_impl_index is None:
            self._ifc_impl_index = build_impl_reverse_index(
                self.global_scope.symbols.values(),
            )
        return self._ifc_impl_index

    def _bind_pattern_taint(
        self, pat: A.Pattern, src: set, env: dict, scrutinee_tyname=None,
    ) -> None:
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
        a same-named public field of an unrelated struct is not tainted.

        ``scrutinee_tyname`` is the scrutinee's static TYPE name. When it is
        a TRAIT, ``_raise_trait_destructure_taint`` closes the cross-function
        trait-downcast launder (the summary mirror of
        ``_raise_trait_destructure_binds``)."""
        if isinstance(pat, A.IdentPat):
            env[pat.name] = env.get(pat.name, set()) | src
            return
        for name in _pattern_bound_names(pat):
            env[name] = env.get(name, set()) | src
        self._bind_pattern_field_secrets(pat, env)
        self._raise_trait_destructure_taint(pat, scrutinee_tyname, env)

    def _raise_trait_destructure_taint(
        self, pat: A.Pattern, scrutinee_tyname, env: dict,
    ) -> None:
        """When a ``StructPat`` destructures a TRAIT-typed scrutinee, taint
        each bound field with ``INTERNAL_SECRET`` iff the JOIN, over every
        implementor of the trait, of the implementor's same-named declared
        field label is ``@secret`` (``trait_destructure_field_label``, the
        SAME single source the intra pass calls, over the SAME struct-filtered
        implementor labels via ``_struct_decl_field_labels``). The
        cross-function mirror of ``_raise_trait_destructure_binds``: without it
        a callee ``reveal(s: Shape) { let OtherCircle{r}=s; return r }`` whose
        caller sinks the result launders the secret across the boundary.

        ``scrutinee_tyname`` is resolved by ``_scrutinee_static_type``, the
        COMPOSITIONAL resolver, so this certifies the destructure for every hop
        the NAME-ONLY type representation can CARRY -- a parameter / ``self`` /
        copy / field chain / struct-literal root, composed through single-level
        element reads, named field reads, hoisted call/method/index bindings,
        named-function return types and (receiver-typed, including
        trait-receiver) method return types. It does NOT fire on either
        disclosed residual: a hop whose type is ERASED by the name-only
        representation (a NESTED-container element like ``List<List<Trait>>``
        indexed past the first level, whose inner argument the element-type
        tables collapse to the bare name ``"List"``), or a hop that is not
        statically NAMEABLE at all (a call to a GENERIC callee returning a type
        PARAMETER, ``idish<T>(x: T) -> T``, a dynamic / unknown receiver, or an
        untracked / foreign callee). Both keep the pre-fix behaviour -- a
        conservative MISS, silent across a boundary on Python / ``--ir`` only,
        still caught INTRA-procedurally. See ``_scrutinee_static_type`` for the
        root-cause disclosure of each."""
        from .. import _labels as L
        if not isinstance(pat, A.StructPat) or scrutinee_tyname is None:
            return
        if not self._is_trait_type(scrutinee_tyname):
            return
        index = self._impl_reverse_index()
        for fname, fpat in pat.fields:
            label = trait_destructure_field_label(
                index, self._struct_decl_field_labels,
                scrutinee_tyname, fname,
            )
            if L.normalize(label) != L.SECRET:
                continue
            if fpat is None:
                env[fname] = env.get(fname, set()) | {INTERNAL_SECRET}
            else:
                for name in _pattern_bound_names(fpat):
                    env[name] = env.get(name, set()) | {INTERNAL_SECRET}

    def _struct_decl_field_labels(self, type_name: str) -> dict:
        """``{field name: declared label}`` for ``type_name`` ONLY when it
        resolves to a user STRUCT, else an empty map -- the summary mirror of
        the intra-procedural ``_ifc._struct_decl_field_labels`` restriction, so
        the trait-destructure join consults the SAME implementor set on both
        passes (a non-struct implementor contributes nothing on either, and a
        typestate -- which rejects per-state field syntax -- cannot slip a
        field label into the join through one pass but not the other)."""
        from . import SymbolKind
        sym = self.global_scope.lookup(type_name)
        if sym is None or sym.kind != SymbolKind.TYPE_STRUCT:
            return {}
        return self.struct_field_labels.get(type_name, {})

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

        ``field_keyable`` is ``True`` for BOTH a container mutation and a
        field store, so ``path`` is the parameter-relative field path when
        the chain is rooted directly at param ``j`` (else the whole-value
        carrier) and the caller taints only that ``(root, field-path)`` on
        the branch-scoped container channel. A public SIBLING field stays
        clean (a field read scans only its own path), while a same-root
        WHOLE read-back is still caught: ``_compute_label`` prefix-scans the
        ``(root, *)`` channel for a whole / getter / interpolation /
        pass-whole read (the length-0 access-path query). The field store
        keys at the STORED field's path (``bag.secret_field = v`` ->
        ``("secret_field",)``); a container mutation keys at the container's
        path (``bag.items.push(v)`` -> ``("items",)``). Both fall back to the
        whole-value carrier (``path`` becomes ``None``) for an aliased /
        renamed / unkeyable root or an over-long path, so a cross-function
        whole-value leak never regresses (see ``_mutation_effect_key``)."""
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
        pattern bind any more than through a direct ``e.iban`` read.

        DEPTH: the chain is walked type-precisely from its root through
        ``struct_field_type_names`` at every hop, so a NESTED declared-@secret
        field read (``t.f2.f3.v``) is recognised, not only a depth-1
        ``e.iban``. Depth-1 is the same walk with an empty prefix. The ROOT
        type is resolved from ``_cur_value_types``, seeded with the param
        types and grown by:
          * a ``let`` / ``var`` binding whose PATTERN is a bare ``IdentPat``
            and whose RHS statically denotes a struct: a copy of an
            already-typed value (``let u = t``), a param- / local-rooted field
            chain (``let u = t.f2``), or a struct literal (see
            ``_record_value_type`` / ``_static_struct_type``);
          * a struct-DESTRUCTURING binder -- a ``let Outer { f2 } = t`` or a
            destructuring for-pattern (``for Outer { f2 } in secs``) -- seeded
            from the pattern's DECLARED struct type
            (``_record_pattern_value_types``), so ``return f2.f3.v`` resolves
            even when the @secret leaf is nested BELOW the destructured field
            (item 1c);
          * a FOR-LOOP IdentPat binder (``for u in secs``), seeded BODY-SCOPED
            from the iterable's element struct type
            (``_iter_element_struct_type``), so ``return u.f2.f3.v`` resolves
            (item 1b). The seed is saved/restored around the body so a sibling
            or sequential loop reusing the binder over a different element type
            cannot resolve against a stale type.
        Each hop follows the ACTUAL declared field type, never a field-name
        match, so a same-named field of an unrelated struct is not tainted (no
        by-name FP).

        RESIDUAL (known-open, disclosed): a deep chain whose root type cannot
        be resolved stays a whole-value ``()`` fallback and this deep-return FN
        survives -- the same class as the documented ``G_subreturn`` /
        ``H_alias`` residuals. What STAYS open, each MEASURED to leak clean on
        both backends:
          (a) a CALL / INDEX result root (``return id(t).f2.f3.v``): the
              chain has no ident root at all (``_chain_root_name`` is
              ``None``);
          (b) a FOR-LOOP over a CALL- / INDEX-rooted iterable (``for u in
              mk()``) or a LOCAL-bound list (``let xs = secs; for u in xs``):
              the element type is unresolvable (``_iter_element_struct_type``
              is ``None``), because a ``let``-bound container does not
              propagate its element type into ``_cur_elem_types``;
          (c) a NESTED-GENERIC inner-loop element (``List<List<Outer>>``): only
              the outer container name is recorded as the element type, so a
              for over such a value leaves the binder unresolved."""
        from .. import _labels as L
        # Known-open residual: a chain whose root type is unresolvable stays a
        # whole-value ``()`` FN -- a call- / index-rooted chain
        # (``id(t).f2.f3.v``), a for over a call- / index-rooted or
        # local-bound iterable, or a nested-generic inner element -- the same
        # class as the documented G_subreturn / H_alias residuals.
        root = self._chain_root_name(e)
        path = self._chain_field_path(e)
        if root is None or not path:
            return False
        tyname = self._struct_prov_type(root)
        if tyname is None:
            return False
        # Walk the declared field types down to the leaf's owning struct.
        for hop in path[:-1]:
            tyname = self.struct_field_type_names.get(tyname, {}).get(hop)
            if tyname is None:
                return False
        labels = self.struct_field_labels.get(tyname, {})
        return labels.get(path[-1]) == L.SECRET

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

    def _static_struct_type(self, rhs: A.Expr):
        """The static struct TYPE name a binding's RHS denotes, or ``None``
        when it is not statically a struct value. Recognises the shapes a
        deep field-read chain can be rooted at: a plain COPY of an
        already-typed value (``let u = t`` -> ``t``'s type), a param / local
        FIELD chain (``let u = t.f2`` -> the type of ``t.f2``, walked through
        ``struct_field_type_names``), and a STRUCT LITERAL (its
        ``type_name``). Anything else (a call, an index, ...) is ``None`` and
        the binding is simply not typed, so ``_field_read_is_secret`` falls
        back to whole-value at ``()``.

        Deliberately STRUCT-ONLY: a call result stays ``None`` here so a deep
        read off a call-result binding keeps the whole-value fallback (the
        ``RESTORE_BITES`` residual). The trait-destructure SCRUTINEE has its
        own wider resolver (``_scrutinee_static_type``), which extends this
        with the call / index / if-match forms whose static type can be a
        trait, without perturbing this deep-read typing."""
        if isinstance(rhs, A.Ident):
            return self._struct_prov_type(rhs.name)
        if isinstance(rhs, A.FieldAccess):
            root = self._chain_root_name(rhs)
            path = self._chain_field_path(rhs)
            if root is None or not path:
                return None
            tyname = self._struct_prov_type(root)
            for hop in path:
                if tyname is None:
                    return None
                tyname = self.struct_field_type_names.get(tyname, {}).get(hop)
            return tyname
        if isinstance(rhs, A.StructLit):
            return rhs.type_name
        return None

    def _scrutinee_static_type(self, e: A.Expr):
        """The static struct / trait TYPE name a DESTRUCTURE SCRUTINEE denotes,
        for the trait-downcast join (``_raise_trait_destructure_taint``).

        A single COMPOSITIONAL resolver (``_resolve_static_type``) over the
        tables the summary pass already maintains, NOT a flat list of
        per-spelling special cases: it types a receiver by RECURSION and reads
        the next hop's declared type from an existing signature / field table,
        so a field / index / method chain is typed hop by hop whatever its root
        is (a call, an index, a method result, ...), not only an ``Ident`` root.
        It bottoms out at a tracked binding / parameter / const / ``self``
        (``_cur_value_types``), a named function's declared return type
        (``self.callables``), a method's declared return type keyed by the
        recursively-resolved receiver type (``self.callables`` again, never a
        new return-type map), or a container's declared element type
        (``_cur_elem_types`` / ``struct_field_elem_type_names`` / a return
        type's first generic argument). Because every arm is one hop composed
        onto the SAME recursion, the closed set is "a scrutinee whose every hop
        the pass can name", not an enumerated list of spellings.

        HONEST SCOPE: this certifies a trait-downcast destructure for every hop
        the NAME-ONLY type representation this pass carries can express -- a
        single-level container element, a named struct field, a named function /
        method return, and a hoisted local of any of those -- composed over any
        resolvable root. It does NOT close the launder "by construction" for
        every scrutinee. Two residuals stay disclosed, each by ROOT CAUSE, never
        by spelling:

        * a hop whose type is ERASED by the name-only representation: a
          NESTED-container element, ``List<List<Trait>>`` indexed past the first
          level. The element-type tables (``_param_elem_type_names`` /
          ``_cur_elem_types``) store only ``args[0].name``, so ``List<List<
          Shape>>`` collapses to the bare name ``"List"`` and the inner
          ``<Shape>`` is erased BEFORE this resolver runs; recursion cannot
          recover an erased type. So ``let OtherCircle { r } = xss[0][0]``
          launders a ``@secret`` across a boundary SILENTLY on Python / ``--ir``
          (still caught INTRA-procedurally; Wasm refuses the whole class loud).
          Closing it needs a STRUCTURED-type representation, scheduled as a
          separate design item (B); the same ceiling is pinned at
          ``tests/test_ifc_forloop_destructure_deep_return.py``. Pinned here by
          ``RES_TRAIT_NESTED_CONTAINER_ELEM_LAUNDER``.
        * a hop that is not statically NAMEABLE at all: a call to a GENERIC
          callee whose declared return type is a type PARAMETER (the canonical
          case, ``idish<T>(x: T) -> T``: the declared return NAME is ``"T"``, not
          a trait, so the join does not fire), a receiver of dynamic / unknown
          static type, or an untracked / foreign callee. That is the pre-pass's
          inherent inference ceiling: this summary runs in Phase 1d, BEFORE the
          type-checker's per-expression type map exists (``self.types`` is
          populated in Phase 2 body-checking), so it re-derives types from
          declared signatures ONLY and cannot instantiate ``T`` to ``Shape``.
          Pinned by ``RES_TRAIT_GENERIC_RETURN_LAUNDER``.

        On any unresolved OR erased hop the join simply does not fire and the
        pre-fix behaviour holds -- a conservative MISS, never a wrong-type guess
        -- so both classes cross a function boundary SILENTLY on Python /
        ``--ir`` only (Wasm refuses the whole trait-destructure class loud) and
        are still caught INTRA-procedurally (the in-function sink of the same
        value). Raising either ceiling is a separate, larger architectural
        change, not attempted here.

        Kept SEPARATE from ``_static_struct_type`` on purpose: the deep-read
        typing there is call-BLIND (a call-result binding stays untyped, the
        pinned ``RESTORE_BITES`` residual). This resolver additionally types a
        call / index / method result; a hoisted such binding IS recorded for a
        later scrutinee (``_record_value_type``), but marked CALL-DERIVED so it
        stays invisible to the deep-read path (``_struct_prov_type``) and the
        ``RESTORE_BITES`` residual is preserved."""
        return self._resolve_static_type(e)

    def _resolve_static_type(self, e: A.Expr):
        """Recursively resolve ``e``'s static struct / trait TYPE name by
        composing one hop at a time over the tables the summary pass already
        maintains. Each arm types a strictly smaller sub-expression, so the
        recursion terminates on the AST structure.

        * ``Ident`` -> its tracked static type (``_cur_value_types``: a
          parameter, a ``self`` owner, a ``let`` / ``var`` copy / field-chain /
          struct-literal binding, a destructured binder, a for-loop binder).
        * ``StructLit`` -> its ``type_name``.
        * ``FieldAccess`` -> type the RECEIVER through this recursion, then read
          the field's declared type from ``struct_field_type_names`` -- so a
          field off a call / index / method result types hop by hop
          (``get().s``, ``xs[0].s``), not only off an ``Ident`` root.
        * ``Call`` to a named function -> its DECLARED return type
          (``_call_return_type_expr``).
        * ``MethodCall`` -> type the receiver through this recursion, then read
          the method's DECLARED return type (``_method_return_type_expr``), so
          ``self.make()`` / ``f.make()`` / ``mk().make()`` type hop by hop.
        * ``Index`` -> the receiver's element type (``_resolve_element_type``,
          which handles ``xs[0]`` / ``get()[0]`` / ``bag.items[0]``).
        * an ``if`` / ``match`` EXPRESSION -> the single type its branches agree
          on (``_common_scrutinee_type``), each branch resolved by recursion
          (so a ``match`` arm whose value is itself a call resolves)."""
        if isinstance(e, A.Ident):
            return self._cur_value_types.get(e.name)
        if isinstance(e, A.StructLit):
            return e.type_name
        if isinstance(e, A.FieldAccess):
            recv_ty = self._resolve_static_type(e.receiver)
            if recv_ty is None:
                return None
            return self.struct_field_type_names.get(recv_ty, {}).get(
                e.field_name,
            )
        if isinstance(e, A.Call):
            te = self._call_return_type_expr(e)
            return getattr(te, "name", None) if te is not None else None
        if isinstance(e, A.MethodCall):
            te = self._method_return_type_expr(e)
            return getattr(te, "name", None) if te is not None else None
        if isinstance(e, A.Index):
            return self._resolve_element_type(e.receiver)
        if isinstance(e, A.IfExpr):
            return self._common_scrutinee_type((e.then_expr, e.else_expr))
        if isinstance(e, A.MatchExpr):
            if any(isinstance(arm.body, A.Block) for arm in e.arms):
                return None
            return self._common_scrutinee_type([arm.body for arm in e.arms])
        return None

    def _call_return_type_expr(self, e: A.Call):
        """The declared return TYPE EXPRESSION of a call to a NAMED function
        (``self.callables[("fun", name)]`` -- the SAME signature table the
        boundary summary already threads), or ``None`` for a non-``Ident`` /
        unknown callee. Returns the ``TypeExpr`` (not only its name) so the
        element-type resolver can read its first generic argument too."""
        if not isinstance(e.callee, A.Ident):
            return None
        entry = self.callables.get(("fun", e.callee.name))
        return entry[1].return_type if entry is not None else None

    def _method_return_type_expr(self, e: A.MethodCall):
        """The declared return TYPE EXPRESSION of a method call, resolved by
        typing the RECEIVER through the compositional recursion and reading the
        method signature keyed by ``("method", receiver_type, method)`` from
        ``self.callables`` -- never a new/parallel return-type map. ``None``
        when the receiver type is unresolved (the inference-ceiling residual) or
        the resolved type declares no such method (a trait / built-in method the
        summary does not thread), so the join then does not fire."""
        recv_ty = self._resolve_static_type(e.receiver)
        if recv_ty is None:
            return None
        entry = self.callables.get(("method", recv_ty, e.method))
        return entry[1].return_type if entry is not None else None

    def _resolve_element_type(self, recv: A.Expr):
        """The element struct / trait TYPE name a container-valued expression
        yields, for an ``Index`` scrutinee (``xs[0]`` / ``get()[0]`` /
        ``bag.items[0]``). Composed over the same tables:

        * an ``Ident`` container -> ``_cur_elem_types`` (a parameter's element
          type, or a for-binder's);
        * a ``Call`` / ``MethodCall`` -> the FIRST generic argument of its
          declared return type (``List<Shape>`` -> ``Shape``);
        * a ``FieldAccess`` to a container field -> the receiver's struct type
          (resolved by recursion) then ``struct_field_elem_type_names``.

        ``None`` when the container's element type cannot be named, so the
        ``Index`` scrutinee stays untyped and the join does not fire. This is
        where the NESTED-container residual surfaces: the element-type tables
        (``_cur_elem_types`` / ``_param_elem_type_names``) store only
        ``args[0].name``, so a ``List<List<Trait>>`` container yields the bare
        element NAME ``"List"`` with its inner ``<Trait>`` already erased, and an
        ``Index`` receiver that is itself an ``Index`` (``xss[0][0]``) resolves
        to ``None`` -- the second-level element type is unrecoverable from the
        name-only representation. Closing it needs a structured-type
        representation (design item B); see ``_scrutinee_static_type``. A hop the
        pre-pass cannot name at all (a generic / dynamic / foreign result) is the
        separate inference-ceiling residual disclosed there too."""
        if isinstance(recv, A.Ident):
            return self._cur_elem_types.get(recv.name)
        te = None
        if isinstance(recv, A.Call):
            te = self._call_return_type_expr(recv)
        elif isinstance(recv, A.MethodCall):
            te = self._method_return_type_expr(recv)
        if te is not None:
            args = getattr(te, "args", None)
            return getattr(args[0], "name", None) if args else None
        if isinstance(recv, A.FieldAccess):
            recv_ty = self._resolve_static_type(recv.receiver)
            if recv_ty is None:
                return None
            return self.struct_field_elem_type_names.get(
                recv_ty, {},
            ).get(recv.field_name)
        return None

    def _common_scrutinee_type(self, exprs):
        """The single static type shared by every expression in ``exprs`` (an
        ``if`` / ``match`` scrutinee's branch values), or ``None`` when a branch
        is unresolved (``_resolve_static_type``) or the branches disagree -- so
        a trait-typed conditional resolves only when every branch statically
        denotes the same type."""
        common = None
        for e in exprs:
            ty = self._resolve_static_type(e)
            if ty is None or (common is not None and ty != common):
                return None
            common = ty
        return common

    def _struct_prov_type(self, name):
        """The STRUCT-provenance value type of ``name`` -- the pre-RC1 view of
        ``_cur_value_types``, HIDING a call/method/index-derived entry
        (``_cur_call_derived``). Consulted by every DEEP-READ / capability / ct
        reader, so each keeps its exact pre-RC1 behaviour: a call-result root
        stays unresolved, preserving the ``RESTORE_BITES`` deep-read residual.
        The trait-destructure scrutinee resolver deliberately does NOT use this
        (it reads ``_cur_value_types`` raw, seeing the call-derived entry)."""
        if name in self._cur_call_derived:
            return None
        return self._cur_value_types.get(name)

    def _struct_prov_elem(self, name):
        """The STRUCT-provenance element type of ``name`` -- the pre-RC1 view of
        ``_cur_elem_types``, HIDING a call-derived entry. Consulted by the
        for-loop deep-read binder seed (``_iter_element_struct_type``) so a
        ``let``-bound-container-then-iterate residual stays open exactly as
        before; the ``Index`` scrutinee resolver reads ``_cur_elem_types`` raw."""
        if name in self._cur_call_derived:
            return None
        return self._cur_elem_types.get(name)

    def _seed_call_derived(self, name, value_ty, elem_ty) -> None:
        """The SINGLE writer for a CALL-derived binding's type (RC1). Records
        whichever of ``value_ty`` / ``elem_ty`` resolved and marks ``name``
        call-derived, so the two type maps and the provenance set are always
        seeded together and cannot drift. A no-op when neither resolved (the
        name stays absent, the pre-RC1 conservative miss)."""
        if value_ty is None and elem_ty is None:
            return
        if value_ty is not None:
            self._cur_value_types[name] = value_ty
        if elem_ty is not None:
            self._cur_elem_types[name] = elem_ty
        self._cur_call_derived.add(name)

    def _record_value_type(self, name, type_expr, rhs) -> None:
        """Record ``name``'s static struct TYPE in ``_cur_value_types`` from
        its declared annotation, else from the RHS's static shape.

        An annotation or a struct-provenance RHS (a copy / field chain / struct
        literal, ``_static_struct_type``) records a STRUCT-provenance type: the
        pre-RC1 behaviour, visible to every reader. When neither resolves, the
        RHS is a hoisted CALL / METHOD / INDEX result (``let s = get()``): its
        type is re-derived through the COMPOSITIONAL resolver and recorded
        CALL-DERIVED (``_seed_call_derived``), visible ONLY to the trait-
        destructure scrutinee resolver so a later bare-``Ident`` / ``Index``
        scrutinee off the binding resolves, WITHOUT feeding the deep-read /
        capability / ct readers (which gate call-derived entries out). Recording
        nothing leaves the name absent, so a deep read off it takes the
        whole-value fallback."""
        tyname = getattr(type_expr, "name", None) if type_expr else None
        if tyname is None:
            tyname = self._static_struct_type(rhs)
        if tyname is not None:
            self._cur_value_types[name] = tyname
            return
        self._seed_call_derived(
            name, self._resolve_static_type(rhs),
            self._resolve_element_type(rhs),
        )

    def _record_pattern_value_types(self, pat) -> None:
        """Seed ``_cur_value_types`` for every name a STRUCT destructuring
        pattern binds, from the pattern's DECLARED struct type -- never the
        bound-name spelling (type-precise, no by-name false positive). For a
        ``StructPat`` each destructured field records its declared field type
        under the name it binds: a bare field (``f2``) binds ``f2`` to the
        field's type; a rename (``f2: m``) binds the alias ``m``. So a deep
        read off the binder (``return f2.f3.v``) resolves its root type. Shared
        by the destructuring ``let`` (1c) and the destructuring for-pattern
        (1b). Non-struct patterns bind nothing that can root a deep field read
        here, so they seed nothing (an ``IdentPat`` for-binder is handled by
        the element-type seed instead).

        A field pattern is only ever a bare field or an ``IdentPat`` here: the
        analyzer REJECTS a NESTED struct-pattern in a ``let`` / ``for`` binding
        (``let Outer { f2: Mid { f3 } } = t``) before the summary runs (see
        the ``let`` / ``for`` binding guard in :mod:`._patterns`), so neither
        call site presents one and there is no nesting to recurse into."""
        if not isinstance(pat, A.StructPat):
            return
        field_types = self.struct_field_type_names.get(pat.type_name, {})
        for fname, fpat in pat.fields:
            if fpat is None:
                fty = field_types.get(fname)
                if fty is not None:
                    self._cur_value_types[fname] = fty
            elif isinstance(fpat, A.IdentPat):
                fty = field_types.get(fname)
                if fty is not None:
                    self._cur_value_types[fpat.name] = fty

    def _iter_element_struct_type(self, iter_expr: A.Expr):
        """The element STRUCT TYPE name a for-loop iterable yields, or ``None``
        when it cannot be resolved statically. Recognises the minimal set of
        iterable shapes a body-scoped binder seed needs:

        * a ``ListLit`` (``for u in [o]``) resolves via the FIRST element's
          ``_static_struct_type`` (an empty list yields ``None``);
        * an ``Ident`` (``for u in secs``) resolves via ``_cur_elem_types``
          (a container PARAMETER's element type);
        * a ``FieldAccess`` to a container field (``for u in bag.items``)
          resolves the receiver's struct type via ``_cur_value_types``, walks
          any intermediate hops through ``struct_field_type_names``, then reads
          ``struct_field_elem_type_names`` for the container field.

        Everything else -- a call- / index-rooted iterable (``for u in mk()``),
        a nested-generic element, a local-bound list whose element type was not
        propagated -- resolves to ``None`` (the disclosed residuals), so the
        binder is left unseeded and a deep read off it stays a whole-value
        fallback rather than resolving against a wrong type."""
        if isinstance(iter_expr, A.ListLit):
            if iter_expr.elements:
                return self._static_struct_type(iter_expr.elements[0])
            return None
        if isinstance(iter_expr, A.Ident):
            return self._struct_prov_elem(iter_expr.name)
        if isinstance(iter_expr, A.FieldAccess):
            root = self._chain_root_name(iter_expr)
            path = self._chain_field_path(iter_expr)
            if root is None or not path:
                return None
            tyname = self._struct_prov_type(root)
            for hop in path[:-1]:
                if tyname is None:
                    return None
                tyname = self.struct_field_type_names.get(tyname, {}).get(hop)
            if tyname is None:
                return None
            return self.struct_field_elem_type_names.get(
                tyname, {},
            ).get(path[-1])
        return None

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
            # read-back must reflect it. A bare Ident is a WHOLE read, so it
            # observes EVERY field-path recorded on the name (the length-0
            # access-path query ``_content_at(name, ())``). Additive only --
            # ``env`` alone remains the alias / mutation-target set consulted
            # elsewhere.
            return set(env.get(e.name, set())) | self._content_at(e.name, ())
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
            left = self._taint_of(e.left, env, reaching)
            right = self._taint_of(e.right, env, reaching)
            # CT (IFC-2) recognition sites 1 + 4, mirroring the inline
            # ``_check_ct_arith`` / ``_check_ct_compare``:
            #   1. a VARIABLE-TIME op (``/`` / ``%``) is unconditional and
            #      type-independent -- any param flowing into EITHER operand
            #      becomes ct-sensitive (the variable-latency divider).
            #   4. a SHORT-CIRCUIT compare (``==`` / ``!=`` / ordering) is a
            #      byte-scan ONLY when an operand's static type resolves to
            #      String / List (an Int / Float compare is fixed-latency);
            #      union the RESOLVED operand's taint. When neither operand's
            #      type resolves, do NOT flag (the disclosed-residual class --
            #      blanket-including every ``==`` would over-reject Int
            #      compares).
            if e.op in _VARIABLE_TIME_OPS:
                self._cur_ct_sensitive |= left | right
            elif e.op in _SHORT_CIRCUIT_COMPARE_OPS:
                if self._ct_operand_byte_scanned(e.left):
                    self._cur_ct_sensitive |= left
                if self._ct_operand_byte_scanned(e.right):
                    self._cur_ct_sensitive |= right
            return left | right
        if isinstance(e, A.UnaryOp):
            return self._taint_of(e.operand, env, reaching)
        if isinstance(e, A.Try):
            return self._taint_of(e.expr, env, reaching)
        if isinstance(e, A.Index):
            recv = self._taint_of(e.receiver, env, reaching)
            idx = self._taint_of(e.index, env, reaching)
            # CT (IFC-2) recognition site 2: an index-by-value ``xs[v]`` is a
            # data-dependent memory access (mirrors ``_check_ct_index``), so
            # any param flowing into the INDEX position becomes ct-sensitive.
            self._cur_ct_sensitive |= idx
            return recv | idx
        if isinstance(e, A.FieldAccess):
            # The BASE data-flow taint (the receiver walked for its
            # ``reaching`` side effects, a declared-@secret field of ``type
            # Emp { iban: @secret String }`` folded in via ``_base_taint_of``
            # / ``_field_read_is_secret``) EXCLUDING the content channel,
            # joined with the content channel scanned at THIS read's OWN
            # access path. So a callee that mutated a DIFFERENT field of the
            # receiver does not over-taint this clean sibling, while a read
            # of the mutated path (or a WHOLE read of the receiver) still
            # observes it. Sound, never under-reports (the declared-field
            # rule is unchanged; only the field-insensitive content join is
            # narrowed to the read's own path).
            return (
                self._base_taint_of(e, env, reaching)
                | self._content_contribution(e)
            )
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
            # CT (IFC-2) recognition site 3: the if-expr CONDITION is a
            # data-dependent branch, so its taint is ct-sensitive.
            self._cur_ct_sensitive |= self._taint_of(e.cond, env, reaching)
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
            # CT (IFC-2) recognition site 3: the match SCRUTINEE drives which
            # arm runs, a data-dependent branch, so its taint is ct-sensitive.
            self._cur_ct_sensitive |= scrut
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
                self._bind_pattern_taint(
                    arm.pattern, scrut, arm_env,
                    self._scrutinee_static_type(e.scrutinee),
                )
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
        # ``_cur_returns`` is a per-path map ``{field-path -> sources}``; a
        # ``return`` inside the lambda body records into it. The lambda
        # expression's own VALUE taint is the flattened union over every path.
        lambda_returns: dict = {}
        self._cur_returns = lambda_returns
        # Isolate the content channel like ``body_env``: a cross-function
        # mutation of a CAPTURED local inside the lambda body must not
        # escape into the enclosing body's content map (whether the lambda
        # is ever invoked is unknown), mirroring the env copy above.
        saved_content = self._cur_content
        self._cur_content = self._content_copy(saved_content)
        try:
            if isinstance(e.body, A.Block):
                trailing = self._walk_value_block(e.body, body_env, reaching)
            else:
                trailing = self._taint_of(e.body, body_env, reaching)
            lambda_returns.setdefault((), set()).update(trailing)
        finally:
            self._cur_returns = saved_returns
            self._shadowed_consts = saved_shadowed
            self._cur_content = saved_content
        out: set = set()
        for srcs in lambda_returns.values():
            out |= srcs
        return out

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

    def _capture_sink_paths_of(self, key, lam: A.LambdaExpr) -> dict:
        """Which CAPTURED ``(root, field-path)`` access paths reach a public
        sink INSIDE ``lam``'s body -- keyed by capture NAME, with ``()`` the
        whole-capture sentinel (the R1 fix). The capture-side mirror of the
        parameter ``sink_paths``: the lambda body's FREE identifiers (its
        captures) are seeded as sources and the SAME declassify-aware body
        walk records, per capture, the paths that reach a sink. A sink reached
        via a NAMED HELPER is seen through for free (``_propagate_sink_paths``
        composes the helper's own ``sink_paths``); an in-body ``declassify``
        records no path (``_taint_of_call`` returns no source for it), so it
        stays clean by construction.

        Runs OUTSIDE the parameter fixpoint (it only reads the final named
        summaries), on a fresh set of ``_cur_*`` walk state seeded for the
        captures rather than the parameters. The capture root names index to
        THEMSELVES, so a sink on a capture's own field chain records a
        capture-relative path (``println(bag.data)`` -> ``bag`` sunk at
        ``("data",)``) while an aliased / call-rooted sunk value falls back to
        the whole-capture sentinel ``()`` -- exactly the parameter rule."""
        free = self._lambda_free_names(lam)
        if not free:
            return {}
        # Reuse the value-block wrapper already built for this lambda so an
        # expression body is walked exactly like a named function's trailing
        # implicit-return expression.
        body = self.callables[key][1].body
        env = {name: {name} for name in free}
        reaching: set = set()
        self._cur_content = {}
        self._cur_sink_caps = {}
        sink_paths_local: dict = {}
        self._cur_sink_paths = sink_paths_local
        self._cur_secret_source_params = self.secret_source_params.get(
            key, set(),
        )
        self._cur_param_struct_types = self.param_struct_types.get(key, {})
        self._cur_param_type_names = self.param_type_names.get(key, {})
        # Reset the deep-chain root-type map for this fresh capture walk so it
        # never reads a previous callable's bindings (captures are not typed
        # here, matching the parameter-only scope of this pass).
        self._cur_value_types = dict(self._cur_param_type_names)
        self._cur_call_derived = set()
        self._cur_immutable_params = self.immutable_params.get(
            key, frozenset(),
        )
        self._cur_effects = {}
        self._cur_returns = {}
        self._cur_param_index = {name: name for name in free}
        self._shadowed_consts = set()
        self._walk_value_block(body, env, reaching)
        # Keys are capture-name source keys (``_record_sink_paths`` skips
        # ``INTERNAL_SECRET``); the ``in free`` filter is a belt-and-braces
        # guard against any non-capture source leaking through.
        return {
            name: set(paths) for name, paths in sink_paths_local.items()
            if name in free
        }

    def _lambda_free_names(self, lam: A.LambdaExpr) -> set:
        """The names ``lam``'s body uses but does NOT bind -- its captures.
        Computed syntactically: every identifier in the body minus the
        lambda's own parameters and its top-level ``let`` / ``var`` binds.
        Mirrors the analyzer's ``_capture_read_paths`` bound set, so the call
        site's identity-based capture resolution and this summary agree on
        what counts as a capture. An over-approximation (a nested-block bind,
        or a nested lambda's own parameter, counts as free) is harmless: the
        walk rebinds a nested local at its ``let`` so its seed is discarded,
        a nested lambda masks its own parameters, and the call site intersects
        these names against the resolved captures."""
        bound = {p.name for p in lam.params}
        if isinstance(lam.body, A.Block):
            for stmt in lam.body.stmts:
                if isinstance(stmt, A.LetStmt):
                    bound.update(_pattern_bound_names(stmt.pattern))
                elif isinstance(stmt, A.VarStmt):
                    bound.add(stmt.name)
        out: set = set()
        self._collect_free_names(lam.body, bound, out)
        return out

    def _collect_free_names(self, node, bound: set, out: set) -> None:
        """Add every identifier NAME reachable from ``node`` that is not in
        ``bound`` to ``out``. A generic dataclass / list walk, the name-only
        analogue of the analyzer's ``_lambda_free_idents``."""
        if isinstance(node, A.Ident):
            if node.name not in bound:
                out.add(node.name)
            return
        if node is None or isinstance(node, str):
            return
        if dataclasses.is_dataclass(node):
            for f in dataclasses.fields(node):
                self._collect_free_names(getattr(node, f.name), bound, out)
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                self._collect_free_names(x, bound, out)

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

    def _sink_reaching_arg(
        self, arg: A.Expr, arg_src: set, callee_paths, env: dict,
        reaching: set,
    ) -> set:
        """The source set that becomes sink-reaching when ``arg`` binds to a
        callee's sink-reaching parameter, FIELD-QUALIFIED to the callee's
        SUNK paths ``callee_paths``. The mirror of ``_sink_arg_field_cleared``
        in :mod:`._ifc` on the summary side.

        The whole-value BASE taint of ``arg`` (excluding the content channel)
        always reaches -- the FN-safety floor that keeps every whole-value
        cross-function leak caught. The content channel is observed ONLY at
        the callee's sunk paths, composed with the caller's access prefix to
        ``arg`` (``_content_at``), so a field-store content taint on a
        DISJOINT sibling does not reach a callee that sinks only a clean path.
        A callee that sinks the WHOLE parameter records the sentinel ``()``
        (prefix-compatible with every path), so it observes every field's
        content and no leak is dropped.

        No-op until the content channel carries field-store taint: today the
        channel holds only container-mutation taint at ``()`` (prefix-
        compatible with every sunk path) and propagated-effect taint at a
        path the caller prefix already covers, so the field-qualified union
        equals the whole-value read. A NON-Ident-rooted argument has no
        field-keyed content of its own, so its whole taint reaches
        unchanged."""
        root = self._chain_root_name(arg)
        prefix = self._chain_field_path(arg)
        if root is None or prefix is None:
            return arg_src
        out = set(self._base_taint_of(arg, env, reaching))
        for sp in (callee_paths or {()}):
            out |= self._content_at(root, prefix + sp)
        return out

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
            # Strict implicit-flow (IFC-1): ``panic`` IS a public sink, so a
            # body that panics is sink-reaching under its own control flow
            # regardless of the message's label.
            self._cur_reaches_sink_pc = True
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
            # Strict implicit-flow (IFC-1) transitive closure: calling a
            # free function that can itself run a public sink under its own
            # control flow makes THIS body sink-reaching too.
            if self.sink_reaching_pc.get(key):
                self._cur_reaches_sink_pc = True
            perm = self._bind_args(e, names)
            sink_params = self.summaries.get(key, set())
            callee_caps = self.sink_caps.get(key, {})
            callee_sink_paths = self.sink_paths.get(key, {})
            # CT (IFC-2) transitive closure, PARALLEL to the sink-reaching
            # loop below: if an argument bound to a ct-sensitive callee
            # parameter carries source taint, that taint drives a variable-
            # time op inside the callee, so it is ct-sensitive HERE too.
            callee_ct = self.ct_sensitive.get(key, set())
            for pidx, arg_idx in perm.items():
                if (
                    pidx in callee_ct
                    and arg_idx < len(arg_srcs)
                    and arg_srcs[arg_idx]
                ):
                    self._cur_ct_sensitive |= arg_srcs[arg_idx]
            for pidx, arg_idx in perm.items():
                if (
                    pidx in sink_params
                    and arg_idx < len(arg_srcs)
                    and arg_srcs[arg_idx]
                ):
                    # Field-qualified to the callee's SUNK paths (the
                    # whole-value base always reaches; the content channel is
                    # observed only at the callee's sunk paths). No-op today.
                    reaching |= self._sink_reaching_arg(
                        e.args[arg_idx], arg_srcs[arg_idx],
                        callee_sink_paths.get(pidx), env, reaching,
                    )
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
            # The return-effect is a per-path map ``{field-path -> sources}``;
            # the whole-value call result unions the sources over EVERY path
            # (path-aware, whole-value granularity).
            for _rpath, srcs in self.return_effects.get(key, {}).items():
                for s in srcs:
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

        # Strict implicit-flow (IFC-1): a DIRECT built-in public sink makes
        # THIS body sink-reaching under its own control flow, independent of
        # the argument labels (the mere fact the sink runs leaks the branch
        # bit). Recognised TYPE-AWARELY: the receiver must resolve, via
        # ``_cur_value_types``, to a built-in sink capability AND ``(cap,
        # method)`` must be a public sink. This is why ``xs.get(i)`` (``xs``
        # -> ``List``, ``("List", "get")`` not a sink) stays clean -- the
        # by-name path below is deliberately NOT reused here.
        cap = self._receiver_capability_name(e)
        if cap in _SINK_CAPS and (cap, e.method) in _PUBLIC_SINKS:
            self._cur_reaches_sink_pc = True

        # CT (IFC-2) recognition site 5: the method-call form of the index /
        # compare checks (mirrors ``_check_ct_method_index`` /
        # ``_check_ct_method_compare``), type-scoped to the RESOLVED receiver
        # capability so ``xs.get(i)`` on a ``List`` is a data-dependent lookup
        # while an unrelated ``get`` is not misread. A ``_CT_INDEX_METHODS``
        # lookup makes the INDEX / key argument ct-sensitive; a
        # ``_CT_SHORT_CIRCUIT_METHODS`` byte-scan makes both the RECEIVER and
        # the listed argument positions ct-sensitive (the scan walks the
        # secret's bytes on either side).
        if cap is not None:
            idx_args = _CT_INDEX_METHODS.get((cap, e.method))
            if idx_args:
                for pos in idx_args:
                    if pos < len(arg_srcs):
                        self._cur_ct_sensitive |= arg_srcs[pos]
            cmp_args = _CT_SHORT_CIRCUIT_METHODS.get((cap, e.method))
            if cmp_args:
                self._cur_ct_sensitive |= recv_src
                for pos in cmp_args:
                    if pos < len(arg_srcs):
                        self._cur_ct_sensitive |= arg_srcs[pos]

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
            # Reflect the pushed value on a later READ of the receiver via
            # the branch-scoped CONTENT channel, NOT ``env`` (which is flat /
            # monotone across branches and doubles as the alias / mutation-
            # TARGET set: raising it leaked a push in one branch into a
            # mutually-exclusive sibling's read, and polluted the alias set
            # with the pushed value's taint). The content channel is isolated
            # per branch and deferred-unioned out. A bare-Ident receiver IS
            # the container (path ``()``); a field-chain receiver rooted at a
            # binding (``box.items.push`` on a LOCAL) records at the
            # container's field path, so a whole read-back of the local -- or
            # that field -- observes it while a disjoint sibling stays clean
            # (admissible now that the pass-to-callee gate is field-qualified,
            # Commit 1). A call- / index-rooted receiver has no keyable root
            # and stays the disclosed residual.
            recv_root = self._chain_root_name(e.receiver)
            if recv_root is not None:
                self._content_write(
                    recv_root,
                    self._content_path_key(
                        self._chain_field_path(e.receiver),
                    ),
                    injected,
                )
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
        # Strict implicit-flow (IFC-1) transitive closure: invoking ANY
        # candidate method that can itself run a public sink under its own
        # control flow makes THIS body sink-reaching too. Over the SAME
        # by-name candidate set the data channel uses, and -- unlike the
        # data loop below -- NOT gated on ``sink_params`` (a method can reach
        # a sink under its own control with no sink-reaching parameter).
        for key in candidate_keys:
            if self.sink_reaching_pc.get(key):
                self._cur_reaches_sink_pc = True
                break
        for key in candidate_keys:
            names, _decl, _is_method = self.callables[key]
            sink_params = self.summaries.get(key, set())
            if not sink_params:
                continue
            callee_caps = self.sink_caps.get(key, {})
            callee_sink_paths = self.sink_paths.get(key, {})
            # Index 0 is ``self`` -> the receiver.
            if 0 in sink_params and recv_src:
                # Field-qualified to the callee's ``self`` (param 0) sunk
                # paths; the whole-value base always reaches. No-op today.
                reaching |= self._sink_reaching_arg(
                    e.receiver, recv_src, callee_sink_paths.get(0),
                    env, reaching,
                )
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
                    # Field-qualified to the callee's ``full_pidx`` sunk
                    # paths; the whole-value base always reaches. No-op today.
                    reaching |= self._sink_reaching_arg(
                        e.args[arg_idx], arg_srcs[arg_idx],
                        callee_sink_paths.get(full_pidx), env, reaching,
                    )
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

        # CT (IFC-2) transitive closure across the (possibly
        # over-approximated) candidate methods, PARALLEL to the data channel
        # above: the receiver binds ``self`` (param 0) and the explicit args
        # follow. If an argument bound to a ct-sensitive callee parameter
        # carries source taint, that taint drives a variable-time op inside
        # the callee, so it is ct-sensitive HERE too. Over the SAME by-name
        # candidate union the data channel uses.
        for key in candidate_keys:
            names, _decl, _is_method = self.callables[key]
            callee_ct = self.ct_sensitive.get(key, set())
            if not callee_ct:
                continue
            if 0 in callee_ct and recv_src:
                self._cur_ct_sensitive |= recv_src
            explicit = names[1:] if names and names[0] == "self" else names
            perm = self._bind_explicit_args(e, explicit)
            for local_pidx, arg_idx in perm.items():
                full_pidx = (
                    local_pidx + 1
                    if names and names[0] == "self" else local_pidx
                )
                if (
                    full_pidx in callee_ct
                    and arg_idx < len(arg_srcs)
                    and arg_srcs[arg_idx]
                ):
                    self._cur_ct_sensitive |= arg_srcs[arg_idx]

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
            # ``sources`` is a per-path map; union over EVERY path (whole-value).
            for _rpath, srcs in sources.items():
                for s in srcs:
                    if s == INTERNAL_SECRET:
                        out.add(INTERNAL_SECRET)
                        continue
                    full_arg_idx = full_perm.get(s)
                    if full_arg_idx is not None and                             full_arg_idx < len(full_srcs):
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
        method cannot under-taint a built-in receiver's result.

        The trait-first ordering itself (a TRAIT-typed receiver takes the
        by-name union BEFORE the exact key, so the trait's OWN abstract
        empty-summary ``("method", trait, m)`` signature -- RC2, registered
        only to declare the return TYPE -- never short-circuits the union to
        its empty return-effect and fails the narrowing open) lives in the
        single shared ``result_effect_keys`` the two intra resolvers delegate
        to as well, so no site can drift on it. ``by_name`` is this pass's
        precomputed trait-EXCLUDED grouping; the fallback is ``()``."""
        if not isinstance(e.receiver, A.Ident):
            return ()
        tyname = self._cur_param_type_names.get(e.receiver.name)
        if tyname is None:
            return ()
        return result_effect_keys(
            tyname, e.method, self.return_effects,
            self._is_trait_type(tyname), by_name, (),
        )

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

    def _receiver_capability_name(self, e: A.MethodCall):
        """The built-in CAPABILITY TYPE name a method-call receiver
        resolves to via the walk's value-type map (``_cur_value_types``,
        seeded from the declared parameter types), or ``None`` when the
        receiver is not a plain Ident or its type is not statically known.

        TYPE-RESOLVED, never by-name: the strict implicit-flow direct-sink
        recognition uses it so ``xs.get(i)`` on a ``List`` receiver resolves
        to ``"List"`` (not a sink) rather than colliding with ``Net.get``.
        A by-name match would over-report the ``get`` / ``write`` / ``send``
        method-name collisions the built-in sink capabilities share with
        container / user methods."""
        if isinstance(e.receiver, A.Ident):
            return self._struct_prov_type(e.receiver.name)
        return None

    def _ct_operand_byte_scanned(self, operand: A.Expr) -> bool:
        """True when a short-circuit-compare OPERAND's static type resolves,
        via ``_cur_value_types`` (seeded from the declared parameter types),
        to String or List -- the byte-scan compare the inline
        ``_check_ct_compare`` scopes to. Only an Ident operand is resolved
        here (the summary tracks value types by name); a non-Ident operand
        (a field read, a call result) leaves the compare unflagged -- the
        disclosed non-Ident-operand-typing residual, so a later widening is a
        conscious choice, never a silent one."""
        if isinstance(operand, A.Ident):
            return self._struct_prov_type(operand.name) in ("String", "List")
        return False

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
            # false negative. FIELD-KEYED at the ``composed`` access path
            # (the caller's prefix to ``arg`` + the callee's field path), so
            # a read-back of a CLEAN SIBLING of the mutated field stays clean
            # while the mutated path and a whole read still observe it; a
            # ``None`` composed path (an aliased / unkeyable effect) takes the
            # whole-value carrier that EVERY read observes. JOINED (never
            # overwritten) so it accumulates straight-line and composes with
            # the deferred per-branch merge (``_content_merge``).
            self._content_write(root, composed, translated)
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
