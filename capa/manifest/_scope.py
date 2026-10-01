"""What the ``unaudited_secret_sinks`` family is entitled to claim.

The per-function ``unaudited_secret_sinks`` list, the composed per-package
``attributed_unaudited_secret_sinks`` / ``unaudited_secret_sink_capabilities``
derived from it, and the ``no-secret-egress`` result evaluated over them are
one fact at three granularities. Its evidence is a subset of the explicit
secret-to-sink flows the warn-tier information-flow check REPORTED (those
whose sink capability the analysis attributed and that it saw inside a
function body), so an empty list is not a proof that nothing leaks.

This module is the ONE place that scope is stated. Every document that
carries the family (``--manifest``, its ``--manifest-digest`` form, the
``--compose-sbom`` product SBOM and the ``--conformance-report``) emits the
sentence verbatim under :data:`UNAUDITED_SECRET_SINKS_SCOPE_KEY`, and the
``docs/trust-model.md`` register entry is generated from it by
``tools/gen_trust_register.py``. Never copy the text elsewhere: import it.

The sentence states the field's universe as well as its evidence: which
sinks the check recognizes, which capabilities a record can name, which
policy capabilities it can never name, and where a record is charged. The
names in it are rendered from the analyzer's declared values below, never
typed into the template.
"""

from __future__ import annotations

from ..analyzer._ifc_tables import _PANIC_SINK_CAP, _PUBLIC_SINKS, _SINK_CAPS
from ..pkg._manifest import _CEILING_CAP_NAMES

# The top-level key each document carries the sentence under. Additive to
# every document's shape; no schema version moves for it.
UNAUDITED_SECRET_SINKS_SCOPE_KEY = "unaudited_secret_sinks_scope"

# The capabilities a record can name. Each of the recorder's call sites
# takes its capability from the sink table (directly, or through a callee
# summary whose attributions read the same table) or is the panic producer,
# which records the panic sink capability; ``tests/test_attestation_scope.py``
# pins those sites and that none of them types a capability name. Both
# values are the analyzer's own, read here.
UNAUDITED_SECRET_SINKS_RECORDABLE_CAPABILITIES: frozenset[str] = (
    _SINK_CAPS | {_PANIC_SINK_CAP}
)
# The capabilities a ``no-secret-egress`` policy may name (the ceiling set)
# that no record can ever carry: on these the policy's un-audited half has
# nothing to match. ``tests/test_attestation_scope.py`` pins the derivation
# and the current value, so a capability added to or moved between the
# declared sets re-renders the sentence and turns a pin red.
UNAUDITED_SECRET_SINKS_NEVER_RECORDABLE_POLICY_CAPABILITIES: frozenset[str] = (
    frozenset(_CEILING_CAP_NAMES) - UNAUDITED_SECRET_SINKS_RECORDABLE_CAPABILITIES
)
# The sink methods the check recognizes, ``Capability.method``, from the
# same table. The builtin ``panic`` is the one sink outside it; its record
# names ``_PANIC_SINK_CAP``.
UNAUDITED_SECRET_SINKS_SINK_METHODS: tuple[str, ...] = tuple(
    sorted(f"{cap}.{meth}" for cap, meth in _PUBLIC_SINKS)
)


def _name_list(names, last_joiner: str) -> str:
    """``names`` sorted and joined with ``", "``, with ``last_joiner``
    before the last one. Refuses an empty set: a clause rendered over no
    name would read as a statement about nothing, so the clause that names
    the set must be re-derived instead."""
    items = sorted(names)
    if not items:
        raise ValueError(
            "the unaudited_secret_sinks scope sentence would render an empty "
            "name set; re-derive the clause that names it",
        )
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + last_joiner + items[-1]


# The sentence. Every clause is load-bearing and pinned by
# ``tests/test_attestation_scope.py``, which also holds it to naming no
# tier as covering anything and to carrying no verdict vocabulary. Every
# capability and method name in it is rendered from the values above; the
# template's literals name none (pinned), so a change to a declared table
# or to the panic sink capability re-renders the sentence. The prose
# clauses are held by member pins over the test corpus, which turn red
# when a member's records or policy results move.
UNAUDITED_SECRET_SINKS_SCOPE = (
    "unaudited_secret_sinks lists ONLY the explicit secret-to-sink flows the "
    "warn-tier information-flow check REPORTED for this function and "
    "RECORDED with a sink capability (a @secret value passed as a sink "
    "argument, or to a callee parameter whose sink capability the analysis "
    "attributed, with no declassify); a reported flow whose sink capability "
    "the analysis did not attribute is not recorded, and neither is one "
    "reported outside every function body (a module-level const "
    "initializer). Every per-package value derived from it inherits this "
    "scope. The check recognizes as sinks only the built-in methods "
    + _name_list(UNAUDITED_SECRET_SINKS_SINK_METHODS, ", ")
    + " and the panic builtin (recorded as "
    + _PANIC_SINK_CAP
    + " whether or not the function holds "
    + _PANIC_SINK_CAP
    + "); through a callee it matches a sink by method name, not receiver "
    "type, so another type's method of the same name can be recorded under "
    "that sink's capability, and a recorded name is not evidence that the "
    "package holds that capability. Any other operation is outside this "
    "field, so a recorded capability is always one of "
    + _name_list(UNAUDITED_SECRET_SINKS_RECORDABLE_CAPABILITIES, ", ")
    + ", and a no-secret-egress policy that names only "
    + _name_list(UNAUDITED_SECRET_SINKS_NEVER_RECORDABLE_POLICY_CAPABILITIES, " or ")
    + " has nothing in this field to match (its declassify co-residence "
    "check still applies to those names). A flow is recorded against the "
    "function in whose body the check saw the @secret value, and that "
    "function's package: at the CALLER for a @secret argument whose callee "
    "sink the analysis attributed, inside the callee for a parameter or "
    "field the callee declares @secret; one flow may be recorded against "
    "the caller, the callee or both, and a policy scoped to a package sees "
    "only the records charged to that package. An empty list is NOT a proof "
    "of absence in either direction: implicit (control-flow) flows are "
    "never recorded at any tier, including under @strict_ifc; the explicit "
    "check itself has documented misses (SECURITY.md and its advisories) "
    "and that list is not closed; a function refused under @strict_ifc "
    "produces no artifact, and an accepted @strict_ifc function can still "
    "leak; and a manifest built without the analysis result carries an "
    "empty list by construction. Read [] as 'the warn-tier explicit check "
    "recorded nothing', never as 'cannot leak'."
)
