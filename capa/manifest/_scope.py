"""What the ``unaudited_secret_sinks`` family is entitled to claim.

The per-function ``unaudited_secret_sinks`` list, the composed per-package
``attributed_unaudited_secret_sinks`` / ``unaudited_secret_sink_capabilities``
derived from it, and the ``no-secret-egress`` result evaluated over them are
one fact at three granularities. Its evidence is a subset of the explicit
secret-to-sink flows the warn-tier information-flow check REPORTED (those
whose sink capability the analysis attributed), so an empty list is not a
proof that nothing leaks.

This module is the ONE place that scope is stated. Every document that
carries the family (``--manifest``, its ``--manifest-digest`` form, the
``--compose-sbom`` product SBOM and the ``--conformance-report``) emits the
sentence verbatim under :data:`UNAUDITED_SECRET_SINKS_SCOPE_KEY`, and the
``docs/trust-model.md`` register entry is generated from it by
``tools/gen_trust_register.py``. Never copy the text elsewhere: import it.
"""

from __future__ import annotations

# The top-level key each document carries the sentence under. Additive to
# every document's shape; no schema version moves for it.
UNAUDITED_SECRET_SINKS_SCOPE_KEY = "unaudited_secret_sinks_scope"

# The sentence. Every clause is load-bearing and pinned by
# ``tests/test_attestation_scope.py``, which also holds it to naming no
# tier as covering anything and to carrying no verdict vocabulary.
UNAUDITED_SECRET_SINKS_SCOPE = (
    "unaudited_secret_sinks lists ONLY the explicit secret-to-sink flows the "
    "warn-tier information-flow check REPORTED for this function and "
    "RECORDED with a sink capability (a @secret value passed as a sink "
    "argument, or to a callee parameter whose sink capability the analysis "
    "attributed, with no declassify); a reported flow whose sink capability "
    "the analysis did not attribute is not recorded. Every per-package value "
    "derived from it inherits this scope. An empty list is NOT a proof of "
    "absence in either direction: implicit (control-flow) flows are never "
    "recorded at any tier, including under @strict_ifc; the explicit check "
    "itself has documented misses (SECURITY.md and its advisories); a "
    "function refused under @strict_ifc produces no artifact, and an "
    "accepted @strict_ifc function can still leak; and a manifest built "
    "without the analysis result carries an empty list by construction. "
    "Read [] as 'the warn-tier explicit check recorded nothing', never as "
    "'cannot leak'."
)
