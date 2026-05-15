"""SLSA Build L1 provenance attestation emission.

Emits an `in-toto Statement v1` envelope carrying a
`SLSA Provenance v1.0` predicate. The result is the standard
attestation document any SLSA-aware tool (cosign verify-blob,
slsa-verifier, in-toto attest) knows how to read.

What this provides:

- **Subject**: SHA-256 of the source .capa file under build.
- **Build definition**: a stable build-type URI identifying the
  Capa transpile-to-Python toolchain, the source filename as an
  external parameter, and the Capa version + target Python
  baseline as internal parameters.
- **Run details**: the builder's identity URI, an invocation ID
  derived deterministically from the source hash + timestamp,
  and start/finish timestamps.

What this does *not* provide (deliberate L1 scope):

- **No signing**. Signature lifts the attestation to L2; left to
  external tooling (cosign, sigstore) so the language stays
  independent of any specific signing service.
- **No byproduct hashes** for the transpiled Python output. The
  attestation is about the source, not the rendered output. Future
  work could add the transpiled-Python hash as a second subject.
- **No resolved-dependencies graph**. Capa has no package
  manager; the only meaningful dependency is the host Python
  interpreter, captured as an internal parameter.

The SLSA Provenance v1.0 spec:
https://slsa.dev/spec/v1.0/provenance
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional


# Stable URI identifying the Capa build process. Versioned so a
# future change in build semantics (e.g. a native backend) can
# bump the URI without breaking verifiers that pinned the v1
# shape.
CAPA_BUILD_TYPE = "https://capa-lang.org/build/transpile-to-python/v1"
CAPA_BUILDER_ID = "https://capa-lang.org/cli"

# Provenance predicate schema we emit.
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
INTOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"

# Python baseline; matches pyproject's requires-python.
CAPA_PYTHON_TARGET = "python>=3.10"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_provenance(
    source: str,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    started_on: Optional[str] = None,
    finished_on: Optional[str] = None,
    invocation_id: Optional[str] = None,
) -> dict[str, Any]:
    """Build an in-toto v1 statement with SLSA Provenance v1.0 predicate.

    ``source`` is the raw text of the .capa file under build (used
    to derive the subject's sha256 digest). ``started_on``,
    ``finished_on``, and ``invocation_id`` are exposed for
    deterministic test output; production callers should leave
    them as the defaults.
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if started_on is None:
        started_on = now
    if finished_on is None:
        finished_on = now

    source_bytes = source.encode("utf-8")
    source_digest = _sha256(source_bytes)
    bom_basename = os.path.basename(filename) or filename

    if invocation_id is None:
        # Deterministic-per-source: a verifier that re-runs the
        # build with the same input gets the same invocation ID.
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://capa-lang.org/provenance")
        invocation_id = str(uuid.uuid5(ns, f"{filename}:{source_digest}"))

    statement: dict[str, Any] = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": bom_basename,
                "digest": {"sha256": source_digest},
            },
        ],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": CAPA_BUILD_TYPE,
                "externalParameters": {
                    "source": bom_basename,
                },
                "internalParameters": {
                    "capaVersion": capa_version,
                    "target": CAPA_PYTHON_TARGET,
                },
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": {
                    "id": CAPA_BUILDER_ID,
                    "version": {
                        "capa": capa_version,
                    },
                },
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started_on,
                    "finishedOn": finished_on,
                },
                "byproducts": [],
            },
        },
    }
    return statement
