"""SLSA Build L1 provenance attestation emission.

Emits an `in-toto Statement v1` envelope carrying a
`SLSA Provenance v1.0` predicate. The result is the standard
attestation document any SLSA-aware tool (cosign verify-blob,
slsa-verifier, in-toto attest) knows how to read.

What this provides:

- **Subject**: SHA-256 of every linked source .capa file. A
  single-file build yields one subject (the root); a multi-file
  build yields one subject per module (root plus every imported
  file), so the attestation covers the whole source surface and a
  rewritten imported module changes the statement.
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

from ._funrec import (
    _display_path,
    _identifier_seed,
    display_filename,
)


# Stable URI identifying the Capa build process. Versioned so a
# future change in build semantics (e.g. a native backend) can
# bump the URI without breaking verifiers that pinned the v1
# shape.
CAPA_BUILD_TYPE = "https://capa-language.com/build/transpile-to-python/v1"
CAPA_BUILDER_ID = "https://capa-language.com/cli"

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
    sources: Optional[dict[str, str]] = None,
) -> dict[str, Any]:
    """Build an in-toto v1 statement with SLSA Provenance v1.0 predicate.

    ``source`` is the raw text of the root .capa file under build.
    ``sources`` is the loader's path -> text map for EVERY linked
    module; when supplied the statement carries one subject per
    source file (each with its own sha256, ordered deterministically
    by display path) so an attestation covers the whole program, not
    just its root (audit 2026-06-17: rewriting an imported module
    must change the attestation). ``started_on``, ``finished_on``,
    and ``invocation_id`` are exposed for deterministic test output;
    production callers should leave them as the defaults.
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if started_on is None:
        started_on = now
    if finished_on is None:
        finished_on = now

    # Seed the invocation ID from the display form of the filename
    # (root-relative; the basename for the root file) plus a digest
    # covering EVERY linked module (see ``_identifier_seed``), never
    # the raw CLI argument: the raw form varies with the invocation
    # style (relative vs absolute, cwd) and across machines, which
    # would break the "re-run the build, get the same attestation"
    # property between two builders.
    display = display_filename(filename)
    bom_basename = os.path.basename(display) or display

    if invocation_id is None:
        # Deterministic-per-program: a verifier that re-runs the
        # build with the same input gets the same invocation ID.
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://capa-language.com/provenance")
        invocation_id = str(
            uuid.uuid5(ns, _identifier_seed(filename, source, sources))
        )

    # One subject per linked source file, sorted by display path for
    # determinism. A single-file build (no ``sources`` map) keeps the
    # historical single-subject shape under the root's basename.
    subjects: list[dict[str, Any]]
    if sources:
        subjects = []
        ordered = sorted(
            sources.items(),
            key=lambda kv: _display_path(kv[0], filename),
        )
        for path, text in ordered:
            # Use the full root-relative display path (not the bare
            # basename) so two modules sharing a basename in different
            # subdirectories stay distinct subjects.
            disp = _display_path(path, filename)
            subjects.append({
                "name": disp,
                "digest": {"sha256": _sha256(text.encode("utf-8"))},
            })
    else:
        subjects = [
            {
                "name": bom_basename,
                "digest": {"sha256": _sha256(source.encode("utf-8"))},
            },
        ]

    statement: dict[str, Any] = {
        "_type": INTOTO_STATEMENT_TYPE,
        "subject": subjects,
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
