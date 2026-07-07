"""Canonical, hashable manifest substrate (composition S1).

The human-readable ``build_manifest`` dict (see :mod:`._funrec`) is
reproducible (SOURCE_DATE_EPOCH, ``program_source_digest``, uuid5) but
it is emitted with ``json.dumps(..., indent=2)`` and NO ``sort_keys``,
so two semantically-identical manifests built with a different dict
key-insertion order serialise to different bytes. That makes the
manifest impossible to content-hash or sign reliably.

This module adds a CANONICAL byte form of the manifest and a content
digest over those bytes, without touching the pretty output. It is the
substrate that composed SBOMs (S2) and signed capability diffs
(feature #2) both need: a stable, content-addressable manifest.

Canonicalisation scheme (Decision 5 of the composition design). The
manifest is JSON with only strings, integers, booleans, ``null``, and
nested objects / arrays -- no floats, so the ECMAScript number
serialisation that makes a full RFC-8785 (JSON Canonicalization Scheme)
implementation heavy is never exercised. A recursive key sort with
fixed separators is therefore both sufficient and dependency-free:

    json.dumps(obj, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False)

``sort_keys`` sorts object member names at EVERY nesting depth, so the
result is byte-identical for semantically-equal manifests regardless of
the order the builder happened to insert keys. Array order is preserved
because it is semantic (the manifest already sorts the lists whose order
is not). The bytes are UTF-8 (``ensure_ascii=False``), matching the
reproducible-builds convention that the artefact is UTF-8 text. The
scheme is versioned via :data:`CANONICALIZATION_SCHEME` so a future
switch to strict RFC-8785 is a visible, verifiable change.

The ``capa-jcs-sorted-v1`` scheme is UNICODE-NORMALIZATION-AGNOSTIC: it
canonicalises strings as authored (their bytes), so two strings that
differ only in NFC vs NFD normalisation yield different canonical bytes
and different digests. This is a known, accepted limitation to weigh in
any future RFC-8785 decision.

The content digest is ``sha256`` over those canonical bytes, reusing
:func:`._funrec._sha256_text`. It is SELF-REFERENCE-FREE: when a
manifest already carries the :data:`CONTENT_INTEGRITY_KEY` envelope, the
envelope is stripped before hashing, so attaching the digest never
changes the digest.

The envelope also carries a DETACHED-SIGNATURE slot: the algorithm, the
signature value, and a key id, all ``null`` when unsigned. Consistent
with the SLSA-L1 posture, the compiler holds no keys and never signs;
an external signer fills the slot over the digest recorded alongside it.
Key custody is out of scope here.
"""

from __future__ import annotations

import json
from typing import Any

from ._funrec import _sha256_text


# The canonicalisation scheme identifier, recorded in the content
# envelope so a verifier knows exactly how the digest bytes were
# produced. Bump this if the scheme ever changes (e.g. a move to a
# strict RFC-8785 JCS implementation).
CANONICALIZATION_SCHEME = "capa-jcs-sorted-v1"

# The digest algorithm over the canonical bytes. sha256, matching every
# other digest the manifest already derives (program_source_digest, the
# uuid5 seeds).
DIGEST_ALGORITHM = "sha256"

# Top-level key under which the content digest + signature slot live
# when attached to a manifest. Excluded from the digest computation so
# the digest is self-reference-free.
CONTENT_INTEGRITY_KEY = "content_integrity"


def canonical_json(obj: Any) -> str:
    """Canonical JSON text of ``obj``: recursively key-sorted, fixed
    separators, UTF-8, no insignificant whitespace.

    Byte-identical (once UTF-8 encoded) for any two semantically-equal
    objects regardless of dict key-insertion order. See the module
    docstring for the scheme rationale.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        # Fail closed on NaN / Infinity. The manifest is provably
        # float-free today, so this is latent insurance: if a float
        # NaN/Inf ever reaches the canonicalizer it would otherwise emit
        # the non-standard, silently non-canonical ``NaN`` / ``Infinity``
        # tokens. For a correctness-critical primitive that is the trust
        # root for signing / diffing / composition, a loud ValueError
        # beats invalid output.
        allow_nan=False,
    )


def canonical_bytes(obj: Any) -> bytes:
    """UTF-8 canonical bytes of ``obj`` (see :func:`canonical_json`).
    These are the exact bytes the content digest is taken over."""
    return canonical_json(obj).encode("utf-8")


def _without_envelope(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return ``manifest`` without the content-integrity envelope, so
    the digest is computed over the bare manifest and stays stable
    whether or not the envelope is already attached."""
    if CONTENT_INTEGRITY_KEY not in manifest:
        return manifest
    return {
        k: v for k, v in manifest.items() if k != CONTENT_INTEGRITY_KEY
    }


def manifest_digest(manifest: dict[str, Any]) -> str:
    """Hex ``sha256`` content digest over the canonical bytes of
    ``manifest``, excluding any content-integrity envelope already on
    it (self-reference-free). This hex string is the thing an external
    signer signs."""
    return _sha256_text(canonical_json(_without_envelope(manifest)))


def content_integrity_block(manifest: dict[str, Any]) -> dict[str, Any]:
    """Build the ``content_integrity`` envelope for ``manifest``: the
    canonicalisation scheme, the content digest, and a detached-signature
    slot.

    The digest is over the canonical bytes of the manifest WITHOUT this
    envelope. The signature slot is empty (all ``null``): the compiler
    does not hold keys and never signs (SLSA-L1 posture); an external
    signer fills ``signature.algorithm`` / ``signature.value`` /
    ``signature.key_id`` over ``digest.value``."""
    return {
        "canonicalization": CANONICALIZATION_SCHEME,
        "digest": {
            "algorithm": DIGEST_ALGORITHM,
            "value": manifest_digest(manifest),
        },
        # Detached-signature slot. Null == unsigned. An external signer
        # signs digest.value above and records the result here; the
        # compiler performs no key custody or signing.
        "signature": {
            "algorithm": None,
            "value": None,
            "key_id": None,
        },
        "note": (
            "content_integrity is computed over the canonical bytes of "
            "this manifest with the content_integrity key removed. To "
            "verify: drop content_integrity, re-serialise with the named "
            "canonicalization, sha256, and compare to digest.value. To "
            "sign: sign digest.value and fill the signature slot; the "
            "compiler holds no keys and never signs (SLSA-L1)."
        ),
    }


def canonical_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Return ``manifest`` with a fresh content-integrity envelope
    attached under :data:`CONTENT_INTEGRITY_KEY`.

    A previously-attached envelope is discarded and recomputed, so the
    operation is idempotent: the digest is always taken over the bare
    manifest. The returned dict is a shallow copy; the caller's manifest
    is left untouched."""
    bare = _without_envelope(manifest)
    out = dict(bare)
    out[CONTENT_INTEGRITY_KEY] = content_integrity_block(bare)
    return out
