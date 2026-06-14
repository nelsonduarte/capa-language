"""Build-timestamp resolution for reproducible SBOM/attestation output.

The CycloneDX, SPDX, VEX, and SLSA-provenance emitters all stamp a
build time into their output. Left to ``datetime.now()`` that field
is the one remaining source of non-determinism: two builds of the
same source produce byte-different artefacts, defeating the
"rebuild and diff byte-for-byte" property the rest of the artefact
already has (the serialNumber, documentNamespace, and invocationId
are derived deterministically from the source digest).

This module honours the reproducible-builds.org ``SOURCE_DATE_EPOCH``
convention (https://reproducible-builds.org/specs/source-date-epoch/):
an integer of Unix UTC seconds. When it is set, every artefact in a
given invocation derives its timestamp from that instant, so the
output is byte-reproducible across runs and machines. When it is
unset the emitters fall back to wall-clock time, preserving the real
build time for interactive builds. Determinism is opt-in via the
standard env var, exactly as dpkg and other toolchains do it.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional


# The same UTC format string the emitters have always used. Kept
# here so the env-derived path and the wall-clock path produce
# byte-identical shapes.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_SOURCE_DATE_EPOCH = "SOURCE_DATE_EPOCH"


class SourceDateEpochError(ValueError):
    """``SOURCE_DATE_EPOCH`` is set but not a valid Unix-seconds integer.

    Raised rather than silently falling back to wall-clock time: a
    user who set the variable is asking for determinism, and a quiet
    fallback would be a trap that produces non-reproducible output
    while looking like it succeeded.
    """


def format_epoch(epoch: int) -> str:
    """Format a Unix-seconds instant as the canonical UTC timestamp."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
        _TIMESTAMP_FORMAT
    )


def resolve_build_timestamp(
    environ: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve the build timestamp for an SBOM/attestation invocation.

    Returns the formatted UTC timestamp string when
    ``SOURCE_DATE_EPOCH`` is set and valid, or ``None`` to signal that
    the emitters should fall back to wall-clock time. Resolve this
    once per CLI invocation and pass the result to every emitter so
    all four artefacts share exactly one instant (four separate
    ``now()`` calls would skew by sub-second amounts even without the
    env var).

    Raises :class:`SourceDateEpochError` when the variable is set but
    is not a non-negative integer.
    """
    env = os.environ if environ is None else environ
    raw = env.get(_SOURCE_DATE_EPOCH)
    if raw is None:
        return None
    raw = raw.strip()
    try:
        epoch = int(raw)
    except ValueError:
        raise SourceDateEpochError(
            f"{_SOURCE_DATE_EPOCH}={raw!r} is not an integer of Unix "
            f"UTC seconds"
        )
    if epoch < 0:
        raise SourceDateEpochError(
            f"{_SOURCE_DATE_EPOCH}={raw!r} must be non-negative"
        )
    return format_epoch(epoch)
