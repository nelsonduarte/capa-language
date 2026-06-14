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
import re
from datetime import datetime, timezone
from typing import Optional


# The same UTC format string the emitters have always used. Kept
# here so the env-derived path and the wall-clock path produce
# byte-identical shapes.
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

_SOURCE_DATE_EPOCH = "SOURCE_DATE_EPOCH"

# reproducible-builds.org mandates a plain decimal integer. Python's
# ``int()`` is more permissive than that spec (it accepts a leading
# ``+``, underscore digit-grouping, and other bases via prefixes), so
# accepting whatever ``int()`` parses would let one toolchain produce a
# timestamp another rejects, defeating cross-toolchain reproducibility.
# Pin the grammar to a canonical decimal: ``0`` alone, or a non-zero
# leading digit followed by more digits. A leading zero (``08``) is an
# octal-looking ambiguity other toolchains may read differently, so it
# is rejected too.
_STRICT_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")


class SourceDateEpochError(ValueError):
    """``SOURCE_DATE_EPOCH`` is set but not a valid Unix-seconds integer.

    Raised rather than silently falling back to wall-clock time: a
    user who set the variable is asking for determinism, and a quiet
    fallback would be a trap that produces non-reproducible output
    while looking like it succeeded.
    """


def _format_epoch(epoch: int) -> str:
    """Format a Unix-seconds instant as the canonical UTC timestamp.

    Raises :class:`SourceDateEpochError` when ``epoch`` is a
    non-negative integer that nonetheless falls outside the range
    ``datetime`` can represent: very large values (beyond a C ``time_t``
    or past year 9999) make ``datetime.fromtimestamp`` raise
    ``OverflowError``/``OSError``/``ValueError`` depending on the
    platform. We convert those into the same controlled error every
    other invalid value gets, so the caller never sees a raw traceback.
    """
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime(
            _TIMESTAMP_FORMAT
        )
    except (OverflowError, OSError, ValueError):
        raise SourceDateEpochError(
            f"{_SOURCE_DATE_EPOCH}={epoch} is out of the representable "
            f"date range"
        )


def resolve_build_timestamp(
    environ: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Resolve the build timestamp for an SBOM/attestation invocation.

    Returns the formatted UTC timestamp string when
    ``SOURCE_DATE_EPOCH`` is set and valid, or ``None`` to signal that
    the emitters should fall back to wall-clock time. A single CLI
    invocation derives every timestamp it emits from this one instant,
    and four separate invocations (one per artefact) with the same
    ``SOURCE_DATE_EPOCH`` therefore agree.

    Raises :class:`SourceDateEpochError` when the variable is set but
    is not a plain non-negative decimal integer within the
    representable date range.
    """
    env = os.environ if environ is None else environ
    raw = env.get(_SOURCE_DATE_EPOCH)
    if raw is None:
        return None
    raw = raw.strip()
    if not _STRICT_DECIMAL.match(raw):
        raise SourceDateEpochError(
            f"{_SOURCE_DATE_EPOCH}={raw!r} is not a plain non-negative "
            f"decimal integer of Unix UTC seconds"
        )
    return _format_epoch(int(raw))
