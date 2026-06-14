"""LF-canonical emission of verifiable artefacts to stdout.

The SBOM / attestation artefacts (``--manifest``, ``--cyclonedx``,
``--spdx``, ``--vex``, ``--provenance``) are sold as byte-reproducible:
"rebuild the same source on any machine and diff byte-for-byte". That
promise is broken by Python's platform newline translation. On Windows
``sys.stdout`` is a text stream in text mode, so every ``\n`` printed
through it is rewritten to ``\r\n``; on Linux it stays ``\n``. The same
artefact therefore leaves a Windows machine as CRLF and a Linux machine
as LF, so the two are not byte-identical even with ``SOURCE_DATE_EPOCH``
pinned.

:func:`emit_artifact` fixes this by writing the artefact's UTF-8 bytes
straight to ``sys.stdout.buffer`` (the underlying binary buffer), which
performs no newline translation, after normalising any ``\r\n`` /
lone ``\r`` to ``\n``. The result is LF on every OS.

Scope is deliberately narrow: only the verifiable artefacts go through
here. The stdout of a *running* Capa program (``--run``, ``--wasm
--run``), diagnostics, and human-readable reports keep ordinary
platform behaviour, because a program a user runs is not a reproducible
artefact.
"""

from __future__ import annotations

import sys


def _canonicalize_newlines(text: str) -> str:
    """Collapse ``\r\n`` and lone ``\r`` to ``\n``.

    The artefact builders produce ``\n``-only text today, but content
    can in principle carry a ``\r`` (e.g. a file name or doc comment
    copied from a CRLF source). Canonicalising here means a stray
    ``\r`` never reaches the binary buffer, so the byte stream is
    guaranteed LF-only regardless of input.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def emit_artifact(text: str, stream=None) -> None:
    """Write a verifiable artefact to *stream* (default ``sys.stdout``)
    with LF-canonical, platform-independent newlines, followed by a
    single trailing ``\n``.

    When the stream exposes a binary ``buffer`` (the real
    ``sys.stdout`` does), the UTF-8 bytes are written there directly,
    bypassing the text layer's platform newline translation. This is
    what makes the bytes identical on Windows and Linux.

    When the stream has no ``buffer`` (e.g. an ``io.StringIO`` under
    the test harness, which already stores ``\n`` verbatim), the
    canonicalised text is written as text. Either way the in-memory /
    on-disk representation of a ``\n`` is a single ``\n``, never
    ``\r\n``.
    """
    if stream is None:
        stream = sys.stdout
    payload = _canonicalize_newlines(text) + "\n"
    buffer = getattr(stream, "buffer", None)
    if buffer is not None:
        buffer.write(payload.encode("utf-8"))
        buffer.flush()
    else:
        stream.write(payload)
