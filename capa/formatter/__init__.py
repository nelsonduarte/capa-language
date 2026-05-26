"""Capa source-code formatter.

The package is split into three layers plus a phase-4 dispatch
hook (currently disabled by default):

- :mod:`._lines` (v1 + v2): purely textual, line-level normalisation
  with an intra-line state machine for spacing. Never invokes the
  lexer or parser, so it is safe on malformed source. This is the
  current default for ``--fmt``.
- :mod:`._comments` (v3 phase 2): :class:`CommentMap` attachment
  pass that ties every plain ``//`` and ``/* */`` comment to an AST
  node, so the pretty-printer can re-emit them in the right place.
  Unit-tested in isolation.
- :mod:`._emit` (v3 phase 3): pretty-printer that walks the AST and
  emits canonical Capa source, optionally consulting the
  :class:`CommentMap` for comment placement. Unit-tested for
  structural AST roundtrip on the full ``examples/`` and
  ``evaluation/sbom_diff/`` corpus (71 files).
- Phase 4 (wiring): the AST-roundtrip pipeline is reachable via
  :func:`format_source_emit` but is NOT the default for
  :func:`format_source` yet. A corpus smoke run surfaced
  comment-ordering quirks (multiple leading comments on the same
  node can re-emit in non-source order in some shapes); fix lands
  before phase 4 promotes the pipeline to default. Until then,
  ``--fmt`` keeps the safe v1 + v2 behaviour.

Public entry points:

``format_source(text: str) -> str``
    Return the canonical formatting of ``text``. Currently the
    v1 + v2 line-level pipeline.

``is_formatted(text: str) -> bool``
    Cheap byte-exact comparison: ``True`` iff
    ``text == format_source(text)``.

``format_source_emit(text: str) -> str``
    Run the v3 AST-roundtrip pipeline directly. Raises on lex /
    parse failure. Available for callers that want to opt in to
    the pretty-printer's stricter canonicalisation.
"""

from __future__ import annotations

from ._lines import format_source as _format_source_lines
from ._emit import format_source_emit  # re-exported for opt-in callers


def format_source(text: str) -> str:
    """Apply the canonical Capa formatting to ``text``.

    Idempotent: applying it twice yields the same result as
    applying it once. Currently the v1 + v2 line-level pipeline;
    promotion to the AST-roundtrip pipeline waits on the
    comment-ordering fix described in this module's docstring.
    """
    return _format_source_lines(text)


def is_formatted(text: str) -> bool:
    """Return ``True`` iff ``text`` is already in canonical form."""
    return text == format_source(text)
