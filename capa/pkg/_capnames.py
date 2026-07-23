"""The vocabulary a ``[capabilities].max`` ceiling may draw its names from.

A ceiling names the capabilities a package (and its whole transitive
subtree) is allowed to reach. Until this module existed the accepted
vocabulary was the built-in capability set and nothing else, which made
a package that declares a ``capability`` of its own UNSATISFIABLE: the
composed authority carries the user-defined name, so a ceiling that
omits it fails with an ``exceeds`` violation, and a ceiling that names
it was refused at parse time. Both spellings red, no third one.

WHERE THE VALIDATION LIVES, AND WHY IT IS STILL THE PARSER.

The obvious alternative is to defer the unknown-name refusal to check
time, where the flattened module knows exactly which ``capability``
declarations are in scope. That is more precise and it is WRONG here,
because the module in scope is the import closure OF ONE ENTRY POINT.
``capa --check-capabilities`` is run per entry point (capa_claimdesk
runs it over sixteen), and a capability declared in a module that a
given entry does not import would be absent from that entry's closure.
The same manifest would then be valid under ``main.capa`` and refused
under ``money.capa``. A ceiling is a property of the PACKAGE; its
vocabulary has to be one too.

So the parser gains access to the declared set instead, by reading it
from the place that is stable no matter which entry point is compiled:
the package's own source tree, ``vendor/`` included. That keeps the
diagnostic where the mistake is (the manifest, named by path, on every
command that reads it) instead of turning a config typo into a ceiling
violation that only surfaces under one flag.

WHY A LEXER SCAN, NOT A REGEX. This vocabulary is an ALLOW-LIST FOR
NAMES, not an authority computation. A name in ``max`` grants nothing
by itself: the ceiling check compares the COMPOSED capability set
against ``max``, so a name no package ever introduces permits nothing.
The check exists to stop a typo from silently widening the ceiling. It
is tempting to answer "which capabilities does this package declare?"
with a regex over the raw source, and a first cut did; a regex gets two
things wrong that the lexer already gets right, so this reuses the
lexer's TOKEN STREAM. A capability is a ``capability`` KEYWORD token
followed by an IDENT token, read straight off ``Lexer.lex()``:

  * comments are stripped by the lexer, so a ``capability Ghost`` inside
    a ``/* ... */`` block comment (or a ``//`` line comment) contributes
    NOTHING, where a text regex would have to re-implement every comment
    form to avoid a phantom name in the vocabulary;
  * identifier tokens follow the real IDENT grammar (the lexer accepts
    any ``str.isalpha`` / ``isalnum`` start/continue, Unicode included),
    so a ``capability Café`` is seen exactly as the parser sees it,
    where an ASCII-only regex would silently drop it and reintroduce the
    unsatisfiable trap this module exists to remove.

Running the full PARSER here would be a step too far the other way:
``capa.manifest._compose`` reports a dependency whose ``capa.toml``
raises as authority-unknown, and a per-declaration parse of a
dependency's ``.capa`` would couple manifest reading to that file's full
grammar. The lexer is the right rung: it settles comments and the
identifier grammar (the two things a regex botched) without taking a
position on statement or item structure.

THE NOT-YET-INSTALLED CASE. A consumer may legitimately name a
capability its DEPENDENCY declares (capa_claimdesk names ``Logger``,
which capa_log defines). Before ``capa install`` runs, that source is
not on disk yet, and refusing the manifest then would make the package
impossible to install: ``capa install`` reads the very manifest it is
about to satisfy. So the refusal is armed only when the package's
declared product dependencies are all materialised on disk; with a
missing one the vocabulary is admittedly incomplete and an unrecognised
name is carried rather than refused. The package is not thereby waved
through: a package with an unresolvable dependency composes as
authority-unknown TOP and its ceiling fails closed anyway, unless it
declared ``allow_unknown = true``.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from ..errors import LexerError
from ..lexer import Lexer
from ..tokens import TokenKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ._manifest import Dependency

# Structural tokens the lexer inserts around content: newlines and the
# indentation frame, plus the end marker. Filtered out when checking that
# a candidate name is a lone identifier.
_STRUCTURAL_TOKENS = frozenset({
    TokenKind.NEWLINE,
    TokenKind.INDENT,
    TokenKind.DEDENT,
    TokenKind.EOF,
})

# Cap on how many files the scan reads, so a package tree with a large
# vendored blob cannot turn a manifest read into an unbounded one. The
# scan only runs when a ceiling actually names a non-built-in.
_MAX_SCANNED_FILES = 20000


def is_capability_name(candidate: str) -> bool:
    """True when ``candidate`` is a single identifier under the LEXER's
    real IDENT grammar, i.e. something that could name a capability.

    Used to separate a malformed ``max`` entry (``"Net Fs"``, ``""``,
    ``"1cap"``) from a well-formed name whose existence is then checked
    against the package's declarations. Delegating to the lexer rather
    than an ASCII regex is what lets a Unicode-named capability
    (``capability Café``) be named in a ceiling at all: the lexer accepts
    the same ``str.isalpha`` / ``isalnum`` identifier the parser does.

    A keyword (``capability``), a wildcard (``_``), or anything that
    lexes to more than one significant token is not a capability name."""
    try:
        tokens = Lexer(candidate).lex()
    except LexerError:
        return False
    significant = [t for t in tokens if t.kind not in _STRUCTURAL_TOKENS]
    return (
        len(significant) == 1
        and significant[0].kind == TokenKind.IDENT
        and significant[0].text == candidate
    )


def _capabilities_in_source(text: str) -> set[str]:
    """The capability names declared in one ``.capa`` source, read off the
    lexer's token stream: each ``capability`` keyword token immediately
    followed by an IDENT names a declaration.

    Comments never reach the token stream, so a ``capability`` mention in
    a ``//`` or ``/* */`` comment contributes nothing. A source that does
    not lex declares nothing this scan can trust; such a package will not
    compile, and its ceiling fails at analysis, so it is not the
    unsatisfiable-name case this vocabulary guards."""
    try:
        tokens = Lexer(text).lex()
    except LexerError:
        return set()
    names: set[str] = set()
    for i, tok in enumerate(tokens):
        if tok.kind is TokenKind.KW_CAPABILITY and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if nxt.kind is TokenKind.IDENT:
                names.add(nxt.text)
    return names


def _scan_dir(pkg_dir: Path) -> frozenset[str]:
    """Every capability declared by ``.capa`` source under ``pkg_dir``.

    Never raises: an unreadable file is skipped, because this runs inside
    ``read_manifest`` and a manifest read that fails is interpreted
    elsewhere as a claim about a dependency's authority."""
    names: set[str] = set()
    scanned = 0
    try:
        for src in pkg_dir.rglob("*.capa"):
            scanned += 1
            if scanned > _MAX_SCANNED_FILES:  # pragma: no cover - defensive
                break
            try:
                text = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            names.update(_capabilities_in_source(text))
    except OSError:  # pragma: no cover - defensive
        pass
    return frozenset(names)


def _dependency_dir(manifest_dir: Path, dep: "Dependency") -> Path:
    """The directory a dependency's source would live in. Mirrors the
    candidate-directory rule ``capa.manifest._compose`` uses
    (``vendor/<name>`` for a git dep, the declared path for a path dep)
    without importing it: this runs in the manifest parser, below that
    layer."""
    if dep.is_path and dep.path is not None:
        raw = (manifest_dir / dep.path).resolve()
        return raw if raw.is_dir() else raw.parent
    return manifest_dir / "vendor" / dep.name


def ceiling_vocabulary(
    manifest_dir: Path, dependencies: Iterable["Dependency"],
) -> tuple[frozenset[str], bool]:
    """``(declared capability names, the vocabulary is complete)``.

    The names come from the package's own tree, which already contains
    ``vendor/`` and so covers its git dependencies, plus each PATH
    dependency's directory, which sits outside the tree by construction.
    Dev-dependencies are not consulted for completeness, exactly as they
    are excluded from the product DAG.

    ``complete`` is False when a declared product dependency has no
    directory on disk. The caller must not refuse an unrecognised name
    then: the source that would have declared it is simply not vendored
    yet, and ``capa install`` reads the very manifest it is about to
    satisfy."""
    roots: list[Path] = [manifest_dir]
    complete = True
    for dep in dependencies:
        cand = _dependency_dir(manifest_dir, dep)
        try:
            present = cand.is_dir()
        except OSError:  # pragma: no cover - defensive
            present = False
        if not present:
            complete = False
        elif dep.is_path:
            # A git dep already lives under ``manifest_dir/vendor``; a
            # path dep can be anywhere, so it needs its own walk.
            roots.append(cand)
    names: set[str] = set()
    for root in roots:
        names |= _scan_dir(root)
    return frozenset(names), complete
