"""Single source of truth for the module search path.

The compiler (``capa.cli``) and the language server (``capa.lsp``) both
resolve ``import`` statements through :class:`capa.loader.ModuleLoader`.
The loader takes two inputs derived from the environment and the
project's ``capa.toml``: the ordered list of search roots and the map of
declared PATH-dependency names to their on-disk directories. This module
computes both ONCE, via :func:`resolve_loader_paths`, so the editor
resolves imports exactly the way a compile would.

Before this module existed the LSP kept a poorer copy of the search-path
logic that read only ``CAPA_PATH`` and dropped ``dependency_roots``
entirely, so go-to-definition and diagnostics went silent on vendored /
path-dependency imports that ``capa --check`` on the same project
resolved fine. The compiler and the editor now share one construction and
cannot drift apart.

Fail-closed behaviour is unchanged from when these helpers lived in
``capa.cli``: a broken ``capa.toml`` raises
:class:`capa.pkg.BrokenRootManifestError` and an unverifiable ``./vendor``
raises :class:`capa.pkg.VendorVerificationError`. The compiler lets those
abort the run; the editor catches them and degrades to single-file
analysis so a mid-edit manifest never crashes a hover.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import NamedTuple


class LoaderPaths(NamedTuple):
    """The two search inputs a :class:`capa.loader.ModuleLoader` takes."""

    search_paths: list[Path]
    dependency_roots: dict[str, Path]


def resolve_loader_paths() -> LoaderPaths:
    """Compute the loader's search roots and declared-dependency map for
    the current working directory.

    This is the single construction both the compiler and the LSP call,
    so the two never disagree on how an ``import`` resolves. It mirrors
    the compiler's historical two-call sequence exactly: it evaluates
    :func:`_capa_search_paths` and :func:`_capa_dependency_roots`, each of
    which reads ``capa.toml`` in the cwd, so the result is byte-for-byte
    what the compiler computed before this was extracted.
    """
    return LoaderPaths(
        search_paths=_capa_search_paths(),
        dependency_roots=_capa_dependency_roots(),
    )


def _capa_search_paths() -> list[Path]:
    """Return additional module-search roots.

    Three sources, in priority order:

    1. ``CAPA_PATH`` environment variable. Entries are separated by
       ``os.pathsep`` (``;`` on Windows, ``:`` elsewhere). Empty
       entries and non-existent directories are silently skipped.

    2. ``capa.toml`` in the cwd. When present, the package
       manager's vendor dir (``./vendor``) and the parent of every
       ``path = "..."`` dependency are added so a project that
       declares its deps in the manifest does not need any
       environment variable.

    3. Conventional fallback: ``./libraries`` relative to the cwd,
       if it exists. Mirrors the ``node_modules`` / ``vendor``
       convention and supports projects that vendor by hand.

    Entries are de-duplicated so an explicit ``CAPA_PATH=libraries``
    does not appear twice. A typo in ``CAPA_PATH`` is silently skipped
    so it does not turn into a noisy error on every run. A broken
    ``capa.toml`` in the cwd, by contrast, ABORTS with
    :class:`BrokenRootManifestError`: it used to warn and continue, and
    continuing meant dropping the declared dependency ``path`` mapping,
    at which point a same-named directory on the search path shadowed
    the audited source. The gate in ``_main_dispatch`` normally refuses
    first; this is the second line, for any caller that reaches module
    resolution another way.
    """
    out: list[Path] = []
    seen: set[Path] = set()

    def _append(p: Path) -> None:
        try:
            resolved = p.resolve()
        except OSError:
            return
        if resolved in seen:
            return
        if p.is_dir():
            out.append(p)
            seen.add(resolved)

    raw = os.environ.get("CAPA_PATH", "")
    if raw:
        for entry in raw.split(os.pathsep):
            entry = entry.strip()
            if not entry:
                continue
            _append(Path(entry).expanduser())

    manifest_path = Path.cwd() / "capa.toml"
    if manifest_path.exists():
        from capa.pkg import read_root_manifest, verify_vendored_deps
        # Fail-closed. There is no ``except`` around this any more:
        # ``read_root_manifest`` raises ``BrokenRootManifestError`` on
        # every parse / read failure and ``verify_vendored_deps`` raises
        # ``VendorVerificationError`` on an unverifiable vendor tree.
        # Both propagate to ``main``, which names the file and refuses
        # (exit 2 for the manifest, 1 for the vendor tree).
        # The floor is NOT re-checked here: the gate in
        # ``_main_dispatch`` is the enforcing one, and a second call
        # printed the ``CAPA_IGNORE_CAPA_FLOOR`` warning twice.
        manifest = read_root_manifest(manifest_path)
        # Dev-dependencies resolve exactly like regular deps:
        # ``capa install`` vendors them into the same ./vendor
        # dir, so test files in the invocation root import them
        # with no extra configuration.
        all_deps = manifest.dependencies + manifest.dev_dependencies
        has_git = any(d.is_git for d in all_deps)
        if has_git:
            # PKG-1: re-verify the vendored git deps against
            # capa.lock BEFORE the loader is allowed to read
            # ./vendor. Fail-closed (raises VendorVerificationError)
            # on a missing lock, a missing / non-git vendor dir, a
            # SHA mismatch, or a declared git dep absent from the
            # lock. The check is the only re-validation of vendor/
            # on the build path; ``capa install`` / ``capa add``
            # never hit this function (they call install() directly)
            # so they are not subject to the circular pre-check.
            verify_vendored_deps(Path.cwd(), manifest)
            _append(Path.cwd() / "vendor")
        for d in all_deps:
            if d.is_path and d.path is not None:
                dep_path = (manifest.manifest_dir / d.path).resolve()
                _append(dep_path.parent)
        # NOTE: the parent of the project root is deliberately NOT
        # a search root. It used to be, to let a seed library whose
        # repository directory *is* the package resolve its own
        # ``import capa_csv.model`` lines. But an open search root
        # also SATISFIES imports that ./vendor cannot: an undeclared
        # transitive dependency resolved against an arbitrary
        # sibling directory that was never fetched, never verified,
        # never locked and never recorded in the SBOM, so the build
        # silently linked sources the provenance machinery never
        # saw. The self-reference is now served precisely, by name,
        # through ``_capa_dependency_roots``; anything else fails
        # closed with a plain "cannot resolve 'import ...'".

    # Conventional fallback. Cheap probe: only the cwd is consulted,
    # so this never escalates I/O for a project that does not use
    # the convention.
    _append(Path.cwd() / "libraries")

    return out


def _capa_dependency_roots() -> dict[str, Path]:
    """Map each declared PATH dependency's NAME to its resolved
    on-disk directory, plus the project's OWN name to its root.

    ``[dependencies.X] path = "vendor/other"`` maps ``X`` to the
    resolved ``<manifest-dir>/vendor/other``. The loader uses this to
    resolve ``import X.mod`` directly from the declared directory, so
    the declared ``path`` is honoured even when the directory's
    basename (``other``) differs from the dependency name (``X``).
    Without it the loader only tried ``<search-root>/X/mod.capa`` and
    silently ignored the declared path.

    ``[package].name`` maps to the manifest directory itself, which is
    what makes a package SELF-REFERENCE resolve: a seed library whose
    repository directory *is* the package (named ``capa_csv``, its
    modules importing one another as ``capa_csv.model``) reaches
    ``<root>/model.capa``. This is deliberately scoped to the one name
    the manifest declares, replacing the former "parent of the project
    root is a search root" fallback: that fallback resolved the
    self-reference, but it also let ANY same-named sibling directory
    on disk satisfy an import that ./vendor could not, linking sources
    that were never fetched, verified, locked or listed in the SBOM.
    A declared dependency of the same name wins, so the self-entry can
    never shadow a vendored or path-declared dep.

    Only path dependencies appear here (regular + dev, matching the
    search-path treatment). Git deps are vendored by name into
    ``./vendor`` and resolved through the search path, so they are
    intentionally excluded; no git verification runs on this cheap
    path (it never reads ``./vendor``). A MISSING ``capa.toml`` yields an
    empty map, so a project that declares nothing still resolves through
    the search-path fallback.

    A BROKEN ``capa.toml`` aborts. It used to yield an empty map, on the
    reasoning that ``_capa_search_paths`` had already warned about it.
    An empty map is precisely the dangerous value: it deletes the
    name-to-directory mapping that makes the declared ``path``
    authoritative, so ``import mylib.util`` stops resolving to the
    declared ``vendor/real/util.capa`` and falls through to whatever
    ``./mylib/`` happens to contain. That is a source substitution
    triggered by a typo, so it is refused.
    """
    roots: dict[str, Path] = {}
    manifest_path = Path.cwd() / "capa.toml"
    if not manifest_path.exists():
        return roots
    from capa.pkg import read_root_manifest
    manifest = read_root_manifest(manifest_path)
    all_deps = manifest.dependencies + manifest.dev_dependencies
    for d in all_deps:
        if d.is_path and d.path is not None:
            roots[d.name] = (manifest.manifest_dir / d.path).resolve()
    declared = {d.name for d in all_deps}
    if manifest.name and manifest.name not in declared:
        roots[manifest.name] = manifest.manifest_dir.resolve()
    return roots
