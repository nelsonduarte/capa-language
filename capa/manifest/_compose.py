"""Composed capability SBOM (composition S2).

S1 made the single-program manifest canonical and content-addressable.
S2 turns "a manifest per program" into "a composed capability SBOM per
PRODUCT": it re-introduces the package boundary the loader flattens
away, walks the dependency tree, and rolls the capability surface up
bottom-up so a regulator can read "which packages in this product can
reach Net", not just "which functions in this one binary do".

The three moving parts, in order:

1. PER-PACKAGE ATTRIBUTION (post-flatten, Decision 1 of the design).
   The whole-program manifest is built exactly as ``--manifest`` builds
   it; then each function is attributed to its owning package by its
   source file. A file under a package's directory -- including
   ``vendor/<dep>`` for a vendored dependency -- belongs to that
   package; the DEEPEST enclosing package wins, so a function under
   ``vendor/a/vendor/b`` is attributed to ``b``, not ``a``. ``caps(P)``
   is the union of the (transitively-reachable) capabilities of the
   functions attributed to ``P``.

2. THE PACKAGE DAG. Built by reading the root ``capa.toml``'s declared
   ``[dependencies]`` and RECURSIVELY each resolvable dependency's OWN
   ``capa.toml`` under ``vendor/<name>`` -- the recursion ``capa
   install`` does not perform today. Edges are the declared
   dependencies. ``[dev-dependencies]`` are excluded: they are
   test/tooling-only and never part of the shipped product.

3. THE BOTTOM-UP JOIN over a lattice whose carrier is {capability set}
   PLUS a distinguished TOP element, "authority unknown / trusted
   boundary" (Decision 3, NON-NEGOTIABLE). ``composed(P) = caps(P)``
   joined over every dependency ``D`` with ``composed(D)``. A dependency
   that is DECLARED but NOT resolvable/analyzable -- no vendored
   directory, an absent/unreadable ``capa.toml``, or no Capa source (a
   native/non-Capa dependency) -- composes as TOP. A package whose own
   attributed functions cross ``Unsafe`` is TOP too: ``Unsafe`` can
   side-step the discipline, so the named capability set is no longer a
   sound upper bound (this is exactly why the single-program manifest
   drops ``provably_excluded`` on such a function). TOP DOMINATES every
   join: a composed set that includes a TOP child is itself marked
   ``authority_unknown`` and is NEVER shrunk (the concrete capabilities
   we DO know are still accumulated and shown). TOP is VISIBLY LABELLED
   in the output, never silently treated as the empty set. This honesty
   is the whole point: an unanalyzable subtree makes the PRODUCT
   authority-unknown, not dishonestly clean, which is what separates the
   composed SBOM from a scanner.

The composed artifact is itself content-addressable: it reuses the S1
canonical form (:mod:`._canonical`), carries no timestamps, and records
every path root-relative in POSIX form, so two builds of the same
product on different machines / working directories produce a
byte-identical artifact and an identical digest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .. import capa_ast as A
from ..lexer import SYNTHETIC_FILENAME


# Version of the COMPOSED-SBOM schema, independent of the per-program
# manifest ``SCHEMA_VERSION``. Bump on any incompatible shape change so
# a consumer can refuse a shape it does not recognise.
COMPOSED_SCHEMA_VERSION = 1


class ComposeError(Exception):
    """Raised when the composed SBOM cannot be produced soundly.

    Notably: no enclosing ``capa.toml`` package root, or an attribution
    key that maps to two different source files (the mis-attribution
    guard for mangled/private functions). We fail loud rather than emit
    a silently-wrong composition."""


# ---------------------------------------------------------------------------
# The composition lattice: {capability set} + a distinguished TOP element.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Authority:
    """A point in the composition lattice.

    ``caps`` is the set of capabilities KNOWN to be reachable. ``unknown``
    is the TOP flag: when true, authority BEYOND ``caps`` may exist and
    could not be ruled out (an unanalyzable dependency, or an
    Unsafe-crossing surface). ``reasons`` records WHY, so the flag is
    always visibly labelled and never a silent empty set.

    The join (:meth:`join`) unions the capability sets, ORs the unknown
    flags (TOP dominates), and unions the reasons. This makes TOP an
    absorbing element for the ``unknown`` component while still
    accumulating every concrete capability that was proven -- so a
    composed value with a TOP child is never SMALLER than its analyzable
    part."""

    caps: frozenset[str] = frozenset()
    unknown: bool = False
    # Each reason is (declared_in_package, dependency_or_package, why),
    # kept as a sorted, de-duplicated tuple so Authority stays hashable
    # and the join is order-independent (determinism).
    reasons: tuple[tuple[str, str, str], ...] = ()

    def join(self, other: "Authority") -> "Authority":
        merged_reasons = tuple(sorted(set(self.reasons) | set(other.reasons)))
        return Authority(
            caps=self.caps | other.caps,
            unknown=self.unknown or other.unknown,
            reasons=merged_reasons,
        )


# ---------------------------------------------------------------------------
# The package DAG.
# ---------------------------------------------------------------------------


@dataclass
class DepEdge:
    """One declared dependency edge from a package to a dependency.

    ``target_dir`` is the resolved package directory when the dependency
    is analyzable, else ``None``. ``resolved`` is the analyzability
    verdict; ``reason`` explains a ``False`` verdict (why the dependency
    composes as TOP)."""

    name: str
    target_dir: Optional[Path]
    resolved: bool
    reason: Optional[str]


@dataclass
class PackageNode:
    """One package in the product DAG, keyed by its (resolved) manifest
    directory. Capability attribution and the Unsafe verdict are filled
    in after the DAG is built."""

    name: str
    version: str
    manifest_dir: Path
    rel_path: str
    dep_edges: list[DepEdge] = field(default_factory=list)
    attributed_caps: frozenset[str] = frozenset()
    crosses_unsafe: bool = False


def _rel_display(path: Path, root_dir: Path) -> str:
    """Root-relative POSIX display of ``path`` (``"."`` for the root
    itself). A path outside the root tree keeps its absolute form -- it
    has no stable base, and "this came from outside the product tree" is
    information the auditor wants -- mirroring the single-program
    manifest's ``_display_path``."""
    try:
        rel = path.resolve().relative_to(root_dir.resolve())
    except (ValueError, OSError):
        return path.as_posix()
    return rel.as_posix() if rel.parts else "."


def _classify_dependency(
    pkg_dir: Path, dep: Any,
) -> tuple[Optional[Path], bool, Optional[str]]:
    """Decide whether a declared dependency is analyzable, returning
    ``(target_dir, resolved, reason)``.

    THE RESOLVABILITY RULE (what makes a dependency an authority-unknown
    TOP node). A dependency is resolved (analyzable) only when ALL hold:

    - a candidate package directory exists (``vendor/<name>`` for a git
      dep; the target directory for a path dep);
    - that directory holds a ``capa.toml`` file;
    - that ``capa.toml`` parses as a valid manifest;
    - the directory holds at least one ``.capa`` source file.

    Any failure returns ``resolved=False`` with a reason and composes as
    TOP: a git dep never vendored (``capa install`` not run), a
    native/non-Capa dependency (a directory with no ``capa.toml`` or no
    Capa source), or a corrupt manifest. We never treat such a
    dependency as the empty capability set."""
    from ..pkg import read_manifest
    from ..pkg import ManifestError

    if dep.is_path and dep.path is not None:
        raw = (pkg_dir / dep.path).resolve()
        cand = raw if raw.is_dir() else raw.parent
    else:
        cand = pkg_dir / "vendor" / dep.name

    if not cand.is_dir():
        return None, False, (
            "no vendored package directory (run `capa install`, or the "
            "dependency ships no Capa source)"
        )
    toml = cand / "capa.toml"
    if not toml.is_file():
        return cand, False, (
            "package directory has no capa.toml (native / non-Capa "
            "dependency; its authority cannot be derived)"
        )
    try:
        read_manifest(toml)
    except (ManifestError, OSError, ValueError):
        return cand, False, "capa.toml is unreadable or invalid"
    if not any(cand.glob("*.capa")):
        return cand, False, (
            "package has a capa.toml but no Capa source (native / "
            "non-Capa dependency; its authority cannot be derived)"
        )
    return cand, True, None


def build_package_dag(
    root_dir: Path,
) -> tuple[dict[Path, PackageNode], PackageNode]:
    """Build the product's package DAG rooted at ``root_dir`` (a
    directory holding ``capa.toml``).

    Reads the root ``capa.toml`` and RECURSIVELY each resolvable
    dependency's own ``capa.toml`` under ``vendor/<name>``. Only declared
    ``[dependencies]`` become edges (dev-dependencies are excluded from
    the product). Returns the node map (keyed by resolved manifest dir)
    and the root node. Cycles are handled by memoising on the resolved
    directory."""
    from ..pkg import read_manifest

    root_dir = root_dir.resolve()
    nodes: dict[Path, PackageNode] = {}

    def visit(pkg_dir: Path) -> PackageNode:
        pkg_dir = pkg_dir.resolve()
        if pkg_dir in nodes:
            return nodes[pkg_dir]
        manifest = read_manifest(pkg_dir / "capa.toml")
        node = PackageNode(
            name=manifest.name,
            version=manifest.version,
            manifest_dir=pkg_dir,
            rel_path=_rel_display(pkg_dir, root_dir),
        )
        # Register BEFORE recursing so a dependency cycle terminates.
        nodes[pkg_dir] = node
        for dep in manifest.dependencies:
            target, resolved, reason = _classify_dependency(pkg_dir, dep)
            node.dep_edges.append(DepEdge(dep.name, target, resolved, reason))
            if resolved and target is not None:
                visit(target)
        return node

    root = visit(root_dir)
    return nodes, root


# ---------------------------------------------------------------------------
# Post-flatten attribution.
# ---------------------------------------------------------------------------


def _function_files(module: A.Module) -> dict[tuple, str]:
    """Map each function's stable attribution key to the ABSOLUTE source
    file it was declared in.

    The key is ``(name, container, line, col)``: the loader-time
    (possibly mangled) name, the enclosing impl type (or ``None`` for a
    top-level function), and the declaration position. This lines up
    exactly with the per-function record ``--manifest`` emits, so a
    mangled/private function is attributed by the same identity the
    manifest keys on. ``fn.pos.filename`` is the file the loader lexed
    the declaration from -- the whole point of attribution -- so an
    imported function carries its OWN file, not the root's.

    A key that would map to two DIFFERENT files is a mis-attribution
    hazard; we raise :class:`ComposeError` rather than pick one
    silently."""
    out: dict[tuple, str] = {}

    def record(fn: A.FunDecl, container: Optional[str]) -> None:
        key = (fn.name, container, fn.pos.line, fn.pos.col)
        filename = fn.pos.filename or ""
        prev = out.get(key)
        if prev is not None and prev != filename:
            raise ComposeError(
                f"ambiguous attribution: function {fn.name!r} maps to both "
                f"{prev!r} and {filename!r}; cannot attribute soundly"
            )
        out[key] = filename

    for item in module.items:
        if isinstance(item, A.FunDecl):
            record(item, None)
        elif isinstance(item, A.ImplBlock):
            for m in item.methods:
                record(m, item.type_name)
    return out


def _owning_dir(filename: str, dirs_by_depth: list[Path]) -> Optional[Path]:
    """The DEEPEST package directory that encloses ``filename`` (so a
    nested ``vendor/a/vendor/b`` file is attributed to ``b``), or ``None``
    when the file is under no package (an external CAPA_PATH module, a
    built-in, or a synthetic position)."""
    if not filename or filename == SYNTHETIC_FILENAME:
        return None
    try:
        resolved = Path(filename).resolve()
    except OSError:
        return None
    for d in dirs_by_depth:
        try:
            resolved.relative_to(d)
            return d
        except ValueError:
            continue
    return None


def _attribute(
    module: A.Module,
    manifest: dict[str, Any],
    nodes: dict[Path, PackageNode],
    root_dir: Path,
) -> None:
    """Attribute every manifest function to its owning package node,
    filling each node's ``attributed_caps`` and ``crosses_unsafe``.

    A capability is attributed to the DEPENDENCY it originates in, not
    the root, because attribution keys on the function's own source file.
    A function under no package (external CAPA_PATH module, built-in,
    synthetic) is attributed to ``root_dir`` so its authority is never
    silently dropped from the product roll-up (soundness: over-attribute
    to the product, never lose a capability)."""
    keyfile = _function_files(module)
    dirs_by_depth = sorted(
        nodes.keys(), key=lambda d: len(d.parts), reverse=True,
    )

    caps: dict[Path, set[str]] = {d: set() for d in nodes}
    unsafe: dict[Path, bool] = {d: False for d in nodes}

    for rec in manifest["functions"]:
        line, col = _pos_line_col(rec["pos"])
        key = (rec["name"], rec["container"], line, col)
        filename = keyfile.get(key, "")
        owner = _owning_dir(filename, dirs_by_depth)
        if owner is None:
            owner = root_dir
        caps[owner] |= set(rec["transitively_reachable_capabilities"])
        if rec["has_unsafe"]:
            unsafe[owner] = True

    for d, node in nodes.items():
        node.attributed_caps = frozenset(caps[d])
        node.crosses_unsafe = unsafe[d]


def _pos_line_col(pos: str) -> tuple[int, int]:
    """Extract ``(line, col)`` from a manifest ``pos`` string
    (``<file>:<line>:<col>``). ``rsplit`` from the right so a Windows
    drive-letter colon in an absolute (out-of-tree) path never confuses
    the split."""
    parts = pos.rsplit(":", 2)
    return int(parts[-2]), int(parts[-1])


# ---------------------------------------------------------------------------
# Bottom-up composition + SBOM assembly.
# ---------------------------------------------------------------------------


def _compose_node(
    node: PackageNode,
    nodes: dict[Path, PackageNode],
    memo: dict[Path, Authority],
    in_progress: set[Path],
) -> Authority:
    """Roll ``node``'s subtree up bottom-up, with TOP domination."""
    if node.manifest_dir in memo:
        return memo[node.manifest_dir]
    own = _own_authority(node)
    if node.manifest_dir in in_progress:
        # Dependency cycle: the node's own authority is already being
        # accumulated on the enclosing path. Return it (never drop caps)
        # without recursing again.
        return own
    in_progress.add(node.manifest_dir)

    result = own
    for edge in node.dep_edges:
        if edge.resolved and edge.target_dir is not None:
            child = nodes[edge.target_dir.resolve()]
            result = result.join(
                _compose_node(child, nodes, memo, in_progress)
            )
        else:
            result = result.join(Authority(
                unknown=True,
                reasons=((node.name, edge.name, edge.reason or "unresolved"),),
            ))

    in_progress.discard(node.manifest_dir)
    memo[node.manifest_dir] = result
    return result


def _own_authority(node: PackageNode) -> Authority:
    """The package's OWN (non-transitive) authority: its attributed
    capabilities, plus a TOP mark when it crosses ``Unsafe``."""
    reasons: tuple[tuple[str, str, str], ...] = ()
    if node.crosses_unsafe:
        reasons = ((node.name, node.name, (
            "a function in this package crosses Unsafe; its capability "
            "set is not a sound upper bound (provably-excluded is dropped)"
        )),)
    return Authority(
        caps=node.attributed_caps,
        unknown=node.crosses_unsafe,
        reasons=reasons,
    )


def _reason_dicts(
    reasons: tuple[tuple[str, str, str], ...],
) -> list[dict[str, str]]:
    return [
        {"declared_in": a, "dependency": b, "reason": c}
        for (a, b, c) in reasons
    ]


def build_composed_sbom(
    module: A.Module,
    manifest: dict[str, Any],
    root_dir: Path,
    *,
    capa_version: Optional[str] = None,
) -> dict[str, Any]:
    """Build the composed product SBOM dict from an analyzed whole-program
    ``module``, its ``--manifest`` ``manifest`` dict, and the product's
    ``root_dir`` (the directory holding the root ``capa.toml``).

    The result is JSON-serialisable, timestamp-free, and canonicalisable
    with the S1 :func:`._canonical.canonical_manifest`. Every path is
    root-relative POSIX, so the artifact is byte-reproducible across
    machines and working directories."""
    if capa_version is None:
        from .. import __version__ as capa_version

    nodes, root = build_package_dag(root_dir)
    _attribute(module, manifest, nodes, root.manifest_dir)

    memo: dict[Path, Authority] = {}
    for node in nodes.values():
        _compose_node(node, nodes, memo, set())

    # Deterministic package ordering: by root-relative path, then name.
    ordered = sorted(nodes.values(), key=lambda n: (n.rel_path, n.name))

    packages: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, str]] = []
    for node in ordered:
        composed = memo[node.manifest_dir]
        own = _own_authority(node)
        packages.append({
            "name": node.name,
            "version": node.version,
            "path": node.rel_path,
            "attributed_capabilities": sorted(node.attributed_caps),
            "authority_unknown": own.unknown,
            "authority_unknown_reasons": _reason_dicts(own.reasons),
            "dependencies": sorted(e.name for e in node.dep_edges),
            "composed_capabilities": sorted(composed.caps),
            "composed_authority_unknown": composed.unknown,
        })
        for e in node.dep_edges:
            to_pkg = None
            if e.resolved and e.target_dir is not None:
                to_pkg = nodes[e.target_dir.resolve()].name
            edges.append({
                "from": node.name,
                "dependency": e.name,
                "to_package": to_pkg,
                "resolved": e.resolved,
                "reason": e.reason,
            })
            if not e.resolved:
                unresolved.append({
                    "declared_in": node.name,
                    "dependency": e.name,
                    "reason": e.reason or "unresolved",
                })

    edges.sort(key=lambda e: (e["from"], e["dependency"]))
    unresolved.sort(key=lambda u: (u["declared_in"], u["dependency"]))

    product = memo[root.manifest_dir]
    return {
        "capa_version": capa_version,
        "composed_schema_version": COMPOSED_SCHEMA_VERSION,
        "product": {"name": root.name, "version": root.version},
        "packages": packages,
        "edges": edges,
        "unresolved_dependencies": unresolved,
        "composed": {
            "capabilities": sorted(product.caps),
            "authority_unknown": product.unknown,
            "authority_unknown_reasons": _reason_dicts(product.reasons),
            "note": (
                "composed = union over the product's package DAG of each "
                "package's attributed capabilities. authority_unknown is "
                "the distinguished TOP element: true when a declared "
                "dependency is not analyzable (no vendored Capa source, an "
                "absent/unreadable capa.toml, a native/non-Capa dependency) "
                "or a package crosses Unsafe. TOP dominates the join and is "
                "NEVER treated as the empty set: the capabilities shown are "
                "a floor, not a ceiling, whenever authority_unknown is true."
            ),
        },
    }


def find_package_root(start: Path) -> Optional[Path]:
    """Nearest ancestor of ``start`` (a file or directory) that holds a
    ``capa.toml``, or ``None``. Lets ``--compose-sbom`` be run from
    anywhere inside a project tree."""
    p = start.resolve()
    if p.is_file():
        p = p.parent
    for d in [p, *p.parents]:
        if (d / "capa.toml").is_file():
            return d
    return None
