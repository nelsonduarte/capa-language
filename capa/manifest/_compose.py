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
   functions attributed to ``P``. ``caps(P)`` is REACHABILITY-SCOPED: it
   is drawn from the flattened manifest, which holds only the source the
   loader LINKED, so a declared + vendored + analyzable but never-
   IMPORTED dependency shows an empty attributed set (dead code is not
   shipped). Its declared-but-unresolvable sub-dependencies still compose
   as TOP through the DAG edges below, which are read from ``capa.toml``
   independently of what the program imports.

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

from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from .. import capa_ast as A
from ..lexer import SYNTHETIC_FILENAME

if TYPE_CHECKING:
    from ..pkg import CapabilityCeiling


# Version of the COMPOSED-SBOM schema, independent of the per-program
# manifest ``SCHEMA_VERSION``. Bump on any incompatible shape change so
# a consumer can refuse a shape it does not recognise.
#
#   1 - initial composed SBOM (S2).
#   2 - per-package ``declared_ceiling`` / ``ceiling_violations`` and the
#       product-level ``capability_ceilings`` pass/fail block (S3).
#   3 - per-package declassification rollup (``attributed_declassifications``
#       / ``attributed_declassification_sites`` /
#       ``composed_declassification_sites`` / ``composed_has_declassification``)
#       and the product-level ``declassification_sites`` /
#       ``has_declassification`` (feature #6, P2).
#   4 - per-package UN-AUDITED secret->egress-sink rollup
#       (``attributed_unaudited_secret_sinks`` /
#       ``unaudited_secret_sink_capabilities``): the WARN-tier raw
#       secret-to-sink flows the IFC analysis surfaced, attributed to the
#       package that owns the leaking code, so ``no-secret-egress`` catches
#       an un-audited leak to a declared egress capability (feature #6, B1).
#   5 - per-package ceiling check additionally FAILS CLOSED (authority_unknown)
#       when a ceiling-DECLARING package's OWN attributed functions are not
#       provable from their types (``authority_provable_from_types`` False:
#       a higher-order function the package invokes, an Unsafe crossing, or a
#       signature reaching a Fun through an impl). Self-scoped; feeds ONLY the
#       ceiling check, so the product roll-up is byte-identical.
#   6 - the same self-scoped ceiling check reads the per-function
#       ``ceiling_authority_provable`` signal instead of the strict
#       ``authority_provable_from_types``, so a ``Fun`` parameter marked
#       ``borrow`` and verified invoke-only no longer voids the ceiling. The
#       product roll-up stays byte-identical (the relaxation is ceiling-only).
COMPOSED_SCHEMA_VERSION = 6


# The per-program manifest ``schema_version`` that first carries the
# per-function ``authority_provable_from_types`` signal the SELF-SCOPED
# ceiling check needs. A manifest below this is missing that evidence, and a
# security check must FAIL CLOSED on the absence of the evidence it needs:
# rather than silently trust an older per-package manifest (which would
# re-introduce the higher-order ceiling hole schema 2 closed), the compose
# entry point REFUSES it outright with an actionable diagnostic. The number
# is fixed at 2 (where the key was added) and does NOT track the current
# ``SCHEMA_VERSION``: the key persists across later bumps.
_MIN_MANIFEST_SCHEMA_FOR_CEILING = 2


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
    composes as TOP).

    The SOURCE fields (``source_kind`` / ``git_url`` / ``pin`` /
    ``pin_kind`` / ``path``) RETAIN the declaring ``Dependency``'s
    identity so a downstream consumer (the SBOM dependency-identity
    record) can name and package-URL the dependency without re-parsing
    the manifest. They describe the DECLARATION, not the resolution: a
    git edge carries its URL + pin even when it never vendored (an
    unresolved TOP node is still a real declared dependency to list)."""

    name: str
    target_dir: Optional[Path]
    resolved: bool
    reason: Optional[str]
    # Declared source identity, retained from the ``Dependency`` this edge
    # was built from. ``source_kind`` is "git" or "path".
    source_kind: str = "git"
    git_url: Optional[str] = None
    pin: Optional[str] = None
    pin_kind: Optional[str] = None
    path: Optional[str] = None


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
    # A function ATTRIBUTED to this package exposes authority its OWN types
    # cannot prove: the manifest's ``ceiling_authority_provable`` is False
    # for it (``has_unsafe or has_fun_in_sig or sig_unprovable`` -- it invokes
    # a caller-supplied Fun, crosses Unsafe, or takes a type reaching a Fun
    # through an impl -- EXCEPT a ``Fun`` parameter marked ``borrow`` and
    # verified invoke-only, whose authority is charged at the closure's
    # creation site, not here). Consumed ONLY by the per-package CEILING check
    # (SELF-SCOPED, ``_ceiling_violations``): a ceiling is a claim about THIS
    # package's subtree, into which a caller can inject authority the types
    # never named, so a declaring package whose own authority is not provable
    # cannot have a verifiable ceiling. It DELIBERATELY does NOT feed the
    # product roll-up (``_own_authority`` / ``_compose_node`` stay
    # byte-identical): a closure's authority is accounted at its CREATION
    # site, so a higher-order-TAKING package gains no authority of its own.
    authority_unprovable: bool = False
    # Feature #4 (F1/F2a): a function in this package INVOKES a typed
    # foreign component. Under the DEFAULT (backend-agnostic / Python)
    # posture the boundary composes as authority-unknown TOP -- claiming
    # a bound nothing enforces would be unsound. Under the Wasm-sandbox
    # ENFORCEMENT posture (F2a) the boundary composes as a BOUNDED node
    # of ``foreign_declared_caps``: the runtime instantiates the child
    # with a restricted linker binding ONLY those caps, so an un-granted
    # capability import fails instantiation (host-enforced cap SET).
    calls_foreign_component: bool = False
    # Feature #4 (F2a): the union of DECLARED capability sets of the
    # foreign boundaries this package invokes -- the bounded cap set the
    # Wasm sandbox host-enforces. Empty unless ``calls_foreign_component``.
    foreign_declared_caps: frozenset[str] = frozenset()
    # The package's DECLARED capability ceiling (S3), or ``None`` when it
    # declares no ``[capabilities]`` section (unconstrained; not checked).
    ceiling: Optional["CapabilityCeiling"] = None
    # Feature #6 (P2): the audited @secret -> @public declassification sites
    # ATTRIBUTED to this package's own functions (each a ``{reason, pos}``
    # dict, sorted canonically). Empty when the package declassifies
    # nothing. The transitive (composed) count is rolled up separately so a
    # policy can gate on where sensitive data is deliberately released.
    declassifications: list[dict[str, str]] = field(default_factory=list)
    # Feature #6 (B1): the UN-AUDITED @secret -> egress-sink flows attributed
    # to this package's OWN functions (each a ``{capability, pos}`` dict,
    # sorted canonically). These are the WARN-tier raw secret-to-sink flows
    # the IFC analysis surfaced -- a secret reaching an egress sink with NO
    # declassify. A leak lives in a SPECIFIC package's own code, so there is
    # no transitive rollup: ``no-secret-egress`` intersects THIS set with the
    # declared egress set. Empty when the package leaks nothing un-audited.
    unaudited_secret_sinks: list[dict[str, str]] = field(default_factory=list)


def _rel_display(path: Path, root_dir: Path) -> str:
    """Root-relative POSIX display of ``path`` (``"."`` for the root
    itself).

    A path OUTSIDE the root tree (a ``../sib`` path dependency) is
    emitted relative to the root with ``..`` segments, NEVER as an
    absolute path: an absolute path would serialise the builder's
    machine-specific filesystem layout into the artifact, so two builds
    of the same product at different absolute locations would produce
    different digests -- breaking the canonical/reproducible contract and
    leaking local layout. A ``..``-relative path stays stable across
    machines and working directories as long as the relative layout
    between the product and its path dep holds (the reproducibility
    contract for path deps). ``os.path.relpath`` is computed purely
    lexically over the resolved paths, so it never touches the
    filesystem and is deterministic."""
    import os

    try:
        resolved = path.resolve()
        root = root_dir.resolve()
    except OSError:
        return path.as_posix()
    try:
        rel = resolved.relative_to(root)
        return rel.as_posix() if rel.parts else "."
    except ValueError:
        # Outside the root tree: fall back to a lexical, ``..``-bearing
        # relative path. On different drives (Windows) relpath raises;
        # only then is there genuinely no relative base.
        try:
            return Path(os.path.relpath(resolved, root)).as_posix()
        except ValueError:
            return resolved.as_posix()


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


def _dep_edge(pkg_dir: Path, dep: Any) -> DepEdge:
    """Build a :class:`DepEdge` from a declared ``Dependency``, resolving
    its analyzability and RETAINING its source identity (source kind, git
    URL + pin, or path) so a downstream SBOM consumer never re-parses the
    manifest."""
    target, resolved, reason = _classify_dependency(pkg_dir, dep)
    if dep.is_path:
        return DepEdge(
            dep.name, target, resolved, reason,
            source_kind="path", path=dep.path,
        )
    pin = dep.tag if dep.tag is not None else dep.rev
    pin_kind = "tag" if dep.tag is not None else ("rev" if dep.rev else None)
    return DepEdge(
        dep.name, target, resolved, reason,
        source_kind="git", git_url=dep.git, pin=pin, pin_kind=pin_kind,
    )


def build_package_dag(
    root_dir: Path,
) -> tuple[dict[Path, PackageNode], PackageNode, dict[str, str]]:
    """Build the product's package DAG rooted at ``root_dir`` (a
    directory holding ``capa.toml``).

    Reads the root ``capa.toml`` and RECURSIVELY each resolvable
    dependency's own ``capa.toml`` under ``vendor/<name>``. Only declared
    ``[dependencies]`` become edges (dev-dependencies are excluded from
    the product). Returns the node map (keyed by resolved manifest dir),
    the root node, and the ``{name: commit}`` map from the root
    ``capa.lock`` (the resolved full SHA per top-level dependency; empty
    when the lock is absent or unreadable). Cycles are handled by
    memoising on the resolved directory.

    The root ``capa.lock`` is read exactly ONCE here, in the resolve
    layer, so no consumer re-reads it. A missing or broken lock degrades
    to an empty commit map rather than crashing: the lock only enriches
    the SBOM with a resolved SHA, and its absence must never fail the
    build."""
    from ..pkg import read_manifest, read_lock, warn_dependency_floor
    from ..pkg import LOCK_FILENAME

    root_dir = root_dir.resolve()
    nodes: dict[Path, PackageNode] = {}

    lock_commits: dict[str, str] = {}
    try:
        for locked in read_lock(root_dir / LOCK_FILENAME):
            lock_commits[locked.name] = locked.commit
    except Exception:
        # A missing lock returns [] (no exception); an unreadable / invalid
        # one must not crash the SBOM (it only enriches deps with a SHA).
        lock_commits = {}

    def visit(pkg_dir: Path) -> PackageNode:
        pkg_dir = pkg_dir.resolve()
        if pkg_dir in nodes:
            return nodes[pkg_dir]
        manifest_path = pkg_dir / "capa.toml"
        manifest = read_manifest(manifest_path)
        if pkg_dir != root_dir:
            # A DEPENDENCY's ``[package].capa`` floor warns; only the
            # root's is a hard error. The floor is the dependency
            # author's declaration about a machine that is not theirs,
            # and the consumer cannot satisfy it by editing their own
            # manifest, so refusing here is the case most likely to be a
            # false stop. Memoisation on ``pkg_dir`` above means each
            # offending package is named exactly once per build.
            warn_dependency_floor(
                manifest.capa_requirement, manifest.name, manifest_path,
            )
        node = PackageNode(
            name=manifest.name,
            version=manifest.version,
            manifest_dir=pkg_dir,
            rel_path=_rel_display(pkg_dir, root_dir),
            ceiling=manifest.capability_ceiling,
        )
        # Register BEFORE recursing so a dependency cycle terminates.
        nodes[pkg_dir] = node
        for dep in manifest.dependencies:
            edge = _dep_edge(pkg_dir, dep)
            node.dep_edges.append(edge)
            if edge.resolved and edge.target_dir is not None:
                visit(edge.target_dir)
        return node

    root = visit(root_dir)
    return nodes, root, lock_commits


# ---------------------------------------------------------------------------
# Dependency-identity records for external SBOM consumers.
#
# The single source of truth for "what are this product's real declared
# dependencies, and how is each one named as a package-URL". A CycloneDX
# (and future SPDX-3) emitter is a pure CONSUMER of these records: it never
# re-parses capa.toml / capa.lock and never assembles a purl of its own.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DependencyIdentity:
    """One resolved (or declared-but-unresolved) capa.toml dependency, as
    an SBOM consumer needs to name it.

    Married from a :class:`DepEdge` (the declaration: source kind, git
    URL + pin, path) and, when the dependency vendored, its target
    :class:`PackageNode` (the resolved ``[package].version``) plus the
    root ``capa.lock`` commit (top-level deps only). ``purl`` is the ONE
    package-URL for this dependency, built exactly once by
    :func:`_construct_purl`; ``None`` for a path dependency (no fabricated
    registry / file identity). ``bom_ref`` is the stable CycloneDX /
    SPDX identifier a consumer keys the component on."""

    name: str
    version: Optional[str]
    source_kind: str
    git_url: Optional[str] = None
    pin: Optional[str] = None
    pin_kind: Optional[str] = None
    commit: Optional[str] = None
    rel_path: Optional[str] = None
    resolved: bool = False
    purl: Optional[str] = None

    @property
    def bom_ref(self) -> str:
        """The stable component identifier. The purl when there is one
        (globally unique by construction), else a deterministic
        ``capa:dep:<name>@<version-or-unknown>`` fallback (a path dep, or
        a git dep with no version)."""
        if self.purl:
            return self.purl
        return f"capa:dep:{self.name}@{self.version or 'unknown'}"


@dataclass(frozen=True)
class DependencyGraph:
    """The declared-dependency edge relation, ready for the CycloneDX
    ``dependencies`` graph. ``root_children`` are the bom-refs of the
    root program's direct (top-level) dependencies; ``child_edges`` maps
    a dependency's own bom-ref to its declared sub-dependency bom-refs.
    Both are sorted + de-duplicated for a byte-reproducible artifact."""

    root_children: tuple[str, ...] = ()
    child_edges: tuple[tuple[str, tuple[str, ...]], ...] = ()


def _construct_purl(
    *,
    name: str,
    version: Optional[str],
    source_kind: str,
    git_url: Optional[str],
    pin: Optional[str],
    commit: Optional[str],
) -> Optional[str]:
    """Build the ONE package-URL for a dependency, or ``None``.

    This is the SOLE purl producer in Capa: no SBOM emitter ever
    assembles a ``pkg:`` string of its own. Every purl is verified
    against the purl-spec (ECMA-427) and round-tripped through the
    vendored ``packageurl`` reference lib (the round-trip lives in the
    tests; the core stays dependency-free, so the string is assembled
    here with stdlib ``urllib.parse.quote`` rather than importing the lib
    at runtime):

    - GITHUB git dep -> the native ``pkg:github/<owner>/<repo>@<revision>``
      form. GitHub is the one host with a first-class purl type, so a
      github-hosted dependency gets the identity every SBOM consumer
      already understands rather than an opaque ``vcs_url`` qualifier. The
      host detection REUSES the sole github parser
      (:func:`capa.pkg._install._parse_github_owner_repo`, whose anchor is
      exact: ``github.example.com`` / ``mygithub.io`` /
      ``github.com.evil.com`` all fall through) so no second github regex
      exists in the codebase; owner + repo are lower-cased (GitHub treats
      them case-insensitively, and the purl-spec canonicalises the
      ``github`` namespace + name to lowercase). The revision is the
      resolved commit SHA when known, else the declared pin (tag / rev);
      when neither is known the ``@<revision>`` is omitted. A github URL
      the parser does NOT match (an ``ssh://`` transport, a dotted repo
      name) falls through to the ``pkg:generic`` rule below, which stays
      sound.

    - NON-GITHUB git dep ->
      ``pkg:generic/<name>[@<version>]?vcs_url=git+<url>@<revision>``.
      The ``vcs_url`` value follows the pip / SPDX form
      ``git+<transport>://<host>/<path>@<revision>``, FULLY
      percent-encoded (``+`` -> ``%2B``, ``@`` -> ``%40``, ``/`` ->
      ``%2F``, ``:`` kept). The revision is the resolved commit SHA when
      known, else the declared pin (tag / rev). When the version is
      unknown (an unresolved dep) the ``@<version>`` is omitted (a purl
      version is optional) but the ``vcs_url`` qualifier is kept, so the
      dependency is still fully identified.

    - PATH dep -> ``None``. A path dependency has no registry / VCS
      identity to package-URL; the component carries its name + version +
      a ``capa:source_kind=path`` property + its root-relative path
      instead. We never fabricate a ``pkg:generic`` / file purl for it."""
    import urllib.parse

    from ..pkg._install import _parse_github_owner_repo

    if source_kind != "git" or not git_url:
        return None
    revision = commit or pin
    github = _parse_github_owner_repo(git_url)
    if github is not None:
        owner, repo = github
        out = (
            f"pkg:github/{urllib.parse.quote(owner.lower(), safe='')}"
            f"/{urllib.parse.quote(repo.lower(), safe='')}"
        )
        if revision:
            out += f"@{urllib.parse.quote(revision, safe='')}"
        return out
    vcs = f"git+{git_url}@{revision}" if revision else f"git+{git_url}"
    out = f"pkg:generic/{urllib.parse.quote(name, safe='')}"
    if version:
        out += f"@{urllib.parse.quote(version, safe='')}"
    return out + "?vcs_url=" + urllib.parse.quote(vcs, safe=":")


def _identity_for_edge(
    edge: DepEdge,
    nodes: dict[Path, PackageNode],
    root_dir: Path,
    commit: Optional[str],
) -> DependencyIdentity:
    """Marry a :class:`DepEdge` with its resolved :class:`PackageNode`
    (version + rel_path) and the lock ``commit`` into one identity, and
    build its single purl. ``commit`` is passed in (resolved by SOURCE from
    the root lock: any edge sharing a locked ``(git_url, pin)`` inherits its
    SHA) rather than looked up here, so the lock scoping lives at the one
    caller that knows the DAG shape."""
    version: Optional[str] = None
    rel_path: Optional[str] = None
    if edge.resolved and edge.target_dir is not None:
        target = nodes.get(edge.target_dir.resolve())
        if target is not None:
            version = target.version
            rel_path = _rel_display(target.manifest_dir, root_dir)
    purl = _construct_purl(
        name=edge.name,
        version=version,
        source_kind=edge.source_kind,
        git_url=edge.git_url,
        pin=edge.pin,
        commit=commit,
    )
    return DependencyIdentity(
        name=edge.name,
        version=version,
        source_kind=edge.source_kind,
        git_url=edge.git_url,
        pin=edge.pin,
        pin_kind=edge.pin_kind,
        commit=commit,
        rel_path=rel_path,
        resolved=edge.resolved,
        purl=purl,
    )


def resolve_dependency_identities(
    root_dir: Path,
) -> tuple[list[DependencyIdentity], DependencyGraph]:
    """Resolve every declared capa.toml dependency of the product at
    ``root_dir`` into a deduplicated, deterministically-ordered list of
    :class:`DependencyIdentity` records, plus the declared-edge relation
    for the CycloneDX ``dependencies`` graph.

    Runs the SAME :func:`build_package_dag` walk the composed SBOM uses
    (never a second walk) and consumes its edges, nodes, and lock-commit
    map. The identities are keyed off EDGES (the complete declared set),
    not just resolved nodes, so a declared-but-unresolved dependency
    (never vendored) is still listed: it has a name + git URL + pin ->
    purl, only its version is unknown.

    The commit SHA from ``capa.lock`` is applied by SOURCE, not by name: a
    dependency declared at the same git URL + pin resolves to the SAME
    commit wherever it appears in the tree, so the root lock is lifted into
    a ``(git_url, pin) -> commit`` map and applied to EVERY edge that shares
    that source (not just the root's direct edges). This is what makes a
    lock-resolved DIAMOND collapse: the direct edge and the transitive edge
    of the same package now carry the same resolved SHA, hence the same
    purl, so they de-duplicate to ONE component that carries the commit. A
    dependency whose source is NOT in the lock (a transitive dep at a URL +
    pin the root never locked) still carries its declared pin. Records are
    de-duplicated by ``purl`` (or ``(name, version)`` when there is no purl)
    and sorted by ``(name, version)`` for a byte-reproducible artifact; a
    diamond dependency reached by several edges is listed once
    (first-visit-wins, and every edge that shares a locked source carries
    the resolved commit)."""
    nodes, root, lock_commits = build_package_dag(root_dir)

    # Lift the root ``capa.lock`` (keyed by top-level dependency NAME) into a
    # ``(git_url, pin) -> commit`` map. The lock records the resolved SHA per
    # top-level dependency, but a dependency declared at the same git URL +
    # pin resolves to the same commit ANYWHERE in the tree, so keying on the
    # source (not the name) lets a transitive edge of a locked package inherit
    # the SHA. This both enriches that edge and makes a lock-resolved diamond
    # collapse to one component.
    lock_by_source: dict[tuple[Optional[str], Optional[str]], str] = {}
    for edge in root.dep_edges:
        if edge.source_kind == "git" and edge.git_url:
            commit = lock_commits.get(edge.name)
            if commit:
                lock_by_source[(edge.git_url, edge.pin)] = commit

    # Pass 1: turn every declared edge into a (parent_dir, identity) pair,
    # in a deterministic global order (parent package by (rel_path, name),
    # then edge by name). The identity's bom-ref REPRESENTS the resolved
    # target dir so a dependency-to-dependency edge can name its parent;
    # first-visit-wins for a dir reached by several edges.
    ordered_nodes = sorted(nodes.values(), key=lambda n: (n.rel_path, n.name))
    edge_identities: list[tuple[Path, DepEdge, DependencyIdentity]] = []
    ref_by_dir: dict[Path, str] = {}
    identities: dict[tuple, DependencyIdentity] = {}
    for node in ordered_nodes:
        for edge in sorted(node.dep_edges, key=lambda e: e.name):
            # The commit is applied by SOURCE (git_url + pin), so a lock-
            # resolved package inherits its SHA on every edge that shares
            # that source -- the root's direct edge AND a deeper transitive
            # one -- which is what deduplicates a lock-resolved diamond. A
            # source the lock never recorded carries no commit (its pin).
            commit = (
                lock_by_source.get((edge.git_url, edge.pin))
                if edge.source_kind == "git" else None
            )
            identity = _identity_for_edge(edge, nodes, root.manifest_dir, commit)
            key = identity.purl or (identity.name, identity.version)
            identities.setdefault(key, identity)
            edge_identities.append((node.manifest_dir, edge, identity))
            if edge.resolved and edge.target_dir is not None:
                ref_by_dir.setdefault(edge.target_dir.resolve(), identity.bom_ref)

    # Pass 2: build the graph relation. The root program's direct edges are
    # ``root_children`` (the emitter attaches them to the program bom-ref);
    # every other edge is keyed on the representative bom-ref of its parent
    # package. Robust to node ordering: ``ref_by_dir`` is fully populated.
    root_children: list[str] = []
    child_edges: dict[str, list[str]] = {}
    for parent_dir, _edge, identity in edge_identities:
        if parent_dir == root.manifest_dir:
            root_children.append(identity.bom_ref)
        else:
            parent_ref = ref_by_dir.get(parent_dir)
            if parent_ref is not None:
                child_edges.setdefault(parent_ref, []).append(identity.bom_ref)

    ordered = sorted(
        identities.values(), key=lambda i: (i.name, i.version or ""),
    )
    graph = DependencyGraph(
        root_children=tuple(sorted(set(root_children))),
        child_edges=tuple(
            (parent, tuple(sorted(set(kids))))
            for parent, kids in sorted(child_edges.items())
        ),
    )
    return ordered, graph


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


def _module_scope_files(module: A.Module) -> dict[tuple, str]:
    """Map each MODULE-SCOPE expression root's attribution key to the
    ABSOLUTE source file it was declared in.

    The module-scope analogue of :func:`_function_files`, for the
    declassification sites that live outside any function body (a
    top-level ``const`` initializer). The key is ``(kind, name, line,
    col)`` -- the expression-root kind, the LOADER-TIME (possibly
    mangled) name, and the declaration position -- which lines up exactly
    with the ``owner_kind`` / ``owner`` / ``owner_pos`` a
    ``module_declassifications`` record carries, so two packages that
    declare same-positioned constants are still told apart.

    Like :func:`_function_files`, a key that would map to two DIFFERENT
    files is a mis-attribution hazard and raises :class:`ComposeError`
    rather than picking one silently."""
    from .._declassify import FUNCTION_KINDS, module_expression_roots

    out: dict[tuple, str] = {}
    for root in module_expression_roots(module):
        if root.kind in FUNCTION_KINDS:
            continue
        key = (root.kind, root.name, root.decl.pos.line, root.decl.pos.col)
        filename = root.decl.pos.filename or ""
        prev = out.get(key)
        if prev is not None and prev != filename:
            raise ComposeError(
                f"ambiguous attribution: {root.kind} {root.name!r} maps to "
                f"both {prev!r} and {filename!r}; cannot attribute soundly"
            )
        out[key] = filename
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
    to the product, never lose a capability).

    Declassification sites that live OUTSIDE any function body (the
    manifest's ``module_declassifications``, e.g. a top-level ``const``
    initializer) are attributed by the same rule, keyed on the owning
    declaration's file instead of the function's."""
    keyfile = _function_files(module)
    modfile = _module_scope_files(module)
    dirs_by_depth = sorted(
        nodes.keys(), key=lambda d: len(d.parts), reverse=True,
    )

    caps: dict[Path, set[str]] = {d: set() for d in nodes}
    unsafe: dict[Path, bool] = {d: False for d in nodes}
    # Self-scoped ceiling signal: a function attributed here whose authority
    # is NOT provable from its own types. Attributed exactly like
    # ``crosses_unsafe`` but consumed ONLY by the ceiling check, never the
    # roll-up.
    unprovable_ceiling: dict[Path, bool] = {d: False for d in nodes}
    foreign: dict[Path, bool] = {d: False for d in nodes}
    foreign_caps: dict[Path, set[str]] = {d: set() for d in nodes}
    # Feature #6 (P2): the audited declassification sites attributed to each
    # package, keyed by the same owner as the capability attribution.
    declass: dict[Path, list[dict[str, str]]] = {d: [] for d in nodes}
    # Feature #6 (B1): the UN-AUDITED secret->egress-sink flows attributed to
    # each package, keyed by the SAME owner. Each entry is a
    # ``{capability, pos}`` dict (full, root-relative position).
    unaudited: dict[Path, list[dict[str, str]]] = {d: [] for d in nodes}

    # Feature #4 (F2a): the DECLARED capability set of each typed
    # foreign-component boundary the module declares, keyed by the
    # component name AS IT APPEARS in a function record's
    # ``foreign_component_calls`` (the invocation's receiver identifier,
    # i.e. the extern component's own name). The Wasm sandbox
    # host-enforces exactly this set per boundary (an un-granted
    # capability import fails child instantiation). Keying off the module
    # rather than the manifest's ``foreign_components`` block matters: that
    # block DEMANGLES the boundary names, whereas ``foreign_component_calls``
    # carries the loader-mangled receiver name, so only the module-level
    # ``ec.name`` matches both.
    from ..foreign import extern_components, declared_capabilities
    comp_caps: dict[str, set[str]] = {}
    for ec in extern_components(module):
        ecaps: set[str] = set()
        for m in ec.methods:
            ecaps.update(declared_capabilities(m))
        comp_caps[ec.name] = ecaps

    # The union across every declared boundary is the SOUND fallback: when
    # a package invokes a foreign component we cannot resolve to a specific
    # declared boundary (an indirect/dynamic call, or a manifest serialised
    # before ``foreign_component_calls`` existed) we credit it the union
    # rather than under-attribute -- never drop a foreign capability a
    # package could actually invoke.
    foreign_caps_union: set[str] = set()
    for ecaps in comp_caps.values():
        foreign_caps_union |= ecaps

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
        # Self-scoped ceiling signal (feeds ONLY the ceiling check below, not
        # the roll-up). The strict ``authority_provable_from_types`` is read
        # DIRECTLY (guaranteed present by the schema-``>=2`` gate); the
        # ceiling-scoped relaxation ``ceiling_authority_provable`` (schema 3)
        # is read with a fallback to the strict flag. That fallback is
        # fail-CLOSED, not fail-open: a pre-borrow (schema-2) manifest has no
        # ``borrow`` inlets, so the ceiling signal equals the strict flag,
        # which is the MORE restrictive value. Only a verified invoke-only
        # ``borrow`` inlet can make this True while the strict flag is False.
        if not rec.get(
            "ceiling_authority_provable", rec["authority_provable_from_types"]
        ):
            unprovable_ceiling[owner] = True
        # Feature #6 (P2): attribute each audited @secret -> @public
        # declassification site to the SAME owner. The manifest records the
        # site position as ``<line>:<col>`` (function-local); prepend the
        # function's own display file (the leading path of ``rec["pos"]``,
        # split from the right so a Windows drive-letter colon never
        # confuses it) so each site carries a full, root-relative,
        # deterministic position. Defensive .get(): a manifest serialised
        # before the declassifications field has no key.
        site_file = rec["pos"].rsplit(":", 2)[0]
        for site in rec.get("declassifications", []):
            declass[owner].append({
                "reason": site.get("reason", ""),
                "pos": f"{site_file}:{site.get('pos', '')}",
            })
        # Feature #6 (B1): attribute each un-audited secret->egress-sink flow
        # to the SAME owner, prepending the function's own display file so the
        # position is full + root-relative + deterministic (as above).
        # Defensive .get(): a manifest serialised before B1 has no key.
        for sink in rec.get("unaudited_secret_sinks", []):
            unaudited[owner].append({
                "capability": sink.get("capability", ""),
                "pos": f"{site_file}:{sink.get('pos', '')}",
            })
        # Feature #4 (F1/F2a): invoking a foreign component composes as
        # TOP under the default posture, or as BOUNDED {declared caps}
        # under the Wasm-sandbox posture (see ``_own_authority``).
        # Defensive .get(): a manifest serialised before F1 has no key.
        if rec.get("calls_foreign_component"):
            foreign[owner] = True
            # Attribute to THIS package ONLY the declared caps of the
            # foreign components ITS OWN functions invoke (precise
            # per-package attribution). ``foreign_component_calls`` names
            # the boundaries as ``<component>.<method>``.
            calls_list = rec.get("foreign_component_calls")
            if not calls_list:
                # A foreign call the record cannot name (pre-F1 manifest):
                # sound fallback to the module-wide union.
                foreign_caps[owner] |= foreign_caps_union
            else:
                for entry in calls_list:
                    comp = entry.rsplit(".", 1)[0]
                    if comp in comp_caps:
                        foreign_caps[owner] |= comp_caps[comp]
                    else:
                        # An unresolvable specific boundary (indirect /
                        # dynamic / missing declaration): sound fallback to
                        # the module-wide union rather than under-attribute.
                        foreign_caps[owner] |= foreign_caps_union

    # Roadmap S2.5: the declassification sites outside any function body.
    # Attributed by the OWNING DECLARATION's file, so a secret released in
    # a dependency's ``const`` lands on that dependency, not the root.
    # Defensive .get(): a manifest serialised before the block existed has
    # no key, and an owner whose file is under no package falls back to the
    # root exactly like a function (over-attribute, never lose a site).
    for site in manifest.get("module_declassifications", []):
        owner_pos = site.get("owner_pos", "")
        owner_file, owner_line, owner_col = _split_owner_pos(owner_pos)
        abs_file = modfile.get(
            (
                site.get("owner_kind", ""), site.get("owner", ""),
                owner_line, owner_col,
            ),
            "",
        )
        owner = _owning_dir(abs_file, dirs_by_depth)
        if owner is None:
            owner = root_dir
        declass[owner].append({
            "reason": site.get("reason", ""),
            "pos": f"{owner_file}:{site.get('pos', '')}",
        })

    for d, node in nodes.items():
        node.attributed_caps = frozenset(caps[d])
        node.crosses_unsafe = unsafe[d]
        node.authority_unprovable = unprovable_ceiling[d]
        node.calls_foreign_component = foreign[d]
        node.foreign_declared_caps = (
            frozenset(foreign_caps[d]) if foreign[d] else frozenset()
        )
        # Canonical, deterministic order: by full position, then reason.
        node.declassifications = sorted(
            declass[d], key=lambda s: (s["pos"], s["reason"]),
        )
        # Feature #6 (B1): canonical order by (capability, position); the
        # evidence is de-duplicated so a repeated (cap, pos) never inflates
        # the byte-reproducible artifact.
        seen_unaudited: set[tuple[str, str]] = set()
        node.unaudited_secret_sinks = []
        for s in sorted(
            unaudited[d], key=lambda s: (s["capability"], s["pos"]),
        ):
            keyed = (s["capability"], s["pos"])
            if keyed in seen_unaudited:
                continue
            seen_unaudited.add(keyed)
            node.unaudited_secret_sinks.append(s)


def _pos_line_col(pos: str) -> tuple[int, int]:
    """Extract ``(line, col)`` from a manifest ``pos`` string
    (``<file>:<line>:<col>``). ``rsplit`` from the right so a Windows
    drive-letter colon in an absolute (out-of-tree) path never confuses
    the split."""
    parts = pos.rsplit(":", 2)
    return int(parts[-2]), int(parts[-1])


def _split_owner_pos(pos: str) -> tuple[str, int, int]:
    """Split a manifest ``<file>:<line>:<col>`` into its three parts.

    The file half is returned as-is (already root-relative display form);
    a malformed / missing position yields ``("", -1, -1)``, which
    attributes the site to the root rather than dropping it."""
    parts = pos.rsplit(":", 2)
    if len(parts) != 3:
        return "", -1, -1
    try:
        return parts[0], int(parts[1]), int(parts[2])
    except ValueError:
        return parts[0], -1, -1


# ---------------------------------------------------------------------------
# Bottom-up composition + SBOM assembly.
# ---------------------------------------------------------------------------


def _compose_node(
    node: PackageNode,
    nodes: dict[Path, PackageNode],
    enforcement: str = "none",
) -> Authority:
    """``composed(node)``: the join of ``node``'s OWN authority over its
    ENTIRE transitively-reachable dependency set.

    Computed as an explicit closure walk rather than a recursive
    subtree fold, so a DEPENDENCY CYCLE can never cause a node to
    under-count capabilities or drop a TOP flag. A recursive fold that
    cut a cycle by returning a node's own (partial) authority and then
    memoised that partial would leave a cycle-closer's ``composed_*``
    fields under-approximating everything reachable only through the cut
    edge -- unsound, and S3 will check ceilings against exactly these
    per-package composed sets.

    The walk collects every node reachable from ``node`` over resolved
    edges (``seen`` makes it cycle-safe) and joins each reachable node's
    own authority; every UNRESOLVED edge encountered anywhere in the
    closure contributes a TOP element. Because :meth:`Authority.join` is
    commutative and associative (union of caps, OR of unknown, union of
    reasons), the result is independent of visit order, and TOP dominates
    naturally: a single unresolved (or Unsafe-crossing) node anywhere in
    the closure marks the whole composed value authority-unknown."""
    result = Authority()
    seen: set[Path] = set()
    stack: list[Path] = [node.manifest_dir]
    while stack:
        d = stack.pop()
        if d in seen:
            continue
        seen.add(d)
        n = nodes[d]
        result = result.join(_own_authority(n, enforcement))
        for edge in n.dep_edges:
            if edge.resolved and edge.target_dir is not None:
                target = edge.target_dir.resolve()
                if target not in seen:
                    stack.append(target)
            else:
                result = result.join(Authority(
                    unknown=True,
                    reasons=((n.name, edge.name, edge.reason or "unresolved"),),
                ))
    return result


def _compose_declassifications(
    node: PackageNode, nodes: dict[Path, PackageNode],
) -> int:
    """The TRANSITIVE count of audited declassification sites over
    ``node``'s entire resolved-edge closure (its own attributed sites plus
    every reachable dependency's).

    Walks the SAME resolved-edge closure as :func:`_compose_node` (``seen``
    makes it cycle-safe) so the declassification rollup lines up exactly
    with the capability rollup: a package's ``composed_declassification_sites``
    counts every deliberate secret->public release reachable from it. An
    UNRESOLVED edge contributes nothing here (it cannot be analyzed); the
    count is therefore a FLOOR when the node's ``composed_authority_unknown``
    is true, which is precisely why a policy over such a node must fail
    closed rather than trust a confident zero."""
    total = 0
    seen: set[Path] = set()
    stack: list[Path] = [node.manifest_dir]
    while stack:
        d = stack.pop()
        if d in seen:
            continue
        seen.add(d)
        n = nodes[d]
        total += len(n.declassifications)
        for edge in n.dep_edges:
            if edge.resolved and edge.target_dir is not None:
                target = edge.target_dir.resolve()
                if target not in seen:
                    stack.append(target)
    return total


def _own_authority(node: PackageNode, enforcement: str = "none") -> Authority:
    """The package's OWN (non-transitive) authority: its attributed
    capabilities, plus a TOP mark when it crosses ``Unsafe``.

    ``enforcement`` is the runtime POSTURE the composed SBOM is claimed
    under (feature #4, F2a). Default ``"none"`` is the backend-agnostic /
    Python posture: nothing enforces a foreign-component's declared bound,
    so a foreign call composes as authority-unknown TOP (honest). Under
    ``"wasm-sandbox"`` the Wasm runtime instantiates each foreign child
    with a restricted linker binding ONLY the declared caps -- an
    un-granted capability import fails instantiation -- so a foreign call
    composes as a BOUNDED node of ``node.foreign_declared_caps`` instead
    of TOP. The bounded claim is made ONLY under the enforcing posture; it
    NEVER leaks into the default / Python path (which would be an unsound
    over-claim). NOTE: this bounds the cap SET (host-enforced); composing
    WITHIN-cap host-granular attenuation across the boundary is feature #6.

    The TOP trigger for an ANALYZED package's ROLL-UP is ``has_unsafe``
    ONLY, even though the single-program manifest drops ``provably_excluded``
    on ``has_unsafe OR has_fun_in_sig OR sig_unprovable``. For the ROLL-UP
    this is a deliberate, sound choice, NOT an oversight:

    - ``Unsafe`` is a genuine escape to unanalyzable (FFI) code that can
      exercise authority the type system never sees, so a package that
      crosses it cannot have a vouched-for capability set -> TOP.

    - ``has_fun_in_sig`` / ``sig_unprovable`` (a package that TAKES a
      ``Fun(...)`` and invokes it) is NOT a product-level authority
      escape. A closure's authority is accounted at the package where the
      closure is CREATED -- its captures require THAT package to hold the
      capability, so the capability is attributed there. A dependency
      exposing ``invoke(f: Fun() -> Unit)`` gains no authority of its own;
      when the root passes it a ``Stdio``-capturing closure, ``Stdio`` is
      attributed to the ROOT (the creator) and composes up into the
      product regardless. Marking every higher-order-taking package TOP in
      the roll-up would therefore be an unsound-for-usability
      over-approximation: it would flag most real packages authority-unknown
      for zero soundness gain. (Pinned by
      ``test_invoke_closure_product_is_sound_without_top``.)

    The per-package CEILING check is DIFFERENT, and does NOT rely on this
    roll-up value. A ceiling is a CLAIM about the declaring package's own
    subtree, and a caller can inject authority the package's types never
    named into a higher-order function it exposes -- exactly the case the
    roll-up correctly attributes ELSEWHERE (the creator). So a package that
    DECLARES a ceiling must ADDITIONALLY have its own authority provable
    from its types: ``_ceiling_violations`` fails such a package closed
    (``authority_unknown``) on the full ``has_unsafe OR has_fun_in_sig OR
    sig_unprovable`` signal, SELF-SCOPED to the declaring package. This
    tighter rule lives in the ceiling check alone; feeding it into this
    roll-up value would corrupt the product join (one Authority value per
    node feeds BOTH), which is why the roll-up keeps the ``has_unsafe``-only
    trigger and the ceiling reads the per-package flag separately."""
    reasons: tuple[tuple[str, str, str], ...] = ()
    if node.crosses_unsafe:
        reasons = reasons + ((node.name, node.name, (
            "a function in this package crosses Unsafe; its capability "
            "set is not a sound upper bound (provably-excluded is dropped)"
        )),)
    # Feature #4 (F1/F2a): calling a typed foreign component.
    caps = set(node.attributed_caps)
    foreign_is_top = False
    if node.calls_foreign_component:
        if enforcement == "wasm-sandbox":
            # F2a: the Wasm sandbox host-enforces the declared cap SET
            # (an un-granted capability import fails child instantiation),
            # so the boundary composes as a BOUNDED node of the declared
            # caps -- NOT authority-unknown. This is the credibility win:
            # static-declared == runtime-enforced for the capability set.
            caps |= set(node.foreign_declared_caps)
            reasons = reasons + ((node.name, node.name, (
                "a function in this package invokes a typed foreign "
                "component; under the Wasm-sandbox enforcement posture the "
                "child is instantiated with a restricted linker binding "
                "ONLY its declared capabilities, so the boundary composes "
                "as a BOUNDED node of {} (cap-set host-enforced), not "
                "authority-unknown".format(
                    sorted(node.foreign_declared_caps) or "no capabilities"
                )
            )),)
        else:
            # Default / Python posture: nothing enforces the declared
            # bound, so claiming it would be unsound -- compose as TOP.
            foreign_is_top = True
            reasons = reasons + ((node.name, node.name, (
                "a function in this package invokes a typed foreign "
                "component; the declared capability bound is not "
                "runtime-enforced on this backend (only the Wasm-sandbox "
                "posture enforces it), so the boundary composes as "
                "authority-unknown"
            )),)
    unknown = node.crosses_unsafe or foreign_is_top
    return Authority(
        caps=frozenset(caps),
        unknown=unknown,
        reasons=reasons,
    )


def _reason_dicts(
    reasons: tuple[tuple[str, str, str], ...],
) -> list[dict[str, str]]:
    return [
        {"declared_in": a, "dependency": b, "reason": c}
        for (a, b, c) in reasons
    ]


# ---------------------------------------------------------------------------
# Ceiling conflict detection (S3).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CeilingViolation:
    """One way a declared-ceiling package is NOT provably within its bound.

    ``kind`` is either ``"exceeds"`` (a KNOWN capability outside ``max``)
    or ``"authority_unknown"`` (the composed authority is TOP: an
    unanalyzable subtree that cannot be proven within ANY ceiling -- the
    fail-closed rule). The two are deliberately distinguished so an
    auditor can tell "this product reaches Net, which you forbade" apart
    from "part of this product is unanalyzable, so the ceiling claim is
    unverifiable".

    ``path`` is the transitive package path from the declaring package to
    the source of the violation (``P -> ... -> D``), so the offending edge
    is attributed, never left as "somewhere in the tree"."""

    package: str
    kind: str
    capability: Optional[str]
    introduced_by: str
    path: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "kind": self.kind,
            "capability": self.capability,
            "introduced_by": self.introduced_by,
            "path": list(self.path),
            "detail": self.detail,
        }

    def sort_key(self) -> tuple:
        return (
            self.package,
            self.kind,
            self.capability or "",
            self.introduced_by,
            self.path,
        )


def _shortest_name_paths(
    start: PackageNode, nodes: dict[Path, PackageNode],
) -> dict[Path, tuple[str, ...]]:
    """Shortest transitive path (as a tuple of PACKAGE NAMES) from
    ``start`` to every node reachable over resolved edges. Neighbours are
    visited in a canonical (name, then dependency-name) order so the
    chosen path is deterministic when several shortest paths exist."""
    paths: dict[Path, tuple[str, ...]] = {start.manifest_dir: (start.name,)}
    q: deque[Path] = deque([start.manifest_dir])
    while q:
        d = q.popleft()
        n = nodes[d]
        neighbours = []
        for edge in n.dep_edges:
            if edge.resolved and edge.target_dir is not None:
                t = edge.target_dir.resolve()
                if t in nodes:
                    neighbours.append((nodes[t].name, edge.name, t))
        for _, _, t in sorted(neighbours, key=lambda x: (x[0], x[1])):
            if t not in paths:
                paths[t] = paths[d] + (nodes[t].name,)
                q.append(t)
    return paths


def _ceiling_violations(
    node: PackageNode,
    composed: Authority,
    nodes: dict[Path, PackageNode],
) -> list[CeilingViolation]:
    """Every way ``node``'s composed authority breaches its declared
    ceiling. Empty when ``node`` declares no ceiling (unconstrained) or is
    provably within it.

    Two independent failure modes, each reported separately:

    - EXCEEDS: a concrete capability in ``composed.caps`` that is not in
      ``max``. Attributed to the nearest reachable package whose OWN code
      introduces it, with the transitive path.

    - AUTHORITY-UNKNOWN (fail closed): ``composed.unknown`` is true (a TOP
      element anywhere in the subtree). You cannot bound what you cannot
      analyze, so a declared ceiling FAILS unless ``allow_unknown`` opts
      out explicitly. The known-capability EXCEEDS check still runs even
      when unknown is waived: the waiver forgives only the unanalyzable
      part, never a capability we positively observed outside the bound."""
    ceiling = node.ceiling
    if ceiling is None:
        return []

    violations: list[CeilingViolation] = []
    paths = _shortest_name_paths(node, nodes)
    max_set = set(ceiling.max)
    max_display = sorted(max_set)

    # 1. EXCEEDS-BY-CAPABILITY: known caps outside the ceiling.
    over = sorted(set(composed.caps) - max_set)
    for cap in over:
        introducers = sorted(
            (
                (paths.get(d, (node.name,)), n.name)
                for d, n in nodes.items()
                if d in paths and cap in n.attributed_caps
            ),
            key=lambda x: (len(x[0]), x[0]),
        )
        if not introducers:
            # The capability is reachable but no single node's ATTRIBUTED
            # set carries it (it can only arrive through a node we walked);
            # attribute to the declaring package itself so it is never
            # dropped.
            introducers = [((node.name,), node.name)]
        for path, who in introducers:
            if who == node.name and len(path) == 1:
                detail = (
                    f"package {node.name!r} declares max={max_display} but "
                    f"its own code introduces {cap!r}"
                )
            else:
                detail = (
                    f"package {node.name!r} declares max={max_display} but "
                    f"dependency {who!r} introduces {cap!r} (via "
                    f"{' -> '.join(path)})"
                )
            violations.append(CeilingViolation(
                package=node.name, kind="exceeds", capability=cap,
                introduced_by=who, path=path, detail=detail,
            ))

    # 2. AUTHORITY-UNKNOWN (TOP) fails closed unless explicitly waived.
    if composed.unknown and not ceiling.allow_unknown:
        for (declared_in, dependency, why) in composed.reasons:
            path = _path_to_named(node, declared_in, paths)
            via = " -> ".join(path)
            if dependency == declared_in:
                # An Unsafe-crossing package: source == the package itself.
                detail = (
                    f"package {node.name!r} declares a capability ceiling "
                    f"but its composed authority is UNKNOWN: package "
                    f"{declared_in!r} ({why}) (via {via}); an unanalyzable "
                    f"subtree cannot be proven within any ceiling"
                )
            else:
                detail = (
                    f"package {node.name!r} declares a capability ceiling "
                    f"but its composed authority is UNKNOWN: dependency "
                    f"{dependency!r} of {declared_in!r} is not analyzable "
                    f"({why}) (via {via}); an unanalyzable subtree cannot be "
                    f"proven within any ceiling"
                )
            violations.append(CeilingViolation(
                package=node.name, kind="authority_unknown", capability=None,
                introduced_by=dependency, path=path, detail=detail,
            ))

    # 3. SELF-SCOPED CEILING-UNPROVABLE (fail closed). A ceiling is a claim
    #    about the DECLARING package's OWN subtree; when THIS package's own
    #    attributed functions expose authority its types cannot prove -- a
    #    Fun in a signature (the ``has_fun_in_sig`` trigger, which fires on a
    #    Fun TAKEN or RETURNED whether or not it is invoked), an Unsafe
    #    crossing, or a type that reaches a Fun through an impl -- a caller
    #    can inject authority the package's types never named, so the ceiling
    #    is UNVERIFIABLE. It is SELF-scoped, NOT closure-scoped: it fires only
    #    on the declaring package's own functions, never on a dependency that
    #    merely HANDS OUT an effectful closure (that package has a provable
    #    ceiling of its own; a consumer that vendors an unprovable-ceiling
    #    package still surfaces the breach through the product-wide pass).
    #    Suppressed when the package is ALREADY authority-unknown TOP (handled
    #    by check 2) so a self-Unsafe crossing is not double-reported, and
    #    waived by ``allow_unknown`` exactly like the TOP rule -- a package
    #    that opts out of the fail-closed rule accepts the weaker ceiling
    #    claim. A genuinely pure combinator (``compose(f, g) -> Fun`` that
    #    only RETURNS a closure, never calling it) is flagged too: that is a
    #    deliberate, sound fail-closed over-approximation, not a bug -- the
    #    types still cannot rule out that the returned Fun carries authority.
    if (
        node.authority_unprovable
        and not composed.unknown
        and not ceiling.allow_unknown
    ):
        detail = (
            f"package {node.name!r} declares a capability ceiling but its "
            f"own code exposes authority its types cannot prove (a Fun in a "
            f"signature -- taken or returned, whether or not it is invoked "
            f"-- an Unsafe crossing, or a type that reaches a Fun through an "
            f"impl); a caller can inject authority the package's types never "
            f"named, so the ceiling claim is unverifiable. A pure combinator "
            f"that only returns a Fun is included by this fail-closed "
            f"over-approximation by design"
        )
        violations.append(CeilingViolation(
            package=node.name, kind="authority_unknown", capability=None,
            introduced_by=node.name, path=(node.name,), detail=detail,
        ))

    violations.sort(key=lambda v: v.sort_key())
    return violations


def _path_to_named(
    node: PackageNode,
    target_name: str,
    paths: dict[Path, tuple[str, ...]],
) -> tuple[str, ...]:
    """Shortest reachable path (by name) ending at ``target_name``. Falls
    back to ``(node.name,)`` when the name is the declaring package itself
    or cannot be located (defensive; keeps a path always present)."""
    if target_name == node.name:
        return (node.name,)
    candidates = [
        p for p in paths.values() if p and p[-1] == target_name
    ]
    if not candidates:
        return (node.name, target_name)
    return min(candidates, key=lambda p: (len(p), p))


def build_composed_sbom(
    module: A.Module,
    manifest: dict[str, Any],
    root_dir: Path,
    *,
    capa_version: Optional[str] = None,
    enforcement: str = "none",
) -> dict[str, Any]:
    """Build the composed product SBOM dict from an analyzed whole-program
    ``module``, its ``--manifest`` ``manifest`` dict, and the product's
    ``root_dir`` (the directory holding the root ``capa.toml``).

    ``enforcement`` is the runtime POSTURE the composed authority is
    claimed under (feature #4, F2a). Default ``"none"`` is the
    backend-agnostic / Python posture: a typed foreign-component call
    composes as authority-unknown TOP (nothing enforces the declared
    bound). Under ``"wasm-sandbox"`` a foreign call composes as a BOUNDED
    node of its declared capability set, because the Wasm runtime
    host-enforces exactly that set (an un-granted capability import fails
    child instantiation). The bounded claim is made ONLY under the
    enforcing posture and never leaks into the default path.

    The result is JSON-serialisable, timestamp-free, and canonicalisable
    with the S1 :func:`._canonical.canonical_manifest`. Every path is
    root-relative POSIX, so the artifact is byte-reproducible across
    machines and working directories.

    FAIL CLOSED on stale evidence. The self-scoped ceiling check reads the
    per-function ``authority_provable_from_types`` signal that manifest
    ``schema_version`` 2 introduced. A manifest below that lacks the signal,
    so trusting it would silently re-open the higher-order ceiling hole this
    subsystem exists to close (an unprovable package would compose as
    authority-known-and-empty and PASS). Rather than default a missing key
    to "provable" (fail-open), the single choke point REFUSES an older
    manifest with a :class:`ComposeError` telling the operator to
    regenerate it. Every CLI path already reports ``ComposeError`` and
    exits non-zero."""
    if capa_version is None:
        from .. import __version__ as capa_version

    schema = manifest.get("schema_version")
    if not isinstance(schema, int) or schema < _MIN_MANIFEST_SCHEMA_FOR_CEILING:
        raise ComposeError(
            f"per-program manifest schema_version {schema!r} is too old to "
            f"compose a ceiling-checked SBOM: the per-function "
            f"'authority_provable_from_types' signal the self-scoped ceiling "
            f"check requires was added in schema "
            f"{_MIN_MANIFEST_SCHEMA_FOR_CEILING}. Regenerate the manifest "
            f"with a current capa build (a security check fails closed on "
            f"missing evidence rather than trust a stale artifact)."
        )

    nodes, root, _lock_commits = build_package_dag(root_dir)
    _attribute(module, manifest, nodes, root.manifest_dir)

    composed_by_dir: dict[Path, Authority] = {
        d: _compose_node(node, nodes, enforcement)
        for d, node in nodes.items()
    }
    # Feature #6 (P2): the transitive declassification-site count per node
    # (its own attributed sites plus every reachable dependency's), over the
    # SAME resolved-edge closure as the capability rollup.
    declass_total_by_dir: dict[Path, int] = {
        d: _compose_declassifications(node, nodes)
        for d, node in nodes.items()
    }

    # Deterministic package ordering: by root-relative path, then name.
    ordered = sorted(nodes.values(), key=lambda n: (n.rel_path, n.name))

    packages: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    unresolved: list[dict[str, str]] = []
    all_violations: list[CeilingViolation] = []
    any_ceiling = False
    for node in ordered:
        composed = composed_by_dir[node.manifest_dir]
        own = _own_authority(node, enforcement)
        violations = _ceiling_violations(node, composed, nodes)
        all_violations.extend(violations)
        if node.ceiling is not None:
            any_ceiling = True
            declared_ceiling: Optional[list[str]] = sorted(node.ceiling.max)
            allow_unknown: Optional[bool] = node.ceiling.allow_unknown
        else:
            declared_ceiling = None
            allow_unknown = None
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
            "declared_ceiling": declared_ceiling,
            "ceiling_allow_unknown": allow_unknown,
            "ceiling_violations": [v.to_dict() for v in violations],
            # Feature #6 (P2): the declassification rollup. The attributed
            # sites are THIS package's own audited secret->public bridges;
            # the composed count is transitive over its resolved-edge
            # closure. When ``composed_authority_unknown`` is true the count
            # is a FLOOR (an unanalyzable subtree may declassify unseen), so
            # a no-declassification / no-secret-egress policy fails closed.
            "attributed_declassifications": node.declassifications,
            "attributed_declassification_sites": len(node.declassifications),
            "composed_declassification_sites":
                declass_total_by_dir[node.manifest_dir],
            "composed_has_declassification":
                declass_total_by_dir[node.manifest_dir] > 0,
            # Feature #6 (B1): the un-audited secret->egress-sink flows in
            # THIS package's own code (evidence + the distinct capability
            # set). No transitive rollup: a leak is in a specific package's
            # own body, so ``no-secret-egress`` intersects this OWN set with
            # the declared egress set. Under ``composed_authority_unknown``
            # the set is a FLOOR (an unanalyzable subtree may leak unseen),
            # so the policy still fails closed on a TOP package.
            "attributed_unaudited_secret_sinks": node.unaudited_secret_sinks,
            "unaudited_secret_sink_capabilities": sorted({
                s["capability"] for s in node.unaudited_secret_sinks
            }),
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

    all_violations.sort(key=lambda v: v.sort_key())
    product = composed_by_dir[root.manifest_dir]
    return {
        "capa_version": capa_version,
        "composed_schema_version": COMPOSED_SCHEMA_VERSION,
        "product": {"name": root.name, "version": root.version},
        # Feature #4 (F2a): the runtime enforcement posture this composed
        # authority is claimed under. ``"none"`` (default) = backend-
        # agnostic / Python: a typed foreign-component call composes as
        # authority-unknown TOP. ``"wasm-sandbox"`` = the Wasm runtime
        # host-enforces each foreign child's declared capability SET, so a
        # foreign call composes as a BOUNDED node instead of TOP.
        "enforcement_posture": enforcement,
        "packages": packages,
        "edges": edges,
        "unresolved_dependencies": unresolved,
        "capability_ceilings": {
            "checked": any_ceiling,
            "pass": not all_violations,
            "violations": [v.to_dict() for v in all_violations],
            "note": (
                "each package that declares a capa.toml [capabilities] "
                "ceiling (max = [...] or pure = true) is checked: its "
                "composed capability set must be a subset of its ceiling. A "
                "package whose composed authority is UNKNOWN (a TOP element "
                "from an unresolvable / native / Unsafe-crossing dependency) "
                "FAILS CLOSED - an unanalyzable subtree cannot be proven "
                "within any bound - unless it sets allow_unknown = true. "
                "pass is product-wide: false if ANY declared ceiling is "
                "breached. A package with no [capabilities] section is "
                "unconstrained and not checked."
            ),
        },
        "composed": {
            "capabilities": sorted(product.caps),
            "authority_unknown": product.unknown,
            "authority_unknown_reasons": _reason_dicts(product.reasons),
            # Feature #6 (P2): the product-wide declassification total (the
            # transitive count over the whole package DAG from the root) and
            # a boolean. When ``authority_unknown`` is true this total is a
            # FLOOR, so a product-scoped no-declassification policy fails
            # closed rather than trust it.
            "declassification_sites": declass_total_by_dir[root.manifest_dir],
            "has_declassification":
                declass_total_by_dir[root.manifest_dir] > 0,
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
