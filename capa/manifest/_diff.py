"""Signed authority changelog between two releases (feature #2).

A first-class, canonical, signABLE AUTHORITY CHANGELOG between version
N and N+1 of a program: which capabilities each exported function (and
the product as a whole) GAINED, LOST, or had a GUARANTEE changed. No
scanner can produce this - it needs the capability semantics Capa
already computes and records in the manifest (:mod:`._funrec`) and the
composed SBOM (:mod:`._compose`).

The two inputs are the JSON artifacts ``--manifest`` /
``--manifest-digest`` / ``--compose-sbom`` already emit (a per-function
manifest, or a composed product SBOM), so the diff composes with the
existing pipeline and needs no registry / git integration. The result is
wrapped in the S1 content-integrity envelope (:mod:`._canonical`), so
the changelog is itself content-addressable and signABLE, and it records
BOTH inputs' S1 digests (``from_digest`` / ``to_digest``) so the
changelog is provably about those two exact manifests.

## Function identity (the one critical decision)

Functions are matched across the two versions by the STABLE key
``(container, name)`` - NEVER ``pos``. ``file:line:col`` changes every
release; a function that only MOVED LINES is not an authority change and
must not appear. The diff is therefore POSITION-INDEPENDENT: two
manifests identical except line numbers produce an EMPTY diff. The
display (demangled) ``source_container`` / ``source_name`` are used when
present so an import-order shift in a loader mangle prefix does not
manufacture a false rename.

## What is classified, and how widening vs narrowing is decided

The manifest records four capability views per function. Each is a set;
the delta between N and N+1 is a pair of set differences, classified as
WIDENING (more authority, the thing a release gate blocks) or NARROWING
(less authority):

- ``transitively_reachable`` GAINED a capability (in N+1 not N) = ADDED =
  WIDENING. LOST one = REMOVED = NARROWING. (``declared`` is a subset of
  ``transitively_reachable``, so the reachable view is the authority set.)
- a capability that LEFT ``provably_excluded`` (excluded in N, not in
  N+1) = GUARANTEE LOST = WIDENING. This is the subtle, high-value
  signal: it fires even when the cap is NOT named in the new signature -
  e.g. the function gained an ``Unsafe`` / higher-order parameter that
  VOIDS its whole exclusion proof, so ``provably_excluded`` collapses to
  empty. A scanner cannot see this.
- a capability that ENTERED ``provably_excluded`` = GUARANTEE GAINED =
  NARROWING.

Only EXPORTED (pub) functions appear in the per-function changelog: they
are the public contract. A widening in a PRIVATE function is not hidden -
it surfaces in the PRODUCT composed-set delta below.

Functions ADDED (a new pub function that carries authority) are a
widening of the public surface; REMOVED pub functions that carried
authority are a narrowing.

Operator grants (``--preopen`` / ``--allow-host``) are modelled as a set
of methods per target (an fs preopen: ``{read}`` for ``ro`` /
``{read,write}`` for ``rw``; a net host: ``{get}`` / ``{post}`` /
``{get,post}`` for ``connect``). A target that GAINED a method (new
grant, or ``ro``->``rw`` / ``get``->``connect``) is a WIDENING; one that
LOST a method is a NARROWING. A mixed change (``get``->``post``) emits
both - honestly, since it both gains and loses authority.

## Product / package level

The composed capability set delta answers "did the product's total
reachable authority grow" even when NO exported signature changed (a
transitive dep gained ``Net``). For a composed-SBOM input the set is
S2's ``composed.capabilities``; for a bare manifest it is the union of
every function's ``transitively_reachable`` set. A product going
authority-KNOWN -> authority-UNKNOWN (a new native / unanalyzable dep: a
TOP appeared) is a HIGH-SEVERITY widening - you lost the ability to
bound the product at all.

To avoid DOUBLE-COUNTING, a product-gained capability that is already
explained by a function-level widening does not count again in the
summary; the summary's product contribution is exactly the caps the
product gained that NO per-function widening accounts for (the
"transitive dep with no exported-signature change" case).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ._canonical import manifest_digest


# Version of the authority-changelog schema, independent of the manifest
# ``SCHEMA_VERSION`` and the composed ``COMPOSED_SCHEMA_VERSION``. Bump
# on any incompatible shape change so a consumer can refuse a shape it
# does not recognise.
DIFF_SCHEMA_VERSION = 1


class DiffError(Exception):
    """Raised when an input artifact is not a shape the diff understands
    (neither a per-function manifest nor a composed product SBOM). We
    fail loud rather than emit a silently-empty changelog."""


# ---------------------------------------------------------------------------
# Normalised view over either input shape (manifest or composed SBOM).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _FunctionView:
    """The three capability views of one function, as sets."""

    declared: frozenset[str]
    reachable: frozenset[str]
    excluded: frozenset[str]
    is_pub: bool


@dataclass
class _View:
    """A version-N (or N+1) artifact reduced to what the diff needs.

    ``pub_functions`` keys on the STABLE ``(container, name)`` identity
    (never ``pos``), so a line-only move is invisible. ``composed_caps``
    /``authority_unknown`` are the product-level roll-up (S2's composed
    set for a composed-SBOM input, or the union over functions for a bare
    manifest). ``grants`` is ``{"fs": {dir: {methods}}, "net": {host:
    {methods}}}`` from the operator-declared block."""

    pub_functions: dict[tuple[Optional[str], str], _FunctionView] = field(
        default_factory=dict
    )
    composed_caps: frozenset[str] = frozenset()
    authority_unknown: bool = False
    grants: dict[str, dict[str, frozenset[str]]] = field(
        default_factory=lambda: {"fs": {}, "net": {}}
    )
    digest: str = ""


def _fn_key(rec: dict[str, Any]) -> tuple[Optional[str], str]:
    """The stable ``(container, name)`` identity of a manifest function
    record. The DISPLAY (demangled) ``source_*`` fields are preferred so
    a shift in a loader mangle prefix (``_capa_m{N}__``) between releases
    does not manufacture a false rename; a bare manifest with only
    ``name`` / ``container`` still keys correctly."""
    container = rec.get("source_container")
    if container is None:
        container = rec.get("container")
    name = rec.get("source_name") or rec.get("name") or ""
    return (container, name)


def _grants_from_block(doc: dict[str, Any]) -> dict[str, dict[str, frozenset[str]]]:
    """Extract the operator-declared grants as a method-set per target.

    Filesystem preopens: ``ro`` -> ``{read}``, ``rw`` -> ``{read,
    write}``. Net hosts: ``get`` -> ``{get}``, ``post`` -> ``{post}``,
    ``connect`` (or missing) -> ``{get, post}``. Modelling a grant as the
    SET of methods it confers makes widening (a method appeared) and
    narrowing (a method vanished) plain set differences, and lets a mixed
    ``get``->``post`` change surface as both."""
    block = doc.get("operator_declared_grants") or {}
    fs: dict[str, frozenset[str]] = {}
    for p in block.get("preopens") or []:
        target = p.get("host_dir")
        if target is None:
            continue
        perm = p.get("permission", "rw")
        methods = frozenset({"read"}) if perm == "ro" else frozenset(
            {"read", "write"}
        )
        fs[target] = methods
    net: dict[str, frozenset[str]] = {}
    for h in block.get("allow_hosts") or []:
        target = h.get("host")
        if target is None:
            continue
        access = h.get("access", "connect")
        if access == "get":
            methods = frozenset({"get"})
        elif access == "post":
            methods = frozenset({"post"})
        else:
            methods = frozenset({"get", "post"})
        net[target] = methods
    return {"fs": fs, "net": net}


def _build_view(doc: dict[str, Any]) -> _View:
    """Reduce a loaded manifest / composed-SBOM JSON to a :class:`_View`.

    A per-function MANIFEST (has ``functions``): the pub functions become
    the per-function surface; the product roll-up is the union of every
    function's ``transitively_reachable`` set, authority-unknown when any
    function crosses ``Unsafe`` (the manifest-level TOP trigger). A
    composed PRODUCT SBOM (has ``composed``): no per-function surface, and
    the product roll-up is S2's ``composed.capabilities`` /
    ``composed.authority_unknown`` (the real TOP). An input that is
    neither is a :class:`DiffError`."""
    view = _View()
    view.digest = manifest_digest(doc)
    view.grants = _grants_from_block(doc)

    has_functions = isinstance(doc.get("functions"), list)
    has_composed = isinstance(doc.get("composed"), dict)
    if not has_functions and not has_composed:
        raise DiffError(
            "input is neither a capability manifest (no 'functions') nor a "
            "composed product SBOM (no 'composed'); expected the JSON that "
            "--manifest / --manifest-digest / --compose-sbom emits"
        )

    if has_functions:
        union: set[str] = set()
        any_unsafe = False
        for rec in doc["functions"]:
            reachable = frozenset(
                rec.get("transitively_reachable_capabilities") or []
            )
            union |= reachable
            if rec.get("has_unsafe"):
                any_unsafe = True
            if rec.get("is_pub"):
                view.pub_functions[_fn_key(rec)] = _FunctionView(
                    declared=frozenset(rec.get("declared_capabilities") or []),
                    reachable=reachable,
                    excluded=frozenset(
                        rec.get("provably_excluded_capabilities") or []
                    ),
                    is_pub=True,
                )
        # A composed-SBOM input carries the AUTHORITATIVE product set;
        # only fall back to the function union when it is absent.
        if has_composed:
            composed = doc["composed"]
            view.composed_caps = frozenset(composed.get("capabilities") or [])
            view.authority_unknown = bool(composed.get("authority_unknown"))
        else:
            view.composed_caps = frozenset(union)
            view.authority_unknown = any_unsafe
    else:
        composed = doc["composed"]
        view.composed_caps = frozenset(composed.get("capabilities") or [])
        view.authority_unknown = bool(composed.get("authority_unknown"))

    return view


# ---------------------------------------------------------------------------
# The diff itself.
# ---------------------------------------------------------------------------


def _function_deltas(
    old: _View, new: _View,
) -> tuple[list[dict[str, Any]], set[str], set[str]]:
    """Per matched PUB function, the four-view delta. Returns the sorted
    changelog entries (only functions with a non-empty delta) plus the
    UNION of caps that widened / narrowed at the function level (used to
    de-duplicate the product-level contribution)."""
    entries: list[dict[str, Any]] = []
    widened_caps: set[str] = set()
    narrowed_caps: set[str] = set()

    for key in sorted(
        set(old.pub_functions) & set(new.pub_functions),
        key=lambda k: (k[0] or "", k[1]),
    ):
        o = old.pub_functions[key]
        n = new.pub_functions[key]
        added = n.reachable - o.reachable
        removed = o.reachable - n.reachable
        guarantee_lost = o.excluded - n.excluded
        guarantee_gained = n.excluded - o.excluded
        if not (added or removed or guarantee_lost or guarantee_gained):
            continue
        widening = bool(added or guarantee_lost)
        narrowing = bool(removed or guarantee_gained)
        if widening and narrowing:
            classification = "mixed"
        elif widening:
            classification = "widening"
        else:
            classification = "narrowing"
        widened_caps |= added | guarantee_lost
        narrowed_caps |= removed | guarantee_gained
        container, name = key
        entries.append({
            "container": container,
            "name": name,
            "added": sorted(added),
            "removed": sorted(removed),
            "guarantee_lost": sorted(guarantee_lost),
            "guarantee_gained": sorted(guarantee_gained),
            "classification": classification,
        })
    return entries, widened_caps, narrowed_caps


def _function_membership_deltas(
    old: _View, new: _View,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, int]:
    """Pub functions that appeared / vanished between the versions.

    An ADDED pub function that carries any authority is a WIDENING of the
    public surface; a REMOVED one that carried authority is a NARROWING.
    A pure (capability-free) function that appears / vanishes is neutral -
    it changes the API but not the authority contract - and does not
    move the gate. Returns the two sorted lists plus the widening /
    narrowing counts they contribute."""
    added_keys = set(new.pub_functions) - set(old.pub_functions)
    removed_keys = set(old.pub_functions) - set(new.pub_functions)

    added_functions: list[dict[str, Any]] = []
    n_widen = 0
    for key in sorted(added_keys, key=lambda k: (k[0] or "", k[1])):
        fv = new.pub_functions[key]
        caps = sorted(fv.reachable)
        classification = "widening" if caps else "neutral"
        if caps:
            n_widen += 1
        added_functions.append({
            "container": key[0],
            "name": key[1],
            "capabilities": caps,
            "classification": classification,
        })

    removed_functions: list[dict[str, Any]] = []
    n_narrow = 0
    for key in sorted(removed_keys, key=lambda k: (k[0] or "", k[1])):
        fv = old.pub_functions[key]
        caps = sorted(fv.reachable)
        classification = "narrowing" if caps else "neutral"
        if caps:
            n_narrow += 1
        removed_functions.append({
            "container": key[0],
            "name": key[1],
            "capabilities": caps,
            "classification": classification,
        })

    return added_functions, removed_functions, n_widen, n_narrow


def _grant_deltas(
    old: _View, new: _View,
) -> tuple[list[dict[str, Any]], int, int]:
    """Operator-grant changes, classified. Returns the sorted entries and
    the widening / narrowing counts. A target that gained a method (new
    grant or a widened access) is a widening; one that lost a method is a
    narrowing; a mixed change emits both."""
    entries: list[dict[str, Any]] = []
    n_widen = 0
    n_narrow = 0

    for grant_type in ("fs", "net"):
        o = old.grants[grant_type]
        n = new.grants[grant_type]
        for target in sorted(set(o) | set(n)):
            o_methods = o.get(target, frozenset())
            n_methods = n.get(target, frozenset())
            if o_methods == n_methods:
                continue
            gained = n_methods - o_methods
            lost = o_methods - n_methods
            if target not in o:
                change = "added"
            elif target not in n:
                change = "removed"
            elif gained and lost:
                change = "changed"
            elif gained:
                change = "widened"
            else:
                change = "narrowed"
            if gained:
                n_widen += 1
            if lost:
                n_narrow += 1
            classification = (
                "mixed" if gained and lost
                else "widening" if gained
                else "narrowing"
            )
            entries.append({
                "grant_type": grant_type,
                "target": target,
                "change": change,
                "from": sorted(o_methods) if o_methods else None,
                "to": sorted(n_methods) if n_methods else None,
                "classification": classification,
            })

    entries.sort(key=lambda e: (e["grant_type"], e["target"]))
    return entries, n_widen, n_narrow


def build_capability_diff(
    old_doc: dict[str, Any],
    new_doc: dict[str, Any],
    *,
    capa_version: Optional[str] = None,
) -> dict[str, Any]:
    """Build the authority-changelog dict between two manifest / composed
    SBOM artifacts (version N = ``old_doc``, N+1 = ``new_doc``).

    The result is JSON-serialisable and deterministic (every list sorted
    by ``(container, name, capability)``); the caller wraps it with the
    S1 :func:`._canonical.canonical_manifest` to attach the content
    digest + detached-signature slot, making the changelog itself
    content-addressable and signABLE. ``from_digest`` / ``to_digest``
    record each input's S1 digest so the changelog is provably about
    those two exact artifacts."""
    if capa_version is None:
        from .. import __version__ as capa_version

    old = _build_view(old_doc)
    new = _build_view(new_doc)

    functions, fn_widened, fn_narrowed = _function_deltas(old, new)
    (added_functions, removed_functions,
     addfn_widen, rmfn_narrow) = _function_membership_deltas(old, new)
    grant_changes, grant_widen, grant_narrow = _grant_deltas(old, new)

    composed_added = new.composed_caps - old.composed_caps
    composed_removed = old.composed_caps - new.composed_caps

    # Authority-unknown transition (a new native / unanalyzable dep made
    # the product unboundable, or - the reverse - a subtree became
    # analyzable). ``gained`` is the high-severity widening.
    if not old.authority_unknown and new.authority_unknown:
        transition: Optional[str] = "gained"
    elif old.authority_unknown and not new.authority_unknown:
        transition = "resolved"
    else:
        transition = None

    # De-duplicate the product contribution against the per-function
    # widenings: a product cap already explained by a function-level
    # widening is not counted twice. What remains is exactly the caps the
    # product gained that NO exported-signature change accounts for (the
    # "transitive dep gained Net" case).
    product_only_widen = composed_added - fn_widened
    product_only_narrow = composed_removed - fn_narrowed

    widenings = (
        len(fn_widened)
        + addfn_widen
        + grant_widen
        + len(product_only_widen)
        + (1 if transition == "gained" else 0)
    )
    narrowings = (
        len(fn_narrowed)
        + rmfn_narrow
        + grant_narrow
        + len(product_only_narrow)
        + (1 if transition == "resolved" else 0)
    )

    return {
        "capa_version": capa_version,
        "diff_schema_version": DIFF_SCHEMA_VERSION,
        "from_digest": {"algorithm": "sha256", "value": old.digest},
        "to_digest": {"algorithm": "sha256", "value": new.digest},
        "functions": functions,
        "added_functions": added_functions,
        "removed_functions": removed_functions,
        "grant_changes": grant_changes,
        "product": {
            "composed_added": sorted(composed_added),
            "composed_removed": sorted(composed_removed),
            "authority_unknown_from": old.authority_unknown,
            "authority_unknown_to": new.authority_unknown,
            "authority_unknown_transition": transition,
        },
        "summary": {
            "widenings": widenings,
            "narrowings": narrowings,
            "authority_unknown_regression": transition == "gained",
        },
        "note": (
            "Authority changelog between two Capa manifests / composed "
            "SBOMs. Functions are matched by the stable (container, name) "
            "identity, never by source position, so a line-only move "
            "produces no entry. added / guarantee_lost are WIDENINGS (more "
            "authority; guarantee_lost = a capability that left "
            "provably_excluded, e.g. an exclusion proof voided by a new "
            "Unsafe / higher-order parameter); removed / guarantee_gained "
            "are NARROWINGS. Only exported (pub) functions appear per "
            "function; a private widening surfaces in product.composed_added. "
            "authority_unknown_transition='gained' is a high-severity "
            "widening: the product became unanalyzable. from_digest / "
            "to_digest are the S1 content digests of the two exact inputs; "
            "this changelog's own content_integrity envelope is signABLE "
            "(the compiler holds no keys)."
        ),
    }
