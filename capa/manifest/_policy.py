"""Organization capability-compliance policies (feature #6, P1).

S2 produced a composed product SBOM (:mod:`._compose`): each package
carries a sound ``composed_capabilities`` set and a distinguished
``authority_unknown`` (TOP) flag, and the product carries a rolled-up
``composed`` surface. S3 let a single package DECLARE its own ceiling.

P1 turns that composed graph into an ENFORCEABLE ORGANIZATION compliance
layer. An auditor writes a product-level ``capa-policy.toml`` (owned by
the organization, at the product root, DISTINCT from any per-package
``capa.toml [capabilities]`` ceiling) declaring product-wide rules over a
FIXED, enumerated set of predicate kinds:

  * ``exclusion``          - no package may hold capabilities X and Y at
                             once (e.g. not (Net and Fs)).
  * ``product-subset``     - the product's composed authority must be a
                             subset-or-equal of a declared set.
  * ``purity``             - a named package (or every package) must be
                             pure (reach no capability).
  * ``forbid-capability``  - no package (or a named package) may hold a
                             given capability.
  * ``forbid-dependency``  - a named package may not depend (directly or
                             transitively) on another named package.
  * ``no-unresolved-dependencies``
                           - the product must have no unresolved
                             dependency (an unanalyzable / unvendored /
                             native edge).
  * ``no-declassification`` - a named package (or the whole product) must
                             contain ZERO audited @secret -> @public
                             declassification sites (feature #6, P2).
  * ``no-secret-egress``   - no secret value may reach a policy-declared
                             egress capability from one package, whether via
                             an AUDITED declassify+egress co-residence or an
                             UN-AUDITED raw secret->egress-sink flow the
                             information-flow analysis proved (the
                             exfiltration-path prohibition) (feature #6,
                             P2 + B1).

The evaluator is PURE over what :func:`._compose.build_composed_sbom`
already emits (``packages`` / ``edges`` / ``unresolved_dependencies`` /
``composed``): no new manifest data, no type-system change. It runs AFTER
the composed SBOM is built and emits a conformance report that is itself
canonical / content-addressable (reuses the S1 content_integrity
envelope) so the evidence is byte-reproducible and signABLE.

FAIL-CLOSED ON AUTHORITY-UNKNOWN (soundness, mirrors S3). A predicate
that quantifies over a package (or the product) whose composed authority
is TOP cannot be PROVEN: an unanalyzable subtree could hold any
capability, so "package P does not hold Net" or "P and its subtree are
pure" cannot be established. Such a predicate FAILS CLOSED with a
distinct ``authority_unknown`` verdict - NEVER reported as passing over
an unanalyzable subtree - unless that policy sets ``allow_unknown =
true`` (an explicit, opt-in waiver of ONLY the TOP failure; a positively
observed concrete violation still fails). ``no-unresolved-dependencies``
is the one exception: it REPORTS the unresolved edges directly, so there
is nothing to fail closed over.
"""

from __future__ import annotations

import sys
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..pkg._manifest import _CEILING_CAP_NAMES

if sys.version_info >= (3, 11):
    import tomllib as _toml
else:  # pragma: no cover - Capa requires 3.10; this branch is dev-only
    try:
        import tomli as _toml  # type: ignore
    except ImportError:
        _toml = None  # type: ignore


# The product-level policy file, at the product root next to ``capa.toml``.
# Deliberately a SEPARATE file: it is organization-owned compliance policy,
# not per-package self-declaration, and it composes over the whole product.
POLICY_FILENAME = "capa-policy.toml"

# Version of the conformance-report schema, independent of the composed
# SBOM version. Bump on any incompatible shape change.
POLICY_SCHEMA_VERSION = 1

# The FIXED, enumerated set of predicate kinds. Strict/closed: an unknown
# kind is a hard parse error, never a silently-ignored policy.
_POLICY_KINDS = frozenset({
    "exclusion",
    "product-subset",
    "purity",
    "forbid-capability",
    "forbid-dependency",
    "no-unresolved-dependencies",
    "no-declassification",
    "no-secret-egress",
})

# Keys every policy entry may carry, plus the kind-specific keys. Anything
# outside the union for a given kind is a hard error (mirrors the closed
# ``[capabilities]`` table parsing).
_COMMON_KEYS = frozenset({"kind", "id", "name", "allow_unknown"})
_KIND_KEYS: dict[str, frozenset[str]] = {
    "exclusion": frozenset({"capabilities", "scope", "over"}),
    "product-subset": frozenset({"max"}),
    "purity": frozenset({"package"}),
    "forbid-capability": frozenset({"capability", "package"}),
    "forbid-dependency": frozenset({"package", "forbidden"}),
    "no-unresolved-dependencies": frozenset(),
    "no-declassification": frozenset({"package"}),
    "no-secret-egress": frozenset({"capabilities", "package"}),
}

# The two capability views a cap-set predicate may test over.
_OVER_VALUES = ("composed", "attributed")


class PolicyError(Exception):
    """Raised on an invalid ``capa-policy.toml`` (unknown key, unknown
    predicate kind, unknown capability name, or a malformed entry). Strict
    by design: a typo in a compliance policy must never become a silent
    weakening of the policy."""


# ---------------------------------------------------------------------------
# The parsed policy.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Policy:
    """One parsed policy entry.

    ``id`` identifies the policy in the conformance report (defaulted to
    ``"<kind>#<index>"`` when the author omits it, so the report stays
    byte-stable in file order). ``params`` holds the validated,
    JSON-ready kind-specific parameters. ``allow_unknown`` opts this
    policy out of the fail-closed-on-authority-unknown rule."""

    id: str
    name: Optional[str]
    kind: str
    allow_unknown: bool
    params: dict[str, Any] = field(default_factory=dict)

    def declared_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "kind": self.kind,
            "allow_unknown": self.allow_unknown,
        }
        out.update(self.params)
        return out


# ---------------------------------------------------------------------------
# A policy violation, with the SAME determinism contract as CeilingViolation.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyViolation:
    """One way a product breaches a declared policy.

    ``verdict`` distinguishes a positively-observed ``"violation"`` from
    an ``"authority_unknown"`` fail-closed (the subtree cannot be
    analyzed, so the policy is unverifiable) and an ``"unsatisfiable"``
    (the policy names a package that is not in the product graph). The
    three are deliberately separated so an auditor can tell "this product
    reaches Net, which you forbade" apart from "part of this product is
    unanalyzable" apart from "your policy targets a package that does not
    exist here"."""

    policy_id: str
    kind: str
    verdict: str
    package: Optional[str]
    capability: Optional[str]
    path: tuple[str, ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy_id,
            "kind": self.kind,
            "verdict": self.verdict,
            "package": self.package,
            "capability": self.capability,
            "path": list(self.path),
            "detail": self.detail,
        }

    def sort_key(self) -> tuple:
        return (
            self.policy_id,
            self.verdict,
            self.kind,
            self.package or "",
            self.capability or "",
            self.path,
        )


# ---------------------------------------------------------------------------
# Parsing ``capa-policy.toml`` (strict / closed).
# ---------------------------------------------------------------------------


def find_policy_file(root_dir: Path) -> Optional[Path]:
    """The product-level ``capa-policy.toml`` at ``root_dir``, or ``None``
    when the product declares no policies."""
    cand = root_dir / POLICY_FILENAME
    return cand if cand.is_file() else None


def read_policy_file(path: Path) -> list[Policy]:
    """Load and strictly validate ``capa-policy.toml``.

    Mirrors the closed-table discipline of ``[capabilities]``: an unknown
    top-level key, an unknown predicate kind, an unknown key inside a
    policy entry, an unknown capability name, or a malformed entry is a
    hard :class:`PolicyError` with a pinpoint message."""
    if _toml is None:  # pragma: no cover - dev-only 3.10 path
        raise PolicyError(
            f"{path}: capa-policy.toml support requires tomllib "
            f"(Python >= 3.11) or the 'tomli' backport"
        )
    text = path.read_text(encoding="utf-8")
    try:
        data = _toml.loads(text)
    except _toml.TOMLDecodeError as e:
        raise PolicyError(f"{path}: {e}") from None
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: policy file root must be a table")

    extras = set(data.keys()) - {"policy"}
    if extras:
        raise PolicyError(
            f"{path}: unknown top-level key(s): {sorted(extras)}; the only "
            f"top-level table is [[policy]]"
        )
    raw = data.get("policy", [])
    if not isinstance(raw, list) or not all(isinstance(e, dict) for e in raw):
        raise PolicyError(
            f"{path}: [[policy]] must be an array of tables"
        )
    policies = [_parse_policy(path, i, entry) for i, entry in enumerate(raw)]
    # S1: policy ids identify results in the SIGNED conformance artifact.
    # A duplicate id would let auditor tooling de-dupe by id and silently
    # drop a result, so reject duplicates loudly at parse time. This covers
    # both explicit ids and the "<kind>#<index>" defaults (which are unique
    # by construction, but an explicit id colliding with a default is
    # caught here too).
    seen: dict[str, int] = {}
    for i, pol in enumerate(policies):
        if pol.id in seen:
            raise PolicyError(
                f"{path}: duplicate policy id {pol.id!r} (policies #{seen[pol.id]} "
                f"and #{i}); each policy id must be unique so the signed "
                f"conformance report has one result per id"
            )
        seen[pol.id] = i
    return policies


def _parse_policy(path: Path, index: int, entry: dict) -> Policy:
    kind = entry.get("kind")
    if not isinstance(kind, str):
        raise PolicyError(
            f"{path}: policy #{index} is missing a string 'kind'"
        )
    if kind not in _POLICY_KINDS:
        raise PolicyError(
            f"{path}: policy #{index} has unknown kind {kind!r}; allowed: "
            f"{sorted(_POLICY_KINDS)}"
        )
    allowed = _COMMON_KEYS | _KIND_KEYS[kind]
    unknown_keys = set(entry.keys()) - allowed
    if unknown_keys:
        raise PolicyError(
            f"{path}: policy #{index} (kind {kind!r}) has unknown key(s): "
            f"{sorted(unknown_keys)}; allowed: {sorted(allowed)}"
        )

    pid = entry.get("id")
    if pid is not None and (not isinstance(pid, str) or not pid.strip()):
        raise PolicyError(
            f"{path}: policy #{index} 'id' must be a non-empty string"
        )
    name = entry.get("name")
    if name is not None and not isinstance(name, str):
        raise PolicyError(
            f"{path}: policy #{index} 'name' must be a string"
        )
    allow_unknown = entry.get("allow_unknown", False)
    if not isinstance(allow_unknown, bool):
        raise PolicyError(
            f"{path}: policy #{index} 'allow_unknown' must be a boolean"
        )

    params = _parse_params(path, index, kind, entry)
    return Policy(
        id=pid if pid else f"{kind}#{index}",
        name=name,
        kind=kind,
        allow_unknown=allow_unknown,
        params=params,
    )


def _parse_params(
    path: Path, index: int, kind: str, entry: dict,
) -> dict[str, Any]:
    where = f"policy #{index} (kind {kind!r})"
    if kind == "exclusion":
        caps = _require_cap_list(path, where, entry, "capabilities")
        if len(caps) < 2:
            raise PolicyError(
                f"{path}: {where} 'capabilities' must name at least two "
                f"capabilities (an exclusion of a single capability is a "
                f"forbid-capability policy)"
            )
        scope = _optional_pkg_name(path, where, entry, "scope")
        over = entry.get("over", "composed")
        if over not in _OVER_VALUES:
            raise PolicyError(
                f"{path}: {where} 'over' must be one of {list(_OVER_VALUES)}"
            )
        return {"capabilities": caps, "scope": scope, "over": over}
    if kind == "product-subset":
        max_caps = _require_cap_list(
            path, where, entry, "max", allow_empty=True,
        )
        return {"max": max_caps}
    if kind == "purity":
        return {"package": _optional_pkg_name(path, where, entry, "package")}
    if kind == "forbid-capability":
        cap = _require_cap(path, where, entry, "capability")
        return {
            "capability": cap,
            "package": _optional_pkg_name(path, where, entry, "package"),
        }
    if kind == "forbid-dependency":
        return {
            "package": _require_pkg_name(path, where, entry, "package"),
            "forbidden": _require_pkg_name(path, where, entry, "forbidden"),
        }
    if kind == "no-declassification":
        return {"package": _optional_pkg_name(path, where, entry, "package")}
    if kind == "no-secret-egress":
        # The author declares the egress set EXPLICITLY (enumerated-and-
        # closed philosophy): no hardcoded default. Each name is validated
        # against the same capability vocabulary as the cap-valued
        # predicates, so a typo is a hard error, not a silently-inert rule.
        caps = _require_cap_list(path, where, entry, "capabilities")
        return {
            "capabilities": caps,
            "package": _optional_pkg_name(path, where, entry, "package"),
        }
    # no-unresolved-dependencies
    return {}


def _require_cap_list(
    path: Path, where: str, entry: dict, key: str, *, allow_empty: bool = False,
) -> list[str]:
    if key not in entry:
        raise PolicyError(f"{path}: {where} is missing required key {key!r}")
    raw = entry[key]
    if not isinstance(raw, list) or not all(isinstance(c, str) for c in raw):
        raise PolicyError(
            f"{path}: {where} {key!r} must be a list of capability name strings"
        )
    if not raw and not allow_empty:
        raise PolicyError(
            f"{path}: {where} {key!r} must not be empty"
        )
    unknown = sorted({c for c in raw if c not in _CEILING_CAP_NAMES})
    if unknown:
        raise PolicyError(
            f"{path}: {where} {key!r} names unknown capability(ies): "
            f"{unknown}; allowed: {sorted(_CEILING_CAP_NAMES)}"
        )
    return sorted(set(raw))


def _require_cap(path: Path, where: str, entry: dict, key: str) -> str:
    if key not in entry:
        raise PolicyError(f"{path}: {where} is missing required key {key!r}")
    cap = entry[key]
    if not isinstance(cap, str):
        raise PolicyError(f"{path}: {where} {key!r} must be a capability name")
    if cap not in _CEILING_CAP_NAMES:
        raise PolicyError(
            f"{path}: {where} {key!r} names unknown capability {cap!r}; "
            f"allowed: {sorted(_CEILING_CAP_NAMES)}"
        )
    return cap


def _require_pkg_name(path: Path, where: str, entry: dict, key: str) -> str:
    if key not in entry:
        raise PolicyError(f"{path}: {where} is missing required key {key!r}")
    v = entry[key]
    if not isinstance(v, str) or not v.strip():
        raise PolicyError(
            f"{path}: {where} {key!r} must be a non-empty package name"
        )
    return v


def _optional_pkg_name(
    path: Path, where: str, entry: dict, key: str,
) -> Optional[str]:
    if key not in entry:
        return None
    return _require_pkg_name(path, where, entry, key)


# ---------------------------------------------------------------------------
# Evaluation over the composed SBOM.
# ---------------------------------------------------------------------------


def evaluate_policies(
    composed: dict[str, Any],
    policies: list[Policy],
    *,
    capa_version: Optional[str] = None,
) -> dict[str, Any]:
    """Evaluate ``policies`` over an already-built composed SBOM
    ``composed`` and return the conformance-report body.

    JSON-serialisable, timestamp-free, and canonicalisable with the S1
    :func:`._canonical.canonical_manifest`. Every reference is a package
    NAME already present (root-relative) in ``composed``, so the report is
    byte-reproducible across machines and working directories."""
    if capa_version is None:
        from .. import __version__ as capa_version

    paths = _name_paths(composed)
    results: list[dict[str, Any]] = []
    for pol in policies:
        violations = _evaluate_one(pol, composed, paths)
        violations.sort(key=lambda v: v.sort_key())
        results.append({
            "policy": pol.id,
            "name": pol.name,
            "kind": pol.kind,
            "pass": not violations,
            "violations": [v.to_dict() for v in violations],
        })

    return {
        "capa_version": capa_version,
        "policy_schema_version": POLICY_SCHEMA_VERSION,
        "product": composed.get("product", {}),
        "policies": [pol.declared_dict() for pol in policies],
        "results": results,
        "pass": all(r["pass"] for r in results),
        "note": (
            "each policy is a predicate over the composed capability graph. "
            "A predicate that quantifies over a package or the product whose "
            "composed authority is UNKNOWN (a TOP element from an "
            "unresolvable / native / Unsafe-crossing subtree) FAILS CLOSED "
            "with verdict 'authority_unknown' - an unanalyzable subtree "
            "cannot be proven to satisfy any capability predicate - unless "
            "that policy sets allow_unknown = true, which waives ONLY the "
            "TOP failure (a positively observed violation still fails). pass "
            "is product-wide: false if ANY policy fails."
        ),
    }


def _evaluate_one(
    pol: Policy, composed: dict[str, Any], paths: dict[str, tuple[str, ...]],
) -> list[PolicyViolation]:
    dispatch = {
        "exclusion": _eval_exclusion,
        "product-subset": _eval_product_subset,
        "purity": _eval_purity,
        "forbid-capability": _eval_forbid_capability,
        "forbid-dependency": _eval_forbid_dependency,
        "no-unresolved-dependencies": _eval_no_unresolved,
        "no-declassification": _eval_no_declassification,
        "no-secret-egress": _eval_no_secret_egress,
    }
    return dispatch[pol.kind](pol, composed, paths)


def _packages(composed: dict[str, Any]) -> list[dict[str, Any]]:
    return composed.get("packages", [])


def _scope_packages(
    composed: dict[str, Any], name: Optional[str],
) -> tuple[list[dict[str, Any]], bool]:
    """The packages a named-or-any scope selects, plus whether a named
    scope was actually found (``True`` for the any-package scope)."""
    if name is None:
        return _packages(composed), True
    matches = [p for p in _packages(composed) if p["name"] == name]
    return matches, bool(matches)


def _unsatisfiable(
    pol: Policy, name: str,
) -> PolicyViolation:
    return PolicyViolation(
        policy_id=pol.id, kind=pol.kind, verdict="unsatisfiable",
        package=name, capability=None, path=(name,),
        detail=(
            f"policy {pol.id!r} names package {name!r}, which is not present "
            f"in the product's composed dependency graph"
        ),
    )


def _unknown_over_package(
    pol: Policy, pkg: dict[str, Any], paths: dict[str, tuple[str, ...]],
    what: str,
) -> PolicyViolation:
    name = pkg["name"]
    return PolicyViolation(
        policy_id=pol.id, kind=pol.kind, verdict="authority_unknown",
        package=name, capability=None, path=paths.get(name, (name,)),
        detail=(
            f"policy {pol.id!r} ({what}) cannot be verified over package "
            f"{name!r}: its composed authority is UNKNOWN (an unresolvable / "
            f"native / Unsafe-crossing dependency in its subtree), so an "
            f"unanalyzable subtree cannot be proven to satisfy the policy. "
            f"Set allow_unknown = true to waive."
        ),
    )


def _eval_exclusion(pol, composed, paths):
    caps = set(pol.params["capabilities"])
    scope = pol.params["scope"]
    over = pol.params["over"]
    cap_field = (
        "composed_capabilities" if over == "composed"
        else "attributed_capabilities"
    )
    unknown_field = (
        "composed_authority_unknown" if over == "composed"
        else "authority_unknown"
    )
    display = sorted(caps)
    pkgs, found = _scope_packages(composed, scope)
    if scope is not None and not found:
        return [_unsatisfiable(pol, scope)]

    out: list[PolicyViolation] = []
    for pkg in pkgs:
        name = pkg["name"]
        known = set(pkg.get(cap_field, []))
        if caps <= known:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=name, capability=None,
                path=paths.get(name, (name,)),
                detail=(
                    f"package {name!r} holds all of {display} simultaneously "
                    f"({over} capabilities), which policy {pol.id!r} forbids"
                ),
            ))
        elif pkg.get(unknown_field) and not pol.allow_unknown:
            # Cannot rule out that the unanalyzable part adds the missing
            # capability(ies), so the exclusion cannot be proven.
            out.append(_unknown_over_package(
                pol, pkg, paths,
                f"exclusion of {display}",
            ))
    return out


def _eval_product_subset(pol, composed, paths):
    max_set = set(pol.params["max"])
    display = sorted(max_set)
    product = composed.get("composed", {})
    root = composed.get("product", {}).get("name", "")
    out: list[PolicyViolation] = []

    over = sorted(set(product.get("capabilities", [])) - max_set)
    for cap in over:
        intro = _introducers(composed, cap, paths)
        if intro:
            path, who = intro[0]
        else:
            path, who = (root,), root
        if who == root and len(path) == 1:
            detail = (
                f"the product declares a subset-of {display} but its own "
                f"code introduces {cap!r}"
            )
        else:
            detail = (
                f"the product declares a subset-of {display} but package "
                f"{who!r} introduces {cap!r} (via {' -> '.join(path)})"
            )
        out.append(PolicyViolation(
            policy_id=pol.id, kind=pol.kind, verdict="violation",
            package=who, capability=cap, path=path, detail=detail,
        ))

    # Fail closed UNCONDITIONALLY when the product's composed authority is
    # TOP (W1): a false PASS over a TOP product would be a soundness hole.
    # evaluate_policies is a public API that accepts ANY composed dict
    # (possibly from an older / foreign producer), so the fail-closed must
    # NOT depend on the reasons list being populated. When reasons are
    # present we attribute each; when the list is empty we still emit one
    # reason-less authority_unknown violation.
    if product.get("authority_unknown") and not pol.allow_unknown:
        reasons = product.get("authority_unknown_reasons", []) or []
        for reason in reasons:
            declared_in = reason.get("declared_in", root)
            dependency = reason.get("dependency", "")
            why = reason.get("reason", "")
            path = _path_to(paths, root, declared_in)
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="authority_unknown",
                package=None, capability=None, path=path,
                detail=(
                    f"the product's composed authority is UNKNOWN: "
                    f"{dependency!r} of {declared_in!r} ({why}) (via "
                    f"{' -> '.join(path)}); a product-subset policy cannot be "
                    f"proven over an unanalyzable subtree. Set allow_unknown "
                    f"= true to waive."
                ),
            ))
        if not reasons:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="authority_unknown",
                package=None, capability=None, path=(root,) if root else (),
                detail=(
                    "the product's composed authority is UNKNOWN (a TOP "
                    "element in its subtree); a product-subset policy cannot "
                    "be proven over an unanalyzable subtree. Set allow_unknown "
                    "= true to waive."
                ),
            ))
    return out


def _eval_purity(pol, composed, paths):
    target = pol.params["package"]
    pkgs, found = _scope_packages(composed, target)
    if target is not None and not found:
        return [_unsatisfiable(pol, target)]

    out: list[PolicyViolation] = []
    for pkg in pkgs:
        name = pkg["name"]
        known = sorted(pkg.get("composed_capabilities", []))
        for cap in known:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=name, capability=cap, path=paths.get(name, (name,)),
                detail=(
                    f"package {name!r} must be pure but reaches {cap!r} "
                    f"(composed capability)"
                ),
            ))
        # The authority-unknown failure is INDEPENDENT of any concrete cap
        # (mirrors S3: exceeds and authority_unknown are reported
        # separately). An unanalyzable subtree cannot be proven pure even
        # when a concrete capability was also observed.
        if pkg.get("composed_authority_unknown") and not pol.allow_unknown:
            out.append(_unknown_over_package(pol, pkg, paths, "purity"))
    return out


def _eval_forbid_capability(pol, composed, paths):
    cap = pol.params["capability"]
    target = pol.params["package"]
    pkgs, found = _scope_packages(composed, target)
    if target is not None and not found:
        return [_unsatisfiable(pol, target)]

    out: list[PolicyViolation] = []
    for pkg in pkgs:
        name = pkg["name"]
        known = set(pkg.get("composed_capabilities", []))
        if cap in known:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=name, capability=cap, path=paths.get(name, (name,)),
                detail=(
                    f"package {name!r} holds capability {cap!r}, which policy "
                    f"{pol.id!r} forbids"
                ),
            ))
        elif pkg.get("composed_authority_unknown") and not pol.allow_unknown:
            out.append(_unknown_over_package(
                pol, pkg, paths, f"forbid-capability {cap!r}",
            ))
    return out


def _eval_forbid_dependency(pol, composed, paths):
    """A named package may not depend (directly or transitively) on another.

    Both ends are validated against the graph so a typo cannot make the
    rule silently inert (a false all-clear): the source ``package`` must be
    a package NAME, and ``forbidden`` must match at least one package name
    OR one declared edge dependency name (the latter keeps the legitimate
    case where ``forbidden`` is an unresolved / native dependency that is
    still a declared edge). Either miss reports ``unsatisfiable`` (loud).

    S2 (conservative fail-closed): the ``authority_unknown`` verdict fires
    when ANY unresolved edge sits in the source package's reachable
    closure - even one unrelated to ``forbidden`` - because a hidden path
    to ``forbidden`` behind an unanalyzable node cannot be ruled out. This
    is deliberately conservative; it is waivable via ``allow_unknown``."""
    src = pol.params["package"]
    forbidden = pol.params["forbidden"]
    names = {p["name"] for p in _packages(composed)}
    if src not in names:
        return [_unsatisfiable(pol, src)]
    # W2: reject a ``forbidden`` that matches nothing (a pure typo), else a
    # misspelled target would match no package / edge and silently pass.
    edge_dep_names = {
        e.get("dependency") for e in composed.get("edges", [])
        if e.get("dependency")
    }
    if forbidden not in names and forbidden not in edge_dep_names:
        return [_unsatisfiable(pol, forbidden)]

    verdict, dep_path, unknown = _dependency_reaches(composed, src, forbidden)
    if verdict:
        return [PolicyViolation(
            policy_id=pol.id, kind=pol.kind, verdict="violation",
            package=src, capability=None, path=dep_path,
            detail=(
                f"package {src!r} depends on {forbidden!r} (via "
                f"{' -> '.join(dep_path)}), which policy {pol.id!r} forbids"
            ),
        )]
    if unknown and not pol.allow_unknown:
        return [PolicyViolation(
            policy_id=pol.id, kind=pol.kind, verdict="authority_unknown",
            package=src, capability=None, path=(src,),
            detail=(
                f"cannot verify that package {src!r} does not depend on "
                f"{forbidden!r}: its dependency subtree contains an "
                f"unresolved edge, so a hidden path to {forbidden!r} cannot "
                f"be ruled out. Set allow_unknown = true to waive."
            ),
        )]
    return []


def _eval_no_unresolved(pol, composed, paths):
    out: list[PolicyViolation] = []
    for u in composed.get("unresolved_dependencies", []):
        declared_in = u.get("declared_in", "")
        dependency = u.get("dependency", "")
        reason = u.get("reason", "")
        out.append(PolicyViolation(
            policy_id=pol.id, kind=pol.kind, verdict="violation",
            package=declared_in, capability=None,
            path=paths.get(declared_in, (declared_in,)),
            detail=(
                f"package {declared_in!r} has an unresolved dependency "
                f"{dependency!r} ({reason}), which policy {pol.id!r} forbids"
            ),
        ))
    return out


def _eval_no_declassification(pol, composed, paths):
    """A named package (or the whole product) must contain ZERO audited
    @secret -> @public declassification sites (feature #6, P2).

    The count is the COMPOSED (transitive) one, mirroring the capability
    predicates: a package "contains" a declassification when it or any
    dependency in its resolved-edge closure declassifies. A positive count
    is a ``violation``. A TOP package / product (composed authority
    unknown) FAILS CLOSED with ``authority_unknown`` unless
    ``allow_unknown`` is set: an unanalyzable subtree may declassify unseen,
    so a confident "zero" cannot be proven. A named package absent from the
    graph is ``unsatisfiable``.

    What this proves, precisely: the package/product performs no AUDITED
    ``declassify`` (an @secret -> @public bridge) anywhere in its resolved
    closure. The stronger reading - "releases no secret data" - holds under
    the opt-in ``@strict_ifc()`` attribute, where a raw secret-to-sink leak
    is a HARD ERROR rather than the default WARNING, so ``declassify`` is the
    only remaining release path. Absent ``@strict_ifc`` this predicate bounds
    the AUDITED release path only; it composes with, and does not replace,
    strict IFC. (A machine-checked strict-IFC precondition is planned as a
    follow-up.)"""
    target = pol.params["package"]
    if target is None:
        # Product-wide: read the roll-up in ``composed``.
        product = composed.get("composed", {})
        root = composed.get("product", {}).get("name", "")
        count = product.get("declassification_sites", 0)
        out: list[PolicyViolation] = []
        if count > 0:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=None, capability=None, path=(root,) if root else (),
                detail=(
                    f"the product contains {count} audited declassification "
                    f"site(s) (@secret -> @public bridges), but policy "
                    f"{pol.id!r} requires zero"
                ),
            ))
        elif product.get("authority_unknown") and not pol.allow_unknown:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="authority_unknown",
                package=None, capability=None, path=(root,) if root else (),
                detail=(
                    f"policy {pol.id!r} (no-declassification) cannot be "
                    f"verified over the product: its composed authority is "
                    f"UNKNOWN (a TOP element from an unresolvable / native / "
                    f"Unsafe-crossing subtree), so an unanalyzable subtree "
                    f"cannot be proven free of declassification. Set "
                    f"allow_unknown = true to waive."
                ),
            ))
        return out

    pkgs, found = _scope_packages(composed, target)
    if not found:
        return [_unsatisfiable(pol, target)]
    out = []
    for pkg in pkgs:
        name = pkg["name"]
        count = pkg.get("composed_declassification_sites", 0)
        if count > 0:
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=name, capability=None, path=paths.get(name, (name,)),
                detail=(
                    f"package {name!r} contains {count} audited "
                    f"declassification site(s) (@secret -> @public bridges), "
                    f"but policy {pol.id!r} requires zero"
                ),
            ))
        elif pkg.get("composed_authority_unknown") and not pol.allow_unknown:
            out.append(_unknown_over_package(
                pol, pkg, paths, "no-declassification",
            ))
    return out


def _eval_no_secret_egress(pol, composed, paths):
    """No secret value may reach a policy-declared egress capability from a
    single in-scope package -- whether via an AUDITED declassify or an
    UN-AUDITED raw flow (feature #6, P2 + B1).

    This is the exfiltration-path prohibition. It fires in TWO concrete
    modes, either of which is a ``violation``:

    * AUDITED co-residence (P2): a package whose OWN code both declassifies
      secret data (an attributed ``declassify`` site) AND can reach a
      declared egress capability (its COMPOSED capability set intersects the
      egress set). The authority to UNMASK secret data and the authority to
      SEND IT OUT must not co-reside in one package, so a review boundary
      sits between them. The test reads the package's OWN (attributed)
      declassification count, NOT the transitive one: a package that merely
      WIRES a separate declassifier dependency and a separate networker
      dependency (the separation-of-duties shape this policy REWARDS)
      composes a transitive declassification and an egress cap from two
      DIFFERENT children without ever unmasking-and-sending in its own code,
      and must not be flagged.

    * UN-AUDITED raw leak (B1): a package whose OWN un-audited
      secret->egress-sink set intersects the declared egress set -- a raw
      @secret value the IFC analysis proved reaches an egress sink (e.g.
      ``net.post(url, token)``) with NO ``declassify``. Capa's
      secret-to-public-sink check is warn-only by default (a hard error only
      under ``@strict_ifc``); this materializes that warn-tier fact as a
      first-class per-package leak set. Because a strict-IFC flow is a
      compile error (no manifest is produced), every recorded flow in a
      COMPILED program is by construction un-audited and non-strict, so the
      recorded set is EXACTLY the un-audited leaks in the shipped code.

    A TOP in-scope package (its declassification status, capability set,
    and/or leak set unknown) FAILS CLOSED with ``authority_unknown`` unless
    ``allow_unknown`` is set; a named absent package is ``unsatisfiable``.

    What this proves, precisely: no secret value reaches a declared egress
    capability from one package, audited or not. The two authorities (unmask
    + send) are separated across packages AND no un-audited raw secret->sink
    flow to a declared egress capability exists in any in-scope package. The
    honest residual is now the IFC analysis's own detection completeness (a
    secret the flow analysis fails to track cannot be recorded), NOT the
    warn-vs-strict distinction: a raw leak no longer needs ``@strict_ifc`` to
    be caught by this predicate."""
    egress = set(pol.params["capabilities"])
    display = sorted(egress)
    target = pol.params["package"]
    pkgs, found = _scope_packages(composed, target)
    if target is not None and not found:
        return [_unsatisfiable(pol, target)]

    out: list[PolicyViolation] = []
    for pkg in pkgs:
        name = pkg["name"]
        count = pkg.get("attributed_declassification_sites", 0)
        held = sorted(egress & set(pkg.get("composed_capabilities", [])))
        # B1: the package's OWN un-audited raw secret->egress-sink flows that
        # land on a declared egress capability.
        leaked = sorted(egress & set(
            pkg.get("unaudited_secret_sink_capabilities", []),
        ))
        fired = False
        if count > 0 and held:
            fired = True
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=name, capability=None, path=paths.get(name, (name,)),
                detail=(
                    f"package {name!r} BOTH declassifies secret data "
                    f"({count} site(s)) AND holds egress capability(ies) "
                    f"{held} (of the declared egress set {display}): the "
                    f"authority to unmask secret data and the authority to "
                    f"send it out must not co-reside in one package (an "
                    f"exfiltration path), which policy {pol.id!r} forbids"
                ),
            ))
        if leaked:
            fired = True
            out.append(PolicyViolation(
                policy_id=pol.id, kind=pol.kind, verdict="violation",
                package=name, capability=None, path=paths.get(name, (name,)),
                detail=(
                    f"package {name!r} routes a @secret value to egress "
                    f"capability(ies) {leaked} (of the declared egress set "
                    f"{display}) with NO declassify: an UN-AUDITED raw "
                    f"secret->egress flow the information-flow analysis "
                    f"proved reaches the sink, which policy {pol.id!r} forbids"
                ),
            ))
        if (
            not fired
            and pkg.get("composed_authority_unknown")
            and not pol.allow_unknown
        ):
            # A TOP package could declassify, hold an egress capability, or
            # leak a raw secret unseen, so the exfiltration path cannot be
            # ruled out: fail closed.
            out.append(_unknown_over_package(
                pol, pkg, paths, f"no-secret-egress of {display}",
            ))
    return out


# ---------------------------------------------------------------------------
# Graph helpers over the composed dict (pure; package-NAME keyed).
# ---------------------------------------------------------------------------


def _name_paths(composed: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Shortest path (tuple of package NAMES) from the product root to
    every package reachable over resolved edges. Neighbours visited in
    name order so the chosen path is deterministic."""
    root = composed.get("product", {}).get("name", "")
    adj: dict[str, set[str]] = {}
    for e in composed.get("edges", []):
        if e.get("resolved") and e.get("to_package"):
            adj.setdefault(e["from"], set()).add(e["to_package"])
    paths: dict[str, tuple[str, ...]] = {root: (root,)}
    q: deque[str] = deque([root])
    while q:
        cur = q.popleft()
        for nxt in sorted(adj.get(cur, ())):
            if nxt not in paths:
                paths[nxt] = paths[cur] + (nxt,)
                q.append(nxt)
    return paths


def _path_to(
    paths: dict[str, tuple[str, ...]], root: str, target: str,
) -> tuple[str, ...]:
    if target == root:
        return (root,)
    p = paths.get(target)
    if p is not None:
        return p
    return (root, target)


def _introducers(
    composed: dict[str, Any], cap: str, paths: dict[str, tuple[str, ...]],
) -> list[tuple[tuple[str, ...], str]]:
    """(path, package-name) for every package whose OWN attributed set
    carries ``cap``, nearest first (shortest path, then name)."""
    res: list[tuple[tuple[str, ...], str]] = []
    for p in _packages(composed):
        if cap in p.get("attributed_capabilities", []):
            name = p["name"]
            res.append((paths.get(name, (name,)), name))
    res.sort(key=lambda x: (len(x[0]), x[0]))
    return res


def _dependency_reaches(
    composed: dict[str, Any], src: str, forbidden: str,
) -> tuple[bool, tuple[str, ...], bool]:
    """Does ``src`` depend (directly or transitively) on ``forbidden``?

    Returns ``(reached, path, unknown)``. A DIRECT edge from a visited
    package whose declared dependency name OR resolved package name equals
    ``forbidden`` is a hit (works even for an unresolved edge that names
    ``forbidden`` outright). Transitive reach follows RESOLVED edges only;
    an unresolved edge anywhere in the closure (that does not itself name
    ``forbidden``) sets ``unknown``: a hidden path to ``forbidden`` behind
    an unanalyzable node cannot be ruled out."""
    edges_by_from: dict[str, list[dict[str, Any]]] = {}
    for e in composed.get("edges", []):
        edges_by_from.setdefault(e["from"], []).append(e)

    parent: dict[str, Optional[str]] = {src: None}
    q: deque[str] = deque([src])
    unknown = False
    while q:
        cur = q.popleft()
        edges = sorted(
            edges_by_from.get(cur, []),
            key=lambda e: (e.get("dependency") or "", e.get("to_package") or ""),
        )
        for e in edges:
            if e.get("dependency") == forbidden or e.get("to_package") == forbidden:
                path = _reconstruct(parent, cur) + (forbidden,)
                return True, path, unknown
            if not e.get("resolved"):
                unknown = True
                continue
            nxt = e.get("to_package")
            if nxt and nxt not in parent:
                parent[nxt] = cur
                q.append(nxt)
    return False, (src,), unknown


def _reconstruct(
    parent: dict[str, Optional[str]], node: str,
) -> tuple[str, ...]:
    chain: list[str] = []
    cur: Optional[str] = node
    while cur is not None:
        chain.append(cur)
        cur = parent[cur]
    return tuple(reversed(chain))
