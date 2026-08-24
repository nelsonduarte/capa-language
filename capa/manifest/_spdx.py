"""SPDX 2.3 SBOM wrapper around the Capa manifest.

Companion to ``_cyclonedx.py``. Emits the same per-function
capability metadata in SPDX 2.3 JSON, so a Capa program can be
ingested by tooling that prefers SPDX (Linux Foundation
ecosystem, OpenChain conformance, license-compliance pipelines)
in addition to the CycloneDX side already covered.

Mapping decisions (mirroring the CycloneDX side where shape
allows; departing where SPDX schema is stricter):

- The Capa file becomes the top-level package; the SPDX document
  ``DESCRIBES`` it.
- Each function becomes its own package (SPDX has no smaller
  granularity than ``package`` for non-file artefacts; packages
  with ``filesAnalyzed: false`` are the standard way to represent
  a logical sub-component).
- Each user-defined capability becomes a package.
- Per-function and per-cap metadata travels via ``annotations[]``
  on each package. SPDX is more rigid than CycloneDX: there is no
  free-form properties array, so annotations with a
  ``capa:<key>=<value>`` payload in the ``comment`` field is the
  closest faithful encoding.
- Capability membership and intra-module calls become explicit
  ``relationships[]`` entries (``DEPENDS_ON``).
- Each resolved capa.toml dependency becomes its own SPDX ``Package``
  carrying the dependency's ``purl`` as an ``externalRefs[]`` entry, and
  the declared-edge relation becomes ``DEPENDS_ON`` relationships. The
  records are RESOLVED upstream (:func:`resolve_dependency_identities` in
  the compose layer) and consumed here verbatim: this emitter never parses
  capa.toml / capa.lock and never assembles a purl of its own -- the exact
  mirror of the CycloneDX dependency side, from the ONE source.

SPDX IDs must match ``SPDXRef-[a-zA-Z0-9.-]+``. Function names
like ``Foo::bar`` are sanitised by replacing non-conforming
characters with ``-`` so the IDs validate without losing
readability.
"""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .. import capa_ast as A

from ..typesys import CAPABILITY_NAMES as _BUILTIN_CAPABILITY_NAMES
from ._compose import ComposeError
from ._funrec import _identifier_seed, build_manifest, display_filename
from ._strings import _cap_sbom_value


# Target SPDX specification version. 2.3 is the current stable
# (2024) and the version every major tool understands. 3.0 is JSON-
# Lite-shaped and breaks compatibility; not adopted yet.
SPDX_SPEC_VERSION = "SPDX-2.3"

# SPDX requires every document to declare its dataLicense; the
# spec recommends CC0-1.0 and most tools assume it.
SPDX_DATA_LICENSE = "CC0-1.0"

# Compliance-grade SPDX consumers (OpenChain, spdx-tool validate
# --strict) require ``licenseConcluded``, ``licenseDeclared``, and
# ``copyrightText`` on every package. SPDX 2.3 blesses
# ``NOASSERTION`` as the placeholder when the producer has not
# determined a license / copyright. Audit 2026-05-25 H5: prior
# output omitted these fields entirely, so strict validators
# refused the document. The default is centralised here so the
# code that builds packages does not repeat the three fields.
_SPDX_NOASSERT_LICENSE_FIELDS: dict[str, str] = {
    "licenseConcluded": "NOASSERTION",
    "licenseDeclared": "NOASSERTION",
    "copyrightText": "NOASSERTION",
}


_SPDXID_RE = re.compile(r"[^a-zA-Z0-9.-]")


def _spdx_id(*parts: str) -> str:
    """Build a syntactically-valid SPDXRef-* identifier from arbitrary
    name parts. Non-conforming characters are replaced with '-'.
    """
    raw = "-".join(p for p in parts if p)
    safe = _SPDXID_RE.sub("-", raw)
    safe = safe.strip("-") or "anonymous"
    return f"SPDXRef-{safe}"


def _annot(timestamp: str, key: str, value: str) -> dict[str, str]:
    """A standard SPDX annotation carrying a single capa:<key>=<value>
    payload. SPDX has no key/value annotation shape; the convention is
    to use the ``comment`` field with a stable prefix.
    """
    return {
        "annotationDate": timestamp,
        "annotationType": "OTHER",
        "annotator": "Tool: capa",
        "comment": f"capa:{key}={value}",
    }


def build_spdx(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    timestamp: Optional[str] = None,
    document_namespace: Optional[str] = None,
    source: Optional[str] = None,
    sources: Optional[dict[str, str]] = None,
    bindings: Optional[dict[int, Any]] = None,
    expr_labels: Optional[dict[int, str]] = None,
    operator_declared_grants: Optional[dict[str, Any]] = None,
    dependency_components: Optional[list[Any]] = None,
    dependency_graph: Optional[Any] = None,
) -> dict[str, Any]:
    """Build an SPDX 2.3 document with embedded Capa capability metadata.

    ``timestamp`` and ``document_namespace`` are exposed for
    deterministic test output; production callers should leave them
    as the defaults. The namespace defaults to a UUIDv5-stable URN
    derived from the display filename plus, when ``source`` (the raw
    .capa text) is given, the source's sha256, so two unrelated
    projects that share a root basename get distinct namespaces.
    The CLI always passes ``source``.

    ``dependency_components`` are the product's resolved capa.toml
    dependencies as ``DependencyIdentity`` records (from
    :func:`resolve_dependency_identities`); each becomes an SPDX
    ``Package`` carrying its name, version, and (for a git dep) its purl
    as an ``externalRefs[]`` entry. ``dependency_graph`` is the matching
    declared-edge relation, rendered as ``DEPENDS_ON`` relationships. Both
    default to empty (a bare .capa file with no project root), leaving the
    program's own package / file / relationship subtree byte-identical to
    today. This emitter is a pure CONSUMER of those records: it never reads
    capa.toml / capa.lock and never assembles a purl -- the exact mirror of
    the CycloneDX dependency side, keyed off the SAME single source.
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    inner = build_manifest(
        module, filename=filename, capa_version=capa_version,
        bindings=bindings,
        expr_labels=expr_labels,
        operator_declared_grants=operator_declared_grants,
    )

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Seed the namespace from the display form (root-relative; the
    # basename for the root file), never the raw CLI argument: the
    # raw form varies with the invocation style (relative vs
    # absolute, cwd) and across machines, which would break
    # byte-reproducibility of the document namespace. The source
    # digest joins the seed (see ``_identifier_seed``) so two
    # projects sharing a basename do not collide.
    display = display_filename(filename)
    if document_namespace is None:
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://capa-language.com/spdx")
        seed = _identifier_seed(filename, source, sources)
        document_namespace = (
            f"https://capa-language.com/spdx/{uuid.uuid5(ns, seed)}"
        )

    bom_basename = os.path.basename(display) or display

    program_id = _spdx_id("Package", bom_basename)
    document_id = "SPDXRef-DOCUMENT"

    # ----- The top-level program package -----
    program_annotations: list[dict[str, str]] = [
        _annot(timestamp, "schema_version", str(inner["schema_version"])),
        _annot(timestamp, "summary:total_functions",
               str(inner["summary"]["total_functions"])),
        _annot(timestamp, "summary:functions_with_capabilities",
               str(inner["summary"]["functions_with_capabilities"])),
        _annot(timestamp, "summary:functions_with_attributes",
               str(inner["summary"]["functions_with_attributes"])),
        _annot(timestamp, "summary:functions_crossing_unsafe",
               str(inner["summary"]["functions_crossing_unsafe"])),
    ]
    # WASI Fs layer b1: operator-DECLARED grants (e.g. --preopen) as
    # program-package annotations, labelled operator-declared (Level 2)
    # so an SPDX consumer does not read them as program-proven authority.
    _grants = inner.get("operator_declared_grants") or {}
    _preopens = _grants.get("preopens") or []
    _allow_hosts = _grants.get("allow_hosts") or []
    if _preopens or _allow_hosts:
        program_annotations.append(_annot(
            timestamp, "operator_declared_grants:trust_level",
            str(_grants.get("trust_level", "operator-declared")),
        ))
        for _pre in _preopens:
            program_annotations.append(_annot(
                timestamp, "operator_declared_grant:preopen",
                f"{_pre.get('host_dir', '')} [{_pre.get('permission', 'rw')}]",
            ))
        # One annotation per operator-granted Net host (--allow-host),
        # Level-2 authority distinct from the compiler-derived surface. The
        # access scope (get / post / connect, the --allow-host method
        # suffix) is rendered in-band so a read-only (get) grant reads as
        # narrower than a connect (get+post) one.
        for _nh in _allow_hosts:
            program_annotations.append(_annot(
                timestamp, "operator_declared_grant:allow-host",
                f"{_nh.get('host', '')} [{_nh.get('access', 'connect')}]",
            ))
    # WASI Layer 1: compiler-DERIVED, program-PROVEN argv -> sink surface
    # as program-package annotations, labelled compiler-derived (the
    # OPPOSITE trust level to the operator-declared grants above) so an
    # SPDX consumer reads it as a machine-verifiable fact, not an operator
    # declaration. One annotation per proven argv -> sink fact.
    _surface = inner.get("compiler_derived_path_arg_surface") or {}
    _args = _surface.get("arguments") or []
    if _args:
        program_annotations.append(_annot(
            timestamp, "compiler_derived_path_arg_surface:trust_level",
            str(_surface.get("trust_level", "compiler-derived")),
        ))
        for _a in _args:
            program_annotations.append(_annot(
                timestamp, "compiler_derived:path_arg_surface",
                f"argv[{_a.get('arg_index', '*')}] -> "
                f"{_a.get('capability', '')}.{_a.get('method', '')} "
                f"({_a.get('access', '')})",
            ))
    program_pkg = {
        "SPDXID": program_id,
        "name": bom_basename,
        "versionInfo": capa_version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        **_SPDX_NOASSERT_LICENSE_FIELDS,
        "annotations": program_annotations,
    }

    packages: list[dict[str, Any]] = [program_pkg]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": document_id,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": program_id,
        },
    ]

    # ----- One package per transitively-reached built-in cap -----
    # Slice 23 (2026-05-29): synthesise a package for each built-
    # in cap any function in the program transitively reaches, so
    # ``DEPENDS_ON`` edges built below can resolve to a real
    # SPDXID. Mirrors the CycloneDX builtin-cap synthesis. Without
    # this the dep graph carries the slice-21 transitive claim as
    # an annotation but not as a walkable edge.
    reached_builtins: set[str] = set()
    for fn in inner["functions"]:
        for cap in fn.get("transitively_reachable_capabilities", []):
            if cap in _BUILTIN_CAPABILITY_NAMES:
                reached_builtins.add(cap)
    builtin_cap_ids: dict[str, str] = {}
    for cap_name in sorted(reached_builtins):
        cap_id = _spdx_id("Builtin", bom_basename, cap_name)
        builtin_cap_ids[cap_name] = cap_id
        packages.append({
            "SPDXID": cap_id,
            "name": cap_name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            **_SPDX_NOASSERT_LICENSE_FIELDS,
            "annotations": [
                _annot(timestamp, "kind", "builtin-capability"),
            ],
        })
        relationships.append({
            "spdxElementId": program_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": cap_id,
        })

    # ----- One package per user-defined capability -----
    user_cap_ids: dict[str, str] = {}
    for uc in inner["user_defined_capabilities"]:
        cap_id = _spdx_id("Cap", bom_basename, uc["name"])
        user_cap_ids[uc["name"]] = cap_id
        annots: list[dict[str, str]] = [
            _annot(timestamp, "kind", "capability"),
        ]
        if uc.get("doc"):
            annots.append(_annot(timestamp, "doc", uc["doc"]))
        for method_name in uc["methods"]:
            annots.append(_annot(timestamp, "capability:method", method_name))
        for impl_name in uc["implementors"]:
            annots.append(
                _annot(timestamp, "capability:implementor", impl_name)
            )
        packages.append({
            "SPDXID": cap_id,
            "name": uc["name"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            **_SPDX_NOASSERT_LICENSE_FIELDS,
            "annotations": annots,
        })
        relationships.append({
            "spdxElementId": program_id,
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": cap_id,
        })

    # ----- One package per function -----
    fn_ids: dict[str, str] = {}
    for fn in inner["functions"]:
        if fn["container"] is None:
            # Top-level function; keyed by name for call-edge resolution.
            fn_ids[fn["name"]] = _spdx_id("Fn", bom_basename, fn["name"])

    for fn in inner["functions"]:
        # SPDXID keyed on the loader-time name (collision-stable);
        # display name uses the source-level identifier so the SBOM
        # reads as a regulator expects. See _funrec.py for the
        # demangle helper that produces source_name / source_container.
        if fn["container"]:
            qualname = (
                f"{fn['source_container'] or fn['container']}"
                f"::{fn['source_name']}"
            )
            fn_id = _spdx_id("Fn", bom_basename, fn["container"], fn["name"])
        else:
            qualname = fn["source_name"]
            fn_id = fn_ids[fn["name"]]

        annots = [
            _annot(timestamp, "kind", "function"),
            _annot(timestamp, "pos", fn["pos"]),
            _annot(timestamp, "return_type", fn["return_type"]),
            _annot(timestamp, "has_unsafe", str(fn["has_unsafe"]).lower()),
            _annot(timestamp, "is_pub", str(fn["is_pub"]).lower()),
        ]
        if fn.get("source_module_index") is not None:
            annots.append(_annot(
                timestamp, "source_module_index",
                str(fn["source_module_index"]),
            ))
        if fn.get("doc"):
            annots.append(_annot(timestamp, "doc", fn["doc"]))
        if fn["container"]:
            annots.append(_annot(
                timestamp, "container",
                fn["source_container"] or fn["container"],
            ))
        for cap_type in fn["declared_capabilities"]:
            annots.append(_annot(timestamp, "declared_capability", cap_type))
        # Slice 23 (2026-05-29): surface the transitively-
        # reachable set so SPDX consumers see the honest
        # authority chain in addition to the signature-only
        # ``declared_capability`` view.
        for cap_type in fn.get("transitively_reachable_capabilities", []):
            annots.append(_annot(
                timestamp, "transitively_reachable_capability", cap_type,
            ))
        for cap_type in fn.get("provably_excluded_capabilities", []):
            annots.append(_annot(
                timestamp, "provably_excluded_capability", cap_type,
            ))
        for param in fn["params"]:
            annots.append(_annot(timestamp, "param", _flat_param(param)))
        for attr in fn["attributes"]:
            for k, v in attr["args"].items():
                annots.append(_annot(
                    timestamp, f"attribute:{attr['name']}:{k}",
                    _cap_sbom_value(v),
                ))
            if not attr["args"]:
                annots.append(_annot(
                    timestamp, f"attribute:{attr['name']}", "",
                ))
        packages.append({
            "SPDXID": fn_id,
            "name": qualname,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            **_SPDX_NOASSERT_LICENSE_FIELDS,
            "annotations": annots,
        })

        relationships.append({
            "spdxElementId": program_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": fn_id,
        })

        # Function -> every capability (user-defined OR built-in)
        # it transitively reaches. Slice 23 (2026-05-29) widened
        # this from the signature-only ``declared_capabilities``
        # to the honest reachable set, matching the CycloneDX
        # side and the per-function exclusion claim.
        seen_targets: set[str] = set()
        for cap_type in fn.get("transitively_reachable_capabilities", []):
            cap_id = user_cap_ids.get(cap_type) or builtin_cap_ids.get(cap_type)
            if cap_id and cap_id not in seen_targets:
                relationships.append({
                    "spdxElementId": fn_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": cap_id,
                })
                seen_targets.add(cap_id)

        # Function -> functions it calls (intra-module).
        for call in fn["calls"]:
            if call["kind"] != "fn":
                continue
            target_id = fn_ids.get(call["callee"])
            if target_id and target_id not in seen_targets:
                relationships.append({
                    "spdxElementId": fn_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target_id,
                })
                seen_targets.add(target_id)

    # ----- Real capa.toml dependency packages (resolved upstream) -----
    # One APPENDED SPDX Package per resolved (or declared-but-unresolved)
    # capa.toml dependency, carrying its name + version + purl externalRef.
    # The records and the edge relation are built by the compose layer's
    # ``resolve_dependency_identities`` and consumed verbatim here (the
    # mirror of the CycloneDX side), so the dependency-identity knowledge
    # and the single purl producer live in exactly one place. The program's
    # own package / file / relationship subtree above is untouched -- deps
    # are strictly appended.
    dep_id_by_ref: dict[str, str] = {}
    for record in dependency_components or []:
        pkg = _dependency_package(record, timestamp)
        packages.append(pkg)
        # A record's bom_ref is globally unique (the purl, or a deterministic
        # ``capa:dep`` fallback), so this table is the edge -> SPDXID
        # translation the relationship graph reads below.
        dep_id_by_ref[record.bom_ref] = pkg["SPDXID"]

    # FAIL-CLOSED uniqueness guard. Every SPDXID in the document must be
    # distinct: SPDX relationships resolve by SPDXID, so a collision would
    # silently merge two elements. The Dep IDs carry a bom_ref hash suffix
    # that should make this never fire, but the guard is the non-negotiable
    # backstop (the codebase's fail-loud idiom, mirroring ``_function_files``
    # in _compose.py). We raise ``ComposeError`` rather than emit a
    # silently-wrong document.
    seen_ids: set[str] = set()
    for pkg in packages:
        sid = pkg["SPDXID"]
        if sid in seen_ids:
            raise ComposeError(
                f"duplicate SPDXID {sid!r} in the SPDX document; cannot "
                f"emit an unambiguous SBOM"
            )
        seen_ids.add(sid)

    # Mirror the CycloneDX dependencies graph as SPDX DEPENDS_ON edges,
    # translating each bom_ref through the table above: the program
    # DEPENDS_ON each top-level dependency, and each parent dependency
    # DEPENDS_ON its declared sub-dependencies.
    if dependency_graph is not None:
        for child_ref in dependency_graph.root_children:
            child_id = dep_id_by_ref.get(child_ref)
            if child_id is not None:
                relationships.append({
                    "spdxElementId": program_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": child_id,
                })
        for parent_ref, child_refs in dependency_graph.child_edges:
            parent_id = dep_id_by_ref.get(parent_ref)
            if parent_id is None:
                continue
            for child_ref in child_refs:
                child_id = dep_id_by_ref.get(child_ref)
                if child_id is not None:
                    relationships.append({
                        "spdxElementId": parent_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": child_id,
                    })

    return {
        "spdxVersion": SPDX_SPEC_VERSION,
        "dataLicense": SPDX_DATA_LICENSE,
        "SPDXID": document_id,
        "name": bom_basename,
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": timestamp,
            "creators": [f"Tool: capa-{capa_version}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def _dependency_package(record: Any, timestamp: str) -> dict[str, Any]:
    """Render one resolved capa.toml ``DependencyIdentity`` as an SPDX
    ``Package``.

    A pure projection of the upstream record: ``name``, ``version`` and
    ``purl`` are read VERBATIM (never re-derived here), so this emitter
    holds no dependency-identity knowledge of its own and assembles no
    purl. ``versionInfo`` is emitted only when the record has a version (an
    unresolved dep has none); the purl travels as a single ``externalRefs``
    entry only when present (a path dep has no purl).

    The SPDXID is ``SPDXRef-Dep-<name>-<version-or-'none'>-<8 hex of the
    bom_ref sha256>``. The ``Dep`` prefix keeps it distinct from the Fn /
    Cap / Builtin / Package IDs; the bom_ref hash suffix makes two
    distinct-source deps that happen to share a name AND version (a
    distinct-source diamond) deterministically distinct. Sanitisation of
    the name / version parts reuses the shared ``_spdx_id`` helper rather
    than a second hand-rolled sanitiser."""
    digest = hashlib.sha256(record.bom_ref.encode("utf-8")).hexdigest()[:8]
    dep_id = _spdx_id("Dep", record.name, record.version or "none", digest)

    annots: list[dict[str, str]] = [
        _annot(timestamp, "kind", "dependency"),
        _annot(timestamp, "source_kind", record.source_kind),
        _annot(timestamp, "resolved", str(record.resolved).lower()),
    ]
    if record.pin:
        annots.append(_annot(timestamp, "pin", record.pin))
    if record.commit:
        annots.append(_annot(timestamp, "commit", record.commit))
    if record.rel_path:
        annots.append(_annot(timestamp, "rel_path", record.rel_path))

    package: dict[str, Any] = {
        "SPDXID": dep_id,
        "name": record.name,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        **_SPDX_NOASSERT_LICENSE_FIELDS,
        "annotations": annots,
    }
    if record.version:
        package["versionInfo"] = record.version
    if record.purl:
        package["externalRefs"] = [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": record.purl,
        }]
    return package


def _flat_param(p: dict[str, Any]) -> str:
    parts = [f"{p['name']}: {p['type']}"]
    if p.get("consuming"):
        parts.append("[consume]")
    if p.get("is_capability"):
        parts.append("[cap]")
    return " ".join(parts)
