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

SPDX IDs must match ``SPDXRef-[a-zA-Z0-9.-]+``. Function names
like ``Foo::bar`` are sanitised by replacing non-conforming
characters with ``-`` so the IDs validate without losing
readability.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .. import capa_ast as A

from ._funrec import build_manifest


# Target SPDX specification version. 2.3 is the current stable
# (2024) and the version every major tool understands. 3.0 is JSON-
# Lite-shaped and breaks compatibility; not adopted yet.
SPDX_SPEC_VERSION = "SPDX-2.3"

# SPDX requires every document to declare its dataLicense; the
# spec recommends CC0-1.0 and most tools assume it.
SPDX_DATA_LICENSE = "CC0-1.0"


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
) -> dict[str, Any]:
    """Build an SPDX 2.3 document with embedded Capa capability metadata.

    ``timestamp`` and ``document_namespace`` are exposed for
    deterministic test output; production callers should leave them
    as the defaults. The namespace defaults to a UUIDv5-stable URN
    derived from the filename (so reruns of the same file produce
    identical output, friendly to SBOM diffing).
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    inner = build_manifest(module, filename=filename, capa_version=capa_version)

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if document_namespace is None:
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://capa-lang.org/spdx")
        document_namespace = (
            f"https://capa-lang.org/spdx/{uuid.uuid5(ns, filename)}"
        )

    bom_basename = os.path.basename(filename) or filename

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
    program_pkg = {
        "SPDXID": program_id,
        "name": bom_basename,
        "versionInfo": capa_version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
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
        if fn["container"]:
            qualname = f"{fn['container']}::{fn['name']}"
            fn_id = _spdx_id("Fn", bom_basename, fn["container"], fn["name"])
        else:
            qualname = fn["name"]
            fn_id = fn_ids[fn["name"]]

        annots = [
            _annot(timestamp, "kind", "function"),
            _annot(timestamp, "pos", fn["pos"]),
            _annot(timestamp, "return_type", fn["return_type"]),
            _annot(timestamp, "has_unsafe", str(fn["has_unsafe"]).lower()),
            _annot(timestamp, "is_pub", str(fn["is_pub"]).lower()),
        ]
        if fn.get("doc"):
            annots.append(_annot(timestamp, "doc", fn["doc"]))
        if fn["container"]:
            annots.append(_annot(timestamp, "container", fn["container"]))
        for cap_type in fn["declared_capabilities"]:
            annots.append(_annot(timestamp, "declared_capability", cap_type))
        for cap_type in fn.get("provably_excluded_capabilities", []):
            annots.append(_annot(
                timestamp, "provably_excluded_capability", cap_type,
            ))
        for param in fn["params"]:
            annots.append(_annot(timestamp, "param", _flat_param(param)))
        for attr in fn["attributes"]:
            for k, v in attr["args"].items():
                annots.append(_annot(
                    timestamp, f"attribute:{attr['name']}:{k}", v,
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
            "annotations": annots,
        })

        relationships.append({
            "spdxElementId": program_id,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": fn_id,
        })

        # Function -> user-defined capabilities it declares.
        seen_targets: set[str] = set()
        for cap_type in fn["declared_capabilities"]:
            cap_id = user_cap_ids.get(cap_type)
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


def _flat_param(p: dict[str, Any]) -> str:
    parts = [f"{p['name']}: {p['type']}"]
    if p.get("consuming"):
        parts.append("[consume]")
    if p.get("is_capability"):
        parts.append("[cap]")
    return " ".join(parts)
