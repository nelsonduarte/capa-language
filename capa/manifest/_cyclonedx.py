"""CycloneDX 1.5 SBOM wrapper around the Capa manifest.

Wraps the internal capability manifest in a valid CycloneDX SBOM so
that Capa programs can be ingested by existing SBOM tooling
(Dependency-Track, OSV-Scanner, syft, etc.).

Mapping decisions (v1):

- The Capa file becomes the top-level component (type
  ``application``).
- Each function becomes a sub-component (type ``library``). The
  bom-ref scheme is deterministic: ``capa:fn:<file>:<name>`` for
  top-level functions, ``capa:fn:<file>:<container>::<name>`` for
  impl methods.
- Each user-defined capability becomes a sub-component
  (``capa:cap:<file>:<name>``).
- Per-function and per-cap metadata is flattened into the standard
  ``properties[]`` array with a ``capa:*`` namespace, so SBOM tooling
  that does not know about Capa still validates the document and
  can read what it cares about.
- Capability membership in a function is encoded both as a
  ``capa:declared_capability`` property AND as a CycloneDX
  ``dependencies[]`` edge from the function to the cap component,
  so dependency-graph tooling sees the relation.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from .. import capa_ast as A

from ._funrec import build_manifest


# Target CycloneDX specification. 1.5 is widely supported by SBOM
# tooling (Dependency-Track, OSV-Scanner, sbom-utility); 1.6 is
# newer but adoption is less universal. Bump when 1.6 is everywhere.
CYCLONEDX_SPEC_VERSION = "1.5"


def build_cyclonedx(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    timestamp: Optional[str] = None,
    serial_number: Optional[str] = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM with embedded Capa capability metadata.

    ``timestamp`` and ``serial_number`` are exposed as parameters for
    deterministic test output; production callers should leave them
    as the defaults. The serial number defaults to a UUIDv5 derived
    from the filename (deterministic across runs of the same file).
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    inner = build_manifest(module, filename=filename, capa_version=capa_version)

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if serial_number is None:
        # Deterministic UUID per filename, reruns produce identical
        # serial numbers, which is friendly to SBOM diffing.
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://capa-lang.org/sbom")
        serial_number = "urn:uuid:" + str(uuid.uuid5(ns, filename))

    bom_basename = os.path.basename(filename) or filename
    program_bom_ref = f"capa:program:{bom_basename}"

    # ----- Top-level metadata block -----
    metadata_properties: list[dict[str, str]] = [
        {"name": "capa:schema_version", "value": str(inner["schema_version"])},
        {"name": "capa:summary:total_functions",
         "value": str(inner["summary"]["total_functions"])},
        {"name": "capa:summary:functions_with_capabilities",
         "value": str(inner["summary"]["functions_with_capabilities"])},
        {"name": "capa:summary:functions_with_attributes",
         "value": str(inner["summary"]["functions_with_attributes"])},
        {"name": "capa:summary:functions_crossing_unsafe",
         "value": str(inner["summary"]["functions_crossing_unsafe"])},
    ]

    metadata = {
        "timestamp": timestamp,
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "capa",
                    "version": capa_version,
                }
            ]
        },
        "component": {
            "bom-ref": program_bom_ref,
            "type": "application",
            "name": bom_basename,
            "version": capa_version,
        },
        "properties": metadata_properties,
    }

    # ----- Components: one per function, one per user-defined cap -----
    components: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []

    # bom-refs of top-level (non-impl-method) functions, keyed by name.
    # Used below to translate intra-module call records into CycloneDX
    # dependency edges. Impl methods are not in this map because the
    # callee in a method call record is "receiver.method", which
    # cannot be resolved to a specific impl without flow tracking.
    fn_refs: dict[str, str] = {}
    for fn in inner["functions"]:
        if fn["container"] is None:
            fn_refs[fn["name"]] = (
                f"capa:fn:{bom_basename}:{fn['name']}"
            )

    # bom-refs of user-defined caps, keyed by cap name
    user_cap_refs: dict[str, str] = {}
    for uc in inner["user_defined_capabilities"]:
        ref = f"capa:cap:{bom_basename}:{uc['name']}"
        user_cap_refs[uc["name"]] = ref
        props: list[dict[str, str]] = [
            {"name": "capa:kind", "value": "capability"},
        ]
        if uc.get("doc"):
            props.append({"name": "capa:doc", "value": uc["doc"]})
        for method_name in uc["methods"]:
            props.append({
                "name": "capa:capability:method",
                "value": method_name,
            })
        for impl_name in uc["implementors"]:
            props.append({
                "name": "capa:capability:implementor",
                "value": impl_name,
            })
        components.append({
            "bom-ref": ref,
            "type": "library",
            "name": uc["name"],
            "scope": "required",
            "properties": props,
        })

    # Functions
    program_depends_on: list[str] = list(user_cap_refs.values())
    for fn in inner["functions"]:
        if fn["container"]:
            qualname = f"{fn['container']}::{fn['name']}"
        else:
            qualname = fn["name"]
        fn_ref = f"capa:fn:{bom_basename}:{qualname}"
        program_depends_on.append(fn_ref)

        props = [
            {"name": "capa:kind", "value": "function"},
            {"name": "capa:pos", "value": fn["pos"]},
            {"name": "capa:return_type", "value": fn["return_type"]},
            {"name": "capa:has_unsafe", "value": str(fn["has_unsafe"]).lower()},
            {"name": "capa:is_pub", "value": str(fn["is_pub"]).lower()},
        ]
        if fn.get("doc"):
            props.append({"name": "capa:doc", "value": fn["doc"]})
        if fn["container"]:
            props.append({
                "name": "capa:container",
                "value": fn["container"],
            })
        for cap_type in fn["declared_capabilities"]:
            props.append({
                "name": "capa:declared_capability",
                "value": cap_type,
            })
        for param in fn["params"]:
            props.append({
                "name": "capa:param",
                "value": _flat_param(param),
            })
        # Attributes (e.g. @security, @audited) flattened as
        # capa:attribute:<name>:<key> = <value>. This is the
        # canonical place an SBOM-consumer should look for CVE
        # references and audit metadata.
        for attr in fn["attributes"]:
            for k, v in attr["args"].items():
                props.append({
                    "name": f"capa:attribute:{attr['name']}:{k}",
                    "value": v,
                })
            if not attr["args"]:
                props.append({
                    "name": f"capa:attribute:{attr['name']}",
                    "value": "",
                })

        components.append({
            "bom-ref": fn_ref,
            "type": "library",
            "name": qualname,
            "scope": "required",
            "properties": props,
        })

        # Dependency edges: function -> capability components it
        # declares, AND function -> functions it actually calls in
        # the same module. Method-call edges (kind="method") are
        # skipped in v1 because resolving the receiver to a specific
        # impl requires type-tracking we do not yet have.
        deps_for_this_fn: list[str] = [
            user_cap_refs[c] for c in fn["declared_capabilities"]
            if c in user_cap_refs
        ]
        seen_call_refs: set[str] = set(deps_for_this_fn)
        for call in fn["calls"]:
            if call["kind"] != "fn":
                continue
            target_ref = fn_refs.get(call["callee"])
            if target_ref and target_ref not in seen_call_refs:
                deps_for_this_fn.append(target_ref)
                seen_call_refs.add(target_ref)
        if deps_for_this_fn:
            dependencies.append({
                "ref": fn_ref,
                "dependsOn": deps_for_this_fn,
            })

    if program_depends_on:
        dependencies.insert(0, {
            "ref": program_bom_ref,
            "dependsOn": program_depends_on,
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }


def _flat_param(p: dict[str, Any]) -> str:
    """Render a parameter record as a single string for property values.

    Format: ``name: Type [consume] [cap]``, terse so it fits in
    an SBOM properties cell; structured enough that downstream
    consumers can parse it back if they wish.
    """
    parts = [f"{p['name']}: {p['type']}"]
    if p.get("consuming"):
        parts.append("[consume]")
    if p.get("is_capability"):
        parts.append("[cap]")
    return " ".join(parts)
