"""capa/manifest.py — capability manifest builder.

Walks an analysed Capa module and emits a JSON-serialisable dict
describing, for every top-level function and impl-method:

    - signature (params with types, return type)
    - declared capabilities (the ones in the signature)
    - whether the function crosses the ``Unsafe`` boundary
    - attached attributes (``@security``, ``@deprecated``, ``@audited``)

Plus, at the module level: the user-defined capability declarations
and their implementors, and a summary count.

Designed as a CRA-aligned audit artefact. Other languages cannot
emit this because the authority graph is not in their type system;
in Capa, it falls out of the analyser for free.

The manifest format is versioned via ``schema_version``. Consumers
should refuse to read manifests with a schema version they do not
recognise.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from . import capa_ast as A
from .typesys import CAPABILITY_NAMES


SCHEMA_VERSION = 1

# Target CycloneDX specification. 1.5 is widely supported by SBOM
# tooling (Dependency-Track, OSV-Scanner, sbom-utility); 1.6 is
# newer but adoption is less universal. Bump when 1.6 is everywhere.
CYCLONEDX_SPEC_VERSION = "1.5"


def build_manifest(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: str = "0.2.0",
) -> dict[str, Any]:
    """Build a manifest dict from an analysed module.

    The dict is directly JSON-serialisable. The caller is expected to
    have run the analyser first; this builder does not re-validate
    attributes or types.
    """
    # Collect user-defined capabilities and the names of types that
    # implement them. Built-in capability names are already in
    # CAPABILITY_NAMES; we extend that set so that struct parameters
    # of user-defined caps are correctly classified.
    user_caps: list[dict[str, Any]] = []
    cap_names: set[str] = set(CAPABILITY_NAMES)
    impl_map: dict[str, list[str]] = {}

    for item in module.items:
        if isinstance(item, A.TraitDecl) and item.is_capability:
            cap_names.add(item.name)
            user_caps.append({
                "name": item.name,
                "methods": [m.name for m in item.methods],
                "implementors": [],  # populated below
            })
        if isinstance(item, A.ImplBlock) and item.trait_name is not None:
            impl_map.setdefault(item.trait_name, []).append(item.type_name)

    for uc in user_caps:
        uc["implementors"] = sorted(impl_map.get(uc["name"], []))

    # Build per-function records. Walks both top-level funs and
    # methods inside impl blocks (which are nested FunDecl nodes).
    functions: list[dict[str, Any]] = []
    for item in module.items:
        if isinstance(item, A.FunDecl):
            functions.append(_fun_record(item, cap_names, filename, container=None))
        elif isinstance(item, A.ImplBlock):
            for m in item.methods:
                functions.append(
                    _fun_record(m, cap_names, filename, container=item.type_name)
                )

    summary = {
        "total_functions": len(functions),
        "functions_with_capabilities": sum(
            1 for f in functions if f["declared_capabilities"]
        ),
        "functions_with_attributes": sum(
            1 for f in functions if f["attributes"]
        ),
        "functions_crossing_unsafe": sum(
            1 for f in functions if f["has_unsafe"]
        ),
    }

    return {
        "capa_version": capa_version,
        "schema_version": SCHEMA_VERSION,
        "filename": filename,
        "user_defined_capabilities": user_caps,
        "functions": functions,
        "summary": summary,
    }


def _fun_record(
    fn: A.FunDecl,
    cap_names: set[str],
    filename: str,
    *,
    container: Optional[str],
) -> dict[str, Any]:
    param_records: list[dict[str, Any]] = []
    for p in fn.params:
        if p.name == "self":
            ty_text = "Self"
        else:
            ty_text = _ty_text(p.type_expr) if p.type_expr else "?"
        is_cap = _root_type_name(p.type_expr) in cap_names if p.type_expr else False
        param_records.append({
            "name": p.name,
            "type": ty_text,
            "consuming": p.consuming,
            "is_capability": is_cap,
        })

    declared_caps = [
        p["type"] for p in param_records if p["is_capability"]
    ]
    has_unsafe = any(
        _root_type_name(p.type_expr) == "Unsafe"
        for p in fn.params
        if p.type_expr
    )
    attrs = [
        {"name": a.name, "args": dict(a.args)}
        for a in fn.attributes
    ]

    return {
        "name": fn.name,
        "container": container,
        "pos": f"{filename}:{fn.pos.line}:{fn.pos.col}",
        "is_pub": fn.is_pub,
        "params": param_records,
        "return_type": _ty_text(fn.return_type) if fn.return_type else "()",
        "declared_capabilities": declared_caps,
        "has_unsafe": has_unsafe,
        "attributes": attrs,
    }


def _ty_text(t: Optional[A.TypeExpr]) -> str:
    """Render a ``TypeExpr`` to source-style text.

    The manifest stores types as strings so that downstream consumers
    (CI gates, SBOM tooling, dashboards) do not need to know Capa's
    internal type representation. Keep this aligned with ``ty_str``
    in ``typesys.py`` for built-in cases.
    """
    if t is None:
        return "()"
    if isinstance(t, A.TypeName):
        if not t.args:
            return t.name
        return f"{t.name}<{', '.join(_ty_text(a) for a in t.args)}>"
    if isinstance(t, A.FunType):
        params = ", ".join(_ty_text(p) for p in t.param_types)
        return f"Fun({params}) -> {_ty_text(t.return_type)}"
    if isinstance(t, A.TupleType):
        return f"({', '.join(_ty_text(e) for e in t.elements)})"
    if isinstance(t, A.UnitType):
        return "()"
    return f"<{type(t).__name__}>"


def _root_type_name(t: Optional[A.TypeExpr]) -> Optional[str]:
    """Return the head name of a type, or None if it is not a TypeName."""
    if isinstance(t, A.TypeName):
        return t.name
    return None


# ===========================================================
# CycloneDX 1.5 wrapper
#
# Wraps the internal capability manifest in a valid CycloneDX
# SBOM so that Capa programs can be ingested by existing SBOM
# tooling (Dependency-Track, OSV-Scanner, syft, etc.).
#
# Mapping decisions (v1):
#
#   - The Capa file becomes the top-level component (type
#     ``application``).
#   - Each function becomes a sub-component (type ``library``).
#     The bom-ref scheme is deterministic: ``capa:fn:<file>:<name>``
#     for top-level functions, ``capa:fn:<file>:<container>::<name>``
#     for impl methods.
#   - Each user-defined capability becomes a sub-component
#     (``capa:cap:<file>:<name>``).
#   - Per-function and per-cap metadata is flattened into the
#     standard ``properties[]`` array with a ``capa:*`` namespace,
#     so SBOM tooling that does not know about Capa still
#     validates the document and can read what it cares about.
#   - Capability membership in a function is encoded both as
#     a ``capa:declared_capability`` property AND as a CycloneDX
#     ``dependencies[]`` edge from the function to the cap
#     component, so dependency-graph tooling sees the relation.
# ===========================================================


def build_cyclonedx(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: str = "0.2.0",
    timestamp: Optional[str] = None,
    serial_number: Optional[str] = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM with embedded Capa capability metadata.

    ``timestamp`` and ``serial_number`` are exposed as parameters for
    deterministic test output; production callers should leave them
    as the defaults. The serial number defaults to a UUIDv5 derived
    from the filename (deterministic across runs of the same file).
    """
    inner = build_manifest(module, filename=filename, capa_version=capa_version)

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if serial_number is None:
        # Deterministic UUID per filename — reruns produce identical
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

    # bom-refs of user-defined caps, keyed by cap name
    user_cap_refs: dict[str, str] = {}
    for uc in inner["user_defined_capabilities"]:
        ref = f"capa:cap:{bom_basename}:{uc['name']}"
        user_cap_refs[uc["name"]] = ref
        props: list[dict[str, str]] = [
            {"name": "capa:kind", "value": "capability"},
        ]
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

        # Dependency edges: function -> capability components it declares.
        cap_deps: list[str] = [
            user_cap_refs[c] for c in fn["declared_capabilities"]
            if c in user_cap_refs
        ]
        if cap_deps:
            dependencies.append({"ref": fn_ref, "dependsOn": cap_deps})

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

    Format: ``name: Type [consume] [cap]`` — terse so it fits in
    an SBOM properties cell; structured enough that downstream
    consumers can parse it back if they wish.
    """
    parts = [f"{p['name']}: {p['type']}"]
    if p.get("consuming"):
        parts.append("[consume]")
    if p.get("is_capability"):
        parts.append("[cap]")
    return " ".join(parts)

