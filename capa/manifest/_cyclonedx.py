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

from ._funrec import _identifier_seed, build_manifest, display_filename
from ._strings import _cap_sbom_value
from ._vex import build_vex_entries


# Target CycloneDX specification. 1.5 is widely supported by SBOM
# tooling (Dependency-Track, OSV-Scanner, sbom-utility); 1.6 is
# newer but adoption is less universal. Bump when 1.6 is everywhere.
CYCLONEDX_SPEC_VERSION = "1.5"

# Strict CycloneDX validators (``cyclonedx-cli validate --strict``,
# OWASP Dependency-Track in compliance mode) expect every component
# to carry ``licenses[]`` and ``supplier``. Audit 2026-05-25 H5:
# the prior output omitted both, so strict tooling refused the
# document. The supplier is the build tool (capa itself); the
# license list is empty because the Capa source's license is the
# host project's concern, not ours, and CycloneDX explicitly allows
# the empty list as the well-defined "no concluded license" state.
_CDX_COMPONENT_COMPLIANCE_FIELDS: dict[str, Any] = {
    "supplier": {"name": "capa-build"},
    "licenses": [],
}

# Built-in capability names live in one place upstream; importing
# the set here keeps the synthesised builtin-cap components and
# the dep-edge resolver in lockstep with the analyzer.
from ..typesys import CAPABILITY_NAMES as _BUILTIN_CAPABILITY_NAMES


def build_cyclonedx(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    timestamp: Optional[str] = None,
    serial_number: Optional[str] = None,
    source: Optional[str] = None,
    sources: Optional[dict[str, str]] = None,
    expr_labels: Optional[dict[int, str]] = None,
    operator_declared_grants: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM with embedded Capa capability metadata.

    ``timestamp`` and ``serial_number`` are exposed as parameters for
    deterministic test output; production callers should leave them
    as the defaults. The serial number defaults to a UUIDv5 derived
    from the display filename plus, when ``source`` (the raw .capa
    text) is given, the source's sha256, so two unrelated projects
    that share a root basename get distinct serial numbers. The CLI
    always passes ``source``.
    """
    if capa_version is None:
        from .. import __version__ as capa_version
    inner = build_manifest(
        module, filename=filename, capa_version=capa_version,
        expr_labels=expr_labels,
        operator_declared_grants=operator_declared_grants,
    )

    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Seed every filename-derived identifier from the display form
    # (root-relative; the basename for the root file), never the raw
    # CLI argument: the raw form varies with the invocation style
    # (relative vs absolute, cwd) and across machines, which would
    # break byte-reproducibility of the serial number. The source
    # digest joins the seed (see ``_identifier_seed``) so two
    # projects sharing a basename do not collide.
    display = display_filename(filename)
    if serial_number is None:
        # Deterministic UUID per (filename, source): reruns produce
        # identical serial numbers, which is friendly to SBOM diffing.
        ns = uuid.uuid5(uuid.NAMESPACE_URL, "https://capa-language.com/sbom")
        seed = _identifier_seed(filename, source, sources)
        serial_number = "urn:uuid:" + str(uuid.uuid5(ns, seed))

    bom_basename = os.path.basename(display) or display
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

    # WASI Fs layer b1: surface operator-DECLARED grants (e.g. --preopen)
    # as top-level metadata properties, clearly namespaced + labelled as
    # operator-declared (Level 2) so an SBOM consumer never mistakes them
    # for the program-proven, compiler-derived capability surface. The
    # trust_level property states the framing in-band; one
    # ``capa:operator_declared_grant:preopen`` property per granted dir.
    _grants = inner.get("operator_declared_grants") or {}
    _preopens = _grants.get("preopens") or []
    if _preopens:
        metadata_properties.append({
            "name": "capa:operator_declared_grants:trust_level",
            "value": str(_grants.get("trust_level", "operator-declared")),
        })
        for _pre in _preopens:
            metadata_properties.append({
                "name": "capa:operator_declared_grant:preopen",
                "value": (
                    f"{_pre.get('host_dir', '')}"
                    f" [{_pre.get('permission', 'rw')}]"
                ),
            })

    # WASI Layer 1: surface the COMPILER-DERIVED, program-PROVEN argv ->
    # sink path-arg surface as top-level metadata properties, explicitly
    # labelled compiler-derived (the OPPOSITE trust level to the
    # operator-declared grants above) so an SBOM consumer reads it as a
    # machine-verifiable fact, not an operator declaration. One
    # ``capa:compiler_derived:path_arg_surface`` property per proven fact.
    _surface = inner.get("compiler_derived_path_arg_surface") or {}
    _args = _surface.get("arguments") or []
    if _args:
        metadata_properties.append({
            "name": "capa:compiler_derived_path_arg_surface:trust_level",
            "value": str(_surface.get("trust_level", "compiler-derived")),
        })
        for _a in _args:
            metadata_properties.append({
                "name": "capa:compiler_derived:path_arg_surface",
                "value": (
                    f"argv[{_a.get('arg_index', '*')}] -> "
                    f"{_a.get('capability', '')}.{_a.get('method', '')} "
                    f"({_a.get('access', '')})"
                ),
            })

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
            **_CDX_COMPONENT_COMPLIANCE_FIELDS,
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

    # Audit slice 23 (2026-05-29): synthesise a component for
    # every built-in capability that any function in the program
    # transitively reaches, so the dep-edges built below can
    # resolve those reach claims to a real bom-ref. Without this
    # the CycloneDX graph would carry the (now sound) per-impl
    # reachability claim only as a flat property and not as a
    # walkable dependency edge - graph-tooling consumers would
    # miss the authority chain that slice 21 made visible at the
    # manifest layer.
    reached_builtins: set[str] = set()
    for fn in inner["functions"]:
        for cap in fn.get("transitively_reachable_capabilities", []):
            if cap in _BUILTIN_CAPABILITY_NAMES:
                reached_builtins.add(cap)
    builtin_cap_refs: dict[str, str] = {}
    for cap_name in sorted(reached_builtins):
        ref = f"capa:builtin:{bom_basename}:{cap_name}"
        builtin_cap_refs[cap_name] = ref
        components.append({
            "bom-ref": ref,
            "type": "library",
            "name": cap_name,
            "scope": "required",
            **_CDX_COMPONENT_COMPLIANCE_FIELDS,
            "properties": [
                {"name": "capa:kind", "value": "builtin-capability"},
            ],
        })

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
            **_CDX_COMPONENT_COMPLIANCE_FIELDS,
            "properties": props,
        })

    # Functions
    program_depends_on: list[str] = (
        list(user_cap_refs.values()) + list(builtin_cap_refs.values())
    )
    for fn in inner["functions"]:
        # bom-ref keyed on the loader-time name to keep
        # collision-resolution stable (two same-source-named helpers
        # imported from different modules get distinct refs). The
        # displayed ``name`` field uses the source-level identifier
        # so the SBOM reads as a regulator expects.
        if fn["container"]:
            qualname_ref = f"{fn['container']}::{fn['name']}"
            qualname_display = (
                f"{fn['source_container'] or fn['container']}"
                f"::{fn['source_name']}"
            )
        else:
            qualname_ref = fn["name"]
            qualname_display = fn["source_name"]
        fn_ref = f"capa:fn:{bom_basename}:{qualname_ref}"
        program_depends_on.append(fn_ref)

        props = [
            {"name": "capa:kind", "value": "function"},
            {"name": "capa:pos", "value": fn["pos"]},
            {"name": "capa:return_type", "value": fn["return_type"]},
            {"name": "capa:has_unsafe", "value": str(fn["has_unsafe"]).lower()},
            {"name": "capa:is_pub", "value": str(fn["is_pub"]).lower()},
        ]
        # Disclose the source-module import index when the function
        # came from a non-pub-imported declaration. Lets the auditor
        # tell two source-name-equal helpers apart even though the
        # displayed name has been de-mangled.
        if fn.get("source_module_index") is not None:
            props.append({
                "name": "capa:source_module_index",
                "value": str(fn["source_module_index"]),
            })
        if fn.get("doc"):
            props.append({"name": "capa:doc", "value": fn["doc"]})
        if fn["container"]:
            props.append({
                "name": "capa:container",
                "value": fn["source_container"] or fn["container"],
            })
        for cap_type in fn["declared_capabilities"]:
            props.append({
                "name": "capa:declared_capability",
                "value": cap_type,
            })
        # Slice 23 (2026-05-29): surface the transitively-
        # reachable set so consumers can read either the
        # signature-only view (``capa:declared_capability``)
        # or the honest authority chain (this one). The two
        # sets overlap by construction (declared ⊆ reachable);
        # emitting both lets a consumer pick the view that
        # matches their compliance question.
        for cap_type in fn.get("transitively_reachable_capabilities", []):
            props.append({
                "name": "capa:transitively_reachable_capability",
                "value": cap_type,
            })
        for cap_type in fn.get("provably_excluded_capabilities", []):
            props.append({
                "name": "capa:provably_excluded_capability",
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
                    "value": _cap_sbom_value(v),
                })
            if not attr["args"]:
                props.append({
                    "name": f"capa:attribute:{attr['name']}",
                    "value": "",
                })

        components.append({
            "bom-ref": fn_ref,
            "type": "library",
            "name": qualname_display,
            "scope": "required",
            **_CDX_COMPONENT_COMPLIANCE_FIELDS,
            "properties": props,
        })

        # Dependency edges: function -> every capability (user-
        # defined OR built-in) it transitively reaches, AND
        # function -> functions it actually calls in the same
        # module. Slice 23 (2026-05-29) widened this from
        # ``declared_capabilities`` to ``transitively_reachable_capabilities``
        # so the dep-graph reflects the same honest reachability
        # the per-function exclusion claim now relies on.
        # Method-call edges (kind="method") are still skipped in
        # v1 because resolving the receiver to a specific impl
        # requires type-tracking we do not yet have.
        deps_for_this_fn: list[str] = []
        seen_call_refs: set[str] = set()
        for cap_type in fn.get("transitively_reachable_capabilities", []):
            cap_ref = user_cap_refs.get(cap_type) or builtin_cap_refs.get(cap_type)
            if cap_ref and cap_ref not in seen_call_refs:
                deps_for_this_fn.append(cap_ref)
                seen_call_refs.add(cap_ref)
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

    # ----- VEX vulnerabilities[] (CycloneDX 1.4+) -----
    # Walk @vex attributes and emit per-function vulnerability
    # entries. Per-function granularity is the novel piece; no other
    # language emits VEX scoped to individual functions today.
    vulnerabilities = build_vex_entries(
        module,
        filename=filename,
        capa_version=capa_version,
        timestamp=timestamp,
    )

    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": dependencies,
    }
    if vulnerabilities:
        document["vulnerabilities"] = vulnerabilities
    return document


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
