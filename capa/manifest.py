"""capa/manifest.py, capability manifest builder.

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

# Maximum length for a stringified call-site argument before it gets
# truncated in the manifest. Pure aesthetics, avoids blowing up the
# JSON when a program passes a long string literal or a complex
# lambda as an argument. The truncated form ends with "..." so it is
# obvious to the reader that a manifest is not the source of truth.
_MAX_ARG_REPR = 80


def build_manifest(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
) -> dict[str, Any]:
    """Build a manifest dict from an analysed module.

    The dict is directly JSON-serialisable. The caller is expected to
    have run the analyser first; this builder does not re-validate
    attributes or types.
    """
    if capa_version is None:
        from . import __version__ as capa_version
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

    calls: list[dict[str, Any]] = []
    _collect_calls(fn.body, calls)

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
        "calls": calls,
    }


# ===========================================================
# Call-site extraction
#
# Walks a function body and records every call (plain function or
# method) found anywhere in expression position, including inside
# nested expressions. Each record carries:
#
#   - kind:    "fn" or "method"
#   - callee:  function name, or "receiver.method" for method calls
#   - pos:     "line:col" of the call site
#   - args:    list of source-like stringifications of the argument
#              expressions, truncated to _MAX_ARG_REPR characters
#
# The call list is the audit primitive, it lets a CRA reviewer see,
# for each function in the program, *what other functions it
# invokes and with what arguments*, including restrictions applied
# via `restrict_to(...)` calls visible directly in the argument
# expressions.
# ===========================================================


def _collect_calls(node, calls: list[dict[str, Any]]) -> None:
    """Recursively collect Call/MethodCall expressions from any node."""
    if node is None:
        return

    if isinstance(node, A.Call):
        if isinstance(node.callee, A.Ident):
            callee_name = node.callee.name
        else:
            callee_name = _stringify_expr(node.callee)
        calls.append({
            "kind": "fn",
            "callee": callee_name,
            "pos": f"{node.pos.line}:{node.pos.col}",
            "args": [_stringify_expr(a) for a in node.args],
        })
        # Recurse into the callee expression (so f(g(x)) records g too)
        # and into each argument.
        _collect_calls(node.callee, calls)
        for arg in node.args:
            _collect_calls(arg, calls)
        return

    if isinstance(node, A.MethodCall):
        receiver_str = _stringify_expr(node.receiver)
        calls.append({
            "kind": "method",
            "callee": f"{receiver_str}.{node.method}",
            "pos": f"{node.pos.line}:{node.pos.col}",
            "args": [_stringify_expr(a) for a in node.args],
        })
        _collect_calls(node.receiver, calls)
        for arg in node.args:
            _collect_calls(arg, calls)
        return

    # Generic AST traversal: visit any Node-typed or list-of-Node field.
    if isinstance(node, A.Node):
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            v = getattr(node, f.name)
            if isinstance(v, A.Node):
                _collect_calls(v, calls)
            elif isinstance(v, list):
                for item in v:
                    if isinstance(item, A.Node):
                        _collect_calls(item, calls)
                    elif isinstance(item, tuple):
                        # struct field pairs (name, Expr), match arms etc.
                        for it in item:
                            if isinstance(it, A.Node):
                                _collect_calls(it, calls)


def _stringify_expr(e) -> str:
    """Render an expression as a short source-like string for the
    manifest. Truncates at ``_MAX_ARG_REPR`` chars with an ellipsis.
    Designed for human-readable manifest output, not round-tripping.
    """
    s = _stringify_expr_full(e)
    if len(s) > _MAX_ARG_REPR:
        s = s[: _MAX_ARG_REPR - 3] + "..."
    return s


def _stringify_expr_full(e) -> str:
    if e is None:
        return ""
    if isinstance(e, A.Ident):
        return e.name
    if isinstance(e, A.IntLit):
        return str(e.value)
    if isinstance(e, A.FloatLit):
        return repr(e.value)
    if isinstance(e, A.StringLit):
        return _quote_string(e.value)
    if isinstance(e, A.InterpolatedString):
        # Approximate. The parts list alternates str literals and
        # expressions; show "${...}" for the expression slots so the
        # reader sees something interpolated without long bodies.
        out = []
        for p in e.parts:
            if isinstance(p, str):
                out.append(p)
            else:
                out.append("${...}")
        return _quote_string("".join(out))
    if isinstance(e, A.CharLit):
        return f"'{e.value}'"
    if isinstance(e, A.BoolLit):
        return "true" if e.value else "false"
    if isinstance(e, A.UnitLit):
        return "()"
    if isinstance(e, A.BinOp):
        return f"{_stringify_expr_full(e.left)} {e.op} {_stringify_expr_full(e.right)}"
    if isinstance(e, A.UnaryOp):
        sep = " " if e.op.isalpha() else ""
        return f"{e.op}{sep}{_stringify_expr_full(e.operand)}"
    if isinstance(e, A.Call):
        callee = _stringify_expr_full(e.callee)
        args = ", ".join(_stringify_expr_full(a) for a in e.args)
        return f"{callee}({args})"
    if isinstance(e, A.MethodCall):
        recv = _stringify_expr_full(e.receiver)
        args = ", ".join(_stringify_expr_full(a) for a in e.args)
        return f"{recv}.{e.method}({args})"
    if isinstance(e, A.FieldAccess):
        return f"{_stringify_expr_full(e.receiver)}.{e.field_name}"
    if isinstance(e, A.Index):
        return f"{_stringify_expr_full(e.receiver)}[{_stringify_expr_full(e.index)}]"
    if isinstance(e, A.Try):
        return f"{_stringify_expr_full(e.expr)}?"
    if isinstance(e, A.ListLit):
        return "[" + ", ".join(_stringify_expr_full(x) for x in e.elements) + "]"
    if isinstance(e, A.TupleLit):
        return "(" + ", ".join(_stringify_expr_full(x) for x in e.elements) + ")"
    if isinstance(e, A.StructLit):
        body = ", ".join(
            f"{k}: {_stringify_expr_full(v)}" for k, v in e.fields
        )
        return f"{e.type_name} {{ {body} }}"
    if isinstance(e, A.RangeExpr):
        op = "..=" if e.inclusive else ".."
        return f"{_stringify_expr_full(e.start)}{op}{_stringify_expr_full(e.end)}"
    if isinstance(e, A.LambdaExpr):
        return "fun(...) => ..."
    if isinstance(e, A.IfExpr):
        return f"if {_stringify_expr_full(e.cond)} then ... else ..."
    if isinstance(e, A.MatchExpr):
        return f"match {_stringify_expr_full(e.scrutinee)} {{ ... }}"
    return f"<{type(e).__name__}>"


def _quote_string(s: str) -> str:
    """Render a Python string as a Capa-style double-quoted literal,
    escaping the obvious problem characters. Used only for the
    manifest representation; we are not round-tripping source."""
    escaped = (
        s.replace("\\", "\\\\")
         .replace('"', '\\"')
         .replace("\n", "\\n")
         .replace("\t", "\\t")
    )
    return f'"{escaped}"'


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
        from . import __version__ as capa_version
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

