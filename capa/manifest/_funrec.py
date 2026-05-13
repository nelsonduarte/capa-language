"""Per-function manifest record building.

The top-level ``build_manifest`` walks an analysed module and emits
the manifest dict. ``_fun_record`` produces the entry for one
function (or impl method): signature, declared capabilities,
``has_unsafe``, attributes, and the call list with attenuation flow.

The manifest format is versioned via ``SCHEMA_VERSION``; consumers
should refuse to read manifests with a schema version they do not
recognise.
"""

from __future__ import annotations

from typing import Any, Optional

from .. import capa_ast as A
from ..typesys import CAPABILITY_NAMES

from ._calls import _collect_calls
from ._flow import _build_attenuation_map
from ._strings import _root_type_name, _ty_text


SCHEMA_VERSION = 1


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
        from .. import __version__ as capa_version
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
                "doc": item.doc,
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

    # Build a syntactic flow map for this function body before
    # collecting calls so each call's args_flow can be enriched
    # with any tracked attenuations on its identifier arguments.
    attenuation_map = _build_attenuation_map(fn.body)

    calls: list[dict[str, Any]] = []
    _collect_calls(fn.body, calls, attenuation_map=attenuation_map)

    return {
        "name": fn.name,
        "container": container,
        "pos": f"{filename}:{fn.pos.line}:{fn.pos.col}",
        "is_pub": fn.is_pub,
        "doc": fn.doc,
        "params": param_records,
        "return_type": _ty_text(fn.return_type) if fn.return_type else "()",
        "declared_capabilities": declared_caps,
        "has_unsafe": has_unsafe,
        "attributes": attrs,
        "calls": calls,
    }
