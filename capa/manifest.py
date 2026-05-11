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

from typing import Any, Optional

from . import capa_ast as A
from .typesys import CAPABILITY_NAMES


SCHEMA_VERSION = 1


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
