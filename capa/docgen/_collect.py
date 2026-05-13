"""Type and trait extraction from a Capa module.

The manifest already carries function records and user-defined
capability declarations; these helpers fill the gap by surfacing
the types and (non-capability) traits a Capa module declares, with
just enough metadata for the renderers.

- ``_collect_traits``: plain ``trait Foo`` declarations only;
  ``capability Foo`` is handled separately via the manifest's
  ``user_defined_capabilities`` list.
- ``_collect_types``: ``type Foo { ... }`` (struct) and
  ``type Foo = A | B(P) | ...`` (sum), each as a dict with name,
  type-params, doc, and members.
"""

from __future__ import annotations

from typing import Any

from .. import capa_ast as A
from ..manifest import _ty_text  # type: ignore[attr-defined]


def _collect_traits(module: A.Module) -> list[dict[str, Any]]:
    """Collect plain (non-capability) traits with their method
    signatures, doc, and implementor types. Capability declarations
    (``capability X``) are out of scope here; they appear in the
    manifest's ``user_defined_capabilities`` list and are rendered
    separately.
    """
    out: list[dict[str, Any]] = []
    impl_map: dict[str, list[str]] = {}
    for item in module.items:
        if isinstance(item, A.ImplBlock) and item.trait_name is not None:
            impl_map.setdefault(item.trait_name, []).append(item.type_name)
    for item in module.items:
        if isinstance(item, A.TraitDecl) and not item.is_capability:
            out.append({
                "name": item.name,
                "type_params": item.type_params,
                "doc": item.doc,
                "methods": [
                    {
                        "name": m.name,
                        "params": [
                            {
                                "name": p.name,
                                "type": _ty_text(p.type_expr)
                                if p.type_expr else "Self",
                            }
                            for p in m.params
                        ],
                        "return_type": _ty_text(m.return_type)
                        if m.return_type else "()",
                    }
                    for m in item.methods
                ],
                "implementors": sorted(impl_map.get(item.name, [])),
            })
    return out


def _collect_types(module: A.Module) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in module.items:
        if isinstance(item, A.TypeStruct):
            out.append({
                "kind": "struct",
                "name": item.name,
                "type_params": item.type_params,
                "doc": item.doc,
                "fields": [
                    {"name": f.name, "type": _ty_text(f.type_expr)}
                    for f in item.fields
                ],
            })
        elif isinstance(item, A.TypeSum):
            out.append({
                "kind": "sum",
                "name": item.name,
                "type_params": item.type_params,
                "doc": item.doc,
                "variants": [
                    {
                        "name": v.name,
                        "payload": _ty_text(v.payload) if v.payload else None,
                    }
                    for v in item.variants
                ],
            })
    return out
