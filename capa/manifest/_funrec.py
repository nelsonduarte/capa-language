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

import re
from typing import Any, Optional

from .. import capa_ast as A
from ..typesys import CAPABILITY_NAMES

from ._calls import _collect_calls
from ._flow import _build_attenuation_map
from ._strings import _contains_fun_type, _root_type_name, _ty_text


SCHEMA_VERSION = 1


# Loader-generated mangle prefix on non-pub items imported from
# another module: ``_capa_m{N}__<source_name>`` (see
# ``capa/loader.py::_mangle_private_items``). The manifest displays
# the source-level name so regulator-facing SBOMs read as the user
# wrote them; the module index ``N`` is preserved as a separate
# field so the auditor still sees which import the symbol came from.
_MANGLE_RE = re.compile(r"^_capa_m(\d+)__(.+)$")


def _demangle(name: str) -> tuple[str, Optional[int]]:
    """Return ``(source_name, module_index)`` for a possibly-mangled
    identifier. ``module_index`` is None when the name carried no
    loader prefix (root-module item or pub-exported import)."""
    m = _MANGLE_RE.match(name)
    if m is None:
        return name, None
    return m.group(2), int(m.group(1))


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
    # For impl methods, when the impl is *of* a capability trait
    # (e.g. ``impl Stdio for FooStdio``), the trait name is fed
    # in as an implicit declared capability: the method
    # exercises that capability through ``self`` even though no
    # parameter has the trait's type. Without this, the
    # ineligibility proof would falsely exclude the trait from
    # the methods that actually implement it.
    functions: list[dict[str, Any]] = []
    for item in module.items:
        if isinstance(item, A.FunDecl):
            functions.append(_fun_record(
                item, cap_names, filename,
                container=None, implicit_cap=None,
            ))
        elif isinstance(item, A.ImplBlock):
            implicit = (
                item.trait_name
                if item.trait_name is not None and item.trait_name in cap_names
                else None
            )
            for m in item.methods:
                functions.append(_fun_record(
                    m, cap_names, filename,
                    container=item.type_name,
                    implicit_cap=implicit,
                ))

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
    implicit_cap: Optional[str] = None,
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
    # When this is an impl method whose impl is *of* a capability
    # trait, the trait is exercised through ``self`` even though
    # no parameter carries the trait's type. Surface it here so
    # ``declared_capabilities`` is a complete upper bound on what
    # the method can exercise; this also keeps the ineligibility
    # proof below from falsely excluding the trait.
    if implicit_cap is not None and implicit_cap not in declared_caps:
        declared_caps.append(implicit_cap)
    has_unsafe = (
        any(
            _root_type_name(p.type_expr) == "Unsafe"
            for p in fn.params
            if p.type_expr
        )
        or implicit_cap == "Unsafe"
    )

    # Ineligibility proof: which capabilities this function
    # provably *cannot* use. Sound because Capa's discipline makes
    # ``declared_caps`` an upper bound on what the function can
    # exercise (any cap a callee touches must be in scope here to
    # be passed; impl-method ``self`` is included via
    # ``implicit_cap`` above).
    #
    # The proof breaks in two cases, both of which downgrade the
    # claim to an empty list rather than over-claim:
    #
    # 1. ``Unsafe`` is in scope -- the escape hatch can side-step
    #    the discipline.
    # 2. The function's signature contains a ``Fun(...)`` type
    #    (in a parameter, return type, or nested generic). Audit
    #    slice 18 (2026-05-29): a function like
    #    ``fun b(f: Fun() -> Unit) { f() }`` exercises whatever
    #    cap the caller captured into the closure, but the type
    #    system does not track captures inside ``Fun(...)``.
    #    Pre-fix the manifest claimed ``b`` provably-excluded
    #    every cap; running ``a(stdio) { let l = fun () =>
    #    stdio.println("x"); b(l) }`` then exercised Stdio through
    #    ``b`` despite ``b``'s manifest. The fix preserves the
    #    intent of ``provably_excluded`` (downstream SBOM /
    #    regulatory tooling consumes it as a hard claim) by
    #    refusing to make the claim when it can't be honored.
    has_fun_in_sig = any(
        _contains_fun_type(p.type_expr) for p in fn.params if p.type_expr
    ) or _contains_fun_type(fn.return_type)
    if has_unsafe or has_fun_in_sig:
        provably_excluded_caps: list[str] = []
    else:
        declared_set = set(declared_caps)
        provably_excluded_caps = sorted(cap_names - declared_set)
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

    # Surface the source-level identifier (the loader's
    # ``_capa_m{N}__<source>`` mangle is for collision-avoidance
    # at analysis / transpile time, not for regulator-facing
    # output). The ``name`` field stays as the loader-time
    # identifier so internal call-resolution + bom-ref keying
    # do not collide on demangling; ``source_name`` is the
    # display form; ``source_module_index`` is the import
    # counter, preserved so SBOM consumers can still tell two
    # same-named helpers from different modules apart.
    source_name, module_index = _demangle(fn.name)
    source_container, _ = _demangle(container) if container is not None else (None, None)

    return {
        "name": fn.name,
        "source_name": source_name,
        "container": container,
        "source_container": source_container,
        "source_module_index": module_index,
        "pos": f"{filename}:{fn.pos.line}:{fn.pos.col}",
        "is_pub": fn.is_pub,
        "doc": fn.doc,
        "params": param_records,
        "return_type": _ty_text(fn.return_type) if fn.return_type else "()",
        "declared_capabilities": declared_caps,
        "provably_excluded_capabilities": provably_excluded_caps,
        "has_unsafe": has_unsafe,
        "attributes": attrs,
        "calls": calls,
    }
