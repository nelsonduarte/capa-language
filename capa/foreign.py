"""Shared helpers for typed foreign components (feature #4, F1).

A typed foreign component (``extern component Bureau from "b.wasm"``) is a
reference to an external Wasm Component Model artifact plus the method
signatures Capa may call across the boundary. This module holds the small
AST-level queries that both the manifest builder and the CLI need:

- which foreign components a module declares, and
- where a program actually INVOKES one (``Bureau.submit(...)``).

The runtime that would SANDBOX such a call is a separate later increment
(F2). Until it lands, a program that invokes a foreign component cannot be
run or codegen'd, and its boundary composes as authority-unknown TOP in
the SBOM (claiming a bound nothing enforces would be unsound).
"""

from __future__ import annotations

from typing import Callable

from . import capa_ast as A
from .tokens import Pos
from .typesys import CAPABILITY_NAMES
from .manifest._strings import _root_type_name


def extern_components(module: A.Module) -> list[A.ExternComponent]:
    """Every ``extern component`` declaration in the module, in order."""
    return [it for it in module.items if isinstance(it, A.ExternComponent)]


def extern_component_names(module: A.Module) -> set[str]:
    """The set of names bound by ``extern component`` declarations."""
    return {it.name for it in extern_components(module)}


# Scalar crossing types F2a marshals across the boundary, mapped to the
# core-wasm value type the parent-side import uses. String and every
# aggregate (Struct / Sum / List / Map / tuple / Option / Result) need
# the linear-memory canonical ABI (indirect return + ``$alloc``) at the
# parent-import boundary, which is deferred to F2b; a call using one is
# rejected up front by the CLI's F2b guard, so this table is exhaustive
# for what actually crosses at runtime in F2a.
SCALAR_CROSSING_WASM: dict[str, str] = {
    "Int": "i64",
    "Bool": "i32",
    "Float": "f64",
}


def is_scalar_crossing_type(root: str) -> bool:
    """True when ``root`` (a source-level type root name) is a scalar
    crossing type F2a marshals at runtime (Int / Bool / Float)."""
    return root in SCALAR_CROSSING_WASM


def method_param_kinds(method: A.MethodSig) -> list[tuple[str, str]]:
    """Per-parameter classification of a foreign method signature, in
    declared order (excluding ``self``): ``("cap", CapName)`` for a
    built-in capability parameter, else ``("scalar", RootTypeName)`` for
    an ordinary crossing value. The lowerer stores this on the
    :class:`ForeignCall` so the emitter knows which operand is an i32
    handle vs a scalar, and the host knows which caps to bind."""
    kinds: list[tuple[str, str]] = []
    for p in method.params:
        if p.name == "self":
            continue
        root = _root_type_name(p.type_expr) if p.type_expr else "?"
        if root in CAPABILITY_NAMES:
            kinds.append(("cap", root))
        else:
            kinds.append(("scalar", root))
    return kinds


def method_return_root(method: A.MethodSig) -> str:
    """The root type name of a foreign method's return type, or
    ``"Unit"`` when it declares none."""
    if method.return_type is None:
        return "Unit"
    return _root_type_name(method.return_type)


def method_is_scalar(method: A.MethodSig) -> bool:
    """True when every non-capability crossing parameter AND the return
    type of ``method`` is a scalar F2a can marshal at runtime (Int /
    Bool / Float), or Unit for the return. A method using String or any
    aggregate crossing type is NOT scalar and must be rejected with the
    F2b guard before it is dispatched at runtime."""
    for kind, root in method_param_kinds(method):
        if kind == "scalar" and not is_scalar_crossing_type(root):
            return False
    ret = method_return_root(method)
    if ret != "Unit" and not is_scalar_crossing_type(ret):
        return False
    return True


def declared_capabilities(method: A.MethodSig) -> list[str]:
    """The built-in host capabilities a foreign-component method's
    signature grants (its explicit capability parameter types). These are
    the ONLY authority the component may receive; the crossing discipline
    (checked in the analyzer) guarantees no other capability can appear."""
    caps: list[str] = []
    for p in method.params:
        if p.name == "self" or p.type_expr is None:
            continue
        root = _root_type_name(p.type_expr)
        if root in CAPABILITY_NAMES:
            caps.append(root)
    return caps


def foreign_runtime_methods(module: A.Module) -> list[dict]:
    """Runtime dispatch metadata for every SCALAR foreign-component
    method the module declares (feature #4, F2a). The Wasm host
    (:meth:`capa.runtime._wasm_host.WasmHost.register_foreign_methods`)
    consumes this to define one ``capa:foreign/<component>`` import per
    method: each param is either a capability (crossing as an i32 handle)
    or a scalar (Int/Bool/Float), and the return is a scalar or Unit.

    Non-scalar methods (String / aggregate crossing types) are OMITTED --
    they cannot be marshalled at runtime in F2a and any INVOCATION of one
    is rejected earlier by the CLI's F2b guard, so the host never needs an
    import for them. ``artifact`` is the raw declared path; the caller
    resolves it relative to the source file."""
    methods: list[dict] = []
    for ec in extern_components(module):
        for m in ec.methods:
            if not method_is_scalar(m):
                continue
            params: list[dict] = []
            for kind, root in method_param_kinds(m):
                if kind == "cap":
                    params.append({"kind": "cap", "cap": root, "wasm": "i32"})
                else:
                    params.append({
                        "kind": "scalar", "root": root,
                        "wasm": SCALAR_CROSSING_WASM[root],
                    })
            ret_root = method_return_root(m)
            ret_wasm = (
                None if ret_root == "Unit" else SCALAR_CROSSING_WASM[ret_root]
            )
            methods.append({
                "component": ec.name,
                "method": m.name,
                "artifact": ec.artifact,
                "params": params,
                "return_root": ret_root,
                "return_wasm": ret_wasm,
            })
    return methods


def _walk(node: object, visit: Callable[[A.Node], None]) -> None:
    """Depth-first walk of an AST subtree, calling ``visit`` on every
    :class:`capa_ast.Node`. Mirrors the manifest's generic traversal so it
    descends into the same nesting the call records are collected from."""
    if isinstance(node, A.Node):
        visit(node)
        for f in node.__dataclass_fields__.values():
            if f.name == "pos":
                continue
            _walk(getattr(node, f.name), visit)
    elif isinstance(node, (list, tuple)):
        for item in node:
            _walk(item, visit)


def foreign_call_sites(
    node: object, names: set[str],
) -> list[tuple[str, str, Pos]]:
    """Every foreign-component invocation in ``node``'s subtree.

    A foreign call is a ``MethodCall`` whose receiver is a bare identifier
    naming one of ``names`` (``Bureau.submit(...)``). Returns a list of
    ``(component_name, method_name, pos)`` triples in source order. An
    empty ``names`` set short-circuits to no sites."""
    if not names:
        return []
    sites: list[tuple[str, str, Pos]] = []

    def visit(n: A.Node) -> None:
        if (
            isinstance(n, A.MethodCall)
            and isinstance(n.receiver, A.Ident)
            and n.receiver.name in names
        ):
            sites.append((n.receiver.name, n.method, n.pos))

    _walk(node, visit)
    return sites


def module_invokes_foreign_component(module: A.Module) -> bool:
    """True if any function / method body in the module invokes a foreign
    component. The signature-only declaration alone is inert (``--check`` /
    ``--manifest`` work); only an actual invocation needs the F2 runtime."""
    names = extern_component_names(module)
    if not names:
        return False
    return bool(foreign_call_sites(module, names))
