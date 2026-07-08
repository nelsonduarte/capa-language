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


# String crossing type (feature #4 F2b). Unlike a scalar it does NOT
# lower to a single core-wasm value: on the parent import it crosses as
# a (ptr, len) i32 pair for an argument and through an 8-byte indirect
# return area for a result, reusing the SAME canonical-ABI machinery the
# WASI cap methods already use for strings (``$alloc`` + the ``string``
# materialiser). An AGGREGATE crossing type (Struct / Sum / List / Map /
# tuple / Option / Result) needs a general, recursive, type-driven
# Capa-heap reader/writer on the HOST side of the parent boundary that
# does not yet exist (the WASI paths only hand-code a fixed set of
# shapes); that is a further sub-phase, so an aggregate crossing type is
# still rejected up front by the CLI guard.
STRING_CROSSING = "String"


def is_scalar_crossing_type(root: str) -> bool:
    """True when ``root`` (a source-level type root name) is a scalar
    crossing type F2a marshals at runtime (Int / Bool / Float)."""
    return root in SCALAR_CROSSING_WASM


def is_string_crossing_type(root: str) -> bool:
    """True when ``root`` is the String crossing type F2b marshals at
    runtime via the canonical-ABI (ptr, len) + ``$alloc`` machinery."""
    return root == STRING_CROSSING


def is_marshallable_crossing_type(root: str) -> bool:
    """True when ``root`` is a crossing type the F2 runtime can marshal:
    a scalar (Int / Bool / Float, F2a) or String (F2b). An aggregate
    crossing type returns False and is rejected before dispatch."""
    return is_scalar_crossing_type(root) or is_string_crossing_type(root)


def method_param_kinds(method: A.MethodSig) -> list[tuple[str, str]]:
    """Per-parameter classification of a foreign method signature, in
    declared order (excluding ``self``): ``("cap", CapName)`` for a
    built-in capability parameter, ``("scalar", RootTypeName)`` for a
    scalar / String crossing value (Int / Bool / Float / String), or
    ``("aggregate", TypeText)`` for a crossing aggregate (struct / List /
    tuple / Option / Result, feature #4 F2c). The lowerer stores this on
    the :class:`ForeignCall` so the emitter knows which operand is an i32
    handle, which is a scalar, which is a String (``("scalar",
    "String")`` -> a (ptr, len) pair), and which is an aggregate (a
    single i32 heap pointer); the host knows which caps to bind."""
    from .foreign_schema import crossing_kind
    from .manifest._strings import _ty_text

    kinds: list[tuple[str, str]] = []
    for p in method.params:
        if p.name == "self":
            continue
        root = _root_type_name(p.type_expr) if p.type_expr else "?"
        kind = crossing_kind(p.type_expr) if p.type_expr else "scalar"
        if kind == "cap":
            kinds.append(("cap", root))
        elif kind == "aggregate":
            kinds.append(("aggregate", _ty_text(p.type_expr)))
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
    aggregate crossing type is NOT scalar."""
    for kind, root in method_param_kinds(method):
        if kind == "scalar" and not is_scalar_crossing_type(root):
            return False
    ret = method_return_root(method)
    if ret != "Unit" and not is_scalar_crossing_type(ret):
        return False
    return True


def method_is_runtime_marshallable(
    method: A.MethodSig, module: "A.Module | None" = None,
) -> bool:
    """True when every non-capability crossing parameter AND the return
    type of ``method`` is a crossing type the F2 runtime can marshal at
    runtime: a scalar (Int / Bool / Float, F2a), String (F2b), or a FLAT
    one-level scalar-leaf AGGREGATE (a struct of scalars, ``List<scalar>``,
    a tuple of scalars, ``Option<scalar>``, ``Result<scalar, scalar>`` --
    feature #4 F2c-1), or Unit for the return.

    A NESTED aggregate (``List<struct>``, a struct with a List / nested
    aggregate field, a multi-payload sum, Map) is NOT yet marshallable and
    must be rejected with the F2c-2 guard before it is dispatched. The
    flat-aggregate check needs ``module`` to resolve struct field types
    and the multi-impl-trait header decision; when ``module`` is ``None``
    an aggregate is treated conservatively as un-marshallable."""
    from .foreign_schema import build_aggregate_schema

    def _ok(type_expr, root: "str | None") -> bool:
        if root in CAPABILITY_NAMES:
            return True
        if is_marshallable_crossing_type(root):
            return True
        if module is None:
            return False
        return build_aggregate_schema(type_expr, module) is not None

    for p in method.params:
        if p.name == "self":
            continue
        root = _root_type_name(p.type_expr) if p.type_expr else "?"
        if root in CAPABILITY_NAMES:
            continue
        if not _ok(p.type_expr, root):
            return False
    if method.return_type is not None:
        ret_root = _root_type_name(method.return_type)
        if not _ok(method.return_type, ret_root):
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
    """Runtime dispatch metadata for every marshallable foreign-component
    method the module declares (feature #4, F2a scalars + F2b String).
    The Wasm host
    (:meth:`capa.runtime._wasm_host.WasmHost.register_foreign_methods`)
    consumes this to define one ``capa:foreign/<component>`` import per
    method. Each param is one of:

    - ``cap``   -- a capability, crossing as an i32 handle (``wasm``
      = ``["i32"]``); the host resolves it to the caller's attenuated cap.
    - ``scalar`` -- Int / Bool / Float (``wasm`` = a single core type).
    - ``string`` -- a String, crossing as a (ptr, len) i32 pair (``wasm``
      = ``["i32", "i32"]``); the host reads the bytes out of the parent's
      linear memory.

    The return is described by ``return_kind`` -- ``"unit"``,
    ``"scalar"`` (with ``return_root`` / ``return_wasm``), or ``"string"``
    (marshalled back through an 8-byte indirect return area the host
    writes into the parent's memory via ``$alloc``).

    Methods using an AGGREGATE crossing type are OMITTED -- they cannot
    be marshalled at runtime yet and any INVOCATION of one is rejected
    earlier by the CLI's aggregate guard, so the host never needs an
    import for them. ``artifact`` is the raw declared path; the caller
    resolves it relative to the source file."""
    from .foreign_schema import crossing_kind, build_aggregate_schema

    methods: list[dict] = []
    for ec in extern_components(module):
        for m in ec.methods:
            if not method_is_runtime_marshallable(m, module):
                continue
            params: list[dict] = []
            for p in m.params:
                if p.name == "self":
                    continue
                root = _root_type_name(p.type_expr) if p.type_expr else "?"
                kind = crossing_kind(p.type_expr) if p.type_expr else "scalar"
                if kind == "cap":
                    params.append(
                        {"kind": "cap", "cap": root, "wasm": ["i32"]}
                    )
                elif kind == "aggregate":
                    params.append({
                        "kind": "aggregate",
                        "schema": build_aggregate_schema(p.type_expr, module),
                        "wasm": ["i32"],
                    })
                elif is_string_crossing_type(root):
                    params.append(
                        {"kind": "string", "root": root,
                         "wasm": ["i32", "i32"]}
                    )
                else:
                    params.append({
                        "kind": "scalar", "root": root,
                        "wasm": [SCALAR_CROSSING_WASM[root]],
                    })
            ret_expr = m.return_type
            ret_kind = crossing_kind(ret_expr) if ret_expr is not None else "unit"
            ret_root = method_return_root(m)
            if ret_expr is None or ret_root == "Unit":
                ret_meta = {"return_kind": "unit", "return_root": "Unit",
                            "return_wasm": None}
            elif ret_kind == "aggregate":
                ret_meta = {
                    "return_kind": "aggregate",
                    "return_root": ret_root,
                    "return_schema": build_aggregate_schema(ret_expr, module),
                    "return_wasm": None,
                }
            elif is_string_crossing_type(ret_root):
                ret_meta = {"return_kind": "string", "return_root": ret_root,
                            "return_wasm": None}
            else:
                ret_meta = {"return_kind": "scalar", "return_root": ret_root,
                            "return_wasm": SCALAR_CROSSING_WASM[ret_root]}
            methods.append({
                "component": ec.name,
                "method": m.name,
                "artifact": ec.artifact,
                "params": params,
                **ret_meta,
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
