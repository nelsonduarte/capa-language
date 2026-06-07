"""Generic type (struct / sum) monomorphisation.

Generic *functions* are specialised in :mod:`._calls`; generic
*types* are specialised here. A ``type Pair<T> { a: T, b: Int }``
referenced concretely as ``Pair<Char>`` must become a distinct
monomorphic struct ``Pair__Char { a: Char, b: Int }`` before the
Wasm layout machinery sees it -- otherwise the field ``a`` is sized /
decoded as the type variable ``T`` (which has no Wasm encoding), and a
struct returned across a function boundary mis-decodes its generic
field. The pass:

  1. finds every concrete instantiation ``G<args>`` of a generic
     type reachable from any type string in the module (plus the
     struct-literal / variant-construction sites, whose bare
     ``type_name`` carries no args and must be inferred from the
     operand types);
  2. synthesises one mangled clone decl per instantiation with the
     type parameters substituted through field / payload types;
  3. rewrites every reference -- type strings, ``Value.ty``,
     ``MakeStruct.type_name``, function locals / params / return
     types, and clone decls' own field types -- to the mangled
     name.

After this pass the module contains no generic type decls and no
type string mentioning a generic head with arguments, so the Wasm
backend emits each instantiation's layout from concrete field
types. The non-generic path is untouched (no generic decls => the
pass is a no-op).
"""

from __future__ import annotations

from dataclasses import fields, is_dataclass, replace
from typing import Optional

from .. import _nodes as N
from ._functions import _specialise_function
from ._typestr import (
    _TYPE_STRING_FIELDS,
    _has_question_mark,
    _is_abstract_ty,
    _mangle_type,
    _parse_ty,
    _strip_head,
    _substitute_ty,
    _unify_ty,
)


def _collect_generic_type_refs(
    ty_str: str, generic_names: set[str], abstract: set[str],
    out: dict[str, tuple[str, list[str]]],
) -> None:
    """Record every fully-concrete instantiation of a generic type
    that appears anywhere inside ``ty_str`` (including nested
    positions like ``List<Pair<Int>>`` or ``Map<String, Box<Bool>>``).
    Each entry maps the canonical instantiation string -> (head,
    args). Instantiations whose args still mention a type variable or
    an unresolved ``?`` marker are skipped: they belong to an
    enclosing generic that has not been resolved, or to a call site
    whose inference is incomplete, and emitting a clone for them
    would produce a bogus (un-encodable) layout."""
    if not ty_str:
        return
    head, args = _parse_ty(ty_str)
    for a in args:
        _collect_generic_type_refs(a, generic_names, abstract, out)
    if head in generic_names and args and not any(
        _is_abstract_ty(a, abstract) for a in args
    ):
        canonical = f"{head}<{', '.join(args)}>"
        out[canonical] = (head, args)


def _rewrite_ty(ty_str: str, rewrites: dict[str, str]) -> str:
    """Rewrite every concrete generic instantiation inside ``ty_str``
    to its mangled monomorphic name, recursing into nested args so
    ``List<Pair<Char>>`` becomes ``List<Pair__Char>``. Leaves
    non-generic and already-monomorphic heads untouched."""
    if not ty_str:
        return ty_str
    # The rewrites map is keyed by the *original* canonical form
    # (``Box<Pair<Int, String>>``); try that before recursing so a
    # whole-string hit resolves the outer generic in one step.
    if ty_str in rewrites:
        return rewrites[ty_str]
    head, args = _parse_ty(ty_str)
    if not args:
        return ty_str
    new_args = [_rewrite_ty(a, rewrites) for a in args]
    if head == "(tuple)":
        return "(" + ", ".join(new_args) + ")"
    if head == "(fun)":
        *params, ret = new_args
        return f"Fun({', '.join(params)}) -> {ret}"
    # Re-check after inner rewrites in case the map was keyed by the
    # inner-mangled form, then fall back to the rebuilt string.
    rebuilt = f"{head}<{', '.join(new_args)}>"
    return rewrites.get(rebuilt, rebuilt)


# Field name on a dataclass node that carries a (bare or generic)
# *type name* used as a constructor target rather than a value type.
_TYPE_NAME_FIELDS = {"type_name"}


def _rewrite_node_types(node, rewrites: dict[str, str]):
    """Recursively rewrite every type-string field of a node so a
    concrete generic instantiation points at its mangled clone.
    Mirrors ``_substitute_node`` but applies the instantiation
    rewrite (``Pair<Char>`` -> ``Pair__Char``) instead of a
    type-parameter substitution."""
    if node is None:
        return node
    if isinstance(node, N.Value):
        new_ty = _rewrite_ty(node.ty, rewrites)
        if new_ty == node.ty:
            return node
        return N.Value(
            kind=node.kind, name=node.name, literal=node.literal, ty=new_ty,
        )
    if isinstance(node, str):
        return node
    if isinstance(node, list):
        return [_rewrite_node_types(x, rewrites) for x in node]
    if isinstance(node, tuple):
        return tuple(_rewrite_node_types(x, rewrites) for x in node)
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            if isinstance(old, str) and f.name in _TYPE_STRING_FIELDS:
                new = _rewrite_ty(old, rewrites)
            elif isinstance(old, str) and f.name in _TYPE_NAME_FIELDS:
                # Bare constructor targets (``MakeStruct.type_name``)
                # carry no args, so a plain-string lookup resolves the
                # per-site instantiation the caller has injected into
                # ``rewrites`` under the bare name.
                new = rewrites.get(old, old)
            else:
                new = _rewrite_node_types(old, rewrites)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


def _infer_make_struct_subst(
    instr: N.MakeStruct, decl: N.StructDecl,
    local_concrete: Optional[dict[str, str]] = None,
) -> Optional[dict[str, str]]:
    """Infer the type-parameter substitution for a generic struct
    literal from its field values' concrete types. ``Pair { a: 'x',
    b: 5 }`` against ``Pair<T> { a: T, b: Int }`` yields ``{T: Char}``.
    Returns None when any type parameter stays unresolved or a field
    value's type is itself unresolved.

    ``local_concrete`` (optional) maps a local name to the full,
    nested concrete type a prior generic-struct literal / alias
    resolved it to (``inner -> "Box<Int>"``). A field value that
    refers to such a local carries only the bare generic head in its
    ``ty`` (the lowerer annotates ``Box``, not ``Box<Int>``), so the
    naive inference would peg the type parameter to the bare head and
    mangle a nested ``Box<Box<Int>>`` down to ``Box__Box`` (whose
    field / method return type is the un-encodable bare ``Box``).
    Consulting this map carries the nested argument at full depth so
    the outer literal infers ``T = Box<Int>`` and mangles to
    ``Box__Box__Int``."""
    type_param_set = set(decl.type_params)
    field_decl_ty = {f.name: f.ty for f in decl.fields}
    mapping: dict[str, str] = {}
    for fname, fval in instr.fields:
        decl_ty = field_decl_ty.get(fname)
        if decl_ty is None:
            return None
        # Carry a nested generic instantiation at full depth: if the
        # field value is a local already resolved to a concrete nested
        # type, unify against that rather than the bare head its ``ty``
        # annotation carries.
        if (
            local_concrete is not None
            and fval.kind in ("local", "param")
            and fval.name in local_concrete
        ):
            if not _unify_ty(
                decl_ty, local_concrete[fval.name], type_param_set, mapping,
            ):
                return None
            continue
        if not fval.ty or fval.ty.startswith("?") or fval.ty in (
            "Unknown", "",
        ):
            # Cannot trust an unresolved field type to drive inference
            # when the field position is generic; if the field is a
            # plain concrete field (e.g. ``b: Int``) an unresolved
            # value type is harmless, so only bail when the decl side
            # is a type variable we still need to resolve.
            if decl_ty in type_param_set and decl_ty not in mapping:
                return None
            continue
        if not _unify_ty(decl_ty, fval.ty, type_param_set, mapping):
            return None
    for tp in decl.type_params:
        if tp not in mapping:
            return None
    return mapping


def _specialise_struct_decl(
    decl: N.StructDecl, subst: dict[str, str], mangled: str,
) -> N.StructDecl:
    return N.StructDecl(
        name=mangled,
        fields=[
            N.StructField(name=f.name, ty=_substitute_ty(f.ty, subst))
            for f in decl.fields
        ],
        type_params=[],
    )


def _specialise_sum_decl(
    decl: N.SumDecl, subst: dict[str, str], mangled: str,
) -> N.SumDecl:
    return N.SumDecl(
        name=mangled,
        variants=[
            N.SumVariant(
                name=v.name,
                payload_tys=[_substitute_ty(p, subst) for p in v.payload_tys],
            )
            for v in decl.variants
        ],
        type_params=[],
    )


def _resolve_partial_against(partial: str, concrete: str) -> Optional[str]:
    """If ``partial`` (which contains ``?`` markers) and ``concrete``
    share a head and arity, fill ``partial``'s ``?`` positions from
    ``concrete``. ``Either<Int, ?>`` + ``Either<Int, String>`` ->
    ``Either<Int, String>``. Returns None when they do not align."""
    p_head, p_args = _parse_ty(partial)
    c_head, c_args = _parse_ty(concrete)
    if p_head != c_head or len(p_args) != len(c_args):
        return None
    resolved_args = []
    for pa, ca in zip(p_args, c_args):
        if "?" in pa:
            sub = _resolve_partial_against(pa, ca)
            if sub is None:
                if pa.startswith("?"):
                    resolved_args.append(ca)
                    continue
                return None
            resolved_args.append(sub)
        else:
            resolved_args.append(pa)
    if p_head == "(tuple)":
        return "(" + ", ".join(resolved_args) + ")"
    return f"{p_head}<{', '.join(resolved_args)}>"


def _resolve_partial_types(fn, generic_names, abstract_names) -> None:
    """Replace partial generic instantiations (those carrying a ``?``)
    in ``fn``'s locals + Value types with the concrete sibling type
    the function already mentions. Collects every fully-concrete
    ``G<args>`` from the function (return type, params, locals, Value
    types) as candidates, then rewrites each partial that aligns with
    one. Mutates ``fn`` in place."""
    concretes: set[str] = set()

    def add_concrete(ty_str: str) -> None:
        if not ty_str or _has_question_mark(ty_str):
            return
        head, args = _parse_ty(ty_str)
        if head in generic_names and args and not any(
            _is_abstract_ty(a, abstract_names) for a in args
        ):
            concretes.add(ty_str)

    add_concrete(fn.return_type)
    for p in fn.params:
        add_concrete(p.ty)
    for lty in fn.locals.values():
        add_concrete(lty)

    def collect_value_concretes(node) -> None:
        if isinstance(node, N.Value):
            add_concrete(node.ty)
        elif isinstance(node, (list, tuple)):
            for x in node:
                collect_value_concretes(x)
        elif is_dataclass(node):
            for f in fields(node):
                collect_value_concretes(getattr(node, f.name))

    for instr in fn.body:
        collect_value_concretes(instr)

    if not concretes:
        return

    def resolve(ty_str: str) -> str:
        if not ty_str or not _has_question_mark(ty_str):
            return ty_str
        for cand in concretes:
            filled = _resolve_partial_against(ty_str, cand)
            if filled is not None and not _has_question_mark(filled):
                return filled
        return ty_str

    fn.locals = {name: resolve(lty) for name, lty in fn.locals.items()}

    def rewrite_values(node):
        if isinstance(node, N.Value):
            new_ty = resolve(node.ty)
            if new_ty == node.ty:
                return node
            return N.Value(
                kind=node.kind, name=node.name,
                literal=node.literal, ty=new_ty,
            )
        if isinstance(node, list):
            return [rewrite_values(x) for x in node]
        if isinstance(node, tuple):
            return tuple(rewrite_values(x) for x in node)
        if is_dataclass(node):
            changes = {}
            for f in fields(node):
                old = getattr(node, f.name)
                new = rewrite_values(old)
                if new is not old:
                    changes[f.name] = new
            if changes:
                return replace(node, **changes)
            return node
        return node

    fn.body = [rewrite_values(instr) for instr in fn.body]


def monomorphise_generic_types(module: N.Module) -> N.Module:
    """Specialise every generic struct / sum type per concrete
    instantiation referenced in the module (see the module-level
    comment above). Mutates ``module`` in place and returns it. A
    no-op when the module declares no generic types."""
    generic_structs: dict[str, N.StructDecl] = {}
    generic_sums: dict[str, N.SumDecl] = {}
    for ty in module.types:
        if isinstance(ty, N.StructDecl) and ty.type_params:
            generic_structs[ty.name] = ty
        elif isinstance(ty, N.SumDecl) and ty.type_params:
            generic_sums[ty.name] = ty
    generic_names = set(generic_structs) | set(generic_sums)
    if not generic_names:
        return module

    # Names that mark a type as not-yet-concrete: every generic decl's
    # type parameters. A ``?...`` marker is handled positionally by
    # ``_is_abstract_ty``. Used to skip instantiations whose args are
    # still abstract (a clone of ``Box<Pair>`` or ``Either<Int, ?>``
    # would have an un-encodable field).
    abstract_names: set[str] = set()
    for decl in (*generic_structs.values(), *generic_sums.values()):
        abstract_names.update(decl.type_params)

    # 0. Resolve partial instantiations (``Either<Int, ?>`` from a
    #    ``Left(7)`` variant constructor that pins only one type arg)
    #    against the concrete type strings the same function already
    #    carries (its return type, params, fully-resolved locals).
    #    Without this the partial type seeds no clone and the emitter
    #    later hits "has no Wasm encoding" on the un-erased ``?``.
    for fn in module.functions:
        _resolve_partial_types(fn, generic_names, abstract_names)

    # 1. Collect concrete instantiations from every type string the
    #    module carries: function signatures + locals, Value types,
    #    decl field / payload types.
    instantiations: dict[str, tuple[str, list[str]]] = {}

    def collect_in(ty_str: str) -> None:
        _collect_generic_type_refs(
            ty_str, generic_names, abstract_names, instantiations,
        )

    def walk_node_tys(node) -> None:
        if node is None:
            return
        if isinstance(node, N.Value):
            collect_in(node.ty)
            return
        if isinstance(node, (list, tuple)):
            for x in node:
                walk_node_tys(x)
            return
        if is_dataclass(node):
            for f in fields(node):
                old = getattr(node, f.name)
                if isinstance(old, str) and f.name in _TYPE_STRING_FIELDS:
                    collect_in(old)
                else:
                    walk_node_tys(old)
            return

    for fn in module.functions:
        for p in fn.params:
            collect_in(p.ty)
        collect_in(fn.return_type)
        for lty in fn.locals.values():
            collect_in(lty)
        for instr in fn.body:
            walk_node_tys(instr)
    for ty in module.types:
        if isinstance(ty, N.StructDecl):
            for f in ty.fields:
                collect_in(f.ty)
        elif isinstance(ty, N.SumDecl):
            for v in ty.variants:
                for p in v.payload_tys:
                    collect_in(p)

    # Per-site inference for generic struct literals whose bare
    # ``type_name`` (and dst local) carry no type arguments. The
    # inferred instantiation both seeds the clone table and lets us
    # rewrite the bare ``type_name`` + dst local for that one site.
    # Keyed by (fn_name, MakeStruct.dst) -> mangled name.
    make_struct_sites: dict[tuple[str, str], str] = {}

    def register_instantiation(head: str, args: list[str]) -> Optional[str]:
        if any(_is_abstract_ty(a, abstract_names) for a in args):
            return None
        canonical = f"{head}<{', '.join(args)}>"
        instantiations[canonical] = (head, args)
        # Recurse into the args so a nested generic instantiation
        # (``Box<Pair<Int, String>>``) also seeds the inner clone.
        for a in args:
            collect_in(a)
        return _mangle_type(head, args)

    for fn in module.functions:
        local_concrete: dict[str, str] = {}
        for instr in fn.body:
            _scan_make_struct_sites(
                fn, instr, generic_structs,
                register_instantiation, make_struct_sites,
                local_concrete,
            )

    # Generic impl blocks, grouped by the bare type name they extend.
    # An impl whose ``type_params`` equal its owning generic decl's
    # ``type_params`` is the generic impl (``impl Box<T>``) and applies
    # to every instantiation; one whose binders differ (``impl
    # Box<Int>``) is a concrete specialisation and applies only to the
    # matching instantiation. Both are specialised below.
    generic_impls: dict[str, list[N.ImplBlock]] = {}
    for impl in module.impls:
        if impl.type_name in generic_names and impl.type_params:
            generic_impls.setdefault(impl.type_name, []).append(impl)

    if not instantiations:
        return module

    # 2. Build clones + the canonical-string -> mangled rewrite map.
    rewrites: dict[str, str] = {}
    new_decls: dict[str, object] = {}
    for canonical, (head, args) in instantiations.items():
        mangled = _mangle_type(head, args)
        rewrites[canonical] = mangled
        if mangled in new_decls:
            continue
        if head in generic_structs:
            decl = generic_structs[head]
            subst = dict(zip(decl.type_params, args))
            new_decls[mangled] = _specialise_struct_decl(decl, subst, mangled)
        elif head in generic_sums:
            decl = generic_sums[head]
            subst = dict(zip(decl.type_params, args))
            new_decls[mangled] = _specialise_sum_decl(decl, subst, mangled)

    # 3. Rewrite the module. Generic decls are dropped; their clones
    #    replace them (themselves run through the rewrite so a generic
    #    field referencing another generic instantiation is threaded).
    new_types: list = []
    for ty in module.types:
        if isinstance(ty, (N.StructDecl, N.SumDecl)) and ty.type_params:
            continue
        new_types.append(_rewrite_node_types(ty, rewrites))
    for decl in new_decls.values():
        new_types.append(_rewrite_node_types(decl, rewrites))
    module.types = new_types

    for fn in module.functions:
        fn.params = [
            N.Param(
                name=p.name,
                ty=_rewrite_ty(p.ty, rewrites),
                is_capability=p.is_capability,
            )
            for p in fn.params
        ]
        fn.return_type = _rewrite_ty(fn.return_type, rewrites)
        fn.locals = {
            name: _rewrite_ty(lty, rewrites) for name, lty in fn.locals.items()
        }
        new_body = []
        for instr in fn.body:
            rewritten = _rewrite_node_types(instr, rewrites)
            new_body.append(rewritten)
        fn.body = new_body
        _patch_bare_generic_struct_refs(fn, make_struct_sites)

    # Variant payloads of a monomorphised sum carry concrete types
    # now (``Either__Int_String`` -> ``Left(Int)``), but a ``match``
    # arm's binder local was typed from the original generic decl
    # (``n: L``). Refine each PatVariant binder's local type from the
    # concrete sum decl so the Wasm match-payload extractor decodes
    # it as its real type rather than choking on the type variable.
    concrete_sum_payloads: dict[str, dict[str, list[str]]] = {}
    for decl in new_decls.values():
        if isinstance(decl, N.SumDecl):
            concrete_sum_payloads[decl.name] = {
                v.name: list(v.payload_tys) for v in decl.variants
            }
    if concrete_sum_payloads:
        for fn in module.functions:
            for instr in fn.body:
                _refine_match_binders(fn, instr, concrete_sum_payloads)

    # 4. Specialise generic impl blocks per instantiation. The struct /
    #    sum decls are now monomorphic (``Box__Int``), but the impl that
    #    carries their methods still extends the bare generic ``Box``
    #    with bodies mentioning the type variable ``T``. The Wasm
    #    method-dispatch table is keyed on the mangled type name, so an
    #    un-specialised impl leaves ``(Box__Int, get)`` unresolved.
    if generic_impls:
        new_impls: list = [
            impl for impl in module.impls
            if not (impl.type_name in generic_names and impl.type_params)
        ]
        # Dedup at METHOD granularity, not impl-block granularity. A
        # generic type may carry more than one inherent ``impl`` block
        # (``impl Box<T>`` twice), all with ``trait_name=None``; a
        # per-block key keyed on ``(mangled, trait_name)`` would collide
        # all inherent blocks onto ``(Box__Int, None)`` and silently
        # drop every block after the first - a silent loss of methods.
        # Keying on the method name as well keeps every method from
        # every block while still not double-emitting the same method
        # for one instantiation (which would produce a duplicate Wasm
        # function name in the dispatch table).
        emitted: set[tuple[str, str | None, str]] = set()
        for canonical, (head, args) in instantiations.items():
            impls = generic_impls.get(head)
            if not impls:
                continue
            mangled = _mangle_type(head, args)
            decl_params = (
                generic_structs[head].type_params if head in generic_structs
                else generic_sums[head].type_params
            )
            for impl in impls:
                # Concrete-specialised impl (``impl Box<Int>``): its
                # binders are concrete types, so it applies only to the
                # exact matching instantiation. The generic impl
                # (binders == decl type_params) applies to all.
                is_generic_impl = impl.type_params == decl_params
                subst = dict(zip(impl.type_params, args))
                if not is_generic_impl and list(impl.type_params) != list(args):
                    continue
                methods = [
                    m for m in impl.methods
                    if (mangled, impl.trait_name, m.name) not in emitted
                ]
                if not methods:
                    continue
                for m in methods:
                    emitted.add((mangled, impl.trait_name, m.name))
                new_impls.append(
                    _specialise_impl(
                        impl, methods, subst, mangled, rewrites,
                        generic_structs, generic_names, abstract_names,
                    )
                )
        module.impls = new_impls

    return module


def _specialise_impl(
    impl, methods, subst: dict[str, str], mangled: str,
    rewrites: dict[str, str], generic_structs: dict,
    generic_names: set, abstract_names: set,
):
    """Clone the given ``methods`` of a generic impl block for one
    concrete instantiation: substitute the type parameters through
    every method, resolve any partial generic type the substitution
    leaves behind, rewrite the now-concrete generic type strings to
    their mangled clone names, and patch the bare-headed struct-literal
    references each generic constructor leaves behind. The result
    extends the mangled type (``Box__Int``) so the Wasm method-dispatch
    table resolves ``(Box__Int, get)`` to the specialised body.

    ``methods`` is the (possibly merged-across-blocks, de-duplicated)
    subset of this block's methods to emit for this instantiation."""
    new_methods = []
    for method in methods:
        # Reuse the function-clone machinery to substitute the type
        # parameters (``T`` -> ``Int``) through params / return /
        # locals / body; the method keeps its own name (the dispatch
        # mangling is ``<type>_<method>``, handled by the emitter).
        spec = _specialise_function(method, subst, method.name)
        # A sum-variant construction inside the method (``return
        # Some_(x)``) leaves the dst local typed ``Opt<?>``: the
        # substitution concretises the variant argument (``T`` ->
        # ``Int``) but the ``?`` is positional, not a type parameter,
        # so it survives. Resolve it against the method's own concrete
        # type strings (its substituted return type ``Opt<Int>``)
        # exactly as free functions are resolved at step 0 - otherwise
        # the un-erased ``Opt<?>`` reaches the emitter ("no Wasm
        # encoding"). Runs BEFORE the mangling rewrite so the resolved
        # ``Opt<Int>`` is then rewritten to ``Opt__Int`` below.
        _resolve_partial_types(spec, generic_names, abstract_names)
        # Patch bare generic-struct constructors inside the method body
        # (``return Box { value: v }``): the literal's ``type_name`` and
        # dst local carry the bare head, which neither the
        # type-parameter substitution nor the instantiation-string
        # rewrite reaches. Infer each site's instantiation from the
        # constructor's now-concrete field-value types. This runs BEFORE
        # the instantiation-string rewrite so the inferred type
        # arguments are still in canonical form (``Cell<Int>``, not the
        # already-mangled ``Cell__Int``); inferring from the mangled
        # form would re-mangle a nested literal a second time
        # (``Cell { value: <Cell__Int> }`` -> ``Cell__Cell__Int``
        # instead of ``Cell__Cell_Int``) and seed a clone that does not
        # exist.
        sites: dict[tuple[str, str], tuple[str, str]] = {}
        local_concrete: dict[str, str] = {}
        for instr in spec.body:
            _collect_method_make_struct_sites(
                spec, instr, generic_structs, sites, local_concrete,
            )
        if sites:
            _patch_bare_generic_struct_refs(spec, sites)
        # The substitution leaves concrete generic instantiations
        # (``Box<Int>``) that must point at their mangled clone.
        spec.return_type = _rewrite_ty(spec.return_type, rewrites)
        spec.params = [
            N.Param(
                name=p.name,
                ty=_rewrite_ty(p.ty, rewrites),
                is_capability=p.is_capability,
            )
            for p in spec.params
        ]
        spec.locals = {
            name: _rewrite_ty(lty, rewrites)
            for name, lty in spec.locals.items()
        }
        spec.body = [_rewrite_node_types(instr, rewrites) for instr in spec.body]
        new_methods.append(spec)
    return N.ImplBlock(
        type_name=mangled,
        trait_name=impl.trait_name,
        methods=new_methods,
        type_params=[],
    )


def _collect_method_make_struct_sites(
    fn, instr, generic_structs, sites, local_concrete=None,
) -> None:
    """Record the (bare_head, mangled) instantiation for every generic
    struct literal in a specialised impl method. The type-parameter
    substitution has already concretised the field-value types, so the
    instantiation is inferred from those exactly as
    ``_scan_make_struct_sites`` does for top-level functions.

    ``local_concrete`` threads a nested generic instantiation at full
    depth across body order, identically to ``_scan_make_struct_sites``,
    so a literal built inside a method whose field references an earlier
    resolved local mangles to the correct nested clone name rather than
    pegging the type parameter to a bare head."""
    if local_concrete is None:
        local_concrete = {}
    if isinstance(instr, N.MakeStruct) and instr.type_name in generic_structs:
        decl = generic_structs[instr.type_name]
        sub = _infer_make_struct_subst(instr, decl, local_concrete)
        if sub is not None:
            args = [sub[tp] for tp in decl.type_params]
            if not any(_is_abstract_ty(a, set(decl.type_params)) for a in args):
                mangled = _mangle_type(instr.type_name, args)
                sites[(fn.name, instr.dst)] = (instr.type_name, mangled)
                local_concrete[instr.dst] = (
                    f"{instr.type_name}<{', '.join(args)}>"
                )
        return
    if isinstance(instr, (N.AssignConst, N.Reassign)):
        src = instr.src
        if (src.kind in ("local", "param")
                and src.name in local_concrete):
            local_concrete[instr.dst] = local_concrete[src.name]
        return
    for sub_list in _child_instr_lists(instr):
        for s in sub_list:
            _collect_method_make_struct_sites(
                fn, s, generic_structs, sites, local_concrete)


def _child_instr_lists(instr):
    """Yield the nested instruction lists of a control-flow node."""
    if isinstance(instr, N.If):
        yield instr.then_body
        yield instr.else_body
    elif isinstance(instr, N.While):
        yield instr.cond_setup
        yield instr.body
    elif isinstance(instr, N.For):
        yield instr.body
    elif isinstance(instr, N.Match):
        for arm in instr.arms:
            yield arm.body


def _refine_match_binders(fn, instr, concrete_sum_payloads: dict) -> None:
    """Set the local type of every PatVariant binder in a ``match``
    against a monomorphised sum to the concrete payload type from the
    specialised decl. Recurses through nested control flow and nested
    sub-patterns."""
    if isinstance(instr, N.Match):
        scrut_head = _strip_head(instr.scrutinee.ty)
        payloads = concrete_sum_payloads.get(scrut_head)
        if payloads is not None:
            for arm in instr.arms:
                _refine_pattern_binders(arm.pattern, payloads, fn)
                for sub in arm.body:
                    _refine_match_binders(fn, sub, concrete_sum_payloads)
        else:
            for arm in instr.arms:
                for sub in arm.body:
                    _refine_match_binders(fn, sub, concrete_sum_payloads)
        return
    if isinstance(instr, N.If):
        for sub in (*instr.then_body, *instr.else_body):
            _refine_match_binders(fn, sub, concrete_sum_payloads)
    elif isinstance(instr, N.While):
        for sub in (*instr.cond_setup, *instr.body):
            _refine_match_binders(fn, sub, concrete_sum_payloads)
    elif isinstance(instr, N.For):
        for sub in instr.body:
            _refine_match_binders(fn, sub, concrete_sum_payloads)


def _refine_pattern_binders(pattern, payloads: dict, fn) -> None:
    """Walk a PatVariant's payload sub-patterns, setting each bound
    identifier's local type to the concrete payload type from the
    specialised sum decl."""
    if isinstance(pattern, N.PatVariant):
        tys = payloads.get(pattern.name)
        if tys is not None:
            for sub, ty in zip(pattern.payloads, tys):
                if isinstance(sub, N.PatIdent):
                    fn.locals[sub.name] = ty


def _patch_bare_generic_struct_refs(fn, make_struct_sites: dict) -> None:
    """Patch the bare-headed references a generic struct literal leaves
    behind. ``MakeStruct.type_name`` and its dst local carry the bare
    head (``Pair``, no args), which the instantiation-string rewrite
    cannot reach. Resolve them from the per-site inference, then
    propagate the concrete instantiation through alias assignments
    (``let p = _ir_t0``) to a fixed point so every later
    ``FieldAccess`` / ``Return`` against the value sees the mangled
    type, and the emitter sizes / decodes it as a struct pointer
    rather than hitting the bare-name fallback."""
    # local name -> (bare_head, mangled) for locals that hold a
    # concrete generic-struct instance. Threaded through nested
    # control-flow bodies in body order, exactly as
    # ``_scan_make_struct_sites`` threads its ``local_concrete``: a
    # branch inherits a copy of the enclosing scope's map so a literal
    # built inside one branch cannot leak its entry into a sibling
    # branch.
    concrete: dict[str, tuple[str, str]] = {}
    _patch_body_scope(fn, fn.body, make_struct_sites, concrete)


def _patch_body_scope(fn, body, make_struct_sites, concrete) -> None:
    """Patch one instruction list in body order, then recurse into any
    nested control-flow bodies with a forked copy of ``concrete`` so
    sibling branches do not cross-contaminate."""
    # 1. Patch MakeStruct sites and propagate aliases in body order.
    for instr in body:
        if isinstance(instr, N.MakeStruct):
            site = make_struct_sites.get((fn.name, instr.dst))
            if site is not None:
                bare_head, mangled = site
                instr.type_name = mangled
                fn.locals[instr.dst] = mangled
                concrete[instr.dst] = (bare_head, mangled)
        elif isinstance(instr, (N.AssignConst, N.Reassign)):
            src = instr.src
            if (src.kind in ("local", "param")
                    and src.name in concrete
                    and instr.dst not in concrete):
                bare_head, mangled = concrete[src.name]
                dst_ty = fn.locals.get(instr.dst, "")
                if dst_ty in (bare_head, mangled):
                    concrete[instr.dst] = (bare_head, mangled)
                    fn.locals[instr.dst] = mangled
    # 2. Rewrite bare local refs at this level, and recurse into the
    #    nested bodies of each control-flow node with a forked scope.
    for idx, instr in enumerate(body):
        if _child_instr_lists_present(instr):
            _recurse_patch_children(fn, instr, make_struct_sites, concrete)
        body[idx] = _rewrite_bare_local_refs_shallow(instr, concrete)


def _child_instr_lists_present(instr) -> bool:
    return isinstance(instr, (N.If, N.While, N.For, N.Match))


def _recurse_patch_children(fn, instr, make_struct_sites, concrete) -> None:
    """Descend into a control-flow node's nested bodies. Each distinct
    branch gets its own forked copy of ``concrete`` so an instantiation
    resolved in one branch is not visible to a sibling branch."""
    if isinstance(instr, N.If):
        _patch_body_scope(fn, instr.then_body, make_struct_sites, dict(concrete))
        _patch_body_scope(fn, instr.else_body, make_struct_sites, dict(concrete))
    elif isinstance(instr, N.While):
        scope = dict(concrete)
        _patch_body_scope(fn, instr.cond_setup, make_struct_sites, scope)
        _patch_body_scope(fn, instr.body, make_struct_sites, scope)
    elif isinstance(instr, N.For):
        _patch_body_scope(fn, instr.body, make_struct_sites, dict(concrete))
    elif isinstance(instr, N.Match):
        for arm in instr.arms:
            _patch_body_scope(fn, arm.body, make_struct_sites, dict(concrete))


def _rewrite_bare_local_refs(node, bare_local_types: dict):
    """Rewrite the ``ty`` of any Value that refers (by name) to a
    local whose concrete generic instantiation was inferred from a
    struct literal, but whose annotated type is still the bare
    generic head. ``return _ir_t0`` where ``_ir_t0: Pair`` (bare) and
    the literal resolved to ``Pair__Char`` gets ``ty="Pair__Char"``."""
    if node is None:
        return node
    if isinstance(node, N.Value):
        if node.name in bare_local_types:
            bare_head, mangled = bare_local_types[node.name]
            if node.ty == bare_head:
                return N.Value(
                    kind=node.kind, name=node.name,
                    literal=node.literal, ty=mangled,
                )
        return node
    if isinstance(node, list):
        return [_rewrite_bare_local_refs(x, bare_local_types) for x in node]
    if isinstance(node, tuple):
        return tuple(
            _rewrite_bare_local_refs(x, bare_local_types) for x in node
        )
    if is_dataclass(node):
        changes = {}
        for f in fields(node):
            old = getattr(node, f.name)
            new = _rewrite_bare_local_refs(old, bare_local_types)
            if new is not old:
                changes[f.name] = new
        if changes:
            return replace(node, **changes)
        return node
    return node


# Fields of control-flow nodes that hold nested instruction lists.
# These are patched per-scope by ``_patch_body_scope`` recursion, so
# the shallow rewriter must not descend into them (doing so would
# re-apply the enclosing scope to a child, defeating per-branch
# isolation).
_BODY_FIELDS = frozenset(
    {"then_body", "else_body", "cond_setup", "body", "arms"}
)


def _rewrite_bare_local_refs_shallow(node, bare_local_types: dict):
    """Like :func:`_rewrite_bare_local_refs`, but for a control-flow
    instruction it rewrites only the node's own value-bearing fields
    (``cond``, ``scrutinee``, ``iter``, ...) and leaves nested
    instruction bodies untouched, since those are rewritten separately
    with their own per-branch scope. For a non-control-flow
    instruction it behaves identically to the deep rewriter."""
    if not _child_instr_lists_present(node):
        return _rewrite_bare_local_refs(node, bare_local_types)
    changes = {}
    for f in fields(node):
        if f.name in _BODY_FIELDS:
            continue
        old = getattr(node, f.name)
        new = _rewrite_bare_local_refs(old, bare_local_types)
        if new is not old:
            changes[f.name] = new
    if changes:
        return replace(node, **changes)
    return node


def _scan_make_struct_sites(
    fn, instr, generic_structs, register_instantiation, sites,
    local_concrete=None,
) -> None:
    """Recurse through an instruction tree recording, for every
    generic struct literal, the mangled instantiation inferred from
    its field values. Registers the instantiation so a clone is built
    even when no annotated type string elsewhere mentions it.

    ``local_concrete`` (a per-function dict, created on the first
    call) maps each local resolved to a concrete generic-struct
    instantiation to its full nested canonical type (``inner ->
    "Box<Int>"``). It is threaded through body order so a later
    literal whose field references an earlier resolved local
    (``Box { value: inner }``) infers the nested type argument at full
    depth instead of pegging it to the bare head. Alias assignments
    (``let outer = _ir_t1``) propagate the entry to the alias."""
    if local_concrete is None:
        local_concrete = {}
    if isinstance(instr, N.MakeStruct) and instr.type_name in generic_structs:
        decl = generic_structs[instr.type_name]
        subst = _infer_make_struct_subst(instr, decl, local_concrete)
        if subst is not None:
            args = [subst[tp] for tp in decl.type_params]
            mangled = register_instantiation(instr.type_name, args)
            if mangled is not None:
                sites[(fn.name, instr.dst)] = (instr.type_name, mangled)
                local_concrete[instr.dst] = (
                    f"{instr.type_name}<{', '.join(args)}>"
                )
        return
    if isinstance(instr, (N.AssignConst, N.Reassign)):
        src = instr.src
        if (src.kind in ("local", "param")
                and src.name in local_concrete):
            local_concrete[instr.dst] = local_concrete[src.name]
        return
    if isinstance(instr, N.If):
        for sub in instr.then_body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites,
                local_concrete)
        for sub in instr.else_body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites,
                local_concrete)
    elif isinstance(instr, N.While):
        for sub in instr.cond_setup:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites,
                local_concrete)
        for sub in instr.body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites,
                local_concrete)
    elif isinstance(instr, N.For):
        for sub in instr.body:
            _scan_make_struct_sites(
                fn, sub, generic_structs, register_instantiation, sites,
                local_concrete)
    elif isinstance(instr, N.Match):
        for arm in instr.arms:
            for sub in arm.body:
                _scan_make_struct_sites(
                    fn, sub, generic_structs, register_instantiation, sites,
                    local_concrete)
