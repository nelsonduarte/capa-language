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
from ._reachability import caps_reachable_via_sig, compute_reachability
from ._strings import _contains_fun_type, _root_type_name, _ty_text


SCHEMA_VERSION = 1


# Loader-generated mangle prefix on non-pub items imported from
# another module: ``_capa_m{N}__<source_name>`` (see
# ``capa/loader.py::_mangle_private_items``). The manifest displays
# the source-level name so regulator-facing SBOMs read as the user
# wrote them; the module index ``N`` is preserved as a separate
# field so the auditor still sees which import the symbol came from.
_MANGLE_RE = re.compile(r"^_capa_m(\d+)__(.+)$")
# Inline form for rewriting mangled identifiers that appear inside
# a type-text string (``List<_capa_m1__Foo>``) — anchored at a
# word boundary so it doesn't munge unrelated names.
_MANGLE_INLINE_RE = re.compile(r"\b_capa_m\d+__([A-Za-z_]\w*)")


def _demangle(name: str) -> tuple[str, Optional[int]]:
    """Return ``(source_name, module_index)`` for a possibly-mangled
    identifier. ``module_index`` is None when the name carried no
    loader prefix (root-module item or pub-exported import)."""
    m = _MANGLE_RE.match(name)
    if m is None:
        return name, None
    return m.group(2), int(m.group(1))


def _demangle_type_text(s: str) -> str:
    """Rewrite every mangled identifier inside a rendered
    ``_ty_text`` string back to its source-level form. Used so
    the manifest's per-param ``type`` fields read as the user
    wrote them rather than carrying the loader's
    ``_capa_m{N}__`` prefix from a non-pub imported type."""
    return _MANGLE_INLINE_RE.sub(r"\1", s)


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
    # ``cap_names`` is the analyzer-internal set of cap-typed names
    # (built-ins + user-defined). For the discipline check we need
    # the MANGLED names (because that's what carries through the
    # module after loader-rewrites). For the human-facing manifest
    # fields below we demangle. Slice 20 (2026-05-29): pre-fix the
    # ``user_defined_capabilities`` / ``provably_excluded_capabilities``
    # / ``implementors`` surfaces leaked the ``_capa_m{N}__`` prefix
    # of any non-pub cap defined in an imported module; downstream
    # SBOM / regulator tooling reads cap names as strings and would
    # render them as e.g. ``_capa_m1__SmtpMailer`` rather than the
    # source-level ``SmtpMailer``.
    cap_names: set[str] = set(CAPABILITY_NAMES)
    impl_map: dict[str, list[str]] = {}

    for item in module.items:
        if isinstance(item, A.TraitDecl) and item.is_capability:
            cap_names.add(item.name)
            source_cap_name, _idx = _demangle(item.name)
            user_caps.append({
                "name": source_cap_name,
                "methods": [m.name for m in item.methods],
                "implementors": [],  # populated below
                "doc": item.doc,
            })
        if isinstance(item, A.ImplBlock) and item.trait_name is not None:
            impl_map.setdefault(item.trait_name, []).append(item.type_name)

    for uc in user_caps:
        # impl_map keys are mangled trait names (analyzer-internal);
        # find by re-mangling uc["name"] back. Since uc["name"] is
        # already source-level, we look up by walking impl_map
        # entries whose mangled key demangles to uc["name"].
        impls: list[str] = []
        for mangled_trait, types in impl_map.items():
            demangled_trait, _ = _demangle(mangled_trait)
            if demangled_trait == uc["name"]:
                impls.extend(_demangle(t)[0] for t in types)
        uc["implementors"] = sorted(impls)

    # Audit slice 21 closure (2026-05-29): compute per-impl
    # reachability so the regulator-facing exclusion list reflects
    # what each function can *transitively* exercise via user-cap
    # impls and cap-bearing struct field caps — not just what it
    # names in its signature. ``user_cap_names_mangled`` is the
    # analyzer-internal name set (loader-prefixed); the
    # reachability machinery stays in that namespace to line up
    # with ``ImplBlock.trait_name`` and ``TypeName.name``.
    user_cap_names_mangled: set[str] = cap_names - frozenset(CAPABILITY_NAMES)
    reachable, unprovable = compute_reachability(
        module, user_cap_names=user_cap_names_mangled,
    )

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
                reachable=reachable, unprovable=unprovable,
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
                    reachable=reachable, unprovable=unprovable,
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
    reachable: Optional[dict[str, set[str]]] = None,
    unprovable: Optional[set[str]] = None,
) -> dict[str, Any]:
    if reachable is None:
        reachable = {}
    if unprovable is None:
        unprovable = set()
    param_records: list[dict[str, Any]] = []
    for p in fn.params:
        if p.name == "self":
            ty_text = "Self"
        else:
            # Demangle the rendered type-text so the manifest's
            # per-param ``type`` field reads as the user wrote it
            # rather than carrying ``_capa_m{N}__`` prefixes from
            # non-pub imported types (audit slice 20, 2026-05-29).
            ty_text = _demangle_type_text(_ty_text(p.type_expr)) if p.type_expr else "?"
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
        implicit_demangled, _ = _demangle(implicit_cap)
        if implicit_demangled not in declared_caps:
            declared_caps.append(implicit_demangled)
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

    # 3. Audit slice 21 closure (2026-05-29): walk the function's
    #    signature through the per-impl reachability map. A
    #    function ``use_logger(lg: FileLogger)`` where
    #    ``FileLogger { out: Stdio }`` and the user-cap impl
    #    method does ``self.out.println(msg)`` exercises Stdio at
    #    runtime even though Stdio isn't named in the signature;
    #    pre-fix the manifest claimed Stdio was provably excluded.
    #    The reachability map gives the conservative closed-world
    #    bound: union over all in-scope impls of caps each impl
    #    can transitively reach. The function's effective declared
    #    set for the exclusion subtraction is its named caps plus
    #    that reachable set; surface the union separately as
    #    ``transitively_reachable_capabilities`` so auditors can
    #    see *why* a cap is or isn't excluded.
    extra_caps, sig_unprovable = caps_reachable_via_sig(
        fn, container=container, reachable=reachable, unprovable=unprovable,
    )
    extra_caps_demangled = {_demangle(c)[0] for c in extra_caps}
    if "Unsafe" in extra_caps_demangled:
        # Unsafe reachable via an impl is the same regulatory risk
        # as Unsafe in the signature: the escape hatch is in play.
        has_unsafe = True

    transitively_reachable: list[str] = sorted(
        set(declared_caps) | extra_caps_demangled
    )

    if has_unsafe or has_fun_in_sig or sig_unprovable:
        provably_excluded_caps: list[str] = []
    else:
        # Compare in the demangled namespace so non-pub imported
        # capability types (loader-prefixed ``_capa_m{N}__Foo``)
        # don't appear in the regulator-facing exclusion list
        # (audit slice 20, 2026-05-29).
        declared_set = set(transitively_reachable)
        cap_names_demangled = {_demangle(n)[0] for n in cap_names}
        provably_excluded_caps = sorted(cap_names_demangled - declared_set)
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
        "return_type": _demangle_type_text(_ty_text(fn.return_type)) if fn.return_type else "()",
        "declared_capabilities": declared_caps,
        "transitively_reachable_capabilities": transitively_reachable,
        "provably_excluded_capabilities": provably_excluded_caps,
        "has_unsafe": has_unsafe,
        "attributes": attrs,
        "calls": calls,
    }
