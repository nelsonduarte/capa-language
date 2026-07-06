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

import hashlib
import re
from pathlib import Path
from typing import Any, Optional

from .. import capa_ast as A
from ..lexer import SYNTHETIC_FILENAME
from ..typesys import CAPABILITY_NAMES

from ._calls import _collect_calls, _collect_declassifications
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
# a type-text string (``List<_capa_m1__Foo>``) - anchored at a
# word boundary so it doesn't munge unrelated names. The optional
# ``sel__`` group is the selective-import infix (see ``_SEL_RE``)
# stamped on a pub item the importer did NOT select; it is dropped
# alongside the module prefix.
_MANGLE_INLINE_RE = re.compile(r"\b_capa_m\d+__(?:sel__)?([A-Za-z_]\w*)")
# Selective-import infix: when ``import foo (X, Y)`` does NOT select a
# pub item, the loader renames it ``_capa_m{N}__sel__<Name>`` (see
# ``capa/loader.py``). After the outer module prefix is stripped the
# ``sel__`` infix remains; strip it too so the regulator-facing SBOM
# shows the source-level ``Name`` (e.g. ``Logger``, never
# ``sel__Logger``). Over-naming, not hiding, but a name-based gate on
# ``Logger`` would still miss the prefixed form.
_SEL_RE = re.compile(r"^sel__(.+)$")


def _display_path(decl_file: str, root_filename: str) -> str:
    """Root-relative, separator-stable display form of a declaration's
    source path.

    The loader lexes every imported module under its *resolved
    absolute* path, so a raw ``fn.pos.filename`` would stamp the
    builder machine's directory layout (and username) into every
    surface that displays the manifest ``pos``: the manifest itself,
    CycloneDX ``capa:pos``, SPDX annotations, docgen and ``capa
    migrate``. For the normal self-contained project -- every source
    file under the root file's directory, vendored modules included --
    the path is therefore recorded relative to that directory, in
    POSIX form (``/`` separators on every OS), so the same project
    produces identical audit artefacts on Windows and Linux and on any
    two builders' machines.

    A file that resolves OUTSIDE the root file's directory (e.g. a
    module found via ``CAPA_PATH``) keeps its path exactly as lexed:
    there is no stable base to relativise against, and "this code came
    from outside the project tree" is information the auditor wants.
    """
    if not decl_file or not root_filename:
        return decl_file
    try:
        root_dir = Path(root_filename).resolve().parent
        rel = Path(decl_file).resolve().relative_to(root_dir)
    except (ValueError, OSError):
        # ValueError: not under the root directory. OSError: a path
        # the OS cannot resolve (synthetic placeholder names).
        return decl_file
    return rel.as_posix()


def display_filename(filename: str) -> str:
    """Display form of the root filename itself.

    The CLI hands the builders the root path exactly as the user
    typed it (absolute or relative, native separators), so the
    manifest's top-level ``filename`` field -- and every
    deterministic identifier seeded from it: the CycloneDX
    ``serialNumber``, the SPDX ``documentNamespace``, the provenance
    ``invocationId`` -- used to vary with the invocation style and
    leak the builder machine's directory layout. Routing the root
    through the same relativisation as the per-function ``pos``
    (for the root file that is its basename) makes two builders on
    different machines, or two invocation styles on the same
    machine, produce byte-identical artefacts modulo timestamps.
    Synthetic placeholders (the lexer's ``<input>``) pass through
    unchanged, exactly as they do for ``pos``.
    """
    return _display_path(filename, filename)


def program_source_digest(
    filename: str,
    source: Optional[str],
    sources: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Single sha256 covering ALL source files of the linked program.

    Audit 2026-06-17: the provenance subject and the CycloneDX /
    SPDX identifier seeds historically digested ONLY the root file.
    A program whose capability surface lives in an IMPORTED module
    could have that module rewritten (capabilities changed) while
    the root stayed byte-identical, leaving the attestation subject
    digest, the CDX ``serialNumber`` and the SPDX
    ``documentNamespace`` UNCHANGED -- so a verifier accepted a
    program whose imported modules had been swapped.

    When ``sources`` (the loader's path -> text map for every linked
    module) is given, the digest covers every module: it is
    ``sha256`` over a canonical, deterministically ORDERED join of
    ``<display_path>\\n<sha256(text)>`` lines, one per file, sorted by
    display path. Ordering by the machine-stable display path (POSIX,
    root-relative) keeps the result byte-reproducible across machines
    and invocation styles, so two builds of the same multi-file input
    produce identical SBOMs and SOURCE_DATE_EPOCH still governs only
    timestamps.

    A SINGLE-FILE program is digested as the bare ``sha256(text)`` of
    its one source, byte-identical to the pre-2026-06-17 behaviour, so
    its serialNumber / documentNamespace / invocationId never move.
    This holds whether the caller passes no ``sources`` map at all
    (library callers) or -- as the CLI always does -- a one-entry map
    whose single file IS the root (a program with no imports): the CLI
    unconditionally forwards ``linked.sources``, which for an
    import-free program contains exactly the root, and the multi-file
    ``<display>\n<sha256(text)>`` join would otherwise silently change
    every single-file program's identifiers (audit 2026-06-17). The
    multi-file join is taken only when more than one module is linked.
    With no ``sources`` and no ``source``, returns ``None``.
    """
    if sources and not _is_single_root(sources, filename):
        lines: list[str] = []
        for path, text in sources.items():
            disp = _display_path(path, filename)
            lines.append(f"{disp}\n{_sha256_text(text)}")
        joined = "\n".join(sorted(lines))
        return _sha256_text(joined)
    if sources:
        # One linked file that is the root: bare single-file digest.
        (only_text,) = sources.values()
        return _sha256_text(only_text)
    if source is not None:
        return _sha256_text(source)
    return None


def _is_single_root(sources: dict[str, str], filename: str) -> bool:
    """True when ``sources`` holds exactly one file and that file is the
    root (an import-free program). Path comparison is by resolved
    absolute path so the loader's resolved keys match the CLI's raw
    ``filename`` argument; if resolution fails (synthetic placeholder
    names), a single-entry map is still treated as the root."""
    if len(sources) != 1:
        return False
    (only_path,) = sources.keys()
    try:
        return Path(only_path).resolve() == Path(filename).resolve()
    except OSError:
        return True


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identifier_seed(
    filename: str,
    source: Optional[str],
    sources: Optional[dict[str, str]] = None,
) -> str:
    """Seed string for the deterministic uuid5 identifiers
    (CycloneDX ``serialNumber``, the UUID component of the SPDX
    ``documentNamespace``, the provenance ``invocationId``).

    The display form alone would make two unrelated projects that
    share a root basename (every project called ``main.capa``)
    collide on the same identifier, so when source text is
    available the seed is ``<display>:<digest>``. ``digest`` covers
    EVERY linked module when the ``sources`` map is supplied (audit
    2026-06-17: rewriting an imported module must change the seed),
    falling back to the root source alone otherwise. Without any
    source (library callers that only hold the analysed module) the
    seed falls back to the display form alone.
    """
    display = display_filename(filename)
    digest = program_source_digest(filename, source, sources)
    if digest is None:
        return display
    return f"{display}:{digest}"


def _demangle(name: str) -> tuple[str, Optional[int]]:
    """Return ``(source_name, module_index)`` for a possibly-mangled
    identifier. ``module_index`` is None when the name carried no
    loader prefix (root-module item or pub-exported import)."""
    m = _MANGLE_RE.match(name)
    if m is None:
        return name, None
    source_name = m.group(2)
    sel = _SEL_RE.match(source_name)
    if sel is not None:
        source_name = sel.group(1)
    return source_name, int(m.group(1))


def _demangle_type_text(s: str) -> str:
    """Rewrite every mangled identifier inside a rendered
    ``_ty_text`` string back to its source-level form. Used so
    the manifest's per-param ``type`` fields read as the user
    wrote them rather than carrying the loader's
    ``_capa_m{N}__`` prefix from a non-pub imported type."""
    return _MANGLE_INLINE_RE.sub(r"\1", s)


def build_operator_declared_grants(
    preopens: Optional[list[dict[str, Any]]] = None,
    *,
    net_hosts: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Build the ``operator_declared_grants`` manifest block (WASI Fs
    layer b1, 2026-06-30; Net ``--allow-host``, 2026-07-05).

    This block records authority the OPERATOR declared at build / run
    time (e.g. ``--preopen <dir>``, ``--allow-host <host>``), as DISTINCT
    from the compiler-DERIVED capability surface that the rest of the
    manifest proves. A regulator MUST read it as Level-2 operator-DECLARED
    authority, NOT as program-proven: the compiler could not derive
    these grants (that is precisely why the operator had to declare
    them), so they are an explicit trust the operator placed in the
    deployment, not a property the type system established.

    ``preopens`` is a list of ``{"host_dir": str, "permission":
    "ro"|"rw", "kind": "fs"}`` entries; ``net_hosts`` is a list of
    ``{"kind": "net", "host": str, "access": "get"|"post"|"connect"}``
    entries (each an operator-granted Net host from ``--allow-host``). The
    ``access`` field records the method SCOPE of the grant (Phase 2,
    2026-07-06): ``"get"`` for a ``--allow-host h:get`` read-only grant,
    ``"post"`` for ``h:post``, and ``"connect"`` for a suffix-less
    ``--allow-host h`` (get+post). Either list may be None / empty when no
    grant of that kind was declared. The block is always present so a
    consumer can rely on its shape; empty lists mean "no operator grant was
    declared"."""
    return {
        # The honest label a regulator-facing consumer keys on: this is
        # NOT derived/proven authority.
        "trust_level": "operator-declared",
        "note": (
            "Authority declared by the operator at build/run time "
            "(e.g. --preopen, --allow-host). DISTINCT from the "
            "compiler-derived, program-proven capability surface; the "
            "compiler could not derive these grants."
        ),
        "preopens": list(preopens or []),
        "allow_hosts": list(net_hosts or []),
    }


def build_path_arg_surface(module: A.Module) -> dict[str, Any]:
    """Build the ``compiler_derived_path_arg_surface`` manifest block: the
    COMPILER-PROVEN facts about which ``argv`` (``env.args()``) arguments
    reach which Fs / Net / Env sinks, and whether the access is read or
    write (WASI Layer 1, 2026-06-30).

    This is a DERIVED / PROVEN-BY-CONSTRUCTION fact, the OPPOSITE trust
    level to ``operator_declared_grants``: the compiler PROVED, by a sound
    over-approximating static analysis, that these argv elements flow to
    these sinks. A regulator reads it as a machine-verifiable property of
    the program text, not as an operator's declared trust. Each entry is
    ``{"arg_index": int | "*", "capability": "Fs"|"Net"|"Env", "method":
    str, "access": "read"|"write"}``; ``arg_index`` is ``"*"`` when an argv
    element provably reaches the sink but which one is not statically
    determinate (the sound widening). The block is always present so the
    field shape is stable for consumers; an empty ``arguments`` list means
    "no argv argument was proven to reach any Fs / Net / Env sink"."""
    from ..ir._wasi_path_arg_surface import compute_path_arg_surface, ANY_INDEX
    surface = compute_path_arg_surface(module)
    arguments = [
        {
            "arg_index": "*" if f.arg_index is ANY_INDEX else f.arg_index,
            "capability": f.cap,
            "method": f.method,
            "access": f.access,
        }
        for f in surface.facts
    ]
    return {
        # The honest label a regulator-facing consumer keys on: this IS
        # compiler-derived / program-proven authority surface, DISTINCT
        # from the operator-declared grants.
        "trust_level": "compiler-derived",
        "note": (
            "argv (env.args()) arguments the compiler PROVED reach an Fs / "
            "Net / Env sink, and whether read or write. A sound "
            "over-approximation (no reaching argument omitted; arg_index "
            "'*' when the concrete index is not statically determinate). "
            "Closures are covered SOUND BY CONSTRUCTION: a closure whose "
            "parameter reaches a sink is reported at '*' UNLESS the compiler "
            "proves it is applied only locally to non-argv values -- so a "
            "closure that escapes its frame (returned, passed to a helper, "
            "stored in an aggregate, or reached through a match/if arm or a "
            "name bound to one) fails closed, with no per-shape enumeration. "
            "Scope is EXHAUSTIVELY covered: the statement traversal descends "
            "into EVERY sub-scope that holds sub-statements -- if/while/for "
            "statement blocks, match-arm blocks, and lambda bodies, "
            "at any nesting depth -- so a binding or sink in any sub-block "
            "(including a match-arm block) is never skipped (pinned by a meta-test "
            "over the AST node inventory). RESIDUAL (the one honest gap, "
            "VALUE-FLOW only): a closure carried by a value the AST-level "
            "pass cannot statically tie back to a lambda -- re-extracted from "
            "a runtime container by key, or threaded through an opaque "
            "computed value -- may be under-reported. This "
            "does NOT grant authority -- a dynamic Fs/Net path still "
            "fail-closes in --wasi without --preopen; it is an auditable "
            "fact, distinct from operator_declared_grants."
        ),
        "arguments": arguments,
    }


def build_manifest(
    module: A.Module,
    *,
    filename: str = "<input>",
    capa_version: Optional[str] = None,
    expr_labels: Optional[dict[int, str]] = None,
    operator_declared_grants: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Build a manifest dict from an analysed module.

    The dict is directly JSON-serialisable. The caller is expected to
    have run the analyser first; this builder does not re-validate
    attributes or types.

    ``expr_labels`` is the analyser's ``id(expr) -> label`` map
    (``AnalysisResult.expr_labels``). When supplied, the
    ``declassification_sites`` count records only genuine ``@secret ->
    @public`` bridges, dropping no-op declassifies of already-public
    values. When omitted, every syntactic declassify is counted (the
    historical, analysis-free behaviour).

    ``operator_declared_grants`` (WASI Fs layer b1, 2026-06-30): the
    block produced by :func:`build_operator_declared_grants` recording
    operator-DECLARED authority (e.g. ``--preopen``), clearly distinct
    from the derived surface. When None, an EMPTY grants block is
    recorded so the field shape is stable for consumers.
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
    # impls and cap-bearing struct field caps - not just what it
    # names in its signature. ``user_cap_names_mangled`` is the
    # analyzer-internal name set (loader-prefixed); the
    # reachability machinery stays in that namespace to line up
    # with ``ImplBlock.trait_name`` and ``TypeName.name``.
    user_cap_names_mangled: set[str] = cap_names - frozenset(CAPABILITY_NAMES)
    reachable, unprovable = compute_reachability(
        module, user_cap_names=user_cap_names_mangled,
    )

    # Roadmap S1: names of ``linear type`` structs, so per-function
    # records can flag must-consume params + obligations.
    linear_types: set[str] = {
        item.name for item in module.items
        if isinstance(item, A.TypeStruct) and getattr(item, "is_linear", False)
    }

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
                linear_types=linear_types,
                expr_labels=expr_labels,
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
                    linear_types=linear_types,
                    expr_labels=expr_labels,
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
        # Roadmap S2.5: program-wide count of auditable secret->public
        # declassification sites.
        "declassification_sites": sum(
            len(f["declassifications"]) for f in functions
        ),
    }

    # Roadmap S3: the protocols (typestates) the module declares, with
    # their ordered states. A regulator-facing record of the state
    # machines the program enforces by construction.
    protocol_states = [
        {
            "name": _demangle(item.name)[0],
            "states": list(item.states),
        }
        for item in module.items
        if isinstance(item, A.TypestateDecl)
    ]
    summary["protocol_states"] = len(protocol_states)

    return {
        "capa_version": capa_version,
        "schema_version": SCHEMA_VERSION,
        # Display form (root-relative, i.e. the basename for the root
        # file), never the raw CLI argument: the raw form varies with
        # the invocation style and embeds the builder's directory
        # layout, breaking artefact-level byte-reproducibility.
        "filename": display_filename(filename),
        "user_defined_capabilities": user_caps,
        "typestates": protocol_states,
        "functions": functions,
        # WASI Fs layer b1: operator-declared authority (e.g. --preopen),
        # honestly labelled Level-2 / operator-declared, distinct from the
        # derived surface above. Always present (empty when none declared).
        "operator_declared_grants": (
            operator_declared_grants
            if operator_declared_grants is not None
            else build_operator_declared_grants()
        ),
        # WASI Layer 1: compiler-DERIVED, program-PROVEN argv -> sink
        # surface, the opposite trust level to operator_declared_grants
        # above. Always present (empty ``arguments`` when nothing proven).
        "compiler_derived_path_arg_surface": build_path_arg_surface(module),
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
    linear_types: Optional[set[str]] = None,
    expr_labels: Optional[dict[int, str]] = None,
) -> dict[str, Any]:
    if reachable is None:
        reachable = {}
    if unprovable is None:
        unprovable = set()
    if linear_types is None:
        linear_types = set()
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
        # Roadmap S1: flag a must-consume (linear-typed) parameter so
        # the SBOM surfaces the obligation the caller transfers in.
        root_ty = _root_type_name(p.type_expr) if p.type_expr else None
        is_linear = root_ty in linear_types if root_ty else False
        param_records.append({
            "name": p.name,
            "type": ty_text,
            "consuming": p.consuming,
            "is_capability": is_cap,
            "is_linear": is_linear,
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

    # Roadmap S2.5: the auditable @secret -> @public bridges in this
    # function. Each entry is a deliberate disclosure with a stated
    # reason -- the regulator-facing record of where the program lets
    # secret data cross to a public sink.
    declassifications: list[dict[str, Any]] = []
    _collect_declassifications(
        fn.body, declassifications, expr_labels=expr_labels,
    )

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

    # Roadmap S1: the must-consume surface. ``linear_obligations``
    # lists the linear-typed parameters this function takes by
    # ``consume`` (it receives ownership and must consume/return them)
    # and whether the return type is itself linear (the function hands
    # an obligation back to its caller). Regulator-facing: "this
    # function takes ownership of resource handle X and must release
    # it" / "this function produces a handle the caller must release".
    linear_param_obligations = [
        p["name"] for p in param_records
        if p.get("is_linear") and p["consuming"]
    ]
    return_is_linear = (
        _root_type_name(fn.return_type) in linear_types
        if fn.return_type else False
    )

    # The declaration's own lexed filename, not the root file the
    # manifest was built for: in a linked multi-file program an
    # imported function's ``fn.pos`` carries the file it was actually
    # declared in (the loader lexes each module under its own path).
    # The ``filename`` argument only backs synthetic positions: an
    # empty string (built-ins, fallbacks) or the lexer's
    # ``SYNTHETIC_FILENAME`` placeholder for unnamed in-memory
    # sources. The display form is root-relative and separator-stable
    # (see :func:`_display_path`) so the recorded position never leaks
    # the builder's absolute directory layout.
    decl_file = fn.pos.filename
    if not decl_file or decl_file == SYNTHETIC_FILENAME:
        decl_file = filename
    decl_file = _display_path(decl_file, filename)

    return {
        "name": fn.name,
        "source_name": source_name,
        "container": container,
        "source_container": source_container,
        "source_module_index": module_index,
        "pos": f"{decl_file}:{fn.pos.line}:{fn.pos.col}",
        "is_pub": fn.is_pub,
        "doc": fn.doc,
        "params": param_records,
        "return_type": _demangle_type_text(_ty_text(fn.return_type)) if fn.return_type else "()",
        "declared_capabilities": declared_caps,
        "transitively_reachable_capabilities": transitively_reachable,
        "provably_excluded_capabilities": provably_excluded_caps,
        "linear_obligations": {
            "consumes": linear_param_obligations,
            "produces_linear": return_is_linear,
        },
        "has_unsafe": has_unsafe,
        "constant_time": any(a.name == "constant_time" for a in fn.attributes),
        "attributes": attrs,
        "calls": calls,
        "declassifications": declassifications,
    }
