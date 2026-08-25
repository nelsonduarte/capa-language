"""Wasm / Component Model / WASI execution path for the Capa CLI.

``run_execute`` is the tail of ``_main_dispatch`` that handles running
or emitting a Wasm artifact: the foreign-component gating, the
``--wasm-memory-cap`` bound, the ``--wasi`` / ``--preopen`` /
``--allow-host`` guards, the prefer-wasm auto-run, and the
``--wasm`` build / run / --output pipeline (core module or Component
Model component, with the experimental WASI embed). It reads the
small :class:`~capa.cli._ctx.ExecCtx` core slice (never the emitter
state), returns an int on every handled branch, and returns None to
let ``_main_dispatch`` fall through to the Python transpile / run path.

It imports the leaf modules and ``capa.*``; never :mod:`capa.cli`
(``__init__``). The vendored-WASI anchor in ``_wrap_as_component`` is
``capa.__file__``-based, so it resolves to ``capa/wasi_wit/deps``
unchanged from its new home.
"""

import os
import sys
from pathlib import Path

import capa
from capa import analyze
from capa.cli._ctx import ExecCtx
from capa.cli._diagnostics import C
from capa.cli._grants import (
    _parse_preopen_spec, _classify_internal_ip, _AllowHostSpecError,
    _normalize_allow_hosts,
)
from capa.cli._parser import _WASM32_MAX_PAGES
from capa.cli.subcommands import _wasm_tooling_available


def run_execute(ctx: ExecCtx) -> int | None:
    """Run or emit the Wasm/component artifact for this invocation.

    Returns the process exit code when this path handles the command
    (a Wasm run / --output / --transpile WAT, or a rejection), or None
    when nothing here applies and the caller should continue."""
    # Feature #4 (F2a): a program that actually INVOKES a typed foreign
    # component. --check / --manifest / the SBOM emitters work fully and
    # have already returned above. A SCALAR foreign call (Int / Bool /
    # Float crossing types) now runs end-to-end on the Wasm backend: the
    # core module imports ``capa:foreign/<component>`` and the host
    # dispatches into a sandboxed child sub-component that physically
    # cannot exceed the declared capability set. The remaining paths are
    # guarded here with clear, actionable errors:
    #   - a String or aggregate crossing type is not yet marshalled at
    #     runtime (feature #4 F2b) -- clean error on any backend;
    #   - the Python backend cannot sandbox a foreign component, so a
    #     foreign call requires the Wasm backend (--wasm);
    #   - the Component Model (--component) wrapping path does not yet
    #     carry foreign imports; F2a runs on the core --wasm path.
    # The bare DECLARATION is inert, so a program that only DECLARES a
    # foreign component (and never calls one) runs normally.
    if (ctx.args.run or ctx.args.wasm or ctx.args.transpile
            or getattr(ctx.args, "output", None)):
        from capa.foreign import (
            extern_component_names, extern_components, foreign_call_sites,
            foreign_method_rejection,
        )

        def _foreign_err(_msg: str) -> None:
            if ctx.use_color:
                print(f"{C.RED}{_msg}{C.RESET}", file=sys.stderr)
            else:
                print(_msg, file=sys.stderr)

        _foreign_sites = foreign_call_sites(
            ctx.module, extern_component_names(ctx.module),
        )
        if _foreign_sites:
            _ec_by_name = {ec.name: ec for ec in extern_components(ctx.module)}
            # F2a/F2b/F2c marshal scalar (Int / Bool / Float) and String
            # crossing types plus NESTED, non-self-referential aggregates
            # of struct / List / tuple / Option / Result / sum. Two shapes
            # still cannot cross and reject with a SPECIFIC message: a
            # ``Map`` (different, String-keyed structure) and a
            # self-referential (recursive) type (would need
            # named-recursive WIT machinery). The typed boundary stays
            # fully checked (--check) and recorded in the SBOM
            # (--manifest) for a rejected call.
            for _comp, _method, _fpos in _foreign_sites:
                _ec = _ec_by_name.get(_comp)
                _msig = (
                    next((m for m in _ec.methods if m.name == _method), None)
                    if _ec is not None else None
                )
                if _msig is None:
                    continue
                _reason = foreign_method_rejection(_msig, ctx.module)
                if _reason is not None:
                    _foreign_err(
                        f"capa: foreign call {_comp}.{_method} at line "
                        f"{_fpos.line}:{_fpos.col} {_reason} The typed "
                        "boundary is still fully checked (--check) and "
                        "recorded in the SBOM (--manifest)."
                    )
                    return 1
            # The Wasm sandbox is what makes the declared bound SOUND; the
            # Python backend cannot physically confine a foreign component.
            if not ctx.args.wasm:
                _comp, _method, _fpos = _foreign_sites[0]
                _foreign_err(
                    f"capa: this program invokes a foreign component "
                    f"({_comp}.{_method} at line {_fpos.line}:{_fpos.col}); "
                    "foreign components require the Wasm backend (--wasm), "
                    "whose sandbox physically confines the component to the "
                    "declared capabilities. The Python backend cannot sandbox "
                    "it, so a foreign call is unsupported there."
                )
                return 1
            # F2a runs on the core --wasm path; the --component wrapping
            # path does not yet carry the capa:foreign imports.
            if getattr(ctx.args, "component", False):
                _comp, _method, _fpos = _foreign_sites[0]
                _foreign_err(
                    f"capa: this program invokes a foreign component "
                    f"({_comp}.{_method} at line {_fpos.line}:{_fpos.col}); "
                    "foreign-component calls run on the core --wasm path, not "
                    "the --component wrapping path yet (feature #4 F2a). Drop "
                    "--component."
                )
                return 1

    # Auto-prefer the Wasm pipeline when --prefer-wasm or the
    # CAPA_PREFER_WASM env var is set AND the user did not pass
    # --wasm explicitly AND the Wasm toolchain is available
    # (wasmtime importable + wasm-tools on PATH). Any failure
    # (UnsupportedInIR, WasmEmissionError, missing tool, wasmtime
    # trap) falls back silently to the Python pipeline below.
    prefer_wasm = (
        ctx.args.prefer_wasm
        or os.environ.get("CAPA_PREFER_WASM") == "1"
    )
    # Audit H1 (2026-05): translate the CLI's ``--wasm-memory-cap``
    # to the (page-count | None) shape the emitter wants. ``0``
    # opts out of the cap; any positive int is the limit; absence
    # falls back to the emitter's default.
    if ctx.args.wasm_memory_cap is None:
        wasm_memory_cap: int | None = ...  # type: ignore[assignment]
    elif ctx.args.wasm_memory_cap <= 0:
        wasm_memory_cap = None
    elif ctx.args.wasm_memory_cap > _WASM32_MAX_PAGES:
        # wasm32 caps linear memory at 65536 64KiB pages (4 GiB). A
        # larger value produces a module wasm-tools rejects, which we
        # used to write to disk with a success message + exit 0 (audit
        # slice 30 P2-b). Reject it up front.
        print(
            f"capa: --wasm-memory-cap must be between 1 and "
            f"{_WASM32_MAX_PAGES} pages (wasm32 caps linear memory at "
            f"4 GiB); got {ctx.args.wasm_memory_cap}",
            file=sys.stderr,
        )
        return 2
    else:
        wasm_memory_cap = ctx.args.wasm_memory_cap

    # ``--wasi`` only has an effect on the Wasm Component Model path: it
    # rewrites the WIT world and the component's imports to reference the
    # canonical wasi:random / wasi:clocks packages. Passed without
    # ``--wasm`` it would hit the pure-Python backend, which ignores it
    # entirely; that silent no-op masked typos / wrong invocations. Reject
    # it up front with an actionable message. (The companion
    # ``--wasi`` requires ``--component`` guard lives in the Wasm branch.)
    if bool(getattr(ctx.args, "wasi", False)) and not ctx.args.wasm:
        msg = (
            "capa: --wasi requires --wasm --component (WASI mode only "
            "applies to the Wasm Component Model path; it has no effect "
            "on the default capa:host / pure-Python backend)"
        )
        if ctx.use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    # ``--preopen`` (layer b1) is meaningful in --wasi mode (the
    # operator-declared filesystem grant that unblocks dynamic Fs paths)
    # AND when emitting an SBOM / manifest (it records the same grant as
    # operator-declared authority, distinct from the derived surface).
    # Reject it on any OTHER invocation with an actionable message rather
    # than silently ignore it.
    _emitting_sbom = bool(
        getattr(ctx.args, "manifest", False)
        or getattr(ctx.args, "manifest_digest", False)
        or getattr(ctx.args, "cyclonedx", False)
        or getattr(ctx.args, "spdx", False)
    )
    if (getattr(ctx.args, "preopen", None)
            and not bool(getattr(ctx.args, "wasi", False))
            and not _emitting_sbom):
        msg = (
            "capa: --preopen requires --wasi (or an SBOM / --manifest "
            "command): it is the operator-declared filesystem grant for "
            "the WASI mode, recorded in the SBOM; it has no effect on the "
            "default execution backend"
        )
        if ctx.use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    # ``--allow-host`` (the Net analogue of --preopen) is meaningful in
    # --wasi mode (the operator-declared Net grant that unblocks a dynamic
    # URL) AND when emitting an SBOM / manifest (it records the same grant
    # as operator-declared authority). Reject it on any OTHER invocation
    # with an actionable message, mirroring --preopen.
    if (getattr(ctx.args, "allow_host", None)
            and not bool(getattr(ctx.args, "wasi", False))
            and not _emitting_sbom):
        msg = (
            "capa: --allow-host requires --wasi (or an SBOM / --manifest "
            "command): it is the operator-declared Net grant for the WASI "
            "mode, recorded in the SBOM; it has no effect on the default "
            "execution backend"
        )
        if ctx.use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    if (
        ctx.args.run and not ctx.args.wasm and prefer_wasm
        and _wasm_tooling_available()
    ):
        if ctx.result is None:
            ctx.result = analyze(ctx.module, source=ctx.source, filename=ctx.filename)
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost
        # The silent fallback covers exactly one thing: the Wasm
        # backend cannot COMPILE this program (a construct outside the
        # Phase-6 subset). That is what ``--prefer-wasm`` promises to
        # absorb, and it is safe because nothing has executed yet.
        #
        # It used to wrap ``run_main`` too, under one bare
        # ``except Exception: pass``. Two things were wrong with that.
        # A capability-discipline refusal (``CapBindingError``, or the
        # ``CapHandleError`` a forged binding now raises) was swallowed
        # and the program re-run on the Python pipeline with FULL
        # authority: fail-open in the one mode whose point is to fail
        # closed. And a failure PART-WAY through a run was retried from
        # the top, so whatever the first attempt had already written
        # happened twice. Once execution starts, failures are loud.
        try:
            blob = compile_wasm(
                ctx.module, types=ctx.result.types,
                bindings=ctx.result.bindings,
                memory_cap_pages=wasm_memory_cap,
                filename=ctx.filename,
            )
        except Exception:
            blob = None
        if blob is not None:
            WasmHost(args=ctx.program_args).run_main(blob)
            return 0

    if ctx.args.wasm and (ctx.args.transpile or ctx.args.run or ctx.args.output):
        # Wasm pipeline: AST -> CIR -> WAT -> binary -> (wasmtime
        # | file | component). Failures are loud (no fallback to
        # Python) so coverage gaps in the Wasm backend surface as
        # actionable errors rather than silent shape changes.
        from capa.ir import compile_wat, compile_wasm, compile_wit
        from capa.ir import (
            MainReturnTypeUnsupported, check_main_return_type,
            ComponentExportUnsupported, check_component_exports,
        )
        # Experimental WASI mode is only meaningful for the component
        # path (it rewrites the WIT world + the component imports);
        # ``--transpile`` shows the WAT, which carries the wasi:*
        # imports too, so it is allowed. A bare ``--wasm --output``
        # core module, or ``--wasm --run`` on the core host, would
        # produce wasi:* imports nothing satisfies, so reject early
        # with an actionable message instead of a late link failure.
        wasi_mode = bool(getattr(ctx.args, "wasi", False))
        if wasi_mode and not ctx.args.component and not ctx.args.transpile:
            msg = (
                "capa: --wasi requires --component (the WASI mode "
                "rewrites the Component Model world; the bare core "
                "ctx.module / core host has no WASI provider)"
            )
            if ctx.use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # WASI Fs layer b1: parse the operator ``--preopen``. b1 supports a
        # SINGLE preopen for dynamic-path resolution; reject more than one
        # with a clear message rather than silently picking one. The
        # presence of a preopen is the signal (``wasi_dynamic_fs``) that
        # suppresses the compiler's dynamic-Fs-path rejection, and the
        # parsed ``(host_dir, read_write)`` is the host grant.
        fs_operator_preopen = None
        wasi_dynamic_fs = False
        preopen_specs = getattr(ctx.args, "preopen", None) or []
        if preopen_specs:
            if len(preopen_specs) > 1:
                msg = (
                    "capa: --preopen: this increment (b1) supports a "
                    "single --preopen for dynamic Fs paths; got "
                    f"{len(preopen_specs)}"
                )
                if ctx.use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            fs_operator_preopen = _parse_preopen_spec(preopen_specs[0])
            wasi_dynamic_fs = True
        # Net operator grant (--allow-host, 2026-07-05): parse + normalize
        # each granted host through the SAME normalizer the guest gate uses
        # (capa.ir._net_host.normalize_host), so the operator's spelling and
        # the URL host land on the same allowlist key. Unlike --preopen this
        # is REPEATABLE (an allowlist is a set). The presence of any grant is
        # the signal (``net_operator_allow``) that suppresses the compiler's
        # dynamic-URL Net rejection; the normalized set is unioned into the
        # guest-side host ceiling the emitter materialises.
        from capa.ir._net_host import NetGrant
        net_operator_allow_hosts: NetGrant = NetGrant()
        net_operator_allow = False
        allow_host_specs = getattr(ctx.args, "allow_host", None) or []
        if allow_host_specs:
            try:
                net_operator_allow_hosts, _bad_hosts = _normalize_allow_hosts(
                    allow_host_specs,
                )
            except _AllowHostSpecError as e:
                msg = f"capa: --allow-host: {e}"
                if ctx.use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            if _bad_hosts:
                msg = (
                    "capa: --allow-host: could not parse a host from "
                    + ", ".join(repr(b) for b in _bad_hosts)
                    + " (expected a bare host, host:port, or a URL, "
                    "optionally with a :get / :post method suffix)"
                )
                if ctx.use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            net_operator_allow = bool(net_operator_allow_hosts)
            # SSRF footgun warning (warn, do NOT block, 2026-07-05): an
            # operator may have a legitimate reason to grant an internal
            # address, but granting one via a DYNAMIC URL is the classic
            # SSRF sink, so it is called out loudly on stderr.
            for _h in sorted(net_operator_allow_hosts.all_hosts):
                _kind = _classify_internal_ip(_h)
                if _kind is not None:
                    warn = (
                        f"capa: WARNING: --allow-host {_h} grants a {_kind} "
                        "address; this is usually an SSRF risk"
                    )
                    if ctx.use_color:
                        print(f"{C.YELLOW}{warn}{C.RESET}", file=sys.stderr)
                    else:
                        print(warn, file=sys.stderr)
        if ctx.result is None:
            ctx.result = analyze(ctx.module, source=ctx.source, filename=ctx.filename)
        # Component path only: validate ``main``'s return type BEFORE
        # ``compile_wasm``. A String / composite (Struct / Sum / List /
        # Map / tuple / ...) return on ``main`` cannot be lifted into
        # the WIT world export; without this early gate the core
        # emitter would die first with a cryptic wasm-tools dump (a
        # Struct-returning ``main`` lowers to ``return_call $Struct``
        # the module has no function for), never reaching the clean
        # ``compile_wit`` error. Running the check here makes both the
        # ``--output`` and ``--run`` component paths surface the
        # actionable ``capa: --wasm: main returning '<ty>' is not
        # supported ...`` diagnostic + exit 1 instead. Scalars / Unit
        # pass silently; the non-component path is untouched.
        if ctx.args.component:
            try:
                check_main_return_type(ctx.module, types=ctx.result.types)
                # Same early gate for ``@export`` functions: an
                # unsupported name / signature surfaces here as the clean
                # Capa diagnostic instead of dying later in the component
                # wrap step (mirrors the ``main`` return check above).
                check_component_exports(ctx.module, types=ctx.result.types)
            except (MainReturnTypeUnsupported,
                    ComponentExportUnsupported) as e:
                msg = f"capa: --wasm: {e}"
                if ctx.use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
        try:
            if ctx.args.transpile:
                wat = compile_wat(
                    ctx.module, types=ctx.result.types,
                    bindings=ctx.result.bindings,
                    memory_cap_pages=wasm_memory_cap,
                    filename=ctx.filename,
                    wasi=wasi_mode,
                    wasi_dynamic_fs=wasi_dynamic_fs,
                    net_operator_allow_hosts=net_operator_allow_hosts,
                )
                print(wat)
                return 0
            blob = compile_wasm(
                ctx.module, types=ctx.result.types,
                bindings=ctx.result.bindings,
                memory_cap_pages=wasm_memory_cap,
                filename=ctx.filename,
                wasi=wasi_mode,
                wasi_dynamic_fs=wasi_dynamic_fs,
                net_operator_allow_hosts=net_operator_allow_hosts,
            )
        except Exception as e:
            msg = f"capa: --wasm: {e}"
            if ctx.use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # --output: save the binary instead of running it. With
        # --component, wrap the core module in a Component Model
        # component first.
        if ctx.args.output:
            try:
                if ctx.args.component:
                    blob = _wrap_as_component(
                        blob,
                        compile_wit(
                            ctx.module, types=ctx.result.types, wasi=wasi_mode,
                        ),
                        wasi=wasi_mode,
                    )
                Path(ctx.args.output).write_bytes(blob)
                kind = "component" if ctx.args.component else "core ctx.module"
                print(
                    f"capa: --wasm: wrote {kind} ({len(blob)} bytes) to {ctx.args.output}",
                    file=sys.stderr,
                )
                return 0
            except Exception as e:
                print(f"capa: --wasm: {e}", file=sys.stderr)
                return 1
        # --run path: assemble and execute on a wasmtime host.
        # ``--component --run`` wraps the core module in a
        # Component Model component first and dispatches to the
        # component-aware host (different lift/lower semantics,
        # see capa.runtime._wasm_component_host).
        host = None
        try:
            if ctx.args.component:
                from capa.runtime._wasm_component_host import (
                    WasmComponentHost,
                )
                component_blob = _wrap_as_component(
                    blob,
                    compile_wit(
                        ctx.module, types=ctx.result.types, wasi=wasi_mode,
                    ),
                    wasi=wasi_mode,
                )
                # WASI Env Level 1 (2026-06-27): when --wasi is active,
                # compute the program's static Env read ceiling and hand
                # it to the host. A CLOSED ceiling (every env.get key is
                # a string literal) maps to a restricted WASI env-set,
                # so the component never receives a variable outside the
                # ceiling (closes the leak-by-default). A non-closed
                # ceiling (a dynamic env.get key) makes the host fall
                # back to inherit_env (Level 2). The default capa:host
                # path passes no ceiling and is unaffected.
                env_ceiling = None
                fs_ceiling = None
                net_ceiling = None
                if wasi_mode:
                    from capa.ir import (
                        compute_env_ceiling, compute_fs_ceiling,
                        compute_net_ceiling, collect_used_capabilities,
                    )
                    env_ceiling = compute_env_ceiling(
                        ctx.module, types=ctx.result.types,
                    )
                    # WASI Fs Phase 0 (2026-06-27): the static Fs
                    # preopen ceiling drives the host's preopen_dir
                    # registration (parents of every literal Fs path,
                    # with READ_WRITE for mutating dirs). A non-closed
                    # ceiling (dynamic path) yields no preopens
                    # (fail-closed); the compiler already rejected such
                    # a program in --wasi mode. The default capa:host
                    # path passes no ceiling and is unaffected.
                    fs_ceiling = compute_fs_ceiling(
                        ctx.module, types=ctx.result.types,
                    )
                    # WASI Net (2026-06-28 Phase 1 / Phase 2): compute the
                    # static Net host ceiling ONLY when the program uses a
                    # Net REQUEST op (get or post). Passing it to the host is
                    # the signal to link wasi:http (the FFI receipt); a
                    # program with no request op keeps net_ceiling None so
                    # wasi:http is never linked (a clean total deny, and it
                    # avoids the C-API context panic). A Net program that
                    # only narrows / queries (restrict_to / allows, Phase 3)
                    # builds no outgoing request, so it needs no wasi:http
                    # either. The ceiling is enforced guest-side (codegen);
                    # the host records it for inspection only.
                    # ``collect_used_capabilities`` walks the CIR, so lower
                    # the AST module first (the same lowering
                    # ``compute_net_ceiling`` uses).
                    from capa.ir._lower import Lowerer
                    cir_for_caps = Lowerer(
                        types=ctx.result.types or {},
                    ).lower_module(ctx.module)
                    used_caps = collect_used_capabilities(cir_for_caps)
                    net_request_ops = used_caps.get("Net", set())
                    if "get" in net_request_ops or "post" in net_request_ops:
                        net_ceiling = compute_net_ceiling(
                            ctx.module, types=ctx.result.types,
                        )
                host = WasmComponentHost(
                    args=ctx.program_args,
                    wasi=wasi_mode,
                    env_ceiling=env_ceiling,
                    fs_ceiling=fs_ceiling,
                    fs_operator_preopen=fs_operator_preopen,
                    net_ceiling=net_ceiling,
                )
                host.run_main(component_blob)
            else:
                from capa.runtime._wasm_host import WasmHost
                # Pass the user-visible program args (everything
                # after ``--`` on the CLI) through to the host so
                # env.args inside the wasm module sees the same
                # values it would see under --run on the Python
                # path.
                host = WasmHost(args=ctx.program_args)
                # Feature #4 (F2a): register the typed foreign-component
                # imports BEFORE instantiation so the host can dispatch
                # each ``capa:foreign/<component>`` call into a sandboxed
                # child sub-component. Artifact paths are resolved
                # relative to the source file.
                from capa.foreign import foreign_runtime_methods
                _foreign_methods = foreign_runtime_methods(ctx.module)
                if _foreign_methods:
                    _base = os.path.dirname(os.path.abspath(ctx.filename))
                    for _m in _foreign_methods:
                        _art = _m["artifact"]
                        if not os.path.isabs(_art):
                            _art = os.path.normpath(
                                os.path.join(_base, _art)
                            )
                        _m["artifact"] = _art
                    # Feature #4 hardening: tune the untrusted-child
                    # resource ceiling from the CLI. A given flag is
                    # None when absent (keep the generous default); 0
                    # opts out of that bound; a positive value sets it.
                    # --foreign-memory-cap is MiB, converted to bytes.
                    _mem_cap_bytes = (
                        None
                        if ctx.args.foreign_memory_cap is None
                        else ctx.args.foreign_memory_cap * 1024 * 1024
                    )
                    _result_cap_bytes = (
                        None
                        if ctx.args.foreign_result_cap is None
                        else ctx.args.foreign_result_cap * 1024 * 1024
                    )
                    host.configure_foreign_limits(
                        fuel=ctx.args.foreign_fuel,
                        memory_cap_bytes=_mem_cap_bytes,
                        result_cap_bytes=_result_cap_bytes,
                    )
                    host.register_foreign_methods(_foreign_methods)
                host.run_main(blob)
            return 0
        except Exception as e:
            # A deliberate ``panic`` aborts via the guest's
            # ``unreachable``, which surfaces here as a wasmtime
            # trap. The panic host import already wrote the canonical
            # ``panic: <message>`` line to stderr and set
            # ``host.panicked``; in that case exit non-zero WITHOUT a
            # host traceback, matching the Python backend's clean
            # abort. A genuine runtime trap (out-of-bounds access,
            # integer divide-by-zero, ...) leaves ``panicked`` False
            # and still gets the full traceback, since those point at
            # real defects worth surfacing.
            if host is not None and getattr(host, "panicked", False):
                return 1
            # Feature #4 (F2a): a ForeignDenied is an EXPECTED, actionable
            # sandbox outcome -- the child sub-component imported a
            # capability the call did not grant (structural host-enforced
            # cap-set deny), or its artifact was missing / malformed. It
            # surfaces here wrapped in the wasmtime trap that unwound the
            # foreign import; walk the cause chain and print it cleanly
            # (like a capa diagnostic) instead of a host traceback.
            # A WasmHostError is likewise an EXPECTED, actionable host
            # outcome -- e.g. the parent's ``$alloc`` returned 0 (out of
            # memory) while writing a foreign call's returned aggregate
            # back into the caller's linear memory (feature #4 F2c). It is
            # memory-safe and bounded (the host refuses to write at address
            # 0); surface it as a clean capa diagnostic rather than a host
            # traceback, so a malformed / oversized child return reads as a
            # bounded failure, not a crash.
            from capa.runtime._foreign import ForeignDenied
            from capa.runtime._wasm_host import WasmHostError
            _cur = e
            _seen: set[int] = set()
            while _cur is not None and id(_cur) not in _seen:
                _seen.add(id(_cur))
                if isinstance(_cur, (ForeignDenied, WasmHostError)):
                    _fmsg = f"capa: {_cur}"
                    if ctx.use_color:
                        print(f"{C.RED}{_fmsg}{C.RESET}", file=sys.stderr)
                    else:
                        print(_fmsg, file=sys.stderr)
                    return 1
                _cur = _cur.__cause__ or _cur.__context__
            import traceback
            traceback.print_exc(file=sys.stderr)
            return 1



def _wrap_as_component(
    core_wasm: bytes, wit_text: str, *, wasi: bool = False,
) -> bytes:
    """Wrap a core Wasm module in a Component Model component by
    shelling out to ``wasm-tools component embed`` + ``component new``.
    Returns the bytes of the resulting .wasm component, which embeds
    the WIT world and declares the capability interfaces as imports.

    The two-step embed/new flow is what wasm-tools uses canonically:
    embed encodes the WIT metadata into the core module as a custom
    section; new then promotes that core module to a CM component.
    Both steps require ``wasm-tools`` on PATH.

    ``wasi`` (experimental, 2026-06-27): when True, the program world
    references the canonical ``wasi:random`` / ``wasi:clocks`` packages
    for the migrated Random / Clock touch-points. ``embed`` resolves
    those package references from a ``deps/`` directory; we vendor a
    minimal subset of the official WASI Preview 2 WIT in
    ``capa/wasi_wit`` and copy it next to the generated world so the
    embed succeeds offline. The default (False) path is unchanged.
    """
    import subprocess
    import shutil
    import tempfile
    from pathlib import Path as _Path
    with tempfile.TemporaryDirectory() as td:
        td_path = _Path(td)
        # In WASI mode the WIT is a directory (the world plus a
        # vendored ``deps/`` the embed resolves wasi:* from); in the
        # default mode it is a single self-contained file.
        if wasi:
            wit_dir = td_path / "wit"
            wit_dir.mkdir()
            (wit_dir / "program.wit").write_text(wit_text, encoding="utf-8")
            vendored = _Path(capa.__file__).resolve().parent / "wasi_wit" / "deps"
            shutil.copytree(vendored, wit_dir / "deps")
            wit_arg = str(wit_dir)
        else:
            wit_path = td_path / "capa.wit"
            wit_path.write_text(wit_text, encoding="utf-8")
            wit_arg = str(wit_path)
        core_path = td_path / "core.wasm"
        embed_path = td_path / "embed.wasm"
        comp_path = td_path / "component.wasm"
        core_path.write_bytes(core_wasm)
        # embed: stamp the WIT world into the core module.
        embed = subprocess.run(
            [
                "wasm-tools", "component", "embed",
                "--world", "program", wit_arg, str(core_path),
                "-o", str(embed_path),
            ],
            capture_output=True, check=False,
        )
        if embed.returncode != 0:
            raise RuntimeError(
                f"wasm-tools component embed failed:\n"
                f"{embed.stderr.decode('utf-8', errors='replace')}"
            )
        # new: promote to a CM component.
        new = subprocess.run(
            [
                "wasm-tools", "component", "new",
                str(embed_path), "-o", str(comp_path),
            ],
            capture_output=True, check=False,
        )
        if new.returncode != 0:
            raise RuntimeError(
                f"wasm-tools component new failed:\n"
                f"{new.stderr.decode('utf-8', errors='replace')}"
            )
        return comp_path.read_bytes()
