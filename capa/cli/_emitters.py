"""Artifact-emitter branches for the Capa CLI.

Each ``emit_*`` function is one ``capa`` artifact mode (manifest, SBOM,
VEX, provenance, doc, WIT), factored out of ``_main_dispatch``. Every
function takes the shared :class:`~capa.cli._ctx.DispatchCtx` computed
once after analysis and reads ``ctx.<field>`` rather than free locals;
``ctx._file_root`` is the single file-root derivation and the writing
goes through the one :func:`capa._artifact_io.emit_artifact` sink.

It imports the leaf modules (``_ctx``, ``_diagnostics``, ``_floor``) and
``capa.*`` builders, but nothing from :mod:`capa.cli`; the dependency
runs one way, ``capa.cli`` -> ``capa.cli._emitters``.
"""

import sys

from capa._artifact_io import emit_artifact
from capa.docgen import build_html as build_doc_html
from capa.manifest import (
    build_manifest, build_cyclonedx, build_spdx,
    build_vex_document, build_provenance,
)
from capa.cli._ctx import DispatchCtx
from capa.cli._diagnostics import C
from capa.cli._floor import _enforce_floor_for_file_root

def emit_manifest(ctx: DispatchCtx) -> int:
    import json
    manifest = build_manifest(
        ctx.module, filename=ctx.filename,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        unaudited_secret_sinks=ctx.result.unaudited_secret_sinks,
    )
    emit_artifact(json.dumps(manifest, indent=2))
    return 0


def emit_manifest_digest(ctx: DispatchCtx) -> int:
    from capa.manifest import canonical_json, canonical_manifest
    manifest = build_manifest(
        ctx.module, filename=ctx.filename,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        unaudited_secret_sinks=ctx.result.unaudited_secret_sinks,
    )
    # Emit the canonical bytes verbatim (key-sorted, fixed
    # separators): what is printed is exactly what the digest in
    # the content_integrity envelope is taken over, minus the
    # envelope itself. Content-addressable and byte-reproducible.
    emit_artifact(canonical_json(canonical_manifest(manifest)))
    return 0


def emit_compose_sbom(ctx: DispatchCtx) -> int:
    from capa.manifest import (
        build_composed_sbom, canonical_json, canonical_manifest,
        ComposeError,
    )
    root_dir = ctx._file_root
    if root_dir is None:
        msg = (
            "capa: --compose-sbom requires a capa.toml project root "
            f"(none found at or above {ctx.filename}). Composing a "
            "product SBOM needs the package + dependency declarations."
        )
        if ctx.use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1
    _enforce_floor_for_file_root(root_dir, ctx.gated_roots)
    manifest = build_manifest(
        ctx.module, filename=ctx.filename,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        unaudited_secret_sinks=ctx.result.unaudited_secret_sinks,
    )
    # Feature #4 (F2a): claim the Wasm-sandbox enforcement posture
    # only when the product targets the Wasm backend (--wasm),
    # under which the runtime host-enforces each foreign child's
    # declared capability SET, so a foreign-component call composes
    # as a BOUNDED node instead of authority-unknown TOP. Without
    # --wasm the composed SBOM is backend-agnostic and a foreign
    # call stays TOP (honest: nothing enforces the bound there).
    _enforcement = "wasm-sandbox" if ctx.args.wasm else "none"
    try:
        composed = build_composed_sbom(
            ctx.module, manifest, root_dir,
            enforcement=_enforcement,
        )
    except ComposeError as e:
        msg = f"capa: --compose-sbom: {e}"
        if ctx.use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1
    # Canonical, content-addressable bytes: the composed SBOM is
    # wrapped with the same S1 content_integrity envelope as
    # --manifest-digest, so the product artifact is itself
    # hashable and byte-reproducible across runs / machines.
    emit_artifact(canonical_json(canonical_manifest(composed)))
    return 0


def emit_check_capabilities(ctx: DispatchCtx) -> int:
    from capa.manifest import (
        build_composed_sbom, ComposeError,
    )

    def _err(text: str) -> None:
        if ctx.use_color:
            print(f"{C.RED}{text}{C.RESET}", file=sys.stderr)
        else:
            print(text, file=sys.stderr)

    root_dir = ctx._file_root
    if root_dir is None:
        _err(
            "capa: --check-capabilities requires a capa.toml project "
            f"root (none found at or above {ctx.filename})."
        )
        return 1
    _enforce_floor_for_file_root(root_dir, ctx.gated_roots)
    manifest = build_manifest(
        ctx.module, filename=ctx.filename,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        unaudited_secret_sinks=ctx.result.unaudited_secret_sinks,
    )
    # Thread the same enforcement posture the composed SBOM /
    # policy gates use: under --wasm the sandbox host-enforces each
    # foreign boundary's declared cap SET, so a foreign-calling
    # package's ceiling is checked against a BOUNDED authority
    # rather than failing closed at authority-unknown TOP. Without
    # --wasm it stays TOP (honest: nothing enforces the bound).
    _enforcement = "wasm-sandbox" if ctx.args.wasm else "none"
    try:
        composed = build_composed_sbom(
            ctx.module, manifest, root_dir, enforcement=_enforcement,
        )
    except ComposeError as e:
        _err(f"capa: --check-capabilities: {e}")
        return 1
    ceilings = composed["capability_ceilings"]
    if not ceilings["checked"]:
        print(
            "capa: --check-capabilities: no package declares a "
            "[capabilities] ceiling; nothing to verify.",
            file=sys.stderr,
        )
        return 0
    if ceilings["pass"]:
        print(
            "capa: --check-capabilities: OK - every declared "
            "capability ceiling holds.",
            file=sys.stderr,
        )
        return 0
    _err(
        "capa: --check-capabilities: FAILED - "
        f"{len(ceilings['violations'])} ceiling violation(s):"
    )
    for v in ceilings["violations"]:
        _err(f"  - {v['detail']}")
    return 1


def emit_policies(ctx: DispatchCtx) -> int:
    from capa.manifest import (
        build_composed_sbom, canonical_json, canonical_manifest,
        evaluate_policies, find_policy_file,
        read_policy_file, ComposeError, PolicyError,
    )

    flag = (
        "--conformance-report" if ctx.args.conformance_report
        else "--check-policies"
    )

    def _perr(text: str) -> None:
        if ctx.use_color:
            print(f"{C.RED}{text}{C.RESET}", file=sys.stderr)
        else:
            print(text, file=sys.stderr)

    root_dir = ctx._file_root
    if root_dir is None:
        _perr(
            f"capa: {flag} requires a capa.toml project root "
            f"(none found at or above {ctx.filename})."
        )
        return 1
    _enforce_floor_for_file_root(root_dir, ctx.gated_roots)
    policy_path = find_policy_file(root_dir)
    manifest = build_manifest(
        ctx.module, filename=ctx.filename,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        unaudited_secret_sinks=ctx.result.unaudited_secret_sinks,
    )
    _enforcement = "wasm-sandbox" if ctx.args.wasm else "none"
    try:
        composed = build_composed_sbom(
            ctx.module, manifest, root_dir, enforcement=_enforcement,
        )
    except ComposeError as e:
        _perr(f"capa: {flag}: {e}")
        return 1
    try:
        policies = (
            read_policy_file(policy_path)
            if policy_path is not None else []
        )
    except PolicyError as e:
        _perr(f"capa: {flag}: {e}")
        return 1
    report = evaluate_policies(composed, policies)

    if ctx.args.conformance_report:
        # Canonical, content-addressable evidence: the report is
        # wrapped with the same S1 content_integrity envelope as
        # --compose-sbom, so the conformance evidence is itself
        # hashable, signABLE, and byte-reproducible.
        emit_artifact(canonical_json(canonical_manifest(report)))
        return 0

    # --check-policies: the CI gate.
    if not policies:
        print(
            "capa: --check-policies: no capa-policy.toml policies "
            "found; nothing to verify.",
            file=sys.stderr,
        )
        return 0
    if report["pass"]:
        print(
            "capa: --check-policies: OK - every declared compliance "
            "policy holds.",
            file=sys.stderr,
        )
        return 0
    failed = [r for r in report["results"] if not r["pass"]]
    n_viol = sum(len(r["violations"]) for r in failed)
    _perr(
        f"capa: --check-policies: FAILED - {len(failed)} policy(ies), "
        f"{n_viol} violation(s):"
    )
    for r in failed:
        _perr(f"  policy {r['policy']!r} (kind {r['kind']}):")
        for v in r["violations"]:
            _perr(f"    - [{v['verdict']}] {v['detail']}")
    return 1


def emit_cyclonedx(ctx: DispatchCtx, build_ts) -> int:
    import json
    from capa.manifest import resolve_dependency_identities
    # When the input belongs to a capa.toml project, list each
    # resolved dependency as a real component (name + version +
    # purl). No project root (a bare .capa file) -> no dependency
    # components, so the output is exactly as before.
    _dep_components = None
    _dep_graph = None
    _cdx_root = ctx._file_root
    if _cdx_root is not None:
        _dep_components, _dep_graph = resolve_dependency_identities(
            _cdx_root,
        )
    sbom = build_cyclonedx(
        ctx.module, filename=ctx.filename, source=ctx.source,
        sources=ctx.sources,
        timestamp=build_ts,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        dependency_components=_dep_components,
        dependency_graph=_dep_graph,
    )
    emit_artifact(json.dumps(sbom, indent=2))
    return 0


def emit_spdx(ctx: DispatchCtx, build_ts) -> int:
    import json
    from capa.manifest import resolve_dependency_identities
    # Symmetric with --cyclonedx: when the input belongs to a
    # capa.toml project, render each resolved dependency as an SPDX
    # Package (name + version + purl externalRef) from the SAME
    # resolve walk. No project root (a bare .capa file) -> no
    # dependency packages, so the output is exactly as before.
    _dep_components = None
    _dep_graph = None
    _spdx_root = ctx._file_root
    if _spdx_root is not None:
        _dep_components, _dep_graph = resolve_dependency_identities(
            _spdx_root,
        )
    sbom = build_spdx(
        ctx.module, filename=ctx.filename, source=ctx.source,
        sources=ctx.sources,
        timestamp=build_ts,
        bindings=ctx.result.bindings,
        expr_labels=ctx.result.expr_labels,
        operator_declared_grants=ctx.operator_grants,
        dependency_components=_dep_components,
        dependency_graph=_dep_graph,
    )
    emit_artifact(json.dumps(sbom, indent=2))
    return 0


def emit_vex(ctx: DispatchCtx, build_ts) -> int:
    import json
    doc = build_vex_document(
        ctx.module, filename=ctx.filename, timestamp=build_ts,
    )
    emit_artifact(json.dumps(doc, indent=2))
    return 0


def emit_provenance(ctx: DispatchCtx, build_ts) -> int:
    import json
    doc = build_provenance(
        ctx.source, filename=ctx.filename,
        started_on=build_ts, finished_on=build_ts,
        sources=ctx.sources,
    )
    emit_artifact(json.dumps(doc, indent=2))
    return 0


def emit_doc(ctx: DispatchCtx) -> int:
    html = build_doc_html(ctx.module, filename=ctx.filename)
    print(html)
    return 0


def emit_wit(ctx: DispatchCtx) -> int:
    from capa.ir import compile_wit
    try:
        print(compile_wit(ctx.module, types=ctx.result.types))
        return 0
    except Exception as e:
        print(f"capa: --wit: {e}", file=sys.stderr)
        return 1
