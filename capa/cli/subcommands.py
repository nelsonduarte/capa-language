"""Subcommand dispatch handlers for the Capa CLI.

The hand-dispatched ``capa <command>`` handlers (init / install / add /
search / migrate / build / run-aot / test) plus the ``--capability-diff``
flag handler, each an ``argv -> int`` function that builds its own
argparse subparser and runs one command end to end. ``_main_dispatch``
in :mod:`capa.cli` routes to them by bare name (through the re-export
there), which is also the seam ``mock.patch.object(cli, _dispatch_*)``
relies on. This module imports the leaf ``_parser`` and ``capa.*``, but
nothing from :mod:`capa.cli`; the dependency runs one way,
``capa.cli`` -> ``capa.cli.subcommands``.
"""

import argparse
import sys
from pathlib import Path

from capa import Lexer, LexerError, analyze
from capa import __version__ as _CAPA_VERSION
from capa._artifact_io import emit_artifact
from capa.init_project import init_project
from capa.loader_paths import resolve_loader_paths
from capa.cli._parser import _WASM32_MAX_PAGES


def _wasm_tooling_available() -> bool:
    """Return True iff the Wasm toolchain is fully usable.

    Two pieces must be present: ``wasm-tools`` on ``PATH`` (the Rust
    binary that wraps the core ``.wasm`` into a Component Model
    artefact) and the ``wasmtime`` Python binding (loaded by
    :class:`capa.runtime._wasm_host.WasmHost`). Probed lazily so
    ``capa --run`` without ``--prefer-wasm`` pays nothing.
    """
    import shutil
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return False
    return True


def _dispatch_init(argv: list[str]) -> int:
    """Handle ``python -m capa init [name]``.

    Kept separate from the main argparse so the rest of the CLI
    can stay flag-based without disrupting the subcommand shape
    users expect from ``init`` (modelled on ``cargo new`` /
    ``go mod init``).
    """
    sub = argparse.ArgumentParser(
        prog="capa init",
        description=(
            "Scaffold a minimal Capa project (main.capa + README.md "
            "+ .gitignore + .capa-version)."
        ),
    )
    sub.add_argument(
        "name",
        nargs="?",
        default=".",
        help=(
            "directory to create (default: current directory, which "
            "must be empty)"
        ),
    )
    args = sub.parse_args(argv)
    return init_project(Path(args.name), capa_version=_CAPA_VERSION)


def _install_summary(manifest) -> str:
    """One-line ``capa install`` report: dep counts by kind, with
    the dev-dependency count appended only when there are any."""
    n_git = sum(1 for d in manifest.dependencies if d.is_git)
    n_path = sum(1 for d in manifest.dependencies if d.is_path)
    parts = [f"{n_git} git", f"{n_path} path"]
    if manifest.dev_dependencies:
        parts.append(f"{len(manifest.dev_dependencies)} dev")
    return (
        f"capa install: {manifest.name} {manifest.version} "
        f"({', '.join(parts)})"
    )


def _dispatch_install(argv: list[str]) -> int:
    """Handle ``python -m capa install [directory]``.

    Reads ``capa.toml`` from the target directory, fetches every
    declared git dependency into ``vendor/<name>``, validates every
    path dependency, and writes ``capa.lock``.
    """
    sub = argparse.ArgumentParser(
        prog="capa install",
        description=(
            "Resolve and fetch the dependencies declared in capa.toml "
            "into vendor/, and write capa.lock."
        ),
    )
    sub.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="project directory containing capa.toml (default: current)",
    )
    sub.add_argument(
        "--update",
        action="store_true",
        help=(
            "accept a fresh upstream commit even when capa.lock pins a "
            "different SHA for the same git URL + tag. Use only when "
            "the upstream tag move is deliberate (or you have audited "
            "the new commit); the default refusal exists so a "
            "force-pushed tag cannot slip into your build silently."
        ),
    )
    args = sub.parse_args(argv)
    project_dir = Path(args.directory).resolve()
    try:
        from capa.pkg import install, InstallError, ManifestError
    except ImportError as e:
        print(f"capa install: {e}", file=sys.stderr)
        return 2
    try:
        manifest = install(project_dir, allow_lock_update=args.update)
    except (InstallError, ManifestError) as e:
        print(f"capa install: {e}", file=sys.stderr)
        return 2
    print(_install_summary(manifest))
    return 0


def _dispatch_add(argv: list[str]) -> int:
    """Handle ``python -m capa add <name> --git <url> ...``.

    Declares ``[dependencies.<name>]`` in capa.toml, then (unless
    ``--no-install``) runs the existing install flow so the new dep
    is vendored + locked immediately.
    """
    sub = argparse.ArgumentParser(
        prog="capa add",
        description=(
            "Declare a new dependency in capa.toml and (by default) "
            "install it into vendor/."
        ),
    )
    sub.add_argument("name", help="dependency name (used as vendor/<name>)")
    sub.add_argument(
        "--git", metavar="URL",
        help=(
            "git URL of the dependency. Omit to resolve the name "
            "through the public registry index."
        ),
    )
    pin = sub.add_mutually_exclusive_group()
    pin.add_argument("--tag", metavar="TAG", help="pin to a git tag")
    pin.add_argument("--rev", metavar="SHA", help="pin to a git commit")
    pin.add_argument("--branch", metavar="NAME", help="pin to a git branch")
    sub.add_argument(
        "--verify-key", metavar="FINGERPRINT", dest="verify_key",
        help="40-char GPG fingerprint the dep's tag/commit must be signed by",
    )
    sub.add_argument(
        "--dev", action="store_true",
        help=(
            "declare under [dev-dependencies] instead of "
            "[dependencies]. Dev-dependencies are installed only "
            "when this project is the install root; consumers of "
            "this package never fetch them."
        ),
    )
    sub.add_argument(
        "--force", action="store_true",
        help="overwrite an existing [dependencies.<name>] block",
    )
    sub.add_argument(
        "--no-install", action="store_true", dest="no_install",
        help="edit capa.toml only; do not fetch the dependency",
    )
    args = sub.parse_args(argv)
    project_dir = Path(".").resolve()
    try:
        from capa.pkg import (
            add_dependency, install, InstallError, ManifestError,
            RegistryError, resolve_name,
        )
    except ImportError as e:
        print(f"capa add: {e}", file=sys.stderr)
        return 2

    git_url = args.git
    tag, rev, branch = args.tag, args.rev, args.branch
    verify_key = args.verify_key
    if git_url is None:
        # No explicit --git: resolve the name through the registry.
        try:
            entry = resolve_name(args.name)
        except RegistryError as e:
            print(f"capa add: {e}", file=sys.stderr)
            return 2
        git_url = entry.git
        if verify_key is None:
            verify_key = entry.verify_key
        if tag is None and rev is None and branch is None:
            if entry.latest is None:
                print(
                    f"capa add: registry has no latest tag for "
                    f"{args.name!r}; pass --tag / --rev / --branch "
                    f"explicitly",
                    file=sys.stderr,
                )
                return 2
            tag = entry.latest
        latest_note = (
            f" (latest {entry.latest})" if entry.latest is not None else ""
        )
        print(
            f"resolved {args.name} -> {git_url}{latest_note} via registry"
        )

    try:
        pin_desc = add_dependency(
            project_dir, args.name, git_url,
            tag=tag, rev=rev, branch=branch,
            verify_key=verify_key, force=args.force, dev=args.dev,
        )
    except ManifestError as e:
        print(f"capa add: {e}", file=sys.stderr)
        return 2
    table = "dev-dependencies" if args.dev else "dependencies"
    print(f"added {args.name} ({pin_desc}) to capa.toml [{table}]")
    if args.no_install:
        return 0
    try:
        manifest = install(project_dir)
    except (InstallError, ManifestError) as e:
        print(f"capa add: {e}", file=sys.stderr)
        return 2
    print(_install_summary(manifest))
    return 0


def _dispatch_search(argv: list[str]) -> int:
    """Handle ``python -m capa search [query]``.

    Searches the registry index by name and description and prints the
    matching packages as a compact table. With no query term it lists
    the whole registry.
    """
    sub = argparse.ArgumentParser(
        prog="capa search",
        description=(
            "Search the package registry by name and description. "
            "With no query, list every package in the registry."
        ),
    )
    sub.add_argument(
        "query",
        nargs="?",
        default="",
        help="substring to match against package names and descriptions",
    )
    args = sub.parse_args(argv)
    try:
        from capa.pkg import search_packages, RegistryError
    except ImportError as e:
        print(f"capa search: {e}", file=sys.stderr)
        return 2
    try:
        results = search_packages(args.query)
    except RegistryError as e:
        print(f"capa search: {e}", file=sys.stderr)
        return 2

    query = args.query.strip()
    if not results:
        print(f"no packages match {query!r}", file=sys.stderr)
        return 1

    name_w = max(len(e.name) for e in results)
    latest_w = max(len(e.latest or "-") for e in results)
    for e in results:
        desc = e.description or ""
        if len(desc) > 60:
            desc = desc[:60] + "..."
        print(f"{e.name:<{name_w}}  {(e.latest or '-'):<{latest_w}}  {desc}")
    if query:
        print(f"{len(results)} package(s) matching {query!r}")
    else:
        print(f"{len(results)} package(s) in registry")
    return 0


def _dispatch_migrate(argv: list[str]) -> int:
    """Handle ``python -m capa migrate <file.capa>``.

    Reports gradual-hardening progress: what fraction of functions are
    already Unsafe-free, which functions declare an Unsafe they never
    exercise (and can drop it now), and which still-Unsafe functions are
    cheapest to harden next. A multi-file project additionally gets a
    per-file breakdown and a next-file-to-harden recommendation. See
    :mod:`capa.migrate`.
    """
    sub = argparse.ArgumentParser(
        prog="capa migrate",
        description=(
            "Report Python->Capa gradual-hardening progress for a .capa "
            "file: how far the migration has come and which Unsafe to "
            "drop next. Multi-file projects also get a per-file "
            "breakdown and a next-file recommendation."
        ),
    )
    sub.add_argument("file", help=".capa file to analyse")
    sub.add_argument(
        "--json",
        action="store_true",
        help="emit the report as JSON instead of human-readable text",
    )
    args = sub.parse_args(argv)

    path = Path(args.file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"capa migrate: cannot read {path}: {e}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        # Non-UTF-8 file: clean error, not a traceback (audit slice
        # 30 P1-b). ``UnicodeDecodeError`` is a ``ValueError``.
        print(
            f"capa migrate: {path}: not valid UTF-8",
            file=sys.stderr,
        )
        return 2
    filename = str(path)

    # Lex + link (multi-file aware) + analyse, mirroring the --manifest
    # path so a mid-migration multi-file project reports correctly.
    from capa.loader import ModuleLoader, LoaderError
    try:
        tokens = Lexer(source, filename=filename).lex()
        del tokens  # lexing validates; the loader re-lexes the root
        _paths = resolve_loader_paths()
        loader = ModuleLoader(
            search_paths=_paths.search_paths,
            dependency_roots=_paths.dependency_roots,
        )
        linked = loader.load_root(source, filename)
    except LexerError as e:
        print(e.format(), file=sys.stderr)
        return 1
    except LoaderError as le:
        print(le.format(), file=sys.stderr)
        return 1

    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources,
        module_privates=linked.module_privates,
    )
    if not result.ok:
        for err in result.errors:
            print(err.format(), file=sys.stderr)
        n = len(result.errors)
        print(
            f"capa migrate: {filename}: {n} error{'s' if n != 1 else ''}; "
            "fix analysis errors before checking migration progress.",
            file=sys.stderr,
        )
        return 1

    from capa.migrate import migrate_report, render_report
    report = migrate_report(linked.module, filename=filename)
    if args.json:
        import json
        print(json.dumps(report, indent=2))
    else:
        print(render_report(report))
    return 0


def _dispatch_build(argv: list[str]) -> int:
    """Handle ``python -m capa build --release <file> -o <out>``.

    Compiles a Capa program ahead of time: AST -> CIR -> WAT -> binary
    Wasm -> wasmtime/Cranelift serialized module, wrapped in a portable
    AOT container (capa.runtime._aot). The resulting ``.cwasm`` loads +
    runs with no recompile (roadmap P1). Run it with ``capa run-aot``.

    Multi-file aware via the loader, mirroring ``--wasm`` / ``migrate``.
    """
    sub = argparse.ArgumentParser(
        prog="capa build",
        description=(
            "Ahead-of-time compile a Capa program to a portable AOT "
            "artifact (Cranelift-compiled, no recompile on run)."
        ),
    )
    sub.add_argument("file", help=".capa file to build")
    sub.add_argument(
        "--release",
        action="store_true",
        help=(
            "build the AOT artifact (currently the only build mode; "
            "accepted for forward compatibility and cargo-like ergonomics)"
        ),
    )
    sub.add_argument(
        "-o", "--output",
        help="output path for the .cwasm artifact (default: <file>.cwasm)",
    )
    sub.add_argument(
        "--wasm-memory-cap", type=int, default=None, metavar="<pages>",
        help="cap linear memory to N 64KiB pages (1..65536)",
    )
    args = sub.parse_args(argv)

    if not _wasm_tooling_available():
        print(
            "capa build: the Wasm toolchain is required (wasm-tools on "
            "PATH + the 'wasmtime' Python package). Install both and "
            "retry.",
            file=sys.stderr,
        )
        return 2

    path = Path(args.file)
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as e:
        print(f"capa build: cannot read {path}: {e}", file=sys.stderr)
        return 2
    except UnicodeDecodeError:
        print(f"capa build: {path}: not valid UTF-8", file=sys.stderr)
        return 2
    filename = str(path)

    # Validate the memory cap with the same bounds as the --wasm path
    # (slice 30 P2-b): 0 / negative opts out; > wasm32 max is refused.
    if args.wasm_memory_cap is None:
        memory_cap: int | None = ...  # type: ignore[assignment]
    elif args.wasm_memory_cap <= 0:
        memory_cap = None
    elif args.wasm_memory_cap > _WASM32_MAX_PAGES:
        print(
            f"capa build: --wasm-memory-cap must be between 1 and "
            f"{_WASM32_MAX_PAGES} pages; got {args.wasm_memory_cap}",
            file=sys.stderr,
        )
        return 2
    else:
        memory_cap = args.wasm_memory_cap

    from capa.loader import ModuleLoader, LoaderError
    try:
        _paths = resolve_loader_paths()
        loader = ModuleLoader(
            search_paths=_paths.search_paths,
            dependency_roots=_paths.dependency_roots,
        )
        linked = loader.load_root(source, filename)
    except LexerError as e:
        print(e.format(), file=sys.stderr)
        return 1
    except LoaderError as le:
        print(le.format(), file=sys.stderr)
        return 1

    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources,
        module_privates=linked.module_privates,
    )
    # Non-fatal warnings mirror the main() compile flow: printed to
    # stderr with "warning" severity, never affecting the exit code.
    for warn in result.warnings:
        print(warn.format(severity="warning"), file=sys.stderr)
        print(file=sys.stderr)
    if not result.ok:
        for err in result.errors:
            print(err.format(), file=sys.stderr)
        n = len(result.errors)
        print(
            f"capa build: {filename}: {n} error{'s' if n != 1 else ''}; "
            "fix them before building.",
            file=sys.stderr,
        )
        return 1

    from capa.ir import compile_wasm
    from capa.runtime._aot import build_aot
    try:
        blob = compile_wasm(
            linked.module, types=result.types,
            bindings=result.bindings,
            memory_cap_pages=memory_cap,
            filename=filename,
        )
        artifact = build_aot(blob, capa_version=_CAPA_VERSION)
    except Exception as e:
        print(f"capa build: {e}", file=sys.stderr)
        return 1

    out = args.output or (str(path.with_suffix("")) + ".cwasm")
    try:
        Path(out).write_bytes(artifact)
    except OSError as e:
        print(f"capa build: cannot write {out}: {e}", file=sys.stderr)
        return 2
    print(
        f"capa build: wrote AOT artifact ({len(artifact)} bytes) to {out}",
        file=sys.stderr,
    )
    return 0


def _dispatch_run_aot(argv: list[str]) -> int:
    """Handle ``python -m capa run-aot <file.cwasm> [-- args...]``.

    Loads a portable AOT artifact built by ``capa build --release`` and
    runs its ``main`` against the real capability host. The artifact's
    serialized module is deserialized (no recompile) and the recorded
    main-param names map each cap slot to its root handle.
    """
    # Split argv on ``--`` so program args after it are forwarded to the
    # Capa program (env.args), mirroring the --run path.
    program_args: list[str] = []
    if "--" in argv:
        sep = argv.index("--")
        program_args = argv[sep + 1:]
        argv = argv[:sep]

    sub = argparse.ArgumentParser(
        prog="capa run-aot",
        description="Run an AOT artifact built by `capa build --release`.",
    )
    sub.add_argument("file", help=".cwasm artifact to run")
    args = sub.parse_args(argv)

    try:
        artifact = Path(args.file).read_bytes()
    except OSError as e:
        print(f"capa run-aot: cannot read {args.file}: {e}", file=sys.stderr)
        return 2

    from capa.runtime._aot import load_aot, AotError
    from capa.runtime._wasm_host import WasmHost
    host = WasmHost(args=program_args)
    try:
        # Deserialize against the HOST's engine: wasmtime refuses
        # cross-Engine instantiation, so the module must share the
        # engine the linker/store belong to.
        module, header = load_aot(artifact, engine=host.engine)
    except AotError as e:
        print(f"capa run-aot: {e}", file=sys.stderr)
        return 2
    try:
        host.run_main_aot(module, header)
    except Exception as e:
        print(f"capa run-aot: {e}", file=sys.stderr)
        return 1
    return 0


def _dispatch_test(argv: list[str]) -> int:
    """Handle ``python -m capa test [--wasm | --both]``.

    Discovers ``tests/test_*.capa`` under the project root (the
    nearest ancestor of the cwd with a ``capa.toml``, else the cwd)
    and runs each file through the same pipeline as ``capa --run``,
    in deterministic (sorted) order. See :mod:`capa.testrunner`.
    """
    sub = argparse.ArgumentParser(
        prog="capa test",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run the project's Capa tests: every tests/test_*.capa "
            "under the project root (nearest ancestor directory with "
            "a capa.toml, or the cwd), in sorted order, each executed "
            "exactly like `capa --run`."
        ),
        epilog=(
            "result contract:\n"
            "  A test passes when its process exits 0 and fails otherwise.\n"
            "  main's return value is ignored, so a Capa program exits 0\n"
            "  exactly when main runs to completion and 1 when it aborts:\n"
            "  a deliberate panic(\"message\") (the recommended way to\n"
            "  fail a test; the message lands on stderr) or a runtime\n"
            "  error escaping main (division by zero, out-of-bounds\n"
            "  index, a Wasm trap).\n"
            "\n"
            "  With --both, a test additionally fails (DIVERGED) when the\n"
            "  two backends both exit 0 but print different stdout; the\n"
            "  report shows the unified diff.\n"
            "\n"
            "  Dev-dependencies declared in capa.toml must be vendored\n"
            "  (run `capa install`) before testing; capa test never\n"
            "  installs anything itself."
        ),
    )
    backend = sub.add_mutually_exclusive_group()
    backend.add_argument(
        "--wasm",
        action="store_true",
        help="run every test on the Wasm backend (capa --wasm --run)",
    )
    backend.add_argument(
        "--both",
        action="store_true",
        help=(
            "run every test on BOTH backends and diff their stdout; "
            "matching output and exit 0 on both is required to pass"
        ),
    )
    args = sub.parse_args(argv)

    mode = "both" if args.both else ("wasm" if args.wasm else "python")
    if mode in ("wasm", "both") and not _wasm_tooling_available():
        print(
            "capa test: the Wasm toolchain is required for "
            f"--{mode if mode == 'wasm' else 'both'} (wasm-tools on "
            "PATH + the 'wasmtime' Python package). Install both and "
            "retry.",
            file=sys.stderr,
        )
        return 2

    from capa.testrunner import find_project_root, run_tests
    root = find_project_root(Path.cwd())
    return run_tests(root, mode=mode)


def _dispatch_capability_diff(
    paths: list[str], *, fail_on_widening: bool,
) -> int:
    """Handle ``capa --capability-diff <old.json> <new.json>``.

    Reads two capability artifacts (a --manifest / --manifest-digest
    per-function manifest, or a --compose-sbom composed product SBOM),
    builds the signed authority changelog between them, and emits it as
    the canonical, content-addressable bytes (wrapped in the S1
    content_integrity envelope). With ``--fail-on-widening`` the process
    exits non-zero when the changelog contains any widening or an
    authority-unknown transition; otherwise it always exits 0 (a pure
    report).
    """
    import json
    from capa.manifest import (
        build_capability_diff, canonical_json, canonical_manifest, DiffError,
    )

    old_path, new_path = paths
    docs: list[dict] = []
    for p in (old_path, new_path):
        try:
            text = Path(p).read_text(encoding="utf-8")
        except OSError as e:
            print(f"capa: --capability-diff: cannot read {p}: {e}",
                  file=sys.stderr)
            return 2
        except UnicodeDecodeError:
            print(f"capa: --capability-diff: {p}: not valid UTF-8",
                  file=sys.stderr)
            return 2
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as e:
            print(f"capa: --capability-diff: {p}: not valid JSON ({e})",
                  file=sys.stderr)
            return 2
        if not isinstance(doc, dict):
            print(
                f"capa: --capability-diff: {p}: expected a JSON object "
                "(a capability manifest or composed SBOM)",
                file=sys.stderr,
            )
            return 2
        docs.append(doc)

    try:
        diff = build_capability_diff(
            docs[0], docs[1], capa_version=_CAPA_VERSION,
        )
    except DiffError as e:
        print(f"capa: --capability-diff: {e}", file=sys.stderr)
        return 2

    emit_artifact(canonical_json(canonical_manifest(diff)))

    if fail_on_widening:
        summary = diff["summary"]
        transition = diff["product"]["authority_unknown_transition"]
        if summary["widenings"] > 0 or transition == "gained":
            print(
                "capa: --capability-diff: FAILED --fail-on-widening: "
                f"{summary['widenings']} widening(s)"
                + (
                    " including a product authority-UNKNOWN transition"
                    if transition == "gained" else ""
                ),
                file=sys.stderr,
            )
            return 1
    return 0