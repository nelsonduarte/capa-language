"""capa-lex, command-line utility for the Capa lexer.

Usage:
    python cli.py <file.capa>
    python cli.py --stdin < file.capa

By default, prints each token on a line in the format:
    LINE:COL  TOKEN_KIND  text  [value]

Useful to visually inspect the tokenization of a program,
diagnose indentation problems, or simply verify that
the lexer processes the file without errors.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from capa import (
    Lexer, LexerError, Parser, TokenKind, analyze, ast_dump, transpile,
)
from capa import __version__ as _CAPA_VERSION
from capa.manifest import (
    build_manifest, build_cyclonedx, build_spdx,
    build_operator_declared_grants,
    build_vex_document, build_provenance,
    resolve_build_timestamp, SourceDateEpochError,
)
from capa._artifact_io import emit_artifact
from capa.pkg import VendorVerificationError
from capa.docgen import build_html as build_doc_html
from capa.formatter import format_source, is_formatted
from capa.init_project import init_project
from capa._debug import _rewrite_traceback


# wasm32 caps linear memory at 65536 pages of 64 KiB = 4 GiB. A
# ``--wasm-memory-cap`` above this produces a module that wasm-tools
# rejects, so the CLI refuses it rather than writing an invalid
# artifact (audit slice 30 P2-b).
_WASM32_MAX_PAGES = 65536


# ANSI colors for terminal highlighting
class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    MAGENTA = "\033[95m"
    RED = "\033[91m"
    GRAY = "\033[90m"


def color_for(kind: TokenKind) -> str:
    name = kind.name
    if name.startswith("KW_"):
        return C.MAGENTA
    if name in ("INDENT", "DEDENT", "NEWLINE", "EOF"):
        return C.GRAY
    if name in ("INT_LIT", "FLOAT_LIT"):
        return C.CYAN
    if name in ("STRING_LIT", "CHAR_LIT"):
        return C.GREEN
    if name == "IDENT":
        return C.BLUE
    return C.YELLOW


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


def _capa_search_paths() -> list[Path]:
    """Return additional module-search roots.

    Three sources, in priority order:

    1. ``CAPA_PATH`` environment variable. Entries are separated by
       ``os.pathsep`` (``;`` on Windows, ``:`` elsewhere). Empty
       entries and non-existent directories are silently skipped.

    2. ``capa.toml`` in the cwd. When present, the package
       manager's vendor dir (``./vendor``) and the parent of every
       ``path = "..."`` dependency are added so a project that
       declares its deps in the manifest does not need any
       environment variable.

    3. Conventional fallback: ``./libraries`` relative to the cwd,
       if it exists. Mirrors the ``node_modules`` / ``vendor``
       convention and supports projects that vendor by hand.

    Entries are de-duplicated so an explicit ``CAPA_PATH=libraries``
    does not appear twice. A typo in ``CAPA_PATH`` is silently
    skipped so it does not turn into a noisy error on every run; a
    broken ``capa.toml`` emits a one-line warning to stderr but does
    not abort the CLI.
    """
    out: list[Path] = []
    seen: set[Path] = set()

    def _append(p: Path) -> None:
        try:
            resolved = p.resolve()
        except OSError:
            return
        if resolved in seen:
            return
        if p.is_dir():
            out.append(p)
            seen.add(resolved)

    raw = os.environ.get("CAPA_PATH", "")
    if raw:
        for entry in raw.split(os.pathsep):
            entry = entry.strip()
            if not entry:
                continue
            _append(Path(entry).expanduser())

    manifest_path = Path.cwd() / "capa.toml"
    if manifest_path.exists():
        try:
            from capa.pkg import read_manifest, verify_vendored_deps
            manifest = read_manifest(manifest_path)
            # Dev-dependencies resolve exactly like regular deps:
            # ``capa install`` vendors them into the same ./vendor
            # dir, so test files in the invocation root import them
            # with no extra configuration.
            all_deps = manifest.dependencies + manifest.dev_dependencies
            has_git = any(d.is_git for d in all_deps)
            if has_git:
                # PKG-1: re-verify the vendored git deps against
                # capa.lock BEFORE the loader is allowed to read
                # ./vendor. Fail-closed (raises VendorVerificationError)
                # on a missing lock, a missing / non-git vendor dir, a
                # SHA mismatch, or a declared git dep absent from the
                # lock. The check is the only re-validation of vendor/
                # on the build path; ``capa install`` / ``capa add``
                # never hit this function (they call install() directly)
                # so they are not subject to the circular pre-check.
                verify_vendored_deps(Path.cwd(), manifest)
                _append(Path.cwd() / "vendor")
            for d in all_deps:
                if d.is_path and d.path is not None:
                    dep_path = (manifest.manifest_dir / d.path).resolve()
                    _append(dep_path.parent)
            # A ``capa.toml`` in the cwd marks it as the project root,
            # so add its parent as a search root. This makes a package
            # self-reference resolve: a seed library whose repository
            # directory *is* the package (the dir is named ``capa_csv``
            # and its modules import one another as ``capa_csv.model``)
            # needs ``<root>/../capa_csv/model.capa`` to be reachable.
            # ``capa test`` already injects the same parent into the
            # child's ``CAPA_PATH`` (see ``testrunner._child_env``);
            # without this, ``capa --check`` / ``--run`` on those files
            # failed to resolve imports that ``capa test`` resolved, an
            # inconsistency between the two build paths. Added AFTER
            # ./vendor and the path-deps above (and de-duped) so it can
            # never shadow a verified vendored dep or a declared path
            # dep with a same-named sibling working copy of the parent.
            _append(Path.cwd().parent)
        except VendorVerificationError:
            # Fail-closed: an unverifiable vendor tree is a hard stop,
            # NOT a "broken capa.toml" warning. Re-raise so the CLI
            # surfaces a clear error and refuses the build, rather than
            # silently dropping ./vendor from the search path (which
            # would degrade to a confusing "module not found").
            raise
        except Exception as e:
            # A broken capa.toml should produce a clear warning but
            # not block unrelated operations (e.g. `capa --check` on
            # a file outside the project).
            print(
                f"capa: warning: ignoring capa.toml ({e})",
                file=sys.stderr,
            )

    # Conventional fallback. Cheap probe: only the cwd is consulted,
    # so this never escalates I/O for a project that does not use
    # the convention.
    _append(Path.cwd() / "libraries")

    return out


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
        loader = ModuleLoader(search_paths=_capa_search_paths())
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
        loader = ModuleLoader(search_paths=_capa_search_paths())
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


def main() -> int:
    """CLI entry point. Wraps the dispatch in a fail-closed guard for
    ``VendorVerificationError`` (PKG-1): an unverifiable ./vendor tree
    is a clean, named error + exit 1 on any read/build path, never a
    traceback."""
    try:
        return _main_dispatch()
    except VendorVerificationError as e:
        print(f"capa: {e}", file=sys.stderr)
        return 1


def _main_dispatch() -> int:
    # Make stdout/stderr UTF-8 with replacement so CLI output never
    # crashes the process on a non-ASCII byte. The token dump uses a
    # ``->`` arrow glyph, error messages can carry unicode file names,
    # and the default Windows console codec is cp1252 -- printing
    # either to a redirected file raised UnicodeEncodeError +
    # traceback (audit slice 30 P1-a). ``reconfigure`` exists on the
    # real text streams (3.7+); under the test harness stdout is an
    # ``io.StringIO`` without it (and StringIO is already unicode, so
    # it needs no reconfigure). Guarded so neither case fails.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    # Subcommand dispatch happens before argparse so the rest of
    # the CLI can stay flag-based without complicating help output.
    if len(sys.argv) >= 2 and sys.argv[1] == "init":
        return _dispatch_init(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "install":
        return _dispatch_install(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "add":
        return _dispatch_add(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "search":
        return _dispatch_search(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "migrate":
        return _dispatch_migrate(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "build":
        return _dispatch_build(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "run-aot":
        return _dispatch_run_aot(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "test":
        return _dispatch_test(sys.argv[2:])
    if len(sys.argv) >= 2 and sys.argv[1] == "lsp":
        from capa.lsp_server import serve
        return serve()
    if len(sys.argv) >= 2 and sys.argv[1] == "repl":
        from capa.repl import serve as repl_serve
        return repl_serve()

    # Split argv on `--`: anything after the separator is forwarded
    # to the transpiled program via ``sys.argv`` when ``--run``
    # executes. Done before argparse so the Capa CLI does not try
    # to interpret the program's own flags. When the separator is
    # absent, ``program_args`` stays empty and behaviour is
    # unchanged.
    program_args: list[str] = []
    cli_argv = sys.argv[1:]
    if "--" in cli_argv:
        sep = cli_argv.index("--")
        program_args = cli_argv[sep + 1:]
        cli_argv = cli_argv[:sep]

    parser = argparse.ArgumentParser(
        description="Lexer, parser and analyzer for the Capa language",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"capa {_CAPA_VERSION}",
        help="print the Capa compiler version and exit",
    )
    parser.add_argument("file", nargs="?", help=".capa file to process")
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="read source from standard input",
    )
    parser.add_argument(
        "--parse",
        action="store_true",
        help="parse and print the AST (instead of tokens)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="parse and semantically analyze (lexer + parser + analyzer)",
    )
    parser.add_argument(
        "--transpile",
        action="store_true",
        help="transpile to Python and print the generated code",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help=(
            "transpile and execute the program (calls main with "
            "capabilities). Arguments after `--` are forwarded to the "
            "program (visible via env.args())"
        ),
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help=(
            "re-run the program every time it (or any of its imported "
            "modules) changes on disk. Implies --run. Ctrl-C to exit."
        ),
    )
    parser.add_argument(
        "--manifest",
        action="store_true",
        help=(
            "emit a JSON capability manifest: per-function declared "
            "capabilities, attributes, signature, and the user-defined "
            "capability declarations and their implementors"
        ),
    )
    parser.add_argument(
        "--cyclonedx",
        action="store_true",
        help=(
            "emit a CycloneDX 1.5 SBOM with the capability manifest "
            "embedded as standard properties[] entries (consumable by "
            "Dependency-Track, OSV-Scanner, syft, etc.). Set "
            "SOURCE_DATE_EPOCH (Unix UTC seconds) to pin the build "
            "timestamp and make this and the other SBOM/attestation "
            "artefacts byte-reproducible."
        ),
    )
    parser.add_argument(
        "--spdx",
        action="store_true",
        help=(
            "emit an SPDX 2.3 SBOM with the capability manifest "
            "embedded as annotations[] (Linux Foundation companion "
            "to --cyclonedx, consumable by SPDX-aware tools and "
            "OpenChain-conformant pipelines)"
        ),
    )
    parser.add_argument(
        "--vex",
        action="store_true",
        help=(
            "emit a standalone CycloneDX 1.5 VEX-only document "
            "from @vex(cve, status, justification, detail) "
            "attributes on functions. Per-function VEX granularity, "
            "the affects[] of each entry pinpoints the function the "
            "claim was made on, not the package."
        ),
    )
    parser.add_argument(
        "--provenance",
        action="store_true",
        help=(
            "emit a SLSA Build L1 provenance attestation: an "
            "in-toto Statement v1 with a SLSA Provenance v1.0 "
            "predicate, subject = SHA-256 of the source .capa "
            "file. Consumable by SLSA-aware verifiers "
            "(slsa-verifier, in-toto attest, cosign verify-blob)."
        ),
    )
    parser.add_argument(
        "--doc",
        action="store_true",
        help=(
            "emit a self-contained HTML documentation page built from "
            "doc comments (///, /** */), capability signatures, and "
            "attached attributes; the human-readable counterpart to "
            "--manifest"
        ),
    )
    parser.add_argument(
        "--fmt",
        action="store_true",
        help=(
            "rewrite the file in canonical Capa style (line-level: "
            "indentation normalised to 4-space multiples, trailing "
            "whitespace stripped, blank-line clusters collapsed, "
            "final newline ensured); prints to stdout when used "
            "with --stdin"
        ),
    )
    parser.add_argument(
        "--fmt-check",
        action="store_true",
        help=(
            "verify that the file is already in canonical style; "
            "exits 0 if it is, 1 if it is not (no rewrite)"
        ),
    )
    parser.add_argument(
        "--ir",
        action="store_true",
        help=(
            "use the CIR pipeline (AST -> CIR -> Python) instead of "
            "the direct legacy transpiler. Same observable output for "
            "the subset CIR currently covers; falls back to the legacy "
            "path when CIR lowering raises UnsupportedInIR."
        ),
    )
    parser.add_argument(
        "--wasm",
        action="store_true",
        help=(
            "compile via CIR to WebAssembly text (WAT). With "
            "--transpile, prints the WAT. With --run, assembles the "
            "WAT to binary via wasm-tools and executes it on a "
            "wasmtime-backed host that provides the Capa capability "
            "interfaces. Coverage matches Phase 6 of the IR roadmap; "
            "constructs outside that subset fail loudly rather than "
            "fall back to Python."
        ),
    )
    parser.add_argument(
        "--wit",
        action="store_true",
        help=(
            "emit the WIT spec describing the program's capability "
            "imports. Useful for inspecting the capability surface "
            "the Wasm backend would generate; does not produce "
            "executable output."
        ),
    )
    parser.add_argument(
        "--prefer-wasm",
        action="store_true",
        help=(
            "with --run: try the Wasm backend first and fall back "
            "to the Python pipeline only when CIR lowering or Wasm "
            "emission rejects a construct. Honoured automatically "
            "when CAPA_PREFER_WASM=1 is set in the environment. "
            "Requires the [wasm] extra (wasmtime-py) and wasm-tools "
            "on PATH."
        ),
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default=None,
        help=(
            "with --wasm, save the assembled binary to the given "
            "path instead of executing it. Use with --component to "
            "save a Component Model wrapper (.wasm) instead of the "
            "core module."
        ),
    )
    parser.add_argument(
        "--component",
        action="store_true",
        help=(
            "with --wasm --output, wrap the core module in a "
            "Component Model component via 'wasm-tools component "
            "new'. Requires 'wasm-tools' on PATH. The resulting "
            "file embeds the WIT spec and is consumable by any "
            "Component-Model-aware runtime."
        ),
    )
    parser.add_argument(
        "--wasi",
        action="store_true",
        help=(
            "EXPERIMENTAL: with --wasm --component, migrate the "
            "supported touch-points of Random, Clock, Env, Fs and Net to "
            "import canonical WASI Preview 2 interfaces (wasi:random / "
            "wasi:clocks / wasi:cli/environment / wasi:filesystem / "
            "wasi:http) instead of the custom capa:host ones. Every other "
            "capability (Stdio, etc.) stays on capa:host (hybrid). Env / "
            "Fs / Net attenuation (restrict_to / allows) is supported "
            "guest-side; Clock.sleep and Clock attenuation are not "
            "supported in this mode. Requires 'wasm-tools' on PATH; "
            "--run additionally needs wasmtime-py with WASI P2 support. "
            "The default capa:host path is unaffected."
        ),
    )
    parser.add_argument(
        "--preopen",
        action="append",
        default=None,
        metavar="<dir>[:ro|:rw]",
        help=(
            "with --wasi, grant the component filesystem authority over "
            "<dir> as an OPERATOR-DECLARED preopen (Level 2, the WASI "
            "--dir model), unblocking DYNAMIC (non-literal) Fs paths that "
            "the compiler cannot derive a preopen for. The path is "
            "resolved at runtime relative to <dir>. Append ':ro' for "
            "read-only or ':rw' for read-write (default: rw). Recorded in "
            "the SBOM as a declared grant, distinct from the "
            "compiler-derived capability surface. This increment (b1) "
            "supports a SINGLE --preopen for dynamic paths."
        ),
    )
    parser.add_argument(
        "--wasi-surface",
        action="store_true",
        help=(
            "print the WASI path-arg surface: the argv (env.args()) "
            "arguments the compiler PROVES reach an Fs / Net / Env sink, "
            "and whether read or write (e.g. 'argv[0] -> Fs.read "
            "(read-only)'). A compiler-derived, by-construction audit fact "
            "(distinct from operator-declared grants); read-only, does not "
            "compile or run the program. A sound over-approximation: no "
            "reaching argument is omitted (a closure that escapes its frame "
            "has its param-fed sinks reported conservatively at argv[*]), "
            "and argv[*] denotes an argument that reaches a sink at a "
            "statically-indeterminate index."
        ),
    )
    parser.add_argument(
        "--wasm-memory-cap",
        type=int,
        default=None,
        metavar="<pages>",
        help=(
            "with --wasm, cap the emitted linear memory at this many "
            "64 KiB pages. The bump allocator's memory.grow then "
            "traps via 'unreachable' at a deterministic ceiling "
            "instead of at a host-dependent OOM point (audit fix H1). "
            "Default: 256 pages (16 MiB). Use 0 to skip the cap "
            "(host decides)."
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI colors in the output",
    )
    parser.add_argument(
        "--no-layout",
        action="store_true",
        help="omit layout tokens (NEWLINE/INDENT/DEDENT/EOF) in the output",
    )
    args = parser.parse_args(cli_argv)

    # --watch wraps the regular --run flow in a re-run-on-change
    # loop. Implemented as an outer process that spawns a fresh
    # `capa --run <file>` subprocess on each iteration; the watch
    # loop just polls mtimes. Trade-off: ~50-100ms process startup
    # per iteration, against zero refactor of main()'s state
    # machine.
    if args.watch:
        if not args.file:
            print(
                "capa: --watch requires a file argument",
                file=sys.stderr,
            )
            return 2
        return _run_watch_loop(args.file, program_args)

    if args.stdin:
        source = sys.stdin.read()
        filename = "<stdin>"
    elif args.file:
        path = Path(args.file)
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as e:
            print(f"error opening {path}: {e}", file=sys.stderr)
            return 2
        except UnicodeDecodeError:
            # A binary / non-UTF-8 file is a user error, not a crash.
            # ``UnicodeDecodeError`` is a ``ValueError``, so the
            # ``OSError`` clause above does not catch it (audit slice
            # 30 P1-b).
            print(
                f"error: {path}: not valid UTF-8 (Capa source must be "
                f"UTF-8 encoded)",
                file=sys.stderr,
            )
            return 2
        filename = str(path)
    else:
        parser.print_usage(sys.stderr)
        return 2

    use_color = sys.stdout.isatty() and not args.no_color
    layout_kinds = {
        TokenKind.NEWLINE,
        TokenKind.INDENT,
        TokenKind.DEDENT,
        TokenKind.EOF,
    }

    # --fmt and --fmt-check operate on the raw source text, before
    # lexing, so they work on files with syntax errors as well.
    if args.fmt_check:
        if is_formatted(source):
            return 0
        # Print a one-line diagnostic to stderr (no diff, to keep
        # the output compact for CI). Callers wanting the diff can
        # use --fmt and compare to the original.
        print(
            f"{filename}: not in canonical Capa style "
            f"(use --fmt to reformat)",
            file=sys.stderr,
        )
        return 1
    if args.fmt:
        formatted = format_source(source)
        if args.stdin:
            sys.stdout.write(formatted)
            return 0
        # Only rewrite the file if its contents change, to keep
        # mtimes stable for build systems.
        if formatted != source:
            try:
                path.write_text(formatted, encoding="utf-8")
            except OSError as e:
                print(f"error writing {path}: {e}", file=sys.stderr)
                return 2
        return 0

    try:
        tokens = Lexer(source, filename=filename).lex()
    except LexerError as e:
        if use_color:
            print(f"{C.RED}{e.format()}{C.RESET}", file=sys.stderr)
        else:
            print(e.format(), file=sys.stderr)
        return 1

    needs_analysis = (
        args.check or args.run or args.manifest or args.cyclonedx
        or args.spdx or args.vex or args.provenance or args.doc
        or args.wit or args.wasm
    )
    # --wasi-surface needs the loader-linked AST (so imported helpers are
    # inlined and the argv -> sink surface sees the whole program) but no
    # full semantic analysis: it is a read-only static inspection.
    needs_link = needs_analysis or bool(getattr(args, "wasi_surface", False))
    linked = None
    if args.parse or args.transpile or needs_link:
        try:
            if needs_link or args.transpile:
                # Resolve transitive imports before analysis. The
                # loader does its own lex + parse of the root file
                # so all source positions are consistent; imported
                # modules become extra Items in the linked AST.
                from capa.loader import ModuleLoader, LoaderError
                try:
                    loader = ModuleLoader(
                        search_paths=_capa_search_paths(),
                    )
                    linked = loader.load_root(source, filename)
                    module = linked.module
                except LoaderError as le:
                    msg = le.format()
                    if use_color:
                        print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                    else:
                        print(msg, file=sys.stderr)
                    return 1
            else:
                # --parse-only: skip the linker so the inspected AST
                # shows the root file's imports verbatim (useful
                # for debugging the module system itself).
                module = Parser(
                    tokens, source=source, filename=filename,
                ).parse_module()
        except LexerError as e:
            if use_color:
                print(f"{C.RED}{e.format()}{C.RESET}", file=sys.stderr)
            else:
                print(e.format(), file=sys.stderr)
            return 1

    # --wasi-surface: read-only inspection of the proven argv -> sink
    # path-arg surface. No semantic analysis / compilation; prints the
    # facts (or a clear "no argv argument reaches a sink" line) and exits.
    if getattr(args, "wasi_surface", False):
        from capa.ir._wasi_path_arg_surface import compute_path_arg_surface
        surface = compute_path_arg_surface(module)
        if surface.is_empty():
            print(
                f"{filename}: no argv (env.args()) argument is proven to "
                f"reach an Fs / Net / Env sink"
            )
        else:
            print(
                f"{filename}: WASI path-arg surface "
                f"(compiler-derived, by-construction):"
            )
            for line in surface.describe_lines():
                print(f"  {line}")
            print(
                "  (sound over-approximation: no reaching argv argument is "
                "omitted; argv[*] = a reaching argument at an indeterminate "
                "index. Closures are sound by construction: a closure whose "
                "param reaches a sink is reported at argv[*] unless proven "
                "applied only locally to non-argv values, so an escaping "
                "closure -- returned, passed to a helper, stored in an "
                "aggregate, or reached through a match/if arm or a name "
                "bound to one -- fails closed, including a named closure "
                "bound inside another lambda's body. Residual gap (VALUE-FLOW "
                "only): a closure carried by a value not statically tied back "
                "to a lambda (re-extracted from a runtime container by key, or "
                "threaded through an opaque computed value) may be "
                "under-reported.)"
            )
        return 0

    result = None
    if (args.check or args.run or args.manifest or args.cyclonedx
            or args.spdx or args.vex or args.provenance or args.doc
            or args.wit or args.wasm):
        # Semantic analysis is required before running. If the
        # loader produced a sources map (multi-file program),
        # pass it so errors in imported modules render with the
        # imported file's source snippet.
        sources_map = linked.sources if linked is not None else None
        privates_map = (
            linked.module_privates if linked is not None else None
        )
        # Belt-and-braces: the parser caps both nesting depth and flat
        # chain length, so a pathological expression is rejected before
        # an AST that could blow the analyzer's recursive walks is ever
        # built. Should any path still recurse past the interpreter
        # limit, convert the RecursionError into a clean diagnostic
        # rather than letting a raw stack trace escape ``capa --check``.
        try:
            result = analyze(
                module, source=source, filename=filename,
                sources=sources_map,
                module_privates=privates_map,
            )
        except RecursionError:
            msg = (
                f"{filename}: error: expression too deep or complex to "
                "analyze; simplify or split it"
            )
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # Non-fatal warnings (information-flow secret->sink under the
        # warn-then-enforce roll-out, roadmap S2.4; the dead-Unsafe
        # migrate nudge) print regardless of whether the program
        # compiles and never change the exit code.
        for warn in getattr(result, "warnings", []):
            text = warn.format(severity="warning")
            if use_color:
                print(f"{C.YELLOW}{text}{C.RESET}", file=sys.stderr)
            else:
                print(text, file=sys.stderr)
            print(file=sys.stderr)
        if not result.ok:
            for err in result.errors:
                if use_color:
                    print(f"{C.RED}{err.format()}{C.RESET}", file=sys.stderr)
                    print(file=sys.stderr)
                else:
                    print(err.format(), file=sys.stderr)
                    print(file=sys.stderr)
            n_errs = len(result.errors)
            msg = f"{filename}: {n_errs} error{'s' if n_errs != 1 else ''}"
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # WASI Fs layer b1: the operator-declared grant block (--preopen),
        # surfaced in the manifest / CycloneDX / SPDX as Level-2
        # operator-declared authority, distinct from the derived surface.
        _operator_grants = _operator_grants_from_args(
            getattr(args, "preopen", None)
        )
        if args.manifest:
            import json
            manifest = build_manifest(
                module, filename=filename,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
            )
            emit_artifact(json.dumps(manifest, indent=2))
            return 0
        if args.cyclonedx or args.spdx or args.vex or args.provenance:
            # Each invocation emits exactly one artefact (every branch
            # below returns), so the instant is derived deterministically
            # from SOURCE_DATE_EPOCH: four separate invocations (one per
            # artefact) with the same value share the same timestamp, and
            # within CycloneDX-with-VEX the one instant feeds both
            # metadata.timestamp and the per-vulnerability firstIssued.
            # When SOURCE_DATE_EPOCH is set, this makes the output
            # byte-reproducible across runs and machines; when it is
            # unset, ``None`` lets the emitters fall back to wall-clock
            # time. An invalid value is a hard error rather than a silent
            # wall-clock fallback.
            try:
                build_ts = resolve_build_timestamp()
            except SourceDateEpochError as e:
                print(f"capa: {e}", file=sys.stderr)
                return 2
        if args.cyclonedx:
            import json
            sbom = build_cyclonedx(
                module, filename=filename, source=source,
                sources=linked.sources if linked is not None else None,
                timestamp=build_ts,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
            )
            emit_artifact(json.dumps(sbom, indent=2))
            return 0
        if args.spdx:
            import json
            sbom = build_spdx(
                module, filename=filename, source=source,
                sources=linked.sources if linked is not None else None,
                timestamp=build_ts,
                expr_labels=result.expr_labels,
                operator_declared_grants=_operator_grants,
            )
            emit_artifact(json.dumps(sbom, indent=2))
            return 0
        if args.vex:
            import json
            doc = build_vex_document(
                module, filename=filename, timestamp=build_ts,
            )
            emit_artifact(json.dumps(doc, indent=2))
            return 0
        if args.provenance:
            import json
            doc = build_provenance(
                source, filename=filename,
                started_on=build_ts, finished_on=build_ts,
                sources=linked.sources if linked is not None else None,
            )
            emit_artifact(json.dumps(doc, indent=2))
            return 0
        if args.doc:
            html = build_doc_html(module, filename=filename)
            print(html)
            return 0
        if args.check and not args.run:
            n_items = len(module.items)
            n_typed = len(result.types)
            n_bound = len(result.bindings)
            msg = (
                f"{filename}: ok ({n_items} items, "
                f"{n_typed} expressions typed, {n_bound} bindings)"
            )
            if use_color:
                print(f"{C.GREEN}{msg}{C.RESET}")
            else:
                print(msg)
            return 0
        if args.wit:
            from capa.ir import compile_wit
            try:
                print(compile_wit(module, types=result.types))
                return 0
            except Exception as e:
                print(f"capa: --wit: {e}", file=sys.stderr)
                return 1

    # Auto-prefer the Wasm pipeline when --prefer-wasm or the
    # CAPA_PREFER_WASM env var is set AND the user did not pass
    # --wasm explicitly AND the Wasm toolchain is available
    # (wasmtime importable + wasm-tools on PATH). Any failure
    # (UnsupportedInIR, WasmEmissionError, missing tool, wasmtime
    # trap) falls back silently to the Python pipeline below.
    prefer_wasm = (
        args.prefer_wasm
        or os.environ.get("CAPA_PREFER_WASM") == "1"
    )
    # Audit H1 (2026-05): translate the CLI's ``--wasm-memory-cap``
    # to the (page-count | None) shape the emitter wants. ``0``
    # opts out of the cap; any positive int is the limit; absence
    # falls back to the emitter's default.
    if args.wasm_memory_cap is None:
        wasm_memory_cap: int | None = ...  # type: ignore[assignment]
    elif args.wasm_memory_cap <= 0:
        wasm_memory_cap = None
    elif args.wasm_memory_cap > _WASM32_MAX_PAGES:
        # wasm32 caps linear memory at 65536 64KiB pages (4 GiB). A
        # larger value produces a module wasm-tools rejects, which we
        # used to write to disk with a success message + exit 0 (audit
        # slice 30 P2-b). Reject it up front.
        print(
            f"capa: --wasm-memory-cap must be between 1 and "
            f"{_WASM32_MAX_PAGES} pages (wasm32 caps linear memory at "
            f"4 GiB); got {args.wasm_memory_cap}",
            file=sys.stderr,
        )
        return 2
    else:
        wasm_memory_cap = args.wasm_memory_cap

    # ``--wasi`` only has an effect on the Wasm Component Model path: it
    # rewrites the WIT world and the component's imports to reference the
    # canonical wasi:random / wasi:clocks packages. Passed without
    # ``--wasm`` it would hit the pure-Python backend, which ignores it
    # entirely; that silent no-op masked typos / wrong invocations. Reject
    # it up front with an actionable message. (The companion
    # ``--wasi`` requires ``--component`` guard lives in the Wasm branch.)
    if bool(getattr(args, "wasi", False)) and not args.wasm:
        msg = (
            "capa: --wasi requires --wasm --component (WASI mode only "
            "applies to the Wasm Component Model path; it has no effect "
            "on the default capa:host / pure-Python backend)"
        )
        if use_color:
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
        getattr(args, "manifest", False) or getattr(args, "cyclonedx", False)
        or getattr(args, "spdx", False)
    )
    if (getattr(args, "preopen", None)
            and not bool(getattr(args, "wasi", False))
            and not _emitting_sbom):
        msg = (
            "capa: --preopen requires --wasi (or an SBOM / --manifest "
            "command): it is the operator-declared filesystem grant for "
            "the WASI mode, recorded in the SBOM; it has no effect on the "
            "default execution backend"
        )
        if use_color:
            print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
        else:
            print(msg, file=sys.stderr)
        return 1

    if (
        args.run and not args.wasm and prefer_wasm
        and _wasm_tooling_available()
    ):
        if result is None:
            result = analyze(module, source=source, filename=filename)
        try:
            from capa.ir import compile_wasm
            from capa.runtime._wasm_host import WasmHost
            blob = compile_wasm(
                module, types=result.types,
                memory_cap_pages=wasm_memory_cap,
                filename=filename,
            )
            host = WasmHost(args=program_args)
            host.run_main(blob)
            return 0
        except Exception:
            # Fall through to the Python pipeline. The user opted
            # into best-effort Wasm; silent fallback keeps the
            # default execution path predictable.
            pass

    if args.wasm and (args.transpile or args.run or args.output):
        # Wasm pipeline: AST -> CIR -> WAT -> binary -> (wasmtime
        # | file | component). Failures are loud (no fallback to
        # Python) so coverage gaps in the Wasm backend surface as
        # actionable errors rather than silent shape changes.
        from capa.ir import compile_wat, compile_wasm, compile_wit
        # Experimental WASI mode is only meaningful for the component
        # path (it rewrites the WIT world + the component imports);
        # ``--transpile`` shows the WAT, which carries the wasi:*
        # imports too, so it is allowed. A bare ``--wasm --output``
        # core module, or ``--wasm --run`` on the core host, would
        # produce wasi:* imports nothing satisfies, so reject early
        # with an actionable message instead of a late link failure.
        wasi_mode = bool(getattr(args, "wasi", False))
        if wasi_mode and not args.component and not args.transpile:
            msg = (
                "capa: --wasi requires --component (the WASI mode "
                "rewrites the Component Model world; the bare core "
                "module / core host has no WASI provider)"
            )
            if use_color:
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
        preopen_specs = getattr(args, "preopen", None) or []
        if preopen_specs:
            if len(preopen_specs) > 1:
                msg = (
                    "capa: --preopen: this increment (b1) supports a "
                    "single --preopen for dynamic Fs paths; got "
                    f"{len(preopen_specs)}"
                )
                if use_color:
                    print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
                return 1
            fs_operator_preopen = _parse_preopen_spec(preopen_specs[0])
            wasi_dynamic_fs = True
        if result is None:
            result = analyze(module, source=source, filename=filename)
        try:
            if args.transpile:
                wat = compile_wat(
                    module, types=result.types,
                    memory_cap_pages=wasm_memory_cap,
                    filename=filename,
                    wasi=wasi_mode,
                    wasi_dynamic_fs=wasi_dynamic_fs,
                )
                print(wat)
                return 0
            blob = compile_wasm(
                module, types=result.types,
                memory_cap_pages=wasm_memory_cap,
                filename=filename,
                wasi=wasi_mode,
                wasi_dynamic_fs=wasi_dynamic_fs,
            )
        except Exception as e:
            msg = f"capa: --wasm: {e}"
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        # --output: save the binary instead of running it. With
        # --component, wrap the core module in a Component Model
        # component first.
        if args.output:
            try:
                if args.component:
                    blob = _wrap_as_component(
                        blob,
                        compile_wit(
                            module, types=result.types, wasi=wasi_mode,
                        ),
                        wasi=wasi_mode,
                    )
                Path(args.output).write_bytes(blob)
                kind = "component" if args.component else "core module"
                print(
                    f"capa: --wasm: wrote {kind} ({len(blob)} bytes) to {args.output}",
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
            if args.component:
                from capa.runtime._wasm_component_host import (
                    WasmComponentHost,
                )
                component_blob = _wrap_as_component(
                    blob,
                    compile_wit(
                        module, types=result.types, wasi=wasi_mode,
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
                        module, types=result.types,
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
                        module, types=result.types,
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
                        types=result.types or {},
                    ).lower_module(module)
                    used_caps = collect_used_capabilities(cir_for_caps)
                    net_request_ops = used_caps.get("Net", set())
                    if "get" in net_request_ops or "post" in net_request_ops:
                        net_ceiling = compute_net_ceiling(
                            module, types=result.types,
                        )
                host = WasmComponentHost(
                    args=program_args,
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
                host = WasmHost(args=program_args)
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
            import traceback
            traceback.print_exc(file=sys.stderr)
            return 1

    if args.transpile or args.run:
        # If we haven't yet run analyze (in --transpile mode without --check),
        # we run it now silently to obtain types for the
        # type-aware dispatch in the transpiler.
        if result is None:
            result = analyze(module, source=source, filename=filename)
        code = None
        # Statement-level source map (python_line -> Capa Pos), filled
        # by the legacy transpiler. Stays empty on the --ir path, in
        # which case _rewrite_traceback falls back to the plain
        # Python traceback.
        line_map: dict = {}
        if args.ir:
            # Opt-in CIR pipeline. UnsupportedInIR drops back to the
            # legacy transpiler so an --ir invocation still produces
            # runnable Python on programs the CIR doesn't yet cover;
            # the user-visible behaviour is identical, only the path
            # differs. A one-line stderr breadcrumb makes the fallback
            # visible to anyone debugging the IR's coverage.
            from capa.ir import compile_program, UnsupportedInIR
            try:
                code = compile_program(
                    module, filename=filename,
                    types=result.types if result is not None else None,
                )
            except UnsupportedInIR as e:
                msg = f"capa: --ir: falling back to legacy transpiler ({e})"
                if use_color:
                    print(f"{C.YELLOW}{msg}{C.RESET}", file=sys.stderr)
                else:
                    print(msg, file=sys.stderr)
        if code is None:
            code = transpile(
                module, filename=filename,
                types=result.types if result is not None else None,
                bindings=result.bindings if result is not None else None,
                out_line_map=line_map,
            )

    if args.transpile and not args.run:
        print(code)
        return 0

    if args.run:
        # Execute the transpiled Python in the current interpreter.
        #
        # The ``capa.runtime`` package is already importable here (we
        # are running inside the ``capa`` package), so the transpiled
        # code's ``from capa.runtime import ...`` resolves directly.
        # We give it a ``__name__ = "__main__"`` so the conventional
        # entry-point guard works; ``SystemExit`` is intercepted so
        # the exit code propagates back to the OS naturally; any
        # other exception prints a traceback and returns 1.
        #
        # Historical note: a ``subprocess.run([sys.executable, ...])``
        # used to be invoked here. That does not survive PyInstaller
        # bundling: the bundled binary is not a generic Python
        # interpreter able to run an arbitrary ``.py`` file. In-process
        # exec works in both plain-Python and frozen-binary modes,
        # is faster (no fork), and avoids the temp-file dance.
        import traceback
        run_globals = {
            "__name__": "__main__",
            "__file__": "<transpiled>",
        }
        # Override sys.argv for the duration of the run so the
        # program's ``env.args()`` returns the user-visible arguments.
        # argv[0] is the .capa filename (or ``<transpiled>`` for
        # --stdin); argv[1:] is everything after ``--`` on the
        # Capa command line.
        saved_argv = sys.argv
        sys.argv = [args.file or "<transpiled>", *program_args]
        try:
            exec(compile(code, "<transpiled>", "exec"), run_globals)
            return 0
        except SystemExit as e:
            if e.code is None:
                return 0
            if isinstance(e.code, int):
                return e.code
            sys.stderr.write(str(e.code) + "\n")
            return 1
        except BaseException:
            traceback.print_exc(file=sys.stderr)
            # Resolve per-file source text so each Capa frame can show
            # its source line and caret. The root file is always
            # available; the linker's sources map (when present) covers
            # imported modules in a multi-file program.
            sources = {filename: source}
            if linked is not None:
                sources.update(linked.sources)
            summary = _rewrite_traceback(
                sys.exc_info(), line_map,
                sources=sources, default_source=source,
            )
            if summary:
                print(summary, file=sys.stderr)
            return 1
        finally:
            sys.argv = saved_argv

    if args.parse:
        # Belt-and-braces (see the analyze call above): the parser
        # caps nesting and flat-chain length so the dumped AST is
        # never deep enough to overflow ``ast_dump``'s recursive walk;
        # convert any leaked RecursionError into a clean error rather
        # than a raw stack trace under ``capa --parse``.
        try:
            print(ast_dump(module))
        except RecursionError:
            msg = (
                f"{filename}: error: expression too deep or complex to "
                "dump; simplify or split it"
            )
            if use_color:
                print(f"{C.RED}{msg}{C.RESET}", file=sys.stderr)
            else:
                print(msg, file=sys.stderr)
            return 1
        return 0

    for tok in tokens:
        if args.no_layout and tok.kind in layout_kinds:
            continue
        pos = f"{tok.start.line:>4}:{tok.start.col:<3}"
        kind_name = tok.kind.name
        text_repr = repr(tok.text) if tok.text else ""
        value_repr = ""
        if tok.value is not None and tok.value != tok.text:
            value_repr = f"  → {tok.value!r}"
        if use_color:
            col = color_for(tok.kind)
            print(
                f"{C.GRAY}{pos}{C.RESET}  "
                f"{col}{kind_name:<14}{C.RESET}  "
                f"{C.DIM}{text_repr}{C.RESET}"
                f"{value_repr}"
            )
        else:
            print(f"{pos}  {kind_name:<14}  {text_repr}{value_repr}")

    return 0


def _parse_preopen_spec(spec: str) -> tuple[str, bool]:
    """Parse one ``--preopen`` value ``<dir>[:ro|:rw]`` into
    ``(host_dir, read_write)``.

    The default permission is READ_WRITE (``rw``), the WASI ``--dir``
    default; an explicit ``:ro`` suffix makes it READ_ONLY and ``:rw`` is
    READ_WRITE. Only a trailing ``:ro`` / ``:rw`` is treated as a
    permission suffix, so a directory name that itself contains a colon
    (or a Windows drive ``C:\\...``) is preserved -- the split is on the
    LAST ``:`` and only when the tail is exactly ``ro`` / ``rw``."""
    read_write = True
    host_dir = spec
    if ":" in spec:
        head, _, tail = spec.rpartition(":")
        if tail in ("ro", "rw") and head:
            host_dir = head
            read_write = tail == "rw"
    return (host_dir, read_write)


def _operator_grants_from_args(preopen_specs) -> dict | None:
    """Build the SBOM ``operator_declared_grants`` block from the
    ``--preopen`` specs, or None when none were declared.

    Each spec ``<dir>[:ro|:rw]`` becomes a preopen entry; the block is
    honestly labelled operator-declared (Level 2) by
    :func:`capa.manifest.build_operator_declared_grants`, distinct from
    the compiler-derived surface."""
    specs = preopen_specs or []
    if not specs:
        return None
    preopens = []
    for spec in specs:
        host_dir, read_write = _parse_preopen_spec(spec)
        preopens.append({
            "kind": "fs",
            "host_dir": host_dir,
            "permission": "rw" if read_write else "ro",
        })
    return build_operator_declared_grants(preopens)


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
            vendored = _Path(__file__).resolve().parent / "wasi_wit" / "deps"
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


def _run_watch_loop(filename: str, program_args: list[str]) -> int:
    """Re-run ``capa --run <filename>`` whenever the target file or
    any of its imported modules changes on disk.

    Strategy: spawn a fresh ``python -m capa --run <file>``
    subprocess on each iteration so the watch process keeps zero
    compilation state across runs. The set of watched files
    starts at the root and expands after each successful run with
    whatever the loader reported as imported sources.

    Ctrl-C exits cleanly (returning 0). A compile error during
    a rerun is shown via the subprocess's own stderr; the
    watcher keeps polling.
    """
    import time
    from datetime import datetime
    from pathlib import Path

    target = Path(filename)
    if not target.exists():
        print(f"capa: --watch: file not found: {filename}", file=sys.stderr)
        return 2

    print(
        f"Capa watch mode. Watching {filename} for changes. "
        f"Ctrl-C to exit.",
        flush=True,
    )

    watched: dict[str, float] = {}

    def _mtime(p: str) -> float:
        try:
            return os.stat(p).st_mtime
        except OSError:
            return 0.0

    watched[str(target.resolve())] = _mtime(str(target))

    def _expand_watched_after_run() -> None:
        # After a successful run, ask the loader which files it
        # touched and add their mtimes to the watch set. Compile
        # errors don't update the set (the previous set stays
        # in place).
        try:
            from capa.loader import ModuleLoader
            source = target.read_text(encoding="utf-8")
            loader = ModuleLoader(search_paths=_capa_search_paths())
            linked = loader.load_root(source, str(target))
            for f in linked.sources.keys():
                f_abs = str(Path(f).resolve())
                if f_abs not in watched:
                    watched[f_abs] = _mtime(f_abs)
        except Exception:
            # Any failure here: parse error in the file, missing
            # import, etc. Keep watching what we already had.
            pass

    def _do_run(separator: bool) -> None:
        if separator:
            # ANSI clear-screen + home; falls back to plain new-
            # lines on terminals that ignore ANSI.
            sys.stdout.write("\x1b[2J\x1b[H")
            sys.stdout.write(
                f"--- rerun at {datetime.now().strftime('%H:%M:%S')} ---\n"
            )
            sys.stdout.flush()
        try:
            cmd = [sys.executable, "-m", "capa", "--run", str(target)]
            if program_args:
                cmd.append("--")
                cmd.extend(program_args)
            subprocess.run(cmd)
        except KeyboardInterrupt:
            # Ctrl-C during the child's run: re-raise so the
            # watcher exits cleanly.
            raise

    # First run is unconditional.
    try:
        _do_run(separator=False)
    except KeyboardInterrupt:
        print()
        return 0
    _expand_watched_after_run()

    # Poll loop.
    try:
        while True:
            time.sleep(0.2)
            changed_any = False
            for f in list(watched.keys()):
                m = _mtime(f)
                if m != watched[f]:
                    watched[f] = m
                    changed_any = True
            if changed_any:
                _do_run(separator=True)
                _expand_watched_after_run()
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
