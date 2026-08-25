"""Argument-parser construction for the Capa CLI.

Leaf module for :mod:`capa.cli`: :func:`build_parser` builds the
top-level flag-based ``ArgumentParser`` (its ``--help`` is the CLI's
front page), and the argv-shape classifiers decide which prefix of
argv the compiler owns (:func:`_compiler_owned_args`, the split on
``--``) and which invocations bypass the compiler-floor gate
(:func:`_floor_check_exempt`). It imports nothing from :mod:`capa.cli`;
the dependency runs one way, ``capa.cli`` -> ``capa.cli._parser``.
"""

import argparse

from capa import __version__ as _CAPA_VERSION


# wasm32 caps linear memory at 65536 pages of 64 KiB = 4 GiB. A
# ``--wasm-memory-cap`` above this produces a module that wasm-tools
# rejects, so the CLI refuses it rather than writing an invalid
# artifact (audit slice 30 P2-b). The bound for the --wasm-memory-cap
# argument built here, shared by both validators (the build subcommand
# and the --wasm path in _main_dispatch).
_WASM32_MAX_PAGES = 65536


# Subcommands that must run even when the root manifest's declared
# compiler floor is violated, and the reason each one is here. This is
# not a convenience list; every entry is a case where hard-erroring
# would take away the user's route out of the error.
#
#   search  queries the registry and needs no local manifest at all.
#   add     WRITES capa.toml. Blocking it would stop the user repairing
#           the very file that is blocking them.
#   init    scaffolds a NEW project, in a directory that is not the one
#           whose manifest is at fault.
#   lsp     speaks LSP on stdout. A hard error there makes an editor
#           silently lose language support, with the reason in a stderr
#           the editor discards.
#
# ``--help`` and ``--version`` are handled separately below, because
# neither is positional.
_FLOOR_EXEMPT_COMMANDS = frozenset({"search", "add", "init", "lsp"})


# Commands section appended to `capa --help`. The top-level parser is
# flag-based; the subcommands below are dispatched by hand before
# argparse runs (see ``_main_dispatch``), so argparse cannot advertise
# them on its own. This epilog keeps them discoverable. Each summary is
# a one-line condensation of that subcommand's own parser description.
_COMMANDS_EPILOG = (
    "commands:\n"
    "  init      Scaffold a minimal Capa project (main.capa, README, .gitignore).\n"
    "  add       Declare a new dependency in capa.toml and install it into vendor/.\n"
    "  install   Resolve capa.toml dependencies into vendor/, and write capa.lock.\n"
    "  search    Search the package registry by name and description.\n"
    "  test      Run the project's Capa tests (tests/test_*.capa), like `capa --run`.\n"
    "  build     Ahead-of-time compile a Capa program to a portable AOT artifact.\n"
    "  run-aot   Run an AOT artifact built by `capa build --release`.\n"
    "  migrate   Report Python-to-Capa gradual-hardening progress for a .capa file.\n"
    "  lsp       Start the Capa language server (LSP) on stdin/stdout.\n"
    "  repl      Start the interactive Capa REPL.\n"
    "\n"
    "Run 'capa <command> --help' for options of a specific command."
)


def _compiler_owned_args(argv: list[str]) -> list[str]:
    """The prefix of ``argv`` the COMPILER owns, i.e. everything before
    the first ``--``.

    ``--`` is the boundary between the compiler's arguments and the
    transpiled program's: ``_main_dispatch`` forwards the tail to the
    program through ``sys.argv``, where ``env.args()`` reads it. Both
    the split in ``_main_dispatch`` and the floor / broken-manifest
    exemption in :func:`_floor_check_exempt` go through this one
    function ON PURPOSE. They used to compute the boundary separately,
    the exemption not computing it at all, and a ``--help`` meant for
    the program then switched the compiler's own gate off.

    When there is no separator the whole list is compiler-owned, so
    behaviour is unchanged for every invocation that does not use one.
    """
    if "--" in argv:
        return argv[:argv.index("--")]
    return argv


def _floor_check_exempt(argv: list[str]) -> bool:
    """Should the compiler-floor gate be skipped for this invocation?

    ``argv`` is the argument list WITHOUT the program name.

    **Everything at or after a ``--`` separator is discarded first, and
    that is load-bearing rather than tidy.** ``--`` is where the CLI
    stops owning the arguments: ``_main_dispatch`` splits on it and
    forwards the tail to the transpiled program through ``env.args()``.
    Computing this predicate over RAW argv let the PROGRAM's arguments
    decide whether the COMPILER enforced its own gate, which is a
    bypass and not a nicety:

    .. code-block:: text

        project declares capa = ">=99.0.0", compiler is 1.19.0

        capa app.capa --run              -> EXIT=1, floor refused
        capa app.capa --run -- --help    -> EXIT=0, built and ran, silently

    A Capa program that takes ``--help`` is ordinary, so that was an
    accident waiting to be tripped over rather than an attack. The same
    shape defeated the broken-manifest refusal, which shares this gate.
    The invariant to preserve when editing: **this function must never
    read an argument the compiler does not own.**

    Three exemptions beyond the command list:

      * **no compiler arguments at all.** Bare ``capa`` prints usage;
        there is nothing to build and nothing to refuse. ``capa --
        <anything>`` lands here too, and for the same reason rather than
        by accident: argparse is then handed no file and no ``--stdin``,
        so no source is compiled and no artefact is emitted.
      * **``--help`` / ``-h`` ANYWHERE in the compiler's argv.** Not
        just at argv[0]: ``capa build --help`` puts ``build`` first, so
        a naive ``argv[0] in _FLOOR_EXEMPT_COMMANDS`` test would gate
        the help of every subcommand.
      * **``--version``.** This is an argparse ``action="version"``,
        handled inside ``_main_dispatch`` well after this gate. Without
        the exemption, a floor violation would brick the one command the
        error message tells the user to run in order to see which
        compiler they actually have. There is no ``-V`` short form on
        this parser, so none is exempted; adding one here that does not
        exist would only mislead the next reader.
    """
    argv = _compiler_owned_args(argv)
    if not argv:
        return True
    if any(a in ("--help", "-h", "--version") for a in argv):
        return True
    return argv[0] in _FLOOR_EXEMPT_COMMANDS


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level Capa CLI argument parser.

    Flag-based (the subcommands are dispatched by hand before argparse
    in ``_main_dispatch``); the epilog lists them. Takes no runtime
    state, so ``capa --help`` is a pure function of the module-level
    version string and the commands epilog."""
    parser = argparse.ArgumentParser(
        description="Lexer, parser and analyzer for the Capa language",
        epilog=_COMMANDS_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        "--manifest-digest",
        action="store_true",
        help=(
            "emit the CANONICAL, content-addressable capability manifest: "
            "the same manifest as --manifest, serialised in a byte-stable "
            "key-sorted form and wrapped with a content_integrity envelope "
            "carrying a sha256 digest over the canonical bytes plus an "
            "(empty) detached-signature slot. Byte-reproducible across "
            "runs and machines; the digest is what an external signer "
            "signs (the compiler holds no keys)."
        ),
    )
    parser.add_argument(
        "--compose-sbom",
        action="store_true",
        help=(
            "emit the COMPOSED capability SBOM for the whole PRODUCT: "
            "attribute the flattened manifest's functions to their owning "
            "package (root or vendor/<dep>), walk the dependency DAG "
            "(reading each vendored dependency's own capa.toml), and roll "
            "the capability surface up bottom-up. A declared dependency "
            "that is not analyzable (no vendored Capa source, an "
            "absent/unreadable capa.toml, a native/non-Capa dependency) "
            "composes as a distinguished authority-UNKNOWN element that "
            "dominates the join and is visibly labelled, so an "
            "unanalyzable subtree makes the product authority-unknown, not "
            "dishonestly clean. Requires a capa.toml project root. "
            "Canonical / content-addressable (reuses --manifest-digest's "
            "byte-stable form)."
        ),
    )
    parser.add_argument(
        "--check-capabilities",
        action="store_true",
        help=(
            "CI GATE: compose the product SBOM and verify every package "
            "against its declared capa.toml [capabilities] ceiling "
            "(max = [...] or pure = true). EXITS NON-ZERO on any violation "
            "with an actionable message naming the offending capability and "
            "the transitive dependency edge that introduces it. A package "
            "whose composed authority is UNKNOWN (an unresolvable / native / "
            "Unsafe-crossing dependency in its subtree) FAILS CLOSED - an "
            "unanalyzable subtree cannot be proven within any ceiling - "
            "unless it sets allow_unknown = true. A clean product (or one "
            "with no declared ceiling) exits 0. Requires a capa.toml project "
            "root."
        ),
    )
    parser.add_argument(
        "--conformance-report",
        action="store_true",
        help=(
            "emit the signed CONFORMANCE REPORT for the product-level "
            "capa-policy.toml: compose the product SBOM, evaluate every "
            "declared organization compliance policy (exclusion, "
            "product-subset, purity, forbid-capability, forbid-dependency, "
            "no-unresolved-dependencies) over the composed capability graph, "
            "and emit the per-policy pass/fail results wrapped in the same "
            "content_integrity envelope as --compose-sbom (canonical, "
            "byte-reproducible, signABLE; the compiler holds no keys). A "
            "policy that quantifies over an authority-UNKNOWN subtree FAILS "
            "CLOSED unless it sets allow_unknown = true. Requires a capa.toml "
            "project root; emits an empty report when no capa-policy.toml is "
            "present."
        ),
    )
    parser.add_argument(
        "--check-policies",
        action="store_true",
        help=(
            "CI GATE: compose the product SBOM and verify it against the "
            "product-level capa-policy.toml organization compliance policies. "
            "EXITS NON-ZERO on any policy failure with an actionable "
            "per-violation message. A policy that quantifies over an "
            "authority-UNKNOWN subtree (an unresolvable / native / "
            "Unsafe-crossing dependency) FAILS CLOSED - an unanalyzable "
            "subtree cannot be proven to satisfy a capability predicate - "
            "unless it sets allow_unknown = true. A clean product exits 0; a "
            "product with no capa-policy.toml (or no policies) exits 0 with "
            "'nothing to verify'. Requires a capa.toml project root."
        ),
    )
    parser.add_argument(
        "--capability-diff",
        nargs=2,
        metavar=("<old.json>", "<new.json>"),
        dest="capability_diff",
        default=None,
        help=(
            "emit a signed AUTHORITY CHANGELOG between two capability "
            "artifacts (the JSON --manifest / --manifest-digest / "
            "--compose-sbom already produce): for each EXPORTED function "
            "and for the product, which capabilities were GAINED "
            "(widening) or LOST (narrowing), which provably-excluded "
            "GUARANTEE was lost, and any operator-grant / authority-unknown "
            "transition. Functions are matched by the stable "
            "(container, name) identity, never by source position, so a "
            "line-only move produces no entry. The changelog records both "
            "inputs' content digests (from_digest / to_digest) and is "
            "wrapped in the same content_integrity envelope as "
            "--manifest-digest (byte-reproducible, signABLE; the compiler "
            "holds no keys). Takes no .capa file."
        ),
    )
    parser.add_argument(
        "--fail-on-widening",
        action="store_true",
        dest="fail_on_widening",
        help=(
            "CI GATE for --capability-diff: EXIT NON-ZERO when the "
            "changelog contains any WIDENING (a function or the product "
            "gained authority, a guarantee was lost, or an operator grant "
            "was added / widened) or an authority-UNKNOWN transition, so a "
            "release pipeline can block or require sign-off on an authority "
            "increase. A pure narrowing / no-change exits 0."
        ),
    )
    parser.add_argument(
        "--cyclonedx",
        action="store_true",
        help=(
            "emit a CycloneDX 1.6 SBOM with the capability manifest "
            "embedded as standard properties[] entries, plus one component "
            "per resolved capa.toml dependency (name + version + purl); "
            "consumable by Dependency-Track, OSV-Scanner, syft, etc. Set "
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
        "--allow-host",
        action="append",
        default=None,
        metavar="<host>[:get|:post]",
        help=(
            "with --wasi, grant the component network authority to reach "
            "<host> as an OPERATOR-DECLARED Net grant (the Net analogue of "
            "--preopen), unblocking a DYNAMIC (argv-derived / computed) "
            "URL that the compiler otherwise rejects fail-closed. Repeatable "
            "(the allowlist is a set). <host> may be a bare host, host:port, "
            "or a URL; it is normalized (lowercased, port/userinfo stripped, "
            "trailing dot removed) to the exact-hostname key the guest gate "
            "checks. Append ':get' to grant READ (GET) only or ':post' to "
            "grant WRITE (POST) only; with no suffix the host is granted for "
            "BOTH (least-authority: ':get' lets a program read from a host "
            "without permitting a POST). Recorded in the SBOM as "
            "operator-declared, distinct from the compiler-derived surface. "
            "LIMITATION: a hostname allowlist cannot defend against DNS "
            "rebinding (wasi:http is host-side allow-all, so the resolved IP "
            "is not filtered); granting an internal/link-local IP warns but "
            "is allowed."
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
        "--foreign-fuel",
        type=int,
        default=None,
        metavar="<N>",
        help=(
            "with --wasm --run, bound the CPU an untrusted foreign "
            "component (feature #4) may burn per call to N fuel units "
            "(~1 per wasm instruction). An infinite loop / CPU spin then "
            "TRAPS cleanly on fuel exhaustion instead of hanging the "
            "host. Default: 1000000000 (1e9). Use 0 to skip the CPU "
            "bound (host decides)."
        ),
    )
    parser.add_argument(
        "--foreign-memory-cap",
        type=int,
        default=None,
        metavar="<MiB>",
        help=(
            "with --wasm --run, cap the linear memory an untrusted "
            "foreign component (feature #4) may grow to, in MiB. A "
            "runaway self-allocation is refused instead of OOM-ing the "
            "host. Default: 256 MiB. Use 0 to skip the memory bound "
            "(host decides)."
        ),
    )
    parser.add_argument(
        "--foreign-result-cap",
        type=int,
        default=None,
        metavar="<MiB>",
        help=(
            "with --wasm --run, cap the RESULT an untrusted foreign "
            "component (feature #4) may make a granted host-mediated "
            "closure materialise, in MiB: an fs.read file, a net body, a "
            "db.query result set. The fuel / memory caps bound the child "
            "store; this bounds the HOST-side buffer, so a child cannot "
            "OOM the host by reading a multi-GiB result. The read aborts "
            "early instead of buffering the whole result. Default: 256 "
            "MiB. Use 0 to skip the result bound (host decides)."
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
    return parser
