# Changelog

All notable changes to Capa are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
starting at 1.0; before then, minor-version bumps may introduce
breaking changes and the discipline is still being shaped.

## [Unreleased]

### Added

- **`python -m capa --cyclonedx`** — emits a valid CycloneDX 1.5
  SBOM with the capability manifest embedded as standard
  `properties[]` entries under the `capa:*` namespace. Capa
  programs become first-class citizens of existing SBOM tooling
  (Dependency-Track, OSV-Scanner, syft, sbom-utility) without
  those tools needing to know anything Capa-specific.

  Each function and each user-defined capability becomes a
  `library` sub-component with a deterministic `bom-ref`. The
  call from a function to a user-defined capability is encoded
  both as a `capa:declared_capability` property and as a
  CycloneDX `dependencies[]` edge so dependency-graph tooling
  sees the relation. The serial number is a UUIDv5 derived from
  the filename, so re-running the command produces identical
  output (SBOM diff-friendly across releases of the same file).

- **Function attributes** (`@security`, `@deprecated`, `@audited`) as
  static, source-level metadata. Attributes appear on lines
  immediately before a `fun` declaration (top-level or method inside
  an `impl`), can stack, and accept keyword-style string arguments:

  ```
  @security(cve: "CVE-2024-12345", severity: "high")
  @audited(date: "2026-05-11", by: "Nelson Duarte")
  fun verify_token(token: String, expected: String) -> Bool
      return token == expected
  ```

  The analyzer rejects unknown attribute names, unknown keys, and
  duplicates. The v1 catalogue is fixed: `security`, `deprecated`,
  `audited`.

- **`python -m capa --manifest`** — emits a JSON capability manifest
  describing, for every function in the program: its signature,
  the capabilities it declares, whether it crosses the `Unsafe`
  boundary, and any attached attributes. Module-level entries
  include user-defined capability declarations and their
  implementors, plus a summary count.

  Designed as a CRA-aligned audit artefact: other languages cannot
  emit this because the authority graph is not in their type
  system; in Capa, it falls out of the analyser for free. The
  format is schema-versioned (currently `schema_version: 1`).

- **`examples/manifest_demo.capa`** — a small program showing the
  attribute syntax and a manifest worth reading. Covers a
  user-defined capability and its implementor, an audited method,
  a function with a `@security` annotation, a deprecated function,
  a pure function with no caps, an `Unsafe`-crossing function,
  and a clean entry point.

- **VSCode highlighting** for `@attribute` syntax in the bundled
  extension.

- Repository security hardening: Dependabot vulnerability alerts and
  automated security updates, secret scanning with push protection,
  GitHub private vulnerability reporting, CodeQL workflow
  (security-extended + security-and-quality) on push, PR, and a
  weekly cron, and a `.github/dependabot.yml` that keeps the
  GitHub Actions used by the test workflow up to date.
- `SECURITY.md` describing what counts as a security issue, the
  in-scope / out-of-scope boundary, the private reporting channel,
  supported versions, and the coordinated-disclosure flow.
- `CONTRIBUTING.md` covering dev setup, the compiler architecture
  (lexer → parser → analyzer → transpiler → runtime), what kinds of
  contributions help most, what is currently out of scope, and the
  pull-request conventions.
- `CODE_OF_CONDUCT.md` adopting Contributor Covenant 2.1 by
  reference, with a maintainer contact for reports.
- Issue templates (`bug_report.yml`, `feature_request.yml`) using
  GitHub's YAML issue-form schema with required fields and stage /
  OS dropdowns; a `config.yml` that disables blank issues and links
  to the security advisory channel and Discussions; and a
  `PULL_REQUEST_TEMPLATE.md` with a self-review checklist.

### Changed

- Default `GITHUB_TOKEN` permission in `.github/workflows/tests.yml`
  set to `contents: read`. Any future job that needs broader scope
  must opt in explicitly.

## [0.2.0-alpha] — 2026-05-11

First public release. Capa goes from private development to a
public, MIT-licensed, security-hardened repository with a five-page
documentation site, runnable examples, a syntax-highlighting editor
extension, and a comprehensive test suite green on three operating
systems and three Python versions.

### Added

#### Language

- **Capability discipline** enforced at three layers:
  - Structural: capabilities can appear only as function parameters
    (not struct fields, variant payloads, return types, constants,
    locals, or generic args), with a single relaxation for
    cap-bearing structs that implement a user-defined capability.
  - Flow: the same capability cannot be passed as two arguments of
    the same call; declared capability parameters must be used
    (or prefixed with `_`).
  - Linear: the `consume` qualifier marks parameters that take
    ownership, with fork/merge tracking across branches and loops.
- **Seven built-in capabilities**: `Stdio`, `Fs`, `Net`, `Env`,
  `Clock`, `Random`, and `Unsafe` (the explicit escape hatch for
  Python interop).
- **User-defined capabilities** via the `capability X` declaration
  and `impl X for Y` (WhitePaper §4.6). The discipline applies
  uniformly to user-defined and built-in capabilities.
- **First-class attenuation on `Net`**: `Net.restrict_to(host)`
  returns a fresh `Net` whose authority is narrowed to a single
  host. Chaining restrictions intersects allowed-host sets;
  restrictions only narrow, never widen. The runtime check fires
  before any system call.
- **Range expressions**: `a..b` (exclusive) and `a..=b` (inclusive),
  first-class values that can be stored, iterated, and passed.
- **Inline `match` expression form**: `match s { p -> e, p -> e [,] }`
  for one-line matches.
- **`to_int` / `to_float` builtins** for numeric conversion.
- **Types**: `Int`, `Float`, `Bool`, `String`, `Char`, `Unit`,
  tuples, `List`, `Map`, `Set`, `Option`, `Result`, `Fun(...) -> ...`.
- **Generics** with type inference at call sites.
- **Pattern matching** with literal, variant, tuple, and nested
  patterns; exhaustive over covered cases.
- **Closures** as first-class values (`fun (x: Int) -> Int => x * 2`).
- **`?` operator** for `Result` unwrap-or-early-return.
- **String interpolation** with `${...}`.
- **Numeric literals** in decimal, hex (`0x`), octal (`0o`), binary
  (`0b`), with `_` separators.

#### Compiler

- Hand-written four-stage pipeline in pure Python with zero runtime
  dependencies outside the standard library: lexer (with
  significant-indentation handling), recursive-descent parser,
  semantic analyzer (name resolution + types + capability
  discipline), and Python 3.10+ transpiler.
- CLI with five modes: tokenize (default), `--parse`, `--check`,
  `--transpile`, `--run`.
- Programmatic API exposing `Lexer`, `Parser`, `analyze`, and
  `transpile` as a library.
- Module naming convention (`capa_ast.py`, `typesys.py`) chosen to
  avoid colliding with Python stdlib modules under `python -m capa`.

#### Tooling and docs

- **VSCode syntax-highlighting extension** under `vscode/`: TextMate
  grammar covering keywords by category, built-in capabilities
  highlighted distinctly, string interpolation, numeric literals in
  all bases, operators (`..`, `..=`, `=>`, `?`).
- **Event-stream supply-chain demo**: a safe Capa version of the
  `flat_map` function whose JavaScript counterpart shipped a
  Bitcoin-wallet exfiltrator in 2018, plus attack-attempt code
  rejected by the analyzer with source-aligned errors. Lives in
  `examples/demo_event_stream.capa` + `docs/demo-event-stream.md`.
- **Five-page static website** under `docs/` (one stylesheet, no
  JavaScript, no framework, no external fonts): `index.html`,
  `why.html`, `tour.html`, `start.html`, `roadmap.html`. Served by
  GitHub Pages at <https://nelsonduarte.github.io/capa/>.
- **20 example programs** in `examples/` exercising every major
  language feature.
- **420 tests** (unit + end-to-end) green on Ubuntu, macOS, and
  Windows across Python 3.10, 3.12, and 3.14.
- **White paper** (`Capa-WhitePaper.md`) and formal **EBNF grammar**
  (`Capa-EBNF.md`) translated to English and synchronised with the
  implementation.

[Unreleased]: https://github.com/nelsonduarte/capa/compare/v0.2.0-alpha...HEAD
[0.2.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.2.0-alpha
