# Changelog

All notable changes to Capa are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
starting at 1.0; before then, minor-version bumps may introduce
breaking changes and the discipline is still being shaped.

## [Unreleased]

### Added

- **Doc-comment markdown extensions**: `--doc` now renders fenced
  code blocks (triple backticks, with an optional language tag
  emitted as a `class="lang-<name>"` on the inner `<code>`) and
  bulleted lists (lines starting with `- `) inside doc-comment
  bodies. HTML special characters inside code blocks are still
  escaped. Paragraphs and inline `` `code` `` spans continue to
  work as before.

- **Trait section in `--doc`**: plain (non-capability) traits now
  get their own section, listing each method signature and the
  set of types that implement the trait. Capability declarations
  (`capability X`) keep their separate section as before.

### Changed

- **Intel Macs are no longer a release target**. The
  `release-binaries.yml` workflow matrix drops the `macos-13`
  entry; pre-built binaries ship for Linux x86_64, macOS Apple
  Silicon, and Windows x86_64 only. Apple stopped selling Intel
  Macs in 2023 and GitHub's `macos-13` runner pool is unreliable
  (the v0.5.0-alpha Intel job sat queued for over an hour without
  ever picking up a runner). Intel-Mac users install from source
  with Python 3.10+ via `pip install -e .`.

- **Raw string literals**, `r"..."`. No escape processing and no
  `${}` interpolation: every character up to the next `"` is taken
  literally. Useful for Windows paths (`r"C:\Users\..."`) and
  regular-expression patterns (`r"\d+\.\d+"`) where backslashes
  would otherwise need to be doubled. A raw string therefore
  cannot itself contain `"`; for that case use a regular string
  with `\"`. The hash-delimited `r#"..."#` form is not part of
  v1.0. The bare identifier `r` continues to lex as `IDENT`; only
  `r"` triggers the raw-string path.

- **Named arguments**, `f(name: "Ana", age: 30)`. The parser
  accepts an optional `IDENT ":"` prefix on each call argument;
  the analyzer reorders the arguments into parameter order before
  type checking and reports parameter-name typos at the
  offending name; the transpiler emits Python keyword arguments.
  Positional arguments must precede any named argument. Built-in
  methods on `String`, `Map`, `Set`, and on the built-in
  capabilities (`Stdio`, `Net`, `Fs`, ...) reject named arguments
  because their parameter names are not tracked.

### Documentation

- **Indent-based `match` inside parentheses** is now documented as
  a deliberate restriction rather than a known bug. Inside `(...)`
  the lexer suppresses NEWLINE/INDENT/DEDENT to support implicit
  line continuation, so the indent form (`match x` then indented
  arms) cannot be reached. The braced inline form
  (`match x { P1 -> e1, P2 -> e2 }`) works inside a call
  expression and may itself be spread over multiple lines.

## [0.5.0-alpha], 2026-05-12

The fourth tagged release. Focus: independence from Python at
the end-user level, the live HTTPS deployment of the public site,
two new HTML documentation pages, and closing the capability-
attenuation arc.

Users no longer need to install Python to run Capa programs. The
release ships standalone binaries for Linux, macOS Apple Silicon,
and Windows; each bundles the compiler and a Python interpreter
into a single ~8 MB executable. Intel Macs are not shipped as a
pre-built binary (Apple stopped selling Intel Macs in 2023 and
the GitHub Actions Intel runner pool is unreliable); install from
source. The public site is at `https://capa-language.com/` with
HTTPS enforced, HSTS, DNSSEC, full search-engine baseline, and a
per-OS download section on the landing page. The standard library
and language reference docs are now native HTML pages, not bare
markdown. `Random.with_seed` closes the attenuator family so every
built-in capability has one.

### Added

- **Pre-built binaries** for Linux x86_64, macOS Apple Silicon,
  and Windows x86_64. PyInstaller spec at `deploy/capa.spec`
  bundles the compiler and a Python interpreter into a single
  ~8 MB executable, with `.sha256` checksum for verification.
  Built automatically on every version tag by
  `.github/workflows/release-binaries.yml`, a three-platform matrix
  workflow that smoke-tests each binary before uploading to the
  GitHub Release.

- **`Random.with_seed(seed: Int) -> Random`** closes the generic
  attenuation arc. Every built-in capability (`Net`, `Fs`, `Env`,
  `Clock`, `Random`) now has an attenuator. `Random.with_seed`
  returns a deterministic instance whose sequence is a function
  of the integer seed; chained calls re-seed (last wins). Unlike
  the other attenuators there is no denied state, but the audit
  value is in determinism: the manifest's data-flow tracker
  recognises `with_seed` and records it like the `restrict_to*`
  family. Recognised attenuator names are collected in
  `_ATTENUATION_METHODS` for future extensibility.

- **`docs/reference.html` + `docs/stdlib.html`** as native HTML
  pages with the site's chrome, in-page TOC, and tabular method
  references. They replace the broken footer links that
  previously pointed to raw markdown served by GitHub Pages as
  `text/plain`.

- **Download grid on the landing page**, with three clickable
  cards (Linux, macOS, Windows) linking directly to the binary
  in `releases/latest/download/`. The `Get started` page gains
  a per-OS install section with the exact one-liner for each
  platform (curl + chmod for Linux/macOS, Invoke-WebRequest for
  Windows; `xattr -d` for macOS Gatekeeper).

- **SEO + Open Graph metadata** on all ten pages.
  `docs/sitemap.xml` lists every page with realistic lastmod /
  priority; `docs/robots.txt` allows all and points at the
  sitemap. Each page declares page-specific og:title,
  og:description, og:type, og:url, og:image, og:site_name plus
  the matching twitter: equivalents, so links shared on social
  platforms render a structured card with the logo.

- **`community.html` and `brand.html`** site pages, plus the
  hooded-figure logo (header, favicon, hero on landing) and the
  expanded landing-page content (hero code sample, four
  personas, comparison table vs. Python / TypeScript / Rust,
  FAQ with eight questions, release banner).

### Changed

- **`capa --run` executes in-process** via `exec()` rather than
  spawning a subprocess of `sys.executable`. Faster startup, no
  temp-file dance, and survives PyInstaller bundling (the
  subprocess approach assumed `sys.executable` was a generic
  Python interpreter that could run arbitrary `.py` files,
  which fails under PyInstaller). SystemExit propagation
  preserved; runtime tracebacks go to stderr.

- **All in-site `.md` links replaced** with either the matching
  HTML page (Getting started, Tutorial, Reference, Standard
  library) or the rendered GitHub blob URL (white paper, EBNF,
  event-stream demo, SECURITY, CONTRIBUTING). Visitors no
  longer drop onto raw markdown rendered as plain text.

- **Em-dashes removed** from every text file in the repo
  (commit messages, docs, code comments, capa source). Project
  preference is hyphens or commas; the sweep replaced ~430
  occurrences across 63 files.

### Fixed

- `.value-props` and related card grids on the landing/community/
  brand pages now share width equally: added `min-width: 0` so a
  long line in a child `<pre>` triggers `overflow-x: auto`
  rather than stretching the grid column.

- Footer doc links across all eight (now ten) pages no longer
  point at `.md` files served by GitHub Pages as `text/plain`.

### Infrastructure

- **Custom domain `capa-language.com`**, live at HTTPS. DNS
  hosted on Cloudflare with DNSSEC active and the full zone
  reproducible from `deploy/cloudflare-dns.zone`. Cloudflare
  configured with Always Use HTTPS, Full (Strict) SSL/TLS,
  HSTS (max-age six months), Minimum TLS 1.2, and Automatic
  HTTPS Rewrites.

- **`docs/CNAME`** in the repo points GitHub Pages at the
  custom domain.

## [0.4.0-alpha], 2026-05-12

The third tagged release. Focus: closing the audit-artefact loop
and standing the project up on its own domain.

The capability manifest gained a semantic dimension: per-call
data-flow tracking surfaces the actual restriction chain a binding
carries, not just the variable name. The compiler now also emits
HTML documentation generated directly from doc comments, so the
same source produces a machine-readable JSON manifest, a
CycloneDX 1.5 SBOM, and a human-readable doc page. The project
moved off `nelsonduarte.github.io/capa` onto its own DNS at
`capa-language.com`.

### Added

- **Per-call data-flow tracking in the manifest.** Each call site
  in a function's `calls[]` now carries a parallel `args_flow`
  array, the same length as `args`. For arguments that name a
  binding produced by a chain of `.restrict_to*` calls, the entry
  is `{"name": str, "attenuations": [{method, args}, ...]}` in
  source order; for other arguments it is `null`. Example:

  ```
  fun main(net: Net)
      let api = net.restrict_to("api.example.com")
      let narrower = api.restrict_to("v2.api.example.com")
      let ok = fetch_user(narrower, "42")
  ```

  The call record for `fetch_user(narrower, "42")` now reports
  `args_flow[0]` as `narrower` carrying both restrictions, in
  source order. The auditor sees the effective restriction the
  callee received without re-reading the source.

  Scope (v1): only `LetStmt`s with restrict-chain RHSs, only
  intra-function, no scope-awareness (a re-binding inside an `if`
  overwrites the outer one in the map). Method-call resolution
  to a specific `impl` is still out of scope. The syntactic
  `args` field is unchanged; schema_version stays at 1.

- **Doc comments** (`///` line and `/** */` block) attach to the
  next `fun`, `type`, `trait`, or `capability` declaration. The
  block form recognises Javadoc-style `*` left margins and strips
  them, so

      /** line one
       * line two
       */

  reads as `line one\nline two`. Consecutive `///` lines join with
  newlines. `////+` and `/*` (without the second star) remain plain
  comments, dropped by the lexer.

- **`python -m capa --doc`** emits a self-contained HTML page
  documenting every function, type, and user-defined capability in
  a program. Uses the doc comments, capability signatures, and
  attribute metadata already extracted by the analyzer. Inline CSS
  matches the project's dark / accent-purple visual identity. No
  external resources. The human-readable counterpart to the
  machine-readable `--manifest`.

- **Manifest carries doc**: the JSON manifest's per-function and
  per-capability records gain a `doc` field; the CycloneDX output
  surfaces them as `capa:doc` properties on the corresponding
  components.

- **`examples/documented_demo.capa`** uses every form of doc comment
  on a realistic mini-program (capability + impl + factory +
  audited function + CVE-tagged function).

## [0.3.0-alpha], 2026-05-12

The second tagged release. Focus: full CRA alignment of the
capability discipline. The compiler now emits a machine-readable
capability manifest plus a valid CycloneDX 1.5 SBOM with embedded
metadata, and the three remaining built-in capabilities
(`Fs`, `Env`, `Clock`) gained attenuation matching the
`Net.restrict_to` pattern. Function-level audit attributes
(`@security`, `@deprecated`, `@audited`) let authors record CVE
references, deprecation, and audit evidence directly in source.
The website was hardened with a strict Content-Security-Policy
and a Referrer-Policy, and got a proper logo (hooded figure,
purple, with a negative-space C in the body).

### Added

- **Website security hardening.** The static site under `docs/`
  is purely HTML / CSS / SVG (no JavaScript, no external
  resources, no analytics, no fonts off-origin), but the
  defensive headers were missing. All six pages now carry:

  - **Content-Security-Policy** via `<meta http-equiv>`:
    `default-src 'self'; img-src 'self' data:; style-src
    'self'; script-src 'none'; object-src 'none'; base-uri
    'self'; form-action 'self'`. Script execution is denied
    outright; styles must come from the local stylesheet; no
    plugins, no base-tag injection, no form posts off-origin.
  - **Referrer-Policy** `strict-origin-when-cross-origin`, so
    only the origin (not the full path) leaks when a visitor
    clicks an external link.

  To make `style-src 'self'` strict (no `'unsafe-inline'`), the
  seven `style="..."` attributes scattered across the pages were
  refactored into `.section-centered`, `.lead-prose`, and
  `.lead-prose-narrow` classes in `style.css`.

- **`Clock.restrict_to_after(t)` attenuation.** Closes the generic
  attenuation arc started with `Net`, then `Fs` and `Env`. A
  `Clock` can now be narrowed to "active only after time t"
  (seconds since the epoch), the threshold is monotonic across
  chained `restrict_to_after` calls (max wins), and the action
  method `sleep` becomes a silent no-op on a denied Clock
  (fail-closed, consistent with the information-hiding pattern
  used by `Fs.exists` and `Env.get`). Reading the current time
  via `now_secs` / `now_monotonic` stays ungated since it is a
  pure query.

  Example use cases: time-bombed activation, scheduled work that
  is structurally inactive before its window, audit-window
  enforcement.

  `examples/clock_attenuation.capa` demonstrates the pattern with
  one active and one dormant Clock handed to the same helper.

- **Per-call site recording in the manifest.** Each function in
  `--manifest` / `--cyclonedx` output now carries a `calls[]` array
  listing every function and method call in its body, with the
  line:col of the call site and a stringified rendering of the
  argument expressions. An auditor reading the manifest can see,
  for example, that `main` calls `net.restrict_to("api.example.com")`
  on line 5 *before* calling `fetch_user(api, "42")` on line 6 -
  the restriction is visible in the static artefact, no source
  inspection needed.

  Argument expressions are stringified into a Capa-like form
  (literals, identifiers, method chains, field access, struct
  literals, tuple/list literals, etc.) and truncated at 80
  characters with an ellipsis so long literals do not blow up
  the JSON.

  CycloneDX 1.5 output gains `dependencies[]` edges from each
  function to every *function* it calls within the same module.
  Method calls are not yet promoted to edges in v1 because
  resolving `receiver.method` to a specific `impl` requires
  type tracking we have not yet implemented; the call is still
  in `calls[]` of the source function.

- **Generic attenuation: `Fs.restrict_to(prefix)` and
  `Env.restrict_to_keys([...])`.** The `restrict_to` pattern
  established by `Net` now extends to two more built-in
  capabilities. Both narrow monotonically, chaining intersects
  the restriction set, never widens, and both gate every
  operation against the current restriction set *before* any
  system call. Denied operations are information-hiding:
  `Fs.exists` on a denied path returns `False`, and `Env.get`
  on a denied key returns the same `None` as a missing
  variable, so the cap does not leak the existence of resources
  outside its allowed surface.

  Example:

  ```
  fun main(fs: Fs, env: Env, stdio: Stdio)
      let app_fs   = fs.restrict_to("/tmp/myapp/")
      let app_env  = env.restrict_to_keys(["HOME", "APP_TOKEN"])
      do_work(app_fs, app_env, stdio)
  ```

  `do_work` and anything it calls can only touch the filesystem
  under `/tmp/myapp/` and only read the two environment variables,
  no matter what their implementation tries.

- **`examples/fs_env_attenuation.capa`** demonstrating both new
  attenuators and the monotonic-narrowing guarantee.

- **`python -m capa --cyclonedx`**, emits a valid CycloneDX 1.5
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

- **`python -m capa --manifest`**, emits a JSON capability manifest
  describing, for every function in the program: its signature,
  the capabilities it declares, whether it crosses the `Unsafe`
  boundary, and any attached attributes. Module-level entries
  include user-defined capability declarations and their
  implementors, plus a summary count.

  Designed as a CRA-aligned audit artefact: other languages cannot
  emit this because the authority graph is not in their type
  system; in Capa, it falls out of the analyser for free. The
  format is schema-versioned (currently `schema_version: 1`).

- **`examples/manifest_demo.capa`**, a small program showing the
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

## [0.2.0-alpha], 2026-05-11

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
  GitHub Pages at <https://capa-language.com/>.
- **20 example programs** in `examples/` exercising every major
  language feature.
- **420 tests** (unit + end-to-end) green on Ubuntu, macOS, and
  Windows across Python 3.10, 3.12, and 3.14.
- **White paper** (`Capa-WhitePaper.md`) and formal **EBNF grammar**
  (`Capa-EBNF.md`) translated to English and synchronised with the
  implementation.

[Unreleased]: https://github.com/nelsonduarte/capa/compare/v0.5.0-alpha...HEAD
[0.5.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.5.0-alpha
[0.4.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.4.0-alpha
[0.3.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.3.0-alpha
[0.2.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.2.0-alpha
