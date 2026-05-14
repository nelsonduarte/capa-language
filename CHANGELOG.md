# Changelog

All notable changes to Capa are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
starting at 1.0; before then, minor-version bumps may introduce
breaking changes and the discipline is still being shaped.

## [Unreleased]

### Added

- **Runtime-overhead benchmark suite** (`benchmarks/`): a small
  set of paired Capa + hand-Python workloads timed in-process
  with `timeit.repeat`. Three workloads cover three regimes
  (pure compute via `fib(25)`, list-heavy via a 1000-element
  scope analyser, string-heavy via 1000-string user-agent
  parsing). Each `.capa` has a matching `_baseline.py` with
  the same algorithm in idiomatic Python; the runner transpiles
  the Capa once, imports both as modules, and reports
  mean/stdev plus the ratio. Headline numbers on CPython 3.14:
  **1.00x for pure compute, 1.20x for list-heavy, 1.45x for
  string-heavy**. The thesis chapter on practical overhead can
  now cite numbers instead of hand-waving. Methodology and a
  detailed breakdown of what is and is not measured live in
  `benchmarks/README.md`.

- **CVE case study: ua-parser-js 2021 (npm account hijack,
  cryptominer + RAT)** (`examples/cve_ua_parser_js.capa` +
  `docs/cve_ua_parser_js.md`). The sixth CVE walkthrough and
  the fourth clean win. On 22 Oct 2021 the maintainer's npm
  account for `ua-parser-js` (about 7-8M weekly downloads) was
  compromised; three malicious versions shipped a `preinstall`
  script that, on Linux, downloaded an XMRig-based
  cryptominer, and on Windows additionally dropped DanaBot, a
  credential-stealing RAT. The case study is in the repo
  specifically to make the **payload-independence** point:
  same attack mechanism as eslint-scope 2018 (account
  hijack), wildly different payload (cryptominer + RAT vs
  npm token theft), and Capa's response is structurally
  identical. `ua-parser-js` also has the *cleanest* possible
  signature of any of the case studies (`(String) ->
  UserAgent`), so the "the declared signature should mention
  `Fs` if the function reads files" argument is at its most
  rhetorically forceful here. Regression test in
  `tests/test_transpiler.py::test_cve_ua_parser_js`. With
  this sixth study the experimental section now covers four
  clean wins (event-stream, eslint-scope, ua-parser-js,
  torchtriton) and two honest partial losses (node-ipc,
  xz-utils) across two ecosystems (npm, PyPI) and seven
  years (2018-2024).

- **CVE case study: torchtriton 2022 (PyPI typosquat)**
  (`examples/cve_torchtriton.capa` +
  `docs/cve_torchtriton.md`). The fifth CVE walkthrough and
  the third clean win, covering the Python / PyPI ecosystem
  (after event-stream and eslint-scope on npm). Recaps the
  attack: between 25-30 Dec 2022 a malicious PyPI package
  named `torchtriton` was installed by anyone running
  PyTorch's nightly build, because pip's default resolution
  preferred public PyPI over the private index. The payload
  walked `$HOME`, captured SSH keys and env vars, and POSTed
  to `*.h4ck.cfd`. The Capa-shaped kernel-launch-planning
  library has zero capabilities; the typosquat's
  `Fs + Net + Env` widening is a loud SBOM diff. With this
  fifth study the experimental section is now balanced: 3
  wins covering different ecosystems / shapes
  (malicious-dependency, credential-theft, typosquat) and
  2 honest partial losses (legitimate-authority-abuse,
  below-the-language). Regression test in
  `tests/test_transpiler.py::test_cve_torchtriton`. The
  full breakdown lives in `docs/cve_torchtriton.md`
  § "The five-case-study summary".

- **CVE case study: xz-utils 2024 / CVE-2024-3094**
  (`examples/cve_xz_utils.capa` + `docs/cve_xz_utils.md`). The
  fourth CVE walkthrough, and the most pessimistic one: a
  multi-year operation by "Jia Tan" against `xz-utils`,
  delivering a backdoor that hijacked
  `RSA_public_decrypt` in sshd via IFUNC dynamic-linker
  indirection. The attack ran beneath the language layer
  entirely: obfuscated payload bytes in test fixture files,
  build-script assembly via `.m4` autotools, and runtime
  symbol replacement at `ld.so` load time. Capa's source-
  level discipline cannot address any of those. The case
  study is in the repo precisely because a thesis that
  claims any supply-chain defence has to acknowledge attacks
  beneath the language layer. The writeup includes a layered
  table of attack surfaces and which ones Capa addresses
  (one row well, one row partially, four rows not at all).
  Pairs with the
  [positioning document](docs/positioning.md)'s "Capa is one
  defence in a stack, not a sufficient defence" claim and
  references reproducible builds, code signing, transparency
  logs as the orthogonal defences the rest of the stack
  needs. Regression test in
  `tests/test_transpiler.py::test_cve_xz_utils`.

- **Property-based testing phase 3.7**: the multi-cap
  strategy `_program_with_caps_advanced` now also samples a
  ``consumed`` flavour. The strategy emits a helper
  ``fun take_{cap}(consume {var}: {Cap}) -> Bool`` that
  takes the capability with the ``consume`` qualifier (so
  the caller cannot use it afterwards), probes it inside
  the helper, and returns. Main calls ``take_{cap}({var})``
  exactly once per consumed capability, satisfying the
  use-after-consume rule by construction (the call is the
  last action on that capability in main's body).

  Programs in the wild now mix four flavours: ``plain``
  (3.5), ``attenuated``, ``via_helper`` (3.6),
  ``consumed`` (3.7). The renamed test method
  `test_runtime_subset_under_advanced_flavours` runs 50
  Hypothesis examples per CI run; sampling typically
  produces programs that mix all four flavours across the
  declared capabilities. All four preserve
  `runtime_classes ⊆ manifest_classes` by construction; the
  test now also catches use-after-consume regressions in
  the analyser's linear layer alongside the structural and
  flow-layer regressions covered by the earlier phases.
  The property-testing arc of the external whitepaper
  review is now closed.

- **Property-based testing phase 3.6**: introduced the
  three-flavour advanced strategy (plain / attenuated /
  via_helper) that phase 3.7 extends. See the entry above.

- **Property-based testing phase 3.5**: the
  `runtime_caps ⊆ manifest_caps` property is now exercised on
  *non-trivial* inclusions. A new Hypothesis strategy
  `_program_with_caps` threads a random subset of
  `{Fs, Net, Env, Clock, Random}` through `main`'s parameter
  list (alongside the mandatory `Stdio`) and emits one
  read-only probe per declared capability so each is exercised
  at least once. The probes are
  `Fs.allows`, `Net.allows`, `Env.allows`, `Clock.now_secs`,
  `Random.float_unit`, each a pure query with no real
  filesystem or network side effect, so the test stays
  self-contained. New test method
  `TestRuntimeSubsetOfManifest.test_runtime_classes_subset_with_multiple_caps`
  runs 50 examples per CI run; sampling typically produces
  10 to 15 distinct main-signature shapes per run. With this
  the citable thesis property has actual fuzz coverage, not
  just a scaffold.

- **Property-based testing phase 3 (minimal)**: the dynamic
  counterpart of Theorem 2 from `docs/semantics.md`. New
  module `capa/runtime/_trace.py` provides an opt-in
  instrumentation that wraps every public method on every
  built-in capability class so each call appends
  `(class_name, op_name)` to a module-level list. The new
  `TestRuntimeSubsetOfManifest` test class in
  `tests/test_properties.py` runs a generated program with
  the trace enabled, then asserts that the set of capability
  classes observed at runtime is a subset of the set
  declared in the manifest emitted from the AST. Phase 3.5
  (still pending) extends the strategy to thread
  Net / Fs / Env through `main` and exercise them so the
  inclusion is non-trivial; today the strategy only uses
  Stdio so the property is `{Stdio} ⊆ {Stdio}`. The
  *scaffold* is the point: the citable property has a place
  to live and a path to broader coverage.

- **Property-based testing phase 2** (syntax-aware Capa
  program generator). Adds one new property to
  `tests/test_properties.py`: every program produced by a
  small Hypothesis composite strategy (a `main(stdio: Stdio)`
  body with 1-4 statements drawn from `let` / `var` /
  `println` / `if` / `for`, using position-indexed unique
  identifiers to avoid duplicate bindings, and integer
  literals only in expressions to avoid scope-tracking
  complexity) is asserted to lex, parse, analyse, transpile,
  and produce syntactically-valid Python. The strategy
  found two real design bugs during its own development
  (capability-must-use violation when `main` was generated
  without a `stdio` reference; duplicate `let` bindings when
  names were sampled from a fixed pool), exactly the kind of
  signal property-based testing exists to surface. 100
  Hypothesis examples per CI run, ~1 second wall clock.
  The phase 3 work (the actual citable property *runtime
  capability set ⊆ manifest declared set*) needs runtime
  instrumentation and a capability-exercising strategy; it
  is tracked in `TODO.md` and corresponds to Theorem 2 of
  `docs/semantics.md`.

- **CVE case study: node-ipc 2022 (protestware)**
  (`examples/cve_node_ipc.capa` + `docs/cve_node_ipc.md`). The
  third CVE walkthrough in the repo, deliberately picked as the
  case where **Capa partially loses**: the package's legitimate
  role (inter-process communication) requires `Net` and `Fs`,
  so a rogue maintainer with legitimate authority can misuse
  those capabilities within the bounds the type system allows.
  The structural discipline that handled event-stream and
  eslint-scope cleanly does not stop this one. The writeup is
  explicit about that, and walks through what Capa still does
  in this regime: the authority surface is SBOM-visible (not
  hand-authored guesses), the caller can attenuate
  (`net.restrict_to`, `fs.restrict_to`) so the blast radius
  shrinks to a single host or directory, and the audit on the
  SBOM flags any future widening of the declared capability.
  Honest scope claim: Capa raises the bar on supply-chain
  attacks; the height matters, but the ceiling above which it
  does not reach (maintainer takeover, author-as-attacker) is
  a scope limit that orthogonal defences (code signing,
  reproducible builds, transparency logs) have to cover.
  Regression test in
  `tests/test_transpiler.py::test_cve_node_ipc`.

- **CVE case study: eslint-scope 2018**
  (`examples/cve_eslint_scope.capa` +
  `docs/cve_eslint_scope.md`). A miniature scope analyser whose
  signature `(List<Decl>) -> List<Binding>` precludes the
  `Fs`-read + `Net`-POST behaviour that the malicious
  `eslint-scope@3.7.2` carried on 12 July 2018. The companion
  writeup walks through the attack (read `~/.npmrc`, exfiltrate
  the `_authToken` to a Pastebin drop, overwrite the malicious
  code with the legitimate version), the analyzer rejection of
  the transliterated attack, the role of `Fs.restrict_to` as
  defence in depth, and the honest limits (capability holder
  with bad intent, the `Unsafe` boundary, Capa is not a
  sandbox). The second CVE case study in the repo; the
  first was the event-stream walkthrough. Both follow the same
  paired-file pattern so a third is mechanical to add. The
  CRA-aligned policy story for an auditor reading the
  resulting SBOM is in
  `examples/sbom_capability_audit.capa`. Regression test in
  `tests/test_transpiler.py::test_cve_eslint_scope`.

- **Property-based test scaffolding** with Hypothesis, in
  `tests/test_properties.py`. Six initial properties that
  exercise the lexer, parser, and formatter over arbitrary
  printable text (~200 examples per property per CI run):
  formatter idempotence (`format(format(s)) == format(s)`),
  formatter fixpoint convergence in one step, formatter
  output satisfies `is_formatted`, lexer terminates on every
  input with either a valid token list or a `LexerError`,
  same for the parser on well-formed token streams. The
  invariants are conservative on purpose, they hold over the
  entire input space, so they make a stable CI floor without
  needing a Capa-grammar generator. The richer
  "runtime capability set ⊆ manifest declared set" property
  needs a syntax-aware program generator and is phase 2.
  Hypothesis is now an optional dev dependency
  (`pip install -e .[test]`).

- **`docs/semantics.md`** is the working sketch of *λ_cap*, a
  minimal lambda calculus that captures Capa's capability
  discipline at a level a paper reviewer can engage with.
  Defines syntax, typing rules (with a split between
  non-linear and linear contexts so the consume discipline
  rides on standard linear-types machinery), and small-step
  operational semantics with a trace recording every
  capability invocation. States two soundness theorems
  with proof sketches: *Capability Soundness* says every
  invocation in the trace has a class drawn from the
  program's initial capability environment, *Manifest
  Completeness* says the manifest is an upper bound on the
  dynamic capability surface. Deferred to the full thesis
  writeup: the branch/loop bookkeeping of the linear layer,
  attenuation completeness as a lattice property, the
  `Unsafe` boundary's relativised soundness, and the
  translation lemma from full Capa to λ_cap. Linked from
  `WHITEPAPER.md` and `docs/positioning.md`. The intended
  next step is mechanising Theorem 1 in Agda or Coq for
  workshop-paper submission.

- **`docs/positioning.md`** captures the honest case for the
  language: what is and is not unique about Capa, which parts of
  the design predate it (capability typing as an idea is decades
  old), which adjacent languages and tools work in the same
  intellectual space (Pony, Koka / Eff / OCaml 5 effect handlers,
  Haskell with phantom types, Roc, the WebAssembly Component
  Model with WIT), and what one-sentence claim Capa stands
  behind when challenged with "you could do this in Python".
  The page is intended for reviewers and contributors. Linked
  from `docs/why.html` and `WHITEPAPER.md`.

- **SBOM ↔ capability-policy audit, written in Capa**
  (`examples/sbom_capability_audit.capa`): the "auditable
  supply chain" pitch made concrete. End-to-end pipeline with
  real file IO: reads both a CycloneDX SBOM and a JSON policy
  file via the `Fs` capability (attenuated to
  `examples/data/` via `Fs.restrict_to` before either file is
  opened, so the auditor cannot exfiltrate anything outside
  its declared input directory), extracts each function's
  declared capabilities from the `capa:declared_capability`
  properties, and checks them against the per-function
  allow-list. Reports a per-function summary plus a numbered
  list of violations. The novel part vs npm / PyPI / cargo
  SBOM tooling: both sides of the comparison are static.
  Capa's type system makes the declared set rigorous, and the
  audit is a syntactic comparison of two finite lists. A diff
  between SBOM and policy is unambiguous, and it travels with
  the build artefact. Sample data at
  `examples/data/demo-sbom.json` +
  `examples/data/demo-policy.json` (the policy deliberately
  omits one function so the audit fires on a single run).
  Regression test in
  `tests/test_transpiler.py::test_sbom_capability_audit`.

- **Missing capability-attenuator methods registered in the
  builtins table**: `Fs.restrict_to`, `Fs.allows`,
  `Env.restrict_to_keys`, `Env.allows`,
  `Clock.restrict_to_after`, `Clock.allows`, and
  `Random.with_seed` are runtime methods on the
  corresponding capability classes but were not listed in
  `capa/builtins.py`. Before the recent capability-method
  strictness change they slipped through as TyUnknown; that
  change exposed the gap. All five attenuators are now
  type-checked properly, including the return type narrowing
  (`Fs.restrict_to(p) -> Fs`, `Env.restrict_to_keys(ks) -> Env`,
  `Clock.restrict_to_after(t) -> Clock`,
  `Random.with_seed(seed) -> Random`).

- **SPDX license-expression parser, written in Capa**
  (`examples/spdx_license_expr.capa`): a recursive-descent
  parser for the SPDX 2.3 Annex D grammar used in every
  `licenseDeclared` / `licenseConcluded` field of every Package
  in an SBOM. Handles the three precedence levels (`OR` <
  `AND` < `WITH`), parenthesised sub-expressions, and the
  `LicenseRef-...` / `DocumentRef-...` identifier shapes.
  The AST is a sum type (`LicenseId` / `LicenseRef` /
  `WithExc` / `AndAll` / `OrAny`) with mutually recursive
  struct payloads, and a precedence-aware renderer round-trips
  the AST back to source: redundant parens are dropped (e.g.
  `(GPL-2.0-only WITH X) OR Apache-2.0` -> `GPL-2.0-only WITH
  X OR Apache-2.0` because WITH binds tighter than OR), but
  load-bearing parens are preserved (`(MIT OR Apache-2.0) AND
  GPL-3.0-only` stays as-is because OR is lower than AND).
  Malformed input surfaces as a structured `Result<_, String>`
  error with positional context. Regression test in
  `tests/test_transpiler.py::test_spdx_license_expr`.

- **SBOM validation in both parsers, referential integrity +
  cycle detection**:
  `validate_spdx(doc: SpdxDocument) -> List<String>` walks the
  document, collects every defined `SPDXID`
  (`SPDXRef-DOCUMENT` + every `Package.SPDXID`) into a
  `Set<String>`, checks that every `Relationship.source` and
  `Relationship.target` points at a known one, and then runs a
  three-colour DFS over the Relationship graph to detect
  cycles. `validate_cyclonedx(doc: CdxDocument) -> List<String>`
  is the symmetric counterpart: collects `bom-ref` from
  `metadata.component` plus every `components[i].bom-ref`,
  checks every `dependencies[i].ref` and every entry in
  `dependsOn[]`, then runs the same DFS over the dependency
  graph. Both validators return a human-readable violation
  list, empty list = the document is internally consistent and
  the graph is a DAG. Each demo prints "Validation: ok (refs
  resolve + acyclic)" or a numbered list of violations.

- **CycloneDX 1.5 JSON parser, written in Capa**
  (`examples/cyclonedx_parser.capa`): the SBOM-of-record
  companion to the SPDX parser. Reads CycloneDX 1.5 documents
  (the format Dependency-Track, OSV-Scanner, syft, and the Capa
  compiler's own `--cyclonedx` output emit) and builds typed
  Capa structs: `CdxDocument`, `CdxComponent`, `CdxHash`,
  `CdxLicense`, `CdxDependency`, `CdxMetadata`. Handles both
  CycloneDX license shapes — `{license: {id|name}}` (a single
  SPDX identifier or a human-readable name) and `{expression:
  ...}` (a full SPDX-license-expression like `MIT OR
  Apache-2.0`) — plus the dual `metadata.tools` representation
  (modern `tools.components[]` and the legacy flat
  `tools[]` array). Regression test in
  `tests/test_transpiler.py::test_cyclonedx_parser`.

- **SPDX 2.3 JSON parser, written in Capa**
  (`examples/spdx_parser.capa`): the first real-world SBOM demo
  written in the language. Parses the core SPDX 2.3 fields
  (`spdxVersion`, `dataLicense`, document metadata, `packages`
  with `versionInfo` / `licenseConcluded` / `checksums`, and
  `relationships`) into typed Capa structs
  (`SpdxDocument`, `Package`, `Checksum`, `Relationship`,
  `CreationInfo`). Demonstrates: a user-defined
  `capability SbomReader` marking the trust boundary for any
  function that touches an SBOM, pattern matching on every
  `JsonValue` variant, and `?`-chaining on `Result` so each
  parser function reads top-down without manual match-on-error.
  Optional-field helpers (`string_field_or`, `bool_field_or`)
  cover SPDX's "field may be omitted, fall back to a default"
  semantics. Regression test in
  `tests/test_transpiler.py::test_spdx_parser`.

- **Arity errors include the function signature**: the
  analyzer's `call to 'foo': expected 2 arguments, got 3` now
  appends `(signature: fun(Int, Int) -> Int)` so the reader
  sees the parameter types alongside the count. Applies to both
  free-function and method calls, on both the positional and
  named-argument paths.

- **Top-level keyword-typo hints**: writing `def foo()`,
  `class Foo`, `function bar()`, `func baz()`, `fn quux()`,
  `interface I`, `enum E`, `struct S`, or a bare `let` at the
  top level now produces a targeted parser error pointing at
  the Capa equivalent (`fun`, `type`, `trait`, `type Name =
  ...`, `const`). The most common newcomer-from-Python or
  -from-Rust typos no longer produce the generic "expected
  top-level declaration".

- **Built-in capability method typos are now caught**: calling
  a method that does not exist on one of the built-in
  capabilities (`Stdio`, `Fs`, `Env`, `Net`, `Clock`, `Random`,
  `Unsafe`) was previously silently accepted and returned
  `TyUnknown`. The analyzer now raises a `capability 'Stdio'
  has no method 'prntln'; did you mean 'println'?` with the
  same Levenshtein hint already used for type-method typos.
  User-defined capabilities are unchanged (their method tables
  may be intentionally partial).

- **Formatter intra-line spacing pass (v2)**: outside string
  literals, char literals, and `//` comments, runs of two or
  more spaces in code collapse to a single space, and a
  missing space after `,` is inserted. The pass uses a
  character-by-character state machine, so escaped quotes
  inside literals are handled correctly and trailing commas
  before `)` / `]` / `}` are preserved. Expression re-emission
  from the AST (operator spacing around binary operators,
  brace placement) is still deferred to a future v3 pass that
  needs a `//` comment-preservation design first.

- **One-line install scripts** at [deploy/install.sh](deploy/install.sh)
  (Linux / macOS Apple Silicon) and
  [deploy/install.ps1](deploy/install.ps1) (Windows PowerShell).
  Both download the latest pre-built binary, drop it in
  `~/.local/bin/capa` (or `%LOCALAPPDATA%\capa\capa.exe` on
  Windows), and, on Windows, add that directory to the user
  PATH via `[Environment]::SetEnvironmentVariable("Path", ..., "User")`
  so no admin rights are needed. On Unix the script tells the
  user to add the directory to `PATH` themselves (we do not
  modify shell rc files automatically: too many shells, too
  many opinions). Idempotent on rerun. The bash script also
  strips the macOS Gatekeeper quarantine attribute so the
  binary runs without a Settings detour. README and
  `docs/start.html` lead with the one-liners; the manual
  download path remains documented for users who want to
  verify the asset themselves.

- **`capa --version`**: prints the compiler version and exits.
  Used by the installer scripts to verify a successful download
  but generally useful for "what am I running?".

- **LSP semantic tokens** (`textDocument/semanticTokens/full`):
  type-aware highlighting beyond what a TextMate grammar can
  deliver. The legend uses seven LSP-standard token types
  (`function`, `parameter`, `variable`, `interface`, `type`,
  `enumMember`, `property`) and three modifiers
  (`defaultLibrary` for built-ins, `declaration` for sites that
  introduce a name, `readonly` for `let` bindings and
  constants). Capabilities use `interface`; the built-ins
  (`Stdio`, `Net`, `Fs`, `Env`, `Clock`, `Random`) get the
  `defaultLibrary` modifier so themes can render them with a
  different intensity than user-defined ones. Coverage spans
  reference identifiers (via `result.bindings`), declaration
  sites (via the `name_pos` parser change), `TypeName`
  references inside type annotations (resolved by name in
  `result.global_symbols`), `let` / `var` bindings (with
  `var` getting a new `name_pos` field on the AST), and
  struct fields / sum variants / trait methods at their
  declaration positions. Tokens are sorted by source position
  and relative-encoded into the standard
  `[deltaLine, deltaStart, length, tokenType, tokenModifiers]`
  quintuples expected by the LSP protocol.

- **LSP type-aware method completion after `.`**: when the
  cursor sits in a `receiver.<here>` context, the completion
  list narrows to the methods of the receiver's type, with the
  method's `TyFun` signature rendered in the detail column.
  Built-in types (`String`, `List`, `Map`, `Set`, `Option`,
  `Result`, `JsonValue`) and built-in capabilities (`Stdio`,
  `Net`, `Fs`, `Env`, `Clock`, `Random`) are covered, as are
  user-defined struct and sum types with methods declared via
  `impl`. The receiver may be any expression: an identifier, a
  string literal, a parenthesised sub-expression. Mid-edit
  buffers (a bare trailing `.`) are handled with a
  parse-with-placeholder retry: the source is re-parsed with a
  synthetic identifier inserted at the cursor, which makes the
  surrounding `FieldAccess` / `MethodCall` valid in the AST so
  the receiver's type can be resolved. Methods whose names
  start with `_` are filtered (internal-by-convention).
  Unresolvable receivers return no completions (the dot-trigger
  path never falls back to keywords / built-ins, which would
  be misleading).

- **LSP completion** (`textDocument/completion`): suggests
  Capa identifiers at the cursor. v1 is a two-layer answer.
  The **floor** is always present and is computed without
  parsing: 35 Capa keywords, 7 built-in capabilities (`Stdio`,
  `Fs`, ...), 14 built-in types (`Int`, `Float`, `List`,
  `Option`, `Result`, `Map`, `Set`, ...), 4 common variant
  constructors (`Some`, `None`, `Ok`, `Err`), 10 built-in
  functions (`parse_int`, `new_map`, `parse_json`,
  `py_import`, ...). When the buffer parses cleanly, the
  **module layer** is appended: top-level functions (rendered
  with their `fun(params) -> Ret` signature in the detail
  column), constants (with their declared type), structs, sum
  types and each of their variants surfaced individually,
  user-defined traits and capabilities; plus
  the **local layer**: parameters and `let`/`var` bindings
  visible at the cursor inside the enclosing function. Locals
  whose names start with `_` are filtered out (the convention
  for "intentionally unused"). De-dup by label keeps one entry
  when a user binding collides with a built-in name.

- **LSP rename** (`textDocument/rename` + `textDocument/prepareRename`):
  rewrites every reference and the declaration of the symbol
  under the cursor in a single `WorkspaceEdit`. Builds on the
  existing `compute_references` with `include_declaration=True`,
  so coverage matches find-references exactly (functions, types,
  traits, capabilities, constants, parameters, variants, struct
  fields, method signatures). The new name is validated against
  the lexer's IDENT shape via `str.isidentifier()` plus a
  reserved-keyword check, so renaming to `if`, `fun`, the empty
  string, `1greet`, `say-hi`, or any other non-identifier
  is refused with a human-readable message instead of producing
  a broken source. Built-in symbols (`Stdio`, `Net`, `Result`,
  ...) refuse rename cleanly because they have no source
  declaration to edit. `prepareRename` answers
  "is this position renameable?" so editors can grey out the
  rename UI before the user types a new name.

- **Parser records `name_pos` for declared names**: every
  declaration node (FunDecl, TypeStruct, TypeSum, TraitDecl,
  ConstDecl, Param, Variant, Field, MethodSig) now carries a
  `name_pos: Pos` field separate from the existing `pos`. The
  `pos` of a FunDecl is still the start of the `fun` keyword
  (or the first attribute), but `name_pos` points at the IDENT
  token of the declared name. The analyzer's existing position
  semantics are unchanged; `AnalysisResult` additionally exposes
  `global_symbols: dict[str, Symbol]` so LSP tooling can resolve
  a declaration site to its Symbol without poking at private
  Analyzer state.

- **LSP hover, go-to-definition, find-references on
  declaration sites**: with the parser recording `name_pos`, the
  three cursor-driven LSP features now fire on declarations,
  not just references. Hovering on `foo` in `fun foo(name)`
  shows the function signature; hovering on `name` in the same
  declaration shows `name: T` with the *parameter* label;
  hovering on a struct field, sum variant, or trait method
  signature shows the appropriate detail. Go-to-definition from
  a declaration name is a no-op (lands on the name itself);
  find-references from either side returns the same set, with
  the declaration entry placed at the precise name column rather
  than the start of the `fun` keyword. The mechanism is a small
  `_DeclSite` collector + a `_resolve_decl_symbol` helper that
  maps each declaration kind to the matching Symbol via
  `global_symbols`, sum-type variant tables, struct-field tables,
  trait method-sig tables, or a scan over the function body's
  bindings for parameter sites.

- **LSP code actions (Quick Fix for "did you mean" hints)**:
  `textDocument/codeAction` returns a "Replace with 'X'" Quick
  Fix for every diagnostic whose message ends in
  `; did you mean 'X'?` (the five analyzer error families that
  carry the suggestion: undefined name, undefined type, no
  method on type, no field on struct, unknown variant). The
  replacement range is computed by scanning the source line for
  the misspelled token (matched as a whole word, so a typo like
  `in` does not pick up the `in` inside `println`); when the
  token cannot be located on the line (e.g. the user is mid-edit,
  or the diagnostic position is approximate as for typos inside
  string interpolation), the action is skipped cleanly rather
  than committing to a wrong span. Each action is marked
  `isPreferred=True` so it can be applied with the editor's
  default keyboard shortcut.

- **LSP document symbols**: `textDocument/documentSymbol`
  returns the hierarchical outline of the module. Top-level
  constants, structs (nesting their fields), sum types (nesting
  their variants with payload types in the detail), traits and
  capabilities (nesting their method signatures), top-level
  functions (with `(params) -> Return` rendered as detail), and
  impl blocks (with display names like `impl Greet for Foo` and
  the methods nested under each) appear in source order.
  Editors render this in the outline view, breadcrumb bar, and
  workspace symbol search. The capa-side computation is exposed
  as `compute_document_symbols(source, filename)` returning a
  list of `DocSymbol` dataclasses; the LSP handler maps each to
  the matching `lsp.SymbolKind` (`sum` -> `Enum`, `variant` ->
  `EnumMember`, `capability` -> `Interface`, `impl` -> `Class`,
  etc.).

- **LSP find-references**: `textDocument/references` lists
  every other identifier in the file that resolves to the same
  symbol as the one under the cursor. Reuses the
  `collect_idents` + `AnalysisResult.bindings` machinery from
  hover and go-to-definition; results are ordered by source
  position. The `includeDeclaration` flag from the LSP request
  is honoured: when true and the symbol has a real source
  origin, a location for the declaration line is added; built-in
  symbols are still filtered (they have no file location to
  point at).

- **LSP go-to-definition**: `textDocument/definition` jumps
  from any identifier reference to the position where the
  declaring symbol lives. Functions resolve to the
  `fun name(...)` line; parameters resolve to their slot in
  the parameter list; `let`/`var` bindings resolve to their
  introducing statement; variants resolve to the corresponding
  variant declaration inside the sum type. Built-in symbols
  (`Stdio`, `Net`, `Result`, the implicit `Option`, etc.) carry
  the `Pos(0, 0)` sentinel and are filtered cleanly so the
  editor never jumps to "line 0 of an unknown file". As with
  hover, coverage is limited to identifier references; the
  parser does not yet track end positions on declaration
  nodes, so the jump target is the start of the declaration
  line, which is what every mainstream editor expects.

- **LSP hover**: `textDocument/hover` answers
  "what is this symbol?" for the identifier under the cursor.
  Functions render as a Capa-style signature
  (`fun greet(name: String, age: Int) -> String`); parameters,
  bindings, and constants render as `name: T` plus a kind label;
  variants show the owning sum type; user-defined capabilities
  show the `capability X` head. The hover range covers the
  identifier so editors highlight the exact span. Coverage is
  limited to identifier references in v1 (declaration sites
  store names as strings, not Ident nodes, so they are skipped
  cleanly rather than guessed at). A buffer with parse errors
  returns no hover but never raises.

- **Language server (LSP), v1 diagnostics-only**.
  `python -m capa lsp` starts a stdio server that re-runs the
  full lexer + parser + analyzer pipeline on every didOpen,
  didChange, and didSave, and publishes the resulting errors as
  `textDocument/publishDiagnostics`. Capa's 1-based line/col
  positions are translated to LSP's 0-based positions; severities
  default to Error; the diagnostic `source` field is `capa-lsp`.
  The lexer and parser short-circuit on the first error
  (consistent with the CLI); the analyzer surfaces every error it
  finds in a single pass. `pygls>=2.0` is an optional
  dependency (`pip install -e '.[lsp]'`) so the rest of the
  compiler stays standard-library-only. README ships one-line
  config snippets for Helix and Neovim.

### Changed

- **`Range<T>` is now a distinct type from `List<T>`**. The
  `a..b` and `a..=b` expressions previously typed as
  `List<Int>` and lowered to `CapaList(range(...))`, which
  materialised the full range eagerly (~28 bytes per int
  on CPython, gigabytes for large ranges). Range is now its
  own parametric type registered in `capa/builtins.py` with
  a minimal method surface: `length()`, `contains(T)`,
  `is_empty()`, `to_list()`. The full `List<T>` API
  (`filter`, `fold`, `map`, ...) is reached via explicit
  materialisation: `.to_list().filter(...)`. The runtime
  class `CapaRange` in `capa.runtime._list` wraps Python's
  `range` and implements `__iter__` so bound ranges iterate
  lazily; `CapaRange(0, 1_000_000_000)` constructs in 2µs
  with no allocation. The direct `for x in a..b` form keeps
  its fast path, emitting bare `for x in range(...)` with
  no wrapper around it. Five existing tests migrated to the
  new shape; one new test asserts that calling `.filter`
  directly on a `Range` is now a typed rejection rather
  than silently working. Resolves the deferred follow-up
  to the for-loop materialisation fix from the external
  whitepaper review.

- **`for x in a..b` no longer materialises the full range**.
  The naive lowering was `for x in CapaList(range(a, b)):`,
  which forced Python's `list.__init__` to walk the range
  eagerly (~28 bytes per integer on CPython). `for x in
  0..10_000_000` therefore allocated ~270 MB before doing any
  work. The transpiler now special-cases `ForStmt(iter=
  RangeExpr)` and emits `for x in range(start, stop):`
  directly. The inclusive form `0..=n` lowers to
  `range(0, (n) + 1)`. Bound ranges (`let xs = 0..n; for x in
  xs`) still materialise into a `CapaList` so subsequent
  `List<T>` method calls (`.map`, `.length()`, `.filter`)
  continue to work. Found by an external whitepaper review
  that flagged the memory cost as a blocker for the future
  native backend; the long-term fix (a `Range<Int>` type
  distinct from `List<Int>`) is still pending, but the
  for-iteration case is no longer a footgun.

- **README correction on capability-method typing**. A stale
  paragraph in `README.md` claimed that "capabilities (`Stdio`,
  `Fs`, etc.) have no impls in Capa code, their methods are
  still typed as `TyUnknown` and resolved at runtime against
  the Python runtime implementation." This was true at one
  point but is no longer: every built-in capability method is
  declared in `capa/builtins.py` as a closed table, the
  analyzer dispatches against that table, and unknown methods
  on a built-in capability are rejected with a "did you mean"
  hint rather than typed as `TyUnknown`. Updated the paragraph
  to match reality.

- **WhitePaper held back from the public repo until the
  thesis pre-print is published**. The full design rationale
  document (`Capa-WhitePaper.md`) underpins a PhD thesis on
  SBOM Governance under the EU Cyber Resilience Act and is
  embargoed until the pre-print has a citable DOI. `WHITEPAPER.md`
  replaces it with a one-page stub explaining where the document
  is and how to obtain a copy. References in code comments
  (`// see WhitePaper §4.6`) and in the README / CONTRIBUTING /
  docs site / issue templates all point at the stub for now;
  once the pre-print is up the stub will redirect to the DOI.

- **`?` operator now propagates the inner type**: previously the
  analyzer typed every `expr?` as `TyUnknown`, which silently
  defeated type-aware method dispatch on anything downstream of
  a `?`. The most visible symptom was `Map.get(...)` failing to
  lower into the `Some(m[k]) if k in m else None_` ternary when
  `m` was the result of a `Result`-returning helper, producing a
  runtime `UnboundLocalError` inside the transpiled match-as-
  expression. Now `expr?` unwraps `Result<T, E>` / `Option<T>`
  to `T`; other types (and `TyUnknown` inputs) still degrade to
  `TyUnknown`. Fix also exposed a long-standing test-harness
  hole: `tests/test_transpiler.py::transpile_only` was running
  the lexer + parser without the analyzer, so the transpiler
  saw an empty types map and the same dispatch path silently
  degraded under test. The helper now calls `analyze()` before
  `transpile()`.

- **Internal: every compiler file over ~700 lines is now a
  package**. Following the analyzer split, the same mixin /
  per-topic-module pattern was applied to the parser
  (5 mixins), transpiler (4 mixins), runtime (6 topic modules:
  Result/Option, capabilities, py-interop, list, conversion,
  JSON), manifest (5 topic modules), docgen (4 topic modules),
  capa_ast (6 per-category modules), and lexer (4 mixins). Each
  package's `__init__.py` is either a thin re-export or a small
  composition orchestrator. `cli.py` and `lsp/server.py` were
  evaluated and kept whole because their structure is sequential
  pipeline glue (CLI) or pygls-registration closures (LSP),
  neither of which has the seams that justify a split. No
  user-visible behaviour change, but the surface for future
  contributors is dramatically smaller per concern.

- **"Did you mean?" hints on five common analyzer errors**:
  `undefined name`, `undefined type`, `type X has no method Y`,
  `struct S has no field F`, and `unknown variant V` now append
  `; did you mean 'X'?` when a close candidate exists in scope.
  The matcher is a Levenshtein distance with case-aware
  tie-breaking: same-first-letter and same-case beat raw distance,
  so `Pint` prefers `Point` over `Int` and `reslt` prefers a local
  `result` over the built-in `Result`. Suppressed for needles of
  two characters or fewer, where almost everything is plausibly
  similar. Variant suggestions are scoped to the scrutinee's sum
  type when known.

- **Block-body lambdas inside `(...)`** now raise a targeted parser
  error pointing at the recommended workaround, instead of the
  generic "expected expression, got KW_LET". Same root cause as the
  indent-form match-in-parens case already documented: the lexer
  suppresses NEWLINE/INDENT/DEDENT inside parentheses for implicit
  line continuation, so block-bodied constructs cannot reach their
  layout-driven syntax there. The workaround (bind to `let` first,
  then pass the binding) parses cleanly; single-expression lambdas
  remain unaffected.

### Added

- **`capa init`**, project scaffolding subcommand.
  `python -m capa init [name]` creates a minimal Capa project at the
  given path (defaults to the current directory, which must then be
  empty): `main.capa` is a runnable starter that uses `Stdio` so the
  capability discipline is visible from the first line a user reads,
  `README.md` documents the two commands a user needs (`capa --run`
  and `capa --check`), `.gitignore` covers Python bytecode and
  common editor cruft, and `.capa-version` pins the Capa version
  used at scaffold time. The starter passes `--check` and `--run`
  out of the box and is in canonical `--fmt-check` form.

- **`capa-fmt` (v1, line-level)**: CLI flags `--fmt` (rewrite the
  file in place) and `--fmt-check` (verify, exit 1 if not
  canonical). v1 is a safe, whitespace-only formatter: it
  normalises line endings to LF, replaces leading tabs with four
  spaces each, floors partial space-indents to the nearest lower
  4-space multiple (never deepens nesting), strips trailing
  whitespace, collapses runs of blank lines to a single blank, and
  ensures exactly one final newline. Block-comment interiors
  (`/* ... */` and `/** ... */`) are preserved verbatim so
  Javadoc-style `*` continuation lines survive. Idempotent by
  construction. Intra-line canonicalisation (operator spacing, AST
  round-trip, `//` comment preservation) is deferred to v2.

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
- **White paper** (`WHITEPAPER.md`) and formal **EBNF grammar**
  (`Capa-EBNF.md`) translated to English and synchronised with the
  implementation.

[Unreleased]: https://github.com/nelsonduarte/capa/compare/v0.5.0-alpha...HEAD
[0.5.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.5.0-alpha
[0.4.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.4.0-alpha
[0.3.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.3.0-alpha
[0.2.0-alpha]: https://github.com/nelsonduarte/capa/releases/tag/v0.2.0-alpha
