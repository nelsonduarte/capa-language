# Capa, TODO / Roadmap

Living inventory of pending work, captured locally so context survives
across sessions. Loosely ordered by impact. Edit freely.

Legend: **P0** = blocking next public milestone · **P1** = high
impact within the next 1-2 milestones · **P2** = nice to have ·
**P3** = future / research-grade · ⏱ = rough effort estimate.

---

## Current focus (May - October 2026, pre-PhD runway)

Plan-closed development at 8h/week, scoped to ~175h total. The
positioning Capa stands behind: *"a capability-typed language
whose distinctive contribution is the integration between the
type system and the supply-chain governance stack"*. The
sequence below strengthens exactly that axis.

**Tier 1, technical artefacts:**

- [x] **SBOM diff tool**
  ([`examples/sbom_diff.capa`](examples/sbom_diff.capa)).
  Consumes two CycloneDX SBOMs and reports per-function
  capability widenings (alert), narrowings (improvement),
  additions, removals. Companion to the
  `sbom_capability_audit.capa` (which compares ONE SBOM
  against a written policy). First piece of Tier 1, landed
  2026-05-15.
- [x] **SPDX 2.3 emission** (`capa --spdx file.capa`).
  Companion to `--cyclonedx`; emits SPDX 2.3 JSON with
  per-function capability metadata via standard
  `annotations[]`. SPDX IDs sanitised to spec
  (`SPDXRef-[A-Za-z0-9.-]+`). Implementation at
  `capa/manifest/_spdx.py`; 11 tests at
  `tests/test_attributes.py::TestSPDX`. Landed 2026-05-15.
- [ ] **VEX integration** (CycloneDX VEX format).
  Per-function exploitability claims. Genuinely novel: no
  other language emits VEX at function granularity. ~2-3
  weeks.
- [ ] **SLSA Build L1 provenance attestation** at compile
  time. Closes the "where did this SBOM come from?"
  question. ~1 week.

**Tier 2, consolidated regulatory mapping:**

- [ ] **`docs/regulatory.md`**: single comparative table
  covering **CRA + NIS2 + DORA** (cybersecurity articles
  only: Art. 6, 8, 9-15, 17-23, 28-30, **not** broader
  operational resilience) + **NIST SSDF (SP 800-218)** +
  **OWASP SCVS**. Keep existing `docs/cra.md` as deep-dive;
  new doc is the comparative view. **Explicitly excluded**:
  ISO 27001, SOC 2, PCI DSS, HIPAA (organisational not
  technical); EO 14028 (subsumed by SSDF); AI Act, GDPR
  (tangential); SWID (dying). ~25-35h.

**Tier 3, polish:**

- [ ] 1 workshop paper draft based on Tier 1 + Tier 2.
  Target venues: SPLASH-E, PLAS, EuroS&P workshops, NDSS
  workshops. ~30-40h.

When Tier 1 + Tier 2 + paper are done, **stop**. Excess time
goes to PhD preparation, not to Tier 4 expansions.

---

## Historical bridge work, v0.2 alpha (DONE)

Bridge from "working alpha" to "shareable v0.2 alpha". Three pieces:

- [x] **Demo: "Capa would have caught X"**, event-stream (Nov 2018).
  Safe Capa library in `examples/demo_event_stream.capa`; writeup
  with attack-attempt code + analyzer rejections in
  `docs/demo-event-stream.md`; cross-referenced from README.
- [x] **VSCode syntax highlighting**, TextMate grammar covering
  keywords (by category), built-in caps highlighted distinctly,
  string interpolation, numeric literals in all bases, operators
  including `..`, `..=`, `=>`, `?`. Lives in `vscode/`. Install
  manually via symlink/junction; Marketplace publication later.
- [x] **Full website (5 pages)**, `docs/{index,why,tour,start,roadmap}.html`
  + `docs/style.css`. Slim landing with three value-prop cards; "Why
  Capa" makes the case (ambient authority, event-stream, three
  pillars, attenuation, user-defined caps, honest limits); language
  tour in 12 sections; getting-started with full CLI reference;
  honest roadmap with status pills. Dark theme, single accent, no
  JS, no framework, no external fonts. Header is purely typographic
  (a hand-coded SVG logo was attempted and abandoned, bad call,
  see memory). Ready to serve via GitHub Pages when enabled for
  `docs/`.

When the public-readiness items land: tag `v0.2.0-alpha`, flip repo
to public.

---

## WhitePaper promises still open (P1)

- [x] **Atenuação genérica**: every built-in capability has an
  attenuator. `Net.restrict_to(host)`, `Fs.restrict_to(prefix)`,
  `Env.restrict_to_keys([...])`, `Clock.restrict_to_after(t)`,
  and `Random.with_seed(seed)`. The first four monotonically
  narrow authority and are fail-closed on denied access; the
  last has no denied state but produces a deterministic sequence
  whose seed is visible in the manifest's data-flow tracker.
- [ ] **Visibility (`pub`)**, KW_PUB is parsed but not enforced.
  Waits on a real module system. P2/P3
- [ ] **Native Capa module system**, `import` is parsed but
  analyzer-rejected today. Designing this is substantial work, and
  the practical win is small as long as projects are single-file.
  P3
- [ ] **Refinement types**, explicitly future in the WhitePaper. P3

---

## EBNF declares but not implemented (P2)

- [x] **Doc comments** (`///`, `/**`). Lexer emits `DOC_COMMENT`
  tokens with leading-space and Javadoc star-margin stripped;
  parser attaches them to the following `fun` / `type` / `trait` /
  `capability` / `impl` method as the `doc` field; `--doc` runs
  the `capa.docgen` HTML generator. The markdown subset covers
  paragraphs, inline `code` spans, fenced code blocks (with
  optional language tag), and bulleted lists. Plain (non-capability)
  traits get their own section with method signatures and the
  list of implementor types.
- [x] **Raw strings** (`r"..."`), no escape processing and no
  `${}` interpolation; useful for regex and Windows paths. A raw
  string cannot embed `"`; use a regular string with `\"` for that.
- [x] **Named arguments** (`f(name: "Ana", age: 30)`), parser
  accepts an optional `IDENT ":"` prefix on each call argument;
  the analyzer reorders to parameter order before type checking,
  rejects positional-after-named, unknown names, duplicates, and
  arity mismatches; the transpiler emits Python keyword arguments.
  Built-in methods (String, Map, Set, capabilities) reject named
  arguments because their parameter names are not tracked.
- [ ] **Turbofish (`::<T>`)**, EBNF §7.3 mentions; never needed
  because inference has been enough. Only implement if a real case
  comes up. P3

---

## Tooling that moves the adoption needle (P1-P2)

- [~] **LSP server** (Python, `pygls>=2.0`). **v1 landed**:
  `python -m capa lsp` starts a stdio server that delivers
  diagnostics (full pipeline on every didOpen / didChange /
  didSave), hover (signature or `name: T` markdown),
  go-to-definition (jump to declaring symbol), find-references
  (all uses of the same symbol), documentSymbol (hierarchical
  outline: constants, structs with fields, sums with variants,
  traits/capabilities with method signatures, functions, impl
  blocks with methods), and code actions (Quick Fix
  "Replace with 'X'" for every `did you mean 'X'?` hint emitted
  by the analyzer). Coverage spans both **references** (uses of
  a symbol) **and declaration sites**: the parser records
  ``name_pos`` for every declared name (functions, types, traits,
  capabilities, constants, parameters, struct fields, variants,
  trait method signatures), so hovering on `foo` in
  `fun foo(...)` fires the same way as hovering on a call to
  `foo`. Go-to-definition from a declaration is a no-op (lands on
  the name itself); find-references from either side returns the
  same set, with the declaration entry at the precise name column.
  Typos inside string interpolation (`${...}`) still lose
  positions because the interpolation contents go through a
  side parse channel. `pygls` is an optional dependency
  (`pip install -e '.[lsp]'`) so the rest of the compiler stays
  standard-library-only. README carries one-line config snippets
  for Helix and Neovim.
  Rename (`textDocument/rename` + `prepareRename`) also landed:
  validates the new name against the lexer's IDENT shape (and
  rejects reserved keywords), then rewrites every reference and
  the declaration. Built-in symbols (`Stdio`, `Net`, `Result`,
  ...) refuse rename cleanly. Completion
  (`textDocument/completion`) offers a floor of keywords + built-in
  types/capabilities/variants/functions, plus module-level names
  (functions with signatures, constants with types, sum types and
  their variants, user-defined traits and capabilities) and the
  function-scope params/locals visible at the cursor. Mid-edit
  buffers that fail to parse fall back to just the floor, so the
  suggestion list never goes dark on a half-typed line.
  Type-aware completion after `.` also landed: when the cursor
  sits in a `receiver.<here>` context, the analyzer's known
  methods for the receiver's type are offered (with their full
  TyFun signature in the detail column). Built-in types and
  capabilities (String, List, Map, Set, Stdio, Net, Fs, Env,
  Clock, Random, Option, Result, JsonValue) plus user-defined
  struct / sum methods all work. Mid-edit buffers (a bare
  trailing `.`) are handled by re-parsing with a synthetic
  placeholder identifier injected at the cursor.
  Semantic tokens (`textDocument/semanticTokens/full`) deliver
  type-aware highlighting beyond what the TextMate grammar can do.
  The legend distinguishes function, parameter, variable
  (with `readonly` modifier for `let` bindings and constants),
  interface (Capa's capabilities, with `defaultLibrary` modifier
  on the built-ins), type (struct / sum / trait), enumMember
  (sum-type variants), and property (struct fields). Both
  reference and declaration sites are tagged; type-annotation
  references inside parameter / return / field types resolve
  against the global scope so `String`, `Stdio`, etc. get
  coloured wherever they appear.
  **Pending (v2)**: positional fidelity for `${...}` contents.
- [~] **`capa-fmt` (formatter)**, canonical, non-configurable
  (gofmt-style). **v1 (line-level) landed**: CLI flags `--fmt` and
  `--fmt-check` normalise line endings, indentation (tabs to 4
  spaces, partial indents floor to a 4-space multiple), trailing
  whitespace, blank-line clusters (collapse to one), and the final
  newline. Block-comment interiors (`/* ... */` and `/** ... */`)
  are preserved verbatim so Javadoc-style `*` continuation lines
  survive. Idempotent by construction. **v2 intra-line pass also
  landed**: a character-by-character walk over each non-block
  line collapses runs of two or more spaces in code to a single
  space, and inserts a missing space after `,`. Strings, char
  literals, and `//` comments are tracked and skipped; trailing
  commas before `)`/`]`/`}` are preserved. **Pending (v3)**:
  expression re-emission from the AST (operator spacing around
  binary ops, brace placement) and `//` comment preservation
  through the AST round-trip. v3 needs a comment-preservation
  design before any AST round-trip is safe.
- [ ] **Package manager**, only meaningful once there's a module
  system. P3
- [ ] **REPL**, deleted earlier. Reimplement when language is
  stable and demand exists. P2
- [x] **`capa init`**, project scaffolding. `python -m capa init [name]`
  creates `main.capa` (a runnable, canonically-formatted starter that
  uses `Stdio` so the capability discipline shows up on line one),
  `README.md`, `.gitignore`, and `.capa-version`. Refuses to overwrite
  a non-empty directory or a path that is a file. The starter passes
  `--check` and `--run` out of the box.
- [ ] **Debugger integration**, Python debugger works on the
  transpiled output but maps poorly. Source maps would help. P3

---

## Known bugs / partial features (P1)

- [ ] **Indent-based `match` inside parentheses**, by design fails
  because parens suppress NEWLINE/INDENT/DEDENT. The braced inline
  form (`match x { P1 -> e1, P2 -> e2, ... }`) does work inside a
  call expression and is the documented way to write a `match` as
  an argument. Reclassified from "bug" to "documented restriction";
  promote to a real fix only if someone proposes a lexer change
  whose blast radius does not eat the indent-based form elsewhere.
- [x] **Block-body lambdas in deep expression contexts**, verified
  and documented as a deliberate restriction. Same root cause as
  indent-form match inside parens: the lexer suppresses
  NEWLINE/INDENT/DEDENT inside `(...)` for implicit line continuation,
  so block-body lambdas there are unreachable by design. The parser
  now emits a targeted error pointing at the recommended workaround
  (bind to `let` first, then pass the binding, or use a
  single-expression body). README, EBNF section on lambdas, and the
  reference page document this precisely.
- [ ] **Operator `?` uses internal exception**, correct but slower
  than expanded early-return. Optimisation. P2

---

## Code-quality maintenance (P2)

- [x] **Split every >700-line compiler file into a package**.
  Following the analyzer split, the same pattern was applied to
  the parser, transpiler, runtime, manifest, docgen, capa_ast,
  and lexer. All large files now live in `capa/<name>/__init__.py`
  with per-topic submodules; `__init__.py` is either a thin
  re-export (runtime, manifest, docgen, capa_ast) or hosts a
  ``ClassName(MixinA, MixinB, ...)`` composition (analyzer,
  parser, transpiler, lexer). `cli.py` (396 lines) and
  `lsp/server.py` (420 lines) were evaluated and kept whole:
  the first is sequential pipeline glue, the second is a pygls
  registration block where every handler is a closure. The
  analyzer's own split is documented below for reference:
  - `_typing.py` (92 lines): TyVar generation + substitution.
  - `_discipline.py` (252 lines): capability discipline
    (aliasing, no-capability, no-builtin-capability,
    use-after-consume, self-substitution, impls-aware
    compatibility).
  - `_statements.py` (265 lines): block / let / var / assign /
    if / while / for / return + flow-analysis dry-run.
  - `_items.py` (275 lines): const / fun / impl phase-2
    checking + attribute schema validation.
  - `_patterns.py` (329 lines): pattern binding + exhaustiveness.
  - `_dispatch.py` (365 lines): call + method dispatch + named
    arguments.
  - `_declarations.py` (382 lines): phase-1 globals registration
    + type resolution + signature inference.
  - `_expressions.py` (492 lines): lambda / match / if-expr +
    the per-shape expression checkers.

  ``capa/analyzer/__init__.py`` is **423 lines** (down from
  3300+, an 87% reduction), and hosts only the Analyzer
  composition, the state types (Symbol, Scope, AnalysisResult,
  AnalysisError, SymbolKind), `__init__`, the public `analyze()`
  function, the small bookkeeping helpers (`_err`, scope and
  type-param push/pop, suggestion haystack collectors), and the
  shared `_signatures_match` helper.
- [x] **Error-message audit (second pass)**. The five typo-shaped
  hints from the first pass (`did you mean 'X'?` on undefined
  names, types, methods, fields, variants) are now complemented by
  three more:
  - **Arity errors include the signature**: `"call to 'add':
    expected 2 arguments, got 3 (signature: fun(Int, Int) ->
    Int)"`. Same shape for method calls.
  - **Built-in capability method typos are caught**:
    `stdio.prntln(...)` no longer passes silently; it raises
    `"capability 'Stdio' has no method 'prntln'; did you mean
    'println'?"` with the standard Levenshtein hint.
  - **Top-level keyword typos detected**: `def`/`function`/`func`
    /`fn` → suggest `fun`; `class`/`struct` → suggest `type`;
    `interface` → suggest `trait`; `enum` → suggest `type Name
    = ...`; bare `let` at top level → suggest `const`.
- [ ] **Analyzer performance**, no benchmarks. Only worth attacking
  if someone reports slowness. (Runtime-side overhead is covered
  by `benchmarks/`; this row is about lex+parse+analyze+transpile
  wallclock, which is fast enough to not need measurement yet.)
- [x] **Runtime-overhead benchmark suite**, `benchmarks/`. Three
  paired workloads (Capa + hand-Python baseline) covering pure
  compute, list-heavy, and string-heavy regimes. Numbers stable
  across runs: ~1.00x / 1.20x / 1.45x. Methodology and headline
  table in `benchmarks/README.md`. Closes the "is Capa
  practical at the source level?" question for the thesis
  chapter on overhead.
- [ ] **Test-coverage review**, `coverage.py` run + identify which
  parts of the analyzer are under-tested.
- [x] **`for x in a..b` was materialising the full range** as a
  `CapaList(range(a, b))`, allocating ~28 bytes per integer in
  CPython. For large ranges this was gigabytes. The transpiler
  now special-cases `ForStmt(iter=RangeExpr)` to emit
  `for x in range(start, stop)` directly. Bound ranges
  (`let xs = 0..n`) still materialise to keep the
  `List<T>` method surface (`.map`, `.length()`, etc.) working;
  only the direct for-iteration form is lazy. Found by the
  external whitepaper review (analise_capa/capa-revisao-critica.md
  §2.3); same review also notes that the proper long-term fix
  is a `Range<Int>` type distinct from `List<Int>` (still
  pending; the for-loop hack closes the urgent memory bug for
  v1).

---

## External review action items (P1, from analise_capa, 2026-05-13)

A friend-of-the-project review of the whitepaper, EBNF, and
analyzer arrived as two markdown documents kept locally next to
the repo (not checked in: they cite the WhitePaper which itself
is held back, see `WHITEPAPER.md`). Capturing the actionable
items here so they stay visible:

- [~] **Small-step operational semantics + soundness theorem**.
  **Sketch landed** at `docs/semantics.md`. Defines λ_cap (a
  minimal lambda calculus capturing Capa's capability surface),
  states syntax + typing rules + small-step semantics with a
  trace of capability invocations, and proves two theorems at
  the sketch level: *Capability Soundness* (every invocation
  recorded in the trace has class drawn from the initial
  environment) and *Manifest Completeness* (the manifest is
  an upper bound on the dynamic capability surface). The
  proofs are sketched, not mechanised; deferred for full
  paper writeup are (a) the branch/loop discipline of the
  linear layer, (b) attenuation completeness, (c) the
  `Unsafe` boundary, (d) the translation lemma from full Capa
  to λ_cap. **Pending**: mechanisation in Agda or Coq for
  thesis-grade proof of Theorem 1; this is the workshop-paper
  ticket the reviewer was pointing at.
- [x] **3-5 CVE case studies** mapped to Capa typing rules.
  Each is a paired `examples/cve_*.capa` (safe library) +
  `docs/cve_*.md` (walkthrough showing the attack pattern,
  what an attacker would transliterate into Capa, and the
  exact analyzer rejection). Six landed so far:
  - **event-stream 2018**:
    `examples/demo_event_stream.capa` +
    `docs/demo-event-stream.md`. Bitcoin-wallet exfiltration via
    a tampered dependency. Capa wins structurally.
  - **eslint-scope 2018**:
    `examples/cve_eslint_scope.capa` +
    `docs/cve_eslint_scope.md`. npm credential theft via
    reading `~/.npmrc` and POSTing to a Pastebin drop. Capa
    wins structurally.
  - **node-ipc 2022 (protestware)**:
    `examples/cve_node_ipc.capa` +
    `docs/cve_node_ipc.md`. Maintainer-as-attacker with
    legitimate `Net` + `Fs` authority writes `❤️` to files on
    hosts geolocated to Russia / Belarus. Deliberately picked
    as the case where **Capa partially loses**: structural
    rule does not help, attenuation in the caller can bound
    the blast radius, the audit on the SBOM can flag any
    later widening of the declared capability.
  - **xz-utils 2024 (CVE-2024-3094)**:
    `examples/cve_xz_utils.capa` + `docs/cve_xz_utils.md`.
    Multi-year sshd backdoor delivered via .m4 autotools +
    binary test fixtures + IFUNC dynamic-linker indirection.
    Capa's source-level discipline does not apply to any of
    those layers. Deliberately included as the most
    pessimistic case study: the thesis chapter has to
    acknowledge attacks beneath the language layer.
  - **torchtriton 2022 (PyPI typosquat)**:
    `examples/cve_torchtriton.capa` +
    `docs/cve_torchtriton.md`. PyTorch nightly's
    `torchtriton` Python module dependency typosquatted on
    public PyPI. The malicious version walked `$HOME`,
    captured SSH keys and env, POSTed to `*.h4ck.cfd`. A
    Capa-shaped kernel-launch-planning library has zero
    capabilities; the typosquat's `Fs`/`Net`/`Env` widening
    is loud at the SBOM level. Third clean win, different
    ecosystem (Python / PyPI) than event-stream and
    eslint-scope (both npm).
  - **ua-parser-js 2021 (npm account hijack)**:
    `examples/cve_ua_parser_js.capa` +
    `docs/cve_ua_parser_js.md`. Maintainer's npm account
    compromised; three malicious versions shipped a
    `preinstall` script that dropped an XMRig cryptominer on
    Linux and additionally DanaBot (a credential-stealing
    RAT) on Windows. Same attack mechanism as eslint-scope
    but wildly different payload, and Capa's response is
    structurally identical. The case study is in the repo
    specifically to make the **payload-independence** point;
    `ua-parser-js` also has the cleanest possible signature
    of any of the studies (`(String) -> UserAgent`).
  Six demos now give the thesis a balanced experimental
  section: four clean wins (event-stream, eslint-scope,
  ua-parser-js, torchtriton) across npm and PyPI and four
  different payloads (malicious-dependency, credential-
  theft, cryptominer+RAT, kernel exfil); two honest partial
  losses (node-ipc for legitimate-authority-abuse, xz-utils
  for below-the-language attacks). The breakdown is
  summarised in `docs/cve_ua_parser_js.md` § "The
  six-case-study summary".
- [~] **Property-based testing with Hypothesis**. The most
  citable suggestion in the review. **Phases 1, 2 and 3
  (minimal) landed** in `tests/test_properties.py`.
  - Phase 1: six properties on arbitrary text (formatter
    idempotence and fixpoint, lexer / parser robustness).
  - Phase 2: a syntax-aware strategy generates valid Capa
    programs of the shape *main with stdio + N stmts*
    (N ∈ {0..4}, each stmt a `let`/`var`/`println`/`if`/
    `for` with position-indexed unique names) and asserts
    the full pipeline (lex + parse + analyse + transpile +
    `ast.parse` of the transpiled Python) succeeds. The
    strategy itself surfaced two real bugs during its own
    development (capability-must-use violation on a
    `stdio`-less body; duplicate `let` bindings from a
    fixed identifier pool).
  - Phase 3 (minimal): the *citable* property in dynamic
    form. `capa.runtime._trace` wraps the public methods of
    every built-in capability class on first opt-in (the
    `enable()` call) so each method invocation appends
    `(class_name, op_name)` to a module-level list. The
    test transpiles a generated program, execs it in-process
    with `__name__ == "__main__"`, reads the trace, and
    asserts `runtime_classes ⊆ manifest_classes`.
  - Phase 3.5: a second strategy ``_program_with_caps``
    threads a random subset of `{Fs, Net, Env, Clock, Random}`
    through `main` and exercises each declared capability
    with a read-only probe (`Fs.allows`, `Net.allows`,
    `Env.allows`, `Clock.now_secs`, `Random.float_unit`). The
    test exercises non-trivial inclusions like
    `{Stdio, Net, Fs} ⊆ {Stdio, Net, Fs}`. The probes are
    pure queries with no filesystem or network side effects,
    so the property test stays self-contained.
  **Phases 3.6 and 3.7 landed**. The multi-cap strategy
  `_program_with_caps_advanced` picks per capability among
  four call shapes:
    - `plain` (the 3.5 shape, probe directly in main),
    - `attenuated` (`let a = c.restrict_to(...); a.probe()`),
    - `via_helper` (emit `fun use_X(x: Cap) -> Bool`, call from
      main, capability value crosses a function boundary),
    - `consumed` (emit `fun take_X(consume x: Cap) -> Bool`,
      call from main, capability is consumed and cannot be
      used afterwards).
  Programs in the wild mix all four flavours across the
  declared capabilities. Each flavour preserves
  `runtime_classes ⊆ manifest_classes` by construction; the
  test catches regressions where an analyser or transpiler
  change ever lets a method call leak a class not in the
  function's signature, OR a use-after-consume slips through
  the linear-layer bookkeeping. The property-testing arc of
  the external whitepaper review is now closed; the citable
  thesis property is asserted on every generated program
  across the four capability-flow shapes.
- [x] **`Range<Int>` as a distinct type from `List<Int>`**.
  Done. `0..n` and `0..=n` now type as `Range<Int>`, a
  separate parametric type registered in `capa/builtins.py`.
  Method surface: `length`, `contains`, `is_empty`, `to_list`
  (the four pure queries plus explicit materialisation; the
  full `List<T>` API is reached via `.to_list().filter(...)`
  rather than implicitly available on Range). Runtime class
  `CapaRange` in `capa/runtime/_list.py` wraps Python's
  `range` and exposes `__iter__` so bound ranges iterate
  lazily; the direct `for x in a..b` form keeps its fast
  path emitting bare `for x in range(...)` with no wrapper.
  Verified: `CapaRange(0, 1_000_000_000)` constructs in 2µs
  with no allocation; the old `CapaList(range(0, 1B))` would
  allocate ~28 GB. Five existing tests migrated to the new
  shape (`.to_list()` for List-API calls, `Range<Int>`
  instead of `List<Int>` in type assertions). One new test
  asserts that direct `.filter` on a Range is now a typed
  rejection rather than silently working. No `Iterable` trait
  yet; the analyzer enumerates `List` and `Range` as the two
  iterables in `_check_for`. The trait consolidation can come
  if a third iterable shows up.
- [x] **`docs/positioning.md`** with honest comparison vs Pony,
  Koka, Roc, WebAssembly Component Model. The reviewer cited
  it approvingly; already landed.
- [ ] **Ineligibility proofs as SBOM enrichment**. The reviewer
  identified this as the most original idea in their second
  document (the IR design): the SBOM declares not just what a
  function *can* touch but what it is *provably incapable* of
  touching. The antithesis of npm's permission manifest. Real
  thesis contribution; worth a chapter of its own. Needs a
  closed-world story (no `Unsafe`, no dynamic dispatch) so the
  proof has teeth.
- [ ] **IR with capability annotations + monomorphisation**. The
  second review document proposes an ANF + basic-blocks + CFG
  IR with block parameters (MLIR / Swift SIL shape). The right
  long-term move for a native backend, but the thesis defends
  on the soundness theorem and the demos already in place, not
  on the IR. Deferred until after thesis submission.

The reviewer's six-month sequence puts IR redesign in September
and a native backend by December; that ordering trades thesis-
critical work (formalisation + case studies) for infrastructure
that the thesis does not need. My counter-sequence:
formalisation → CVE case studies → Hypothesis tests →
`Range<Int>` type → workshop paper submission → defer IR /
native backend until after submission.

---

## PhD-aligned work (P1, when it makes sense)

Capa as artefact in the SBOM Governance thesis:

- [~] **SPDX 2.3 parser in Capa**, proves Capa can mex with the
  real SBOM format. **Demo landed** at
  `examples/spdx_parser.capa`: parses the core SPDX 2.3 fields
  (document metadata, packages, file checksums, relationships)
  into typed Capa structs, with `capability SbomReader` marking
  the trust boundary, full `?`-chaining on `Result`, and pattern
  matching on every `JsonValue` variant. Regression test in
  `tests/test_transpiler.py::test_spdx_parser`. **Validation
  pass added** (`validate_spdx(doc) -> List<String>`): checks
  two invariants: (1) referential integrity, every
  `Relationship.source` and `Relationship.target` must point at
  a known SPDXID (`SPDXRef-DOCUMENT` plus every
  `Package.SPDXID`); (2) the relationship graph is acyclic,
  via three-colour DFS that returns `Some(witness)` for an
  arbitrary node in a cycle or `None` for a DAG. Returns a
  human-readable violation list, empty list = the document is
  internally consistent. **License-expression parser landed
  separately** at `examples/spdx_license_expr.capa`: a
  recursive-descent parser for the SPDX 2.3 Annex D grammar
  (`MIT OR (Apache-2.0 AND BSD-3-Clause WITH Classpath-
  exception-2.0)`), with a typed LicenseExpr AST (sum +
  mutually recursive struct payloads), structured Result errors
  on malformed input, and a precedence-aware renderer that
  round-trips (drops redundant parens, keeps load-bearing
  ones). **Pending**: optional SPDX fields (annotations,
  snippets, has-extracted-licensing-info), the tag-value
  alternative serialisation, and the thesis-chapter writeup
  that frames this as the "representation + validation" piece.
  Found and fixed a real analyzer bug along the way: `?` was
  returning `TyUnknown` instead of unwrapping `Result<T, E>` /
  `Option<T>` to `T`, which blocked type-aware method dispatch
  (e.g. `Map.get` lowering) on any expression downstream of a
  `?`.
- [~] **CycloneDX 1.5 parser in Capa**, same story. **Demo
  landed** at `examples/cyclonedx_parser.capa`: parses the
  CycloneDX 1.5 JSON shape (metadata with tools and main
  component, components[] with hashes and licenses,
  dependencies[] as a flat (ref, dependsOn[]) graph) into typed
  Capa structs (`CdxDocument`, `CdxComponent`, `CdxHash`,
  `CdxLicense`, `CdxDependency`, `CdxMetadata`). Handles both
  license shapes (`{license: {id|name}}` and `{expression:
  <SPDX-license-expression>}`) plus both `tools[]` shapes
  (modern `tools.components[]` and legacy flat array).
  Regression test in
  `tests/test_transpiler.py::test_cyclonedx_parser`.
  **Validation pass added**
  (`validate_cyclonedx(doc) -> List<String>`): mirrors the
  SPDX validator on both axes: referential integrity (every
  `Dependency.ref` and every entry in `dependsOn[]` must point
  at a known `bom-ref`, drawn from `metadata.component.bom-ref`
  plus every `components[i].bom-ref`) and acyclicity (same
  three-colour DFS as the SPDX side). **Pending**:
  vulnerabilities[] / VEX, services[], evidence[], signatures,
  and the cross-format comparison chapter that ties SPDX and
  CycloneDX into a single "representation + validation"
  narrative for the thesis.
- [ ] **`capability Provenance` (user-defined)**, capability that
  represents the right to query/verify a piece of supply-chain
  metadata. Demonstrates user-defined caps in a real domain.
- [~] **Example linking SBOM ↔ capabilities**: the headline
  "auditable supply chain" pitch made concrete. **Demo landed**
  at `examples/sbom_capability_audit.capa`: a Capa program reads
  both a CycloneDX SBOM and a JSON policy file via the `Fs`
  capability (attenuated to `examples/data/` via
  `Fs.restrict_to` before either file is touched), extracts
  each function's declared capabilities from the
  `capa:declared_capability` properties in the SBOM, and checks
  them against the per-function allow-list policy. Reports a
  per-function summary plus a list of violations. The novel
  part vs npm/PyPI/cargo SBOM tooling: in Capa both sides of
  the comparison are static (the type system makes the
  declared set rigorous; the audit is a syntactic comparison
  of two finite lists), so a diff between SBOM and policy is
  unambiguous and travels with the build artefact. Sample
  data at `examples/data/demo-sbom.json` +
  `examples/data/demo-policy.json` (the policy deliberately
  omits one function so the audit fires). Regression test in
  `tests/test_transpiler.py::test_sbom_capability_audit`.
  **Pending**: support structural cross-function policies
  (e.g. "no Net anywhere except inside an impl of trait
  NetClient"), and the thesis-chapter writeup that bridges
  Representation (the four parsers) and Validation (the
  audit) into the CRA-aligned pitch.

These are not Capa-the-language work; they're Capa-as-research-vehicle
work. Pick them up alongside the thesis chapters they unlock.

---

## Strategic / governance (P0 once we go public)

- [x] **`CONTRIBUTING.md`**, how to file an issue, what makes a good
  PR, dev setup, compiler structure, what kinds of contributions help
  and what does not currently fit.
- [x] **`CHANGELOG.md`**, Keep-a-Changelog format starting at
  `v0.2.0-alpha` (the first tagged release) with an `[Unreleased]`
  section for the post-tag security + governance work.
- [x] **Issue / PR templates** in `.github/`, two YAML issue forms
  (bug, feature) with required fields, a `config.yml` that disables
  blank issues and contact-links to security advisories + discussions,
  plus a `PULL_REQUEST_TEMPLATE.md`.
- [x] **`CODE_OF_CONDUCT.md`**, adopts Contributor Covenant 2.1 by
  reference with maintainer contact for reports.
- [x] **Security policy**, `SECURITY.md` with how to report
  vulnerabilities. Lists in/out-of-scope issues, the GitHub private
  advisory channel, supported versions, disclosure flow.
- [x] **Flip repo to public**, `gh repo edit --visibility public`.
  Tagged `v0.2.0-alpha` first.
- [x] **Repo security hardening**, Dependabot vulnerability alerts +
  security updates, secret scanning + push protection, private
  vulnerability reporting, CodeQL workflow (push + PR + weekly
  cron), `.github/dependabot.yml` for GitHub Actions, explicit
  `permissions: contents: read` on the tests workflow.

---

## Things explicitly NOT planned for v1

For honesty / scope control:

- LLVM backend (Phase 4 of original WhitePaper roadmap; far future)
- Self-hosting (Phase 5; very far future)
- Full async/await (reserved keywords, no implementation)
- Tail-call optimisation
- Garbage collection beyond what CPython provides
- Custom syntax extensions / macros
