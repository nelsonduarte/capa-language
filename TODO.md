# Capa, TODO / Roadmap

Living inventory of pending work. Re-prioritised 2026-05-22.

## Priority levels

- **P0**: blocking the current goal (Wasm CM backend that runs
  the three downstream demos end-to-end). Touch first.
- **P1**: high impact within Capa's positioning (capability
  discipline + supply-chain governance). Touch once P0 is clear.
- **P2**: adoption-moving but not core to the headline claim.
  Touch when P0/P1 lulls.
- **P3**: research-grade or far-future. Parked. Listed for
  completeness; revisit only if a concrete need surfaces.

Status legend: `[x]` done · `[~]` partial · `[ ]` pending.

---

## Current goal (May 2026)

Both Wasm milestones are closed. `audit-trail-reporter`,
`policy-eval`, and `sbom-watch` all run end-to-end via
`capa --wasm --run` with output bit-identical to the Python
reference pipeline, AND build successfully under
`capa --wasm --component --output app.wasm` as Component
Model binaries (canonical ABI canonical-lowered for every
indirect-return capability method).

Session 2026-05-22 closed: pattern-binder shadowing (alpha-
rename in the lowerer), for-loop `continue` skipping the
index increment, Float-typed struct fields using
`i64.store`/`load`, the bump allocator never growing memory
(`memory.grow` in `$alloc`), nested for-loops sharing scratch
locals (`$_f_list_N` / `$_f_idx_N` per depth),
`List<String>.contains` raising in `_emit_list_contains`,
kebab-case WIT identifiers, `io-error` record declaration,
and the canonical-ABI rework for `list<string>` /
`option<string>` / `result<string, io-error>` /
`result<_, io-error>` / `result<u32, string>` / `string`
returns plus the `cabi_realloc` export the Component Model
linker requires.

The Wasm CM backend is functionally complete for the demo
surface; remaining work shifts to P1 (study, polish, paper)
and P2 (LLM tool-use demo).

---

## P0 — done for this milestone

No remaining work in this priority. Future P0 candidates:
end-to-end Component Model instantiation tests
(`--component`-built artifacts are validated by `wasm-tools`
today but not actually instantiated and run yet); and
running each demo through the property-based Wasm test
generator once that lands (see P1).

---

## P1 — High-impact within positioning

Strengthens the capability + supply-chain claim, but isn't on
the current Wasm critical path.

- [~] **CIR coverage gap**. CIR lowers 44 of 46 analysable
  examples; `TuplePat` in match patterns and match-arm guards
  remain unsupported (`UnsupportedInIR`). Closes the CIR
  pipeline as the primary path; legacy direct-to-Python emitter
  becomes the fallback only for unsupported constructs the IR
  doesn't yet model. ⏱ 4-6h.

- [~] **Property-based testing for the Wasm backend**. The
  Hypothesis suite at `tests/test_properties.py` only covers
  the Python pipeline (manifest ⊇ runtime classes). Mirror the
  property for `--wasm`: generate a small program, compile to
  Wasm, run through the host bridge with a traced version of
  the imports, assert `wasm_runtime_classes ⊆ manifest_classes`.
  Same citable invariant, new pipeline. ⏱ 6-8h.

- [~] **Empirical study at scale**. Four design-pattern CVE
  case studies landed in `examples/cve_*.capa` + `docs/cve_*.md`
  (PyYAML, Jinja2 SSTI, lxml XXE, pickle). Bug-class taxonomy
  is structurally complete. **Pending**: the quantitative study,
  transliterate 10-20 real libraries, measure SBOM-diff against
  hand-Python equivalents, report aggregates. Multi-session
  arc. ⏱ 20-30h.

- [~] **Formatter v3, AST round-trip**. v1 (line-level) and v2
  (intra-line spaces / comma fixup) landed. v3 needs expression
  re-emission from the AST and `//` comment preservation through
  the AST round-trip. Comment-preservation design comes first;
  no AST round-trip is safe without it. ⏱ 8-12h, design-heavy.

- [ ] **Test-coverage review**. `coverage.py` run + identify
  which parts of the analyzer / emitters are under-tested.
  Quick pass on the existing 1211 tests probably uncovers
  meaningful gaps. ⏱ 2-3h to measure + 4-8h to fill the worst.

- [~] **CycloneDX / SPDX parsers — pending optional fields**.
  `examples/cyclonedx_parser.capa` and
  `examples/spdx_parser.capa` cover the core fields with
  validation passes. Missing: SPDX annotations / snippets /
  has-extracted-licensing-info; CycloneDX vulnerabilities[] /
  VEX / services[] / evidence[] / signatures; the tag-value
  alternative serialisation; the "representation + validation"
  writeup tying them together. ⏱ 8-12h each.

- [~] **SBOM-capability audit example, structural policies**.
  Today's audit at `examples/sbom_capability_audit.capa`
  supports per-function allow-lists. Pending: structural
  cross-function policies (e.g. "no Net anywhere except inside
  an impl of trait NetClient"). ⏱ 4-6h.

- [~] **Workshop paper revision**. Draft v1 (~5000 words, all
  sections) is local-only. Iterate on revision; convert to
  LaTeX when targeting a specific venue submission. Target
  venues: PLAS, EuroS&P workshops, NDSS workshops. ⏱ 10-20h
  for a publishable revision; 20-40h for venue submission.

---

## P2 — Adoption-moving, not core

The single highest-leverage move per the strategy section is
**LLM tool-use sandboxing**: capability discipline is
structurally the right shape for sandboxing LLM agents that can
call tools. The industry has no good solution; Capa has the
right primitives. Listed at the top of this section accordingly.

- [ ] **LLM tool-use demo**. Small library (`capability
  LlmTool`, attenuated per-tool, embedded in the SBOM as the
  declared authority surface) showing a Capa-shaped agent
  harness where each tool's authority is statically narrowed
  and surfaced in the manifest. Probably the single
  highest-leverage thing to build next. ⏱ 2-3 days.

- [~] **LSP server v2 polish**. v1 covers diagnostics, hover,
  go-to-definition, find-references, documentSymbol, code
  actions, rename, completion (floor + module scope + receiver
  methods), semantic tokens. Pending items: none currently
  identified at the LSP level. Re-evaluate after a real-user
  session. ⏱ depends on what surfaces.

- [~] **REPL v2**. MVP at `capa/repl.py` re-runs everything on
  each input (no incremental state). v2 needs incremental
  analyzer state and readline / history. ⏱ 8-12h.

- [ ] **VSCode marketplace publication**. Grammar lives in
  `vscode/`; install today is manual symlink/junction. Publish
  to Marketplace for one-click install. ⏱ 1-2h once the
  Marketplace account + publisher are set up.

- [ ] **Migration path from Python**. Today's interop is one-way
  via `Unsafe`. A "gradual hardening" mode (start with
  everything `Unsafe`, then narrow function by function) would
  lower the entry barrier significantly. ⏱ design-heavy,
  weeks not hours.

- [ ] **Package manager + minimal registry**. Listed elsewhere
  as P3 ecosystem work. Without it there's no "install Capa,
  run a real program from a real library" path. Chicken-and-egg
  with libraries. ⏱ months as a real product; days as a
  manifest-only MVP.

- [ ] **Debugger integration**. Python debugger works on the
  transpiled output but maps poorly. Source maps would help.
  ⏱ 8-16h depending on Python debug-info granularity.

- [ ] **Analyzer performance benchmarks**. Lex+parse+analyze
  wallclock isn't measured. Probably not slow yet, but a
  measurement bar is cheap to add. ⏱ 2-4h.

---

## P3 — Research-grade, parked

None on the current plan. Each is a multi-month arc of its own.
Listed so the design space is explicit.

### Type-system extensions

- **Linear handles for resources** (must-call types). Smallest
  of the four extensions, most defensible value-add. ROI: high
  — closes a concrete bug class (resource leaks).
- **Information Flow Control (IFC)**. Cost: large; the type
  system needs a label algebra + noninterference proof. ROI:
  highest — addresses privacy leakage and prompt-injection
  attacks where capability discipline alone is not enough.
- **Typestate / session types**. Real for network / protocol
  code; concrete pain point even in Rust.
- **Constant-time markers for crypto**. Niche but high-value
  for the crypto subset. The CVE case studies already include
  CWE-208 (timing attack) examples that this would mechanically
  prevent.
- **Quantitative capabilities** (budgeted authority). ROI:
  marginal; most rate-limiting use cases are solved at the
  application level.
- **Refinement types**. Parked explicitly future.
- **Turbofish (`::<T>`)**. EBNF §7.3 mentions; never needed.
  Implement only if a concrete case comes up.

### Backend / runtime

- **Native LLVM backend**. The single biggest adoption blocker
  long-term. Python target is fine for prototyping; production
  deployment requires real performance.
- **Self-hosting**. Very far future.
- **Async / await with capability-aware semantics**. Hard part
  is the semantics: capabilities cannot leak across `await`
  boundaries; cancellation must not strand resources
  (intersects with linear handles).
- **Tail-call optimisation**.
- **Garbage collection beyond CPython's**.
- **Custom syntax extensions / macros**.

### Wasm-specific gaps that are not P0

- **List<T>.map / filter / fold for non-Int element types**.
  Today Phase 6E supports List<Int> HOFs only. Other element
  types need their packed-i64 / pointer-shape paths threaded
  through the HOF lowering. ⏱ ~8h.
- **Lambdas-inside-lambdas (nested closures)**. Today raises;
  needs env-of-env encoding. Rare in practice. ⏱ unknown.
- **Pure-Wasm JSON parser** (alternative to today's host
  bridge). ~500 lines of WAT; only matters for shipping
  truly host-independent Wasm modules. ⏱ 12-16h.

---

## Known restrictions (documented, not bugs)

- **Indent-based `match` inside parentheses** fails because
  parens suppress NEWLINE / INDENT / DEDENT. Workaround: the
  braced inline form (`match x { P1 -> e1, ... }`) works inside
  call expressions. Reclassified from "bug" to "documented
  restriction"; promote to a fix only if someone proposes a
  lexer change whose blast radius doesn't break the indent-based
  form elsewhere.
- **Block-body lambdas in deep expression contexts**. Same root
  cause as the indent-form match restriction above. Parser
  emits a targeted error pointing at the workaround (bind to
  `let` first, or use a single-expression body).

---

## Known limitations (visible to adopters)

What an adopter should know is not yet there. Surfaced in
`docs/roadmap.html`.

- **No package manager or registry**. No way to share or
  reuse Capa libraries beyond copying source. Waits on the
  module system. (P2)
- **No native backend**. Capa transpiles to Python; runtime
  is CPython. Benchmarks measure 1.00x to 1.45x overhead vs
  hand-Python. The Wasm CM backend (in active development)
  changes this but isn't 1.0-ready yet. (P3 long-term)
- **No async / await**. Keywords are reserved; no
  implementation. Capability-aware async is a research
  question. (P3)
- **REPL: MVP only**. Re-runs the assembled program on each
  input; no incremental state or readline. (P2)

---

## Completed (selective; full history in CHANGELOG.md)

Listed here so a glance shows the shape of done work; one line
per item with a date for time-anchoring. The CHANGELOG carries
the full reasoning.

### Wasm CM backend
- 2026-05-22: **Phase 6E-6I** all landed in a single multi-hour
  session: closures + HOFs, Bool/`()`/`?` follow-ups, JsonValue
  + `capa:host/json` host bridge, `String.split` +
  List<String> baseline, Option/Result method dispatch
  (`is_some/none/ok/err/unwrap_or`), lowerer fix for parametric
  type rendering, List.get + Map<String,String>, String-
  scrutinee match, multi-value String returns. 92 Wasm tests
  green.
- 2026-05-22: **Wasm emitter modularised**. `_emit_wasm/`
  package with 7 focused mixins (closures 888, strings 756,
  maps 450, runtime 432, lists 417, layout 242, match 149,
  json 245, option 174); main `__init__.py` 1506 lines (was
  4628). Composition pattern matches the analyzer / parser /
  transpiler splits.

### Frontend / analyzer
- 2026-05-20: NLL-style consume tracking around divergent
  branches.
- 2026-05-20: Block-scope shadowing rejection.
- 2026-05-20: All four Agda soundness theorems mechanised
  (Stages 1-4 of `proofs/`).
- 2026-05-19: `?` soundness fix (analyzer rejects `?` whose
  enclosing function/lambda doesn't return Result/Option).
- 2026-05-15: `pub` visibility enforcement via per-module name
  mangling.
- 2026-05-15: Stdlib paths via `CAPA_PATH`.

### Supply-chain artefacts
- 2026-05-15: **Tier 1 complete** — SBOM diff tool, SPDX 2.3
  emission, VEX integration, SLSA Build L1 provenance.
- 2026-05-15: **Tier 2 complete** — `docs/regulatory.md`
  covering CRA + NIS2 + DORA + NIST SSDF + OWASP SCVS.
- 2026-05-15: Tier 3 — provenance signing workflow.
- 2026-05-15: Ineligibility proofs as SBOM enrichment
  (`provably_excluded_capabilities` in CycloneDX + SPDX).

### CVE case studies (6 landed)
- event-stream 2018, eslint-scope 2018, node-ipc 2022,
  xz-utils 2024, torchtriton 2022, ua-parser-js 2021. Four
  clean wins + two honest partial losses, balanced experimental
  panel. Plus four design-pattern CVE studies (PyYAML,
  Jinja2 SSTI, lxml XXE, pickle).

### Tooling
- 2026-05-15: LSP v1 (diagnostics, hover, go-to-definition,
  find-references, documentSymbol, code actions, rename,
  completion incl. receiver-method completion after `.`,
  semantic tokens).
- 2026-05-15: Formatter v2 (line-level + intra-line spaces /
  comma fixup).
- 2026-05-15: REPL MVP.
- 2026-05-15: `capa init` project scaffolding.
- 2026-05-15: Property-based testing through Phase 3.7 (multi-
  capability strategies with plain / attenuated / via_helper /
  consumed flavours, 50k+ generated programs stress-tested).
- 2026-05-15: Watch mode (`capa --watch`).
- 2026-05-15: Doc comments (`///`, `/**`), raw strings,
  named arguments.

### Strategic / governance
- All public-readiness items landed; repo flipped public,
  tagged `v0.2.0-alpha`. Security policy, code of conduct,
  contributing guide, issue / PR templates, Dependabot, secret
  scanning, CodeQL workflow.

---

## Things explicitly NOT planned for v1

For honesty / scope control:

- LLVM backend (far future)
- Self-hosting (very far future)
- Full async/await (reserved keywords, no implementation)
- Tail-call optimisation
- Garbage collection beyond CPython's
- Custom syntax extensions / macros
