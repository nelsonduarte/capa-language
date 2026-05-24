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

Wasm milestones closed.
`audit-trail-reporter`, `policy-eval`, and `sbom-watch` all
run end-to-end via both:

- `capa --wasm --run` (core wasm host bridge), and
- `capa --wasm --component --run` (Component Model artifact
  instantiated through an external wasmtime.component runtime)

with output bit-identical to the Python reference pipeline.
`capa --wasm --component --output app.wasm` still produces a
standalone Component Model `.wasm` artifact (`wasm-tools
component new` accepted, WIT spec embedded).

Sessions 2026-05-22 and 2026-05-23 closed: pattern-binder
shadowing (alpha-rename in the lowerer), for-loop `continue`
skipping the index increment, Float-typed struct fields using
`i64.store`/`load`, the bump allocator never growing memory
(`memory.grow` in `$alloc`), nested for-loops sharing scratch
locals (`$_f_list_N` / `$_f_idx_N` per depth),
`List<String>.contains` raising in `_emit_list_contains`,
kebab-case WIT identifiers, `io-error` record declaration,
the canonical-ABI rework for `list<string>` /
`option<string>` / `result<string, io-error>` /
`result<_, io-error>` / `result<u32, string>` / `string`
returns plus the `cabi_realloc` export the Component Model
linker requires, the `export main: func();` WIT entry point,
an external Component Model runtime in
`capa/runtime/_wasm_component_host.py` wired as
`--component --run`, and a pure-Capa JSON parser bundled at
`capa/ir/_builtin_json.capa` that replaces the
`capa:host/json` host bridge so the JsonValue tree lives in
the guest's own linear memory (closing the handle leak that
blocked the three demos under `--component --run`).

The Wasm CM backend is functionally complete for the demo
surface. Remaining work shifts to P1 (study, polish, paper)
and P2 (LLM tool-use demo).

---

## P0 — done for this milestone

No remaining work in this priority.

---

## P1 — High-impact within positioning

Strengthens the capability + supply-chain claim, but isn't on
the current Wasm critical path.


- [ ] **Wasm backend: FormatStr on arbitrary user struct types**.
  IoError landed 2026-05-27 (special case: read ``message``
  field at offset 0). Generalising to any struct that
  declares ``to_string()`` (or every struct with a single
  String field, or a per-type derived ``__str__`` analog)
  is the open design question; the error message at the
  emit site now points the user at ``${e.message}`` as the
  near-term workaround for non-IoError structs. ⏱ unknown.

- [x] **CIR coverage gap** (closed 2026-05-24). CIR now lowers
  46 of 46 analysable examples. `TuplePat` was already supported
  by 2026-05-24 (the TODO had it stale); match-arm guards landed
  in this session. The lowerer captures any ANF prelude the
  guard expression produces into a new `MatchArm.guard_setup`
  field; the Python emitter's `_format_guard` walks the setup
  and inlines it back into a single `case PAT if EXPR:` clause
  by substituting each prelude instruction's expression form
  into a `dst -> python_expr` map. Inlineable shapes today:
  `FieldAccess`, `Index`, `UnaryOp`, `BinOp`. Non-inlineable
  shapes (`Call`, `MethodCall`, etc.) raise `UnsupportedInIR`
  from the emitter, which the CLI's `--ir` path catches as
  before and falls back to the legacy transpiler. The Wasm
  emitter still rejects every guard (arm-level fall-through
  block restructure is its own piece of work). Coverage in
  `TestMatch`: `test_match_arm_with_trivial_guard_runs`,
  `test_match_arm_with_non_trivial_guard_runs`,
  `test_match_arm_guard_with_chained_binops_inlines`,
  `test_match_arm_guard_with_call_emit_raises_unsupported`.
  Suite: 1296 → 1299.

- [x] **Property-based testing for the Wasm backend** (closed
  2026-05-24). `tests/test_properties.py` Phase 4 now mirrors
  Phase 3's split: a basic strategy
  (`test_wasm_runtime_classes_subset_of_manifest_classes`) plus
  an advanced-flavours strategy
  (`test_wasm_runtime_subset_under_advanced_flavours`) that
  exercises plain / attenuated / via_helper / consumed call
  shapes through the lowerer and Wasm emitter. The
  `attenuated` flavour is gated to caps with WIT-encoded
  attenuators (currently `Fs.restrict_to`); the other three
  apply to every cap in `_WASM_CAP_PROBES` (Clock, Env, Fs).
  Same citable invariant as Phase 3:
  `wasm_runtime_classes ⊆ manifest_classes`. Suite: 1295 → 1296.

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

- [~] **Test-coverage review**. First two passes landed
  2026-05-25: `capa/runtime/_wasm_component_host.py` lifted
  0% → 74% via 4 `TestWasmComponentHost` cases. `capa/loader.py`
  lifted 60% → 65% via 7 cases extending `TestQualifiedCallShadowing`
  (TuplePat, StructPat shorthand, for-pat tuple, lambda param,
  if/elif/else nested shadow) plus `TestLoaderErrorFormat`
  (with-pos + without-pos branches of `LoaderError.format`).
  Suite: 1242 → 1253 tests total.
  Still open and worth a future pass:
  `capa/ir/_emit_wasm/_match.py` (41%; remaining gaps are
  variant payloads for Float/Bool, tuple-match sub-patterns,
  String-scrutinee match arms — domain-specific Wasm emission
  paths reached only by particular pattern shapes),
  `capa/loader.py` (still 65%; the ~175-line `_PrivateRenameWalker`
  visit-* dispatch dominates the remaining gap),
  `capa/lsp/server.py` (10%, needs an in-process LSP harness),
  `capa/repl.py` (30%). ⏱ 4-6h.

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

- [x] **LLM tool-use demo** (2026-05-23 landed at
  [nelsonduarte/capa_agent_demo](https://github.com/nelsonduarte/capa_agent_demo)
  v0.1.0). Four-tool agent harness in ~400 lines of Capa,
  talking to the real Anthropic Messages API. Attenuated
  capability wrappers (`ReadOnlyFs`, `GetOnlyHttp`) keep the
  LLM's blast radius statically bounded; `run_agent_loop`
  declares `[Clock, GetOnlyHttp, LlmClient, Logger, ReadOnlyFs,
  Stdio]` and nothing more, even total prompt-injection cannot
  escape because the compiler refuses the call. Live-verified
  against `claude-haiku-4-5`. Tagged v0.1.0 with the full
  three-layer supply-chain stack (signed tag + SLSA L2
  attestation in Sigstore Rekor).

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
- 2026-05-23: **Package-manager supply-chain hardening, three
  stacked layers** in `capa_cli` / `capa_datetime` / `capa_log`
  / `capa_http`:
  (1) lockfile SHA enforcement (catches tag retag);
  (2) GPG tag signatures + `verify_key` pinning (catches
  account compromise that moves a tag to an attacker commit);
  (3) **SLSA L2 build provenance via Sigstore** (each seed
  library's `.github/workflows/release.yml` fires on `v*` tag
  push, builds a tarball, generates a SLSA L2 attestation
  through `actions/attest-build-provenance@v1`, publishes to
  Rekor). v0.1.2 is the first attested release; demos updated.
- 2026-05-23: **Consumer-side SLSA L2 auto-verify**. `capa
  install` now runs `gh attestation verify` implicitly when a
  dep declares `verify_key` and is GitHub-hosted; refuses on
  attestation mismatch, graceful-skips on missing-tarball /
  missing-`gh` / non-GitHub host. Closes the three-layer
  supply-chain claim end-to-end. 10 new unit tests cover the
  branch table.
- 2026-05-23: **Website extracted to standalone repo** at
  [nelsonduarte/capa-language-website](https://github.com/nelsonduarte/capa-language-website).
  `git filter-repo` preserved per-file history; GitHub Pages
  custom-domain cut-over to the new repo completed in the same
  session with no measurable downtime (DNS unchanged, certificate
  carried over). `docs/` in this repo now contains only the
  Markdown source documents the website links to via absolute
  github.com URLs; the HTML pages, `style.css`, learn/ tutorial
  sequence, sitemap, robots, CNAME, and the logo assets all live
  in the new repo. README + CONTRIBUTING + STABILITY + templates
  rewritten to point at the canonical URLs.
- 2026-05-27: **Milestone: every downstream demo runs
  end-to-end under ``--wasm --run``**. Cross-demo smoke
  on the four downstream consumers (capa_showcase,
  policy-eval, audit-trail-reporter, sbom-watch) all
  produce Python-equivalent output under the Wasm CM
  backend. Zero new compiler gaps surfaced beyond the 8
  showcase-driven fixes from the past three days. The
  "Wasm CM backend that runs the demos" public-pitch claim
  is now demonstrably true for every demo, not just toys.
- 2026-05-27: **Wasm backend: ``${io}`` interpolation for
  ``IoError`` values**. ``_emit_format_part_stash`` gains an
  ``IoError`` branch that mirrors Python's ``__str__``:
  read the ``message`` field (String at offset 0 of the
  16-byte IoError record) and push as (ptr, len). The
  ``cause`` field is intentionally skipped (matches
  Python). General struct-to-string codegen for arbitrary
  user types stays a separate item; the error message at
  the unsupported branch now points users at the
  ``${e.message}`` workaround.
- 2026-05-27: **Monomorphiser: ``Fun(T) -> R`` unification**.
  The string-based unifier in ``_monomorphise._parse_ty``
  used to treat closure types as opaque atoms, so a generic
  HOF whose param list included a closure (the showcase's
  ``count_by<T>(items: List<T>, key: Fun(T) -> String)``)
  failed unification at every call site and was never
  monomorphised, leaving an undefined ``$count_by`` call in
  the WAT. Fix: decompose ``Fun(P, ...) -> R`` into a
  pseudo-head ``(fun)`` with the params + return as args so
  the existing recursive unifier infers ``T=LogEntry`` etc.
  Plus the showcase's last blocker: ``capa_showcase`` now
  runs end-to-end under ``--wasm --run`` with byte-identical
  output to the Python path. 2 new tests.
- 2026-05-27: **Lowerer: tag cap_used on built-in cap method
  calls reached via field access**. The lowerer's
  ``_lower_method_call`` only set ``cap_used`` when the
  receiver was a capability parameter (``cap.method(...)``).
  User-defined cap impls that reach a built-in cap through a
  struct field (``self.fs.read(...)``) left cap_used None, so
  the Wasm backend's canonical-ABI detector
  (``_collect_locals``' ``has_indirect_cap_call``) missed the
  call. The ``$_ret_area`` local then went undeclared and
  wasm-tools rejected the WAT with ``unknown local:
  $_ret_area``. Fix: tag cap_used by ``receiver.ty`` (head)
  when the type resolves to a built-in cap, regardless of
  how the receiver was reached. 1 new test:
  ``TestWasmCapCallViaFieldAccess``.
- 2026-05-27: **Wasm backend: top-level String const support
  end-to-end**. Three sites had no ``global`` case:
  ``_push_string_value_as_ptr_len`` (interpolation +
  String-arg push), ``_emit_string_assign`` (let-binding
  copy), and the hand-inlined String-arg branch in
  ``_emit_user_call`` (collapsed into the shared helper).
  Plus a deeper bug: the constant's UTF-8 bytes were never
  interned in the data segment because the discovery pass
  walks function bodies only, not ConstDecl. Fix:
  pre-intern every String-typed top-level constant at
  module-emit init, alongside the existing ``"true"`` /
  ``"false"`` Bool-FormatStr pre-intern. Without the
  pre-intern the recursion would push offset=0 (data
  segment start, NUL bytes interpolated where the user
  expects the constant's text). 3 new tests in
  ``TestWasmGlobalStringConst``.
- 2026-05-26: **Analyzer: propagate user-capability method
  return types**. ``_check_method_call`` used to gate the
  cap-method-table consult on ``recv_ty.name in
  CAPABILITY_NAMES`` (built-ins only). User-defined caps fell
  through to ``TyUnknown``, which propagated as ``?`` through
  the lowerer and broke the Wasm backend on any user-cap
  method call result. Fix: broaden the check to any
  ``SymbolKind.CAPABILITY`` symbol; populate
  ``sym.methods`` for user-defined caps during the second
  declarations pass (same shape that built-in caps get from
  ``register_builtins``). Same root pattern as the Fun-typed
  callee fix from 2026-05-25. Bonus tuple-type fix landed in
  the same change: ``_type_name`` in the lowerer was
  falling through to ``repr(te)`` for bare
  ``TupleType`` AST nodes, stuffing AST text into a ``ty``
  string. The wrapped-in-List form short-circuited via
  ``_wasm_type``'s head check and worked by accident; bare
  tuple params surfaced the gap. 3 new tests:
  ``TestWasmUserCapMethodDispatch`` (2 cases) and
  ``TestWasmTupleParamTypes`` (1 case).
- 2026-05-26: **Wasm backend: multi-value lowering for
  String in lambda params + returns**. The lifted-lambda
  signature now emits two i32s ``(ptr, len)`` per String
  param and a multi-value ``(result i32 i32)`` for a String
  return, matching the call-site convention already in
  ``_emit_closure_call`` + ``_set_string_dst``. Three surgical
  edits (``_register_lambda``, ``_fun_type_to_sig_key``,
  ``_emit_lifted_lambda``) plus two discovery walkers
  (``_uses_format_str``, ``_uses_float_format``) that needed
  ``MakeLambda`` recursion so a format-string inside a closure
  still triggers the ``$itoa`` / ``$ftoa`` helper. The latter
  surfaced a stale ``MakeLambda`` reference in
  ``_discovery.py`` that worked only because the dead code
  path was never reached; fixed the missing imports
  (``MakeList``, ``MakeSet``, ``MakeLambda``, ``Function``).
  Closes the second-to-last Wasm gap from the capa_showcase
  assessment. The remaining gap (analyzer not propagating
  user-cap method return types) is filed as the next item.
  2 new tests in ``TestWasmClosureStringTypes``.
- 2026-05-26: **Wasm backend: generic-function
  monomorphisation**. New IR pass at
  `capa/ir/_monomorphise.py` walks the lowered module,
  identifies generic free functions (`type_params != []`),
  walks every call into them, infers each call's
  type-parameter substitution by string-unifying the call's
  arg types against the callee's generic param types, and
  synthesises a specialised clone per unique substitution
  (mangled name like `first__Int` / `first__String`). Call
  sites are rewritten to target the mangled name; original
  generic Functions are removed before emit. Plumbed into
  `compile_wat` only (Python `--run` doesn't need it).
  Iterates to a fixed point so generic-calls-generic chains
  fully specialise.
  Scope cut: free functions only; generic methods, generic
  struct types, and generic capability methods still hit the
  actionable "no Wasm encoding" error. 3 new tests in
  `TestWasmGenericMonomorphisation` cover the simple
  instantiations + same-fn-called-with-two-types dedupe.
  Closes one of the three Wasm gaps surfaced by the showcase;
  the other (lambda multi-value lowering) stays open.
- 2026-05-25: **Analyzer: propagate return type of calls
  through Fun-typed callees**. The analyzer's `_check_call`
  used to return `TyUnknown` when the callee was a parameter /
  local / constant typed `Fun(P...) -> R`, with a comment
  admitting "Leaving the TyUnknown return matches the
  pre-existing behaviour for these call shapes." Now returns
  `R` directly (with an arity-mismatch error when applicable).
  Closes the third Wasm gap surfaced by the showcase: closure
  invocation through a Fun-typed param returning Bool used to
  produce wasm rejected by the validator (the `_ir_t1` temp
  was declared i64 from the fallback, the call_indirect
  returned i32, mismatch). New regression test
  `test_call_through_fun_typed_param_returning_bool` in
  `TestWasmClosures` pins the case.
- 2026-05-25: **Loader: scope-aware qualified-call rewrite**.
  The post-link `mod.fn() -> fn()` pass now consults a
  per-function set of local-binding names (parameters, let /
  var / for / match-pattern / lambda-param) before rewriting
  a `MethodCall(Ident(name), ...)`. When `name` shadows a
  module alias, the rewrite is skipped and the MethodCall
  survives intact for the analyzer + transpiler. Closes the
  second loose end surfaced by the agent demo (where
  `http: GetOnlyHttp` was being silently downgraded into a
  free-function call to `capa_http.http::get`). 5 new tests
  in `tests/test_loader.py::TestQualifiedCallShadowing`
  covering param / let / for / match-pat / negative control.
  Lambda-param case left as latent (the bound names are
  collected, no test added since LambdaExpr parsing has its
  own quirks worth a separate scope).
- 2026-05-25: **`capa_http` v0.1.3** — vendor-aware sys.path
  in `make_urllib_client`. Probes both `./vendor/capa_http/`
  (package manager) and `./libraries/capa_http/` (legacy
  hand-vendoring), with vendor taking priority. Closes the
  loose end from `capa_agent_demo` v0.1.0 (whose `main` carried
  a workaround); demo bumped to v0.1.3 and the workaround
  removed in commit `1cf666f`. Signed tag + SLSA L2 attestation
  in Sigstore Rekor verified before the cleanup landed.
- 2026-05-23: **LLM tool-use demo** shipped at
  [nelsonduarte/capa_agent_demo](https://github.com/nelsonduarte/capa_agent_demo)
  v0.1.0, the last P2 item from the alignment plan. The pitch:
  capability discipline is structurally the right shape for
  sandboxing LLM agents that can call tools. Industry
  competitors (LangChain, OpenAI function-calling, MCP) ship
  tools as arbitrary Python functions with no permission system;
  Capa replaces convention with a type-system proof. The
  `run_agent_loop` function's capability signature bounds the
  blast radius of *any* prompt injection. Live-verified against
  `claude-haiku-4-5`. First downstream demo that surfaced two
  real Capa-side bugs (capa_http vendor-path, codegen method
  shadow); both filed as P1 follow-ups.

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
