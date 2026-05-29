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

- [x] **Compiler bugs surfaced by capa_governance_pack stress
  test 2026-05-26** (closed 2026-05-27). All five findings
  from writing the first real-world ~900-LOC downstream
  Capa program
  ([nelsonduarte/capa_governance_pack](https://github.com/nelsonduarte/capa_governance_pack)):
  1. **[x] MEDIUM. Variant name collision shadows built-in
     `Result::Ok`** (closed 2026-05-27). Fix: hard-ban
     `Ok` / `Err` / `Some` / `None` as user-declared variant
     names with an actionable diagnostic that suggests
     common alternatives (`Compliant` / `Success` / `Hit` /
     `Ready` for `Ok`, etc.). New `_RESERVED_VARIANT_NAMES`
     constant + small if-block at the top of the variant-
     registration loop in `capa/analyzer/_declarations.py`,
     before the existing generic "conflicts with another
     declaration" branch (whose message references
     `_BUILTIN_POS` and reads poorly). Now the original
     repro emits exactly one error pointing at the user's
     `Ok` declaration; `Result::Ok(1)` in the function body
     stays accessible. Five regression tests in
     `TestReservedVariantNames` (one per reserved name plus
     a positive control). JsonValue variants (JNull /
     JBool / ...) intentionally NOT in the reserved set;
     they are domain-specific and unlikely to collide.
     Workaround used in `capa_governance_pack` (rename to
     `Compliant`) remains the canonical idiom under the
     new rule. Full suite 1775 / 5 skipped / 0 fail.
  2. **[x] LOW (cosmetic). Formatter v3 orphans trailing
     `//` on `match` arm body** (closed 2026-05-27). Root
     cause: `MatchArm` is an `A.Node` but not `A.Stmt` /
     `A.Item`, so `_enclosing_stmt_or_item` walked past it
     up to the enclosing `LetStmt`. Fix: new
     `_enclosing_match_arm_on_line` short-circuit in
     `_attach_trailing` that owns the comment on the arm
     when the arm body is a single `Expr` on the same line.
     `_emit_match_arm` in `_emit_stmts.py` now calls
     `_emit_trailing(arm)` for both single-line arm shapes.
     `Some(v) -> v  // tolerate` round-trips byte-exact.
  3. **[x] LOW (cosmetic). Formatter v3 glues `// =====`
     divider to `///` doc block** (closed 2026-05-27). Root
     cause: `_emit_item` writes the leading comments
     (CommentMap) immediately followed by `_emit_doc` with
     no separator. Fix: `_emit_item` now inserts one blank
     line whenever the item has BOTH a non-empty `leading`
     comment block AND a `///` doc string. Generic
     `_item_doc(item)` helper reads `getattr(item, "doc",
     None)` so the rule applies uniformly to `FunDecl`,
     `TypeStruct`, `TypeSum`, `TraitDecl`. The AST doesn't
     carry the doc's source-line, so this is a deliberate
     canonical choice (always a blank between a non-empty
     leading block and the doc) rather than a
     position-preserving heuristic.
  4. **[x] LOW (diagnostic clarity). Top-of-file `///`
     diagnostic** (closed 2026-05-27). Three "doc comments
     are not valid on X" messages (`import`, `const`,
     `impl`) in `capa/parser/_items.py` rewritten to name
     the `///` syntax and suggest the `//` alternative:
     "doc comments (\`///\`) attach to declarations and are
     not valid on 'import'. Use a plain comment (\`//\`)
     for module-level headers, or move the doc above the
     next declaration."
  5. **[x] OBSERVATION. `--cyclonedx` emits mangled cross-
     module non-pub names** (closed 2026-05-27). Root cause:
     loader's `_mangle_private_items` rewrites every non-pub
     top-level identifier in an imported module to
     `_capa_m{N}__<source>` to keep the merged AST flat
     without name collisions; the manifest builder copied
     `fn.name` directly into the SBOM, so the auditor saw
     `_capa_m2__as_object_or_err` instead of `as_object_or_err`.
     Fix: new `_demangle` helper in `capa/manifest/_funrec.py`
     that parses the prefix back into
     `(source_name, module_index)`; the function record now
     carries `source_name`, `source_container`, and
     `source_module_index` alongside the existing (loader-
     time, possibly-mangled) `name` and `container`. The
     loader-time fields stay because internal call-resolution
     + bom-ref / SPDXID keying rely on them for cross-module
     collision stability. The CycloneDX and SPDX emitters
     now display `source_name` (and `source_container`) on
     the public `name` / `qualname` field and surface the
     import index as a `capa:source_module_index` property
     (CycloneDX) / annotation (SPDX) so an auditor can still
     tell two same-source-named helpers from different
     modules apart. Verified end-to-end on
     capa_governance_pack: `still-mangled: 0` across all 40
     components (was substantial pre-fix). 5 regression
     tests (`TestSourceNameDemangle` x 3 covering root /
     non-pub-imported / pub-imported shapes via the real
     loader harness;
     `TestSourceNameInSboms` x 2 covering CycloneDX and
     SPDX integration). Full suite 1783 / 5 skipped / 0
     fail.
  All five bugs from the capa_governance_pack stress test
  are now closed.

- [x] **Wasm backend: FormatStr on arbitrary user struct types**
  (closed 2026-05-24). Design decision: opt-in Display protocol
  rather than auto-derive. A struct that declares
  ``fun to_string(self) -> String`` in an impl block opts in;
  both backends honour the method consistently
  (``${value}`` -> ``value.to_string()`` rewrite at emit time).
  Structs without it keep their pre-existing behaviour:
  ``--python`` falls through to dataclass repr (unchanged); the
  Wasm emitter raises a `WasmEmissionError` whose message
  points the user at the protocol ("declare
  `fun to_string(self) -> String` in an impl block for X") or
  at field-specific interpolation as a workaround. Auto-derive
  was rejected because reproducing Python's dataclass repr
  byte-for-byte from the Wasm side would have been months of
  brittle work, and inventing a different default format would
  have created backend output drift on the existing corpus.
  Coverage: 4 new `TestWasmStructToStringDisplay` cases (Wasm
  + Python display round-trip; opted-in struct in main and in
  a callee; actionable error for non-opted-in structs).
  Suite: 1345 -> 1349. The Display protocol is itself a small
  language feature; a formal `trait Display` could supersede
  the duck-typed method check in a later slice.

- [x] **CIR coverage gap** (closed 2026-05-24, Wasm-side
  guards 2026-05-25). CIR now lowers 46 of 46 analysable
  examples. `TuplePat` was already supported by 2026-05-24
  (the TODO had it stale); match-arm guards landed in the
  2026-05-24 session for the IR + Python side. The lowerer
  captures any ANF prelude the guard expression produces into
  a new `MatchArm.guard_setup` field; the Python emitter's
  `_format_guard` walks the setup and inlines it back into a
  single `case PAT if EXPR:` clause by substituting each
  prelude instruction's expression form into a
  `dst -> python_expr` map. Inlineable shapes today:
  `FieldAccess`, `Index`, `UnaryOp`, `BinOp`. Non-inlineable
  shapes (`Call`, `MethodCall`, etc.) raise `UnsupportedInIR`
  from the emitter, which the CLI's `--ir` path catches as
  before and falls back to the legacy transpiler. The Wasm
  emitter now supports guards too (2026-05-25) via a
  flat-block-with-labeled-exit restructure: when any arm
  carries a guard the per-scrutinee emitter opens a
  `block $match_done<N>` and emits each arm as
  ``predicate ; if ; bind-payloads ; guard-setup ; guard ;
  if ; body ; br $match_done<N>`` (nested ifs so a failed
  guard falls through to the next arm naturally). Guard-free
  matches keep the legacy nested cascade. Covers
  Bool / String / sum / tuple scrutinees; nested-variant +
  guard arms raise a precise WasmEmissionError pointing the
  user at the two-nested-matches workaround. Coverage in
  `TestMatch`: `test_match_arm_with_trivial_guard_runs`,
  `test_match_arm_with_non_trivial_guard_runs`,
  `test_match_arm_guard_with_chained_binops_inlines`,
  `test_match_arm_guard_with_call_emit_raises_unsupported`.
  Wasm-side coverage in `TestWasmMatchArmGuards`:
  `test_simple_guard_on_int_variant`,
  `test_guard_with_setup`, `test_bool_match_with_guard`,
  `test_string_match_with_guard`,
  `test_guard_failure_falls_through`,
  `test_no_guard_matches_unchanged`.
  Suite: 1296 → 1299 (IR side) → 1488 (Wasm side).

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

- [x] **Empirical study at scale** (closed 2026-05-26). Target
  reached at the upper bound: 20 library pairs, all `--check`
  + `--cyclonedx` + `--run` green, end-to-end harness +
  summary at [`evaluation/sbom_diff/`](evaluation/sbom_diff/).
  Final aggregates: **122 total functions (73 pure / 49
  with caps); 6 distinct cap axes (Clock, Env, Fs, Net,
  Random, Stdio); 61 per_fn_info_bits ((function, capability)
  declaration facts that have no counterpart in a PURL
  SBOM)**. Axis-alone coverage matrix complete for the 5
  Capa-exposed transliterable axes; pair-combination matrix
  covers Fs+Env, Fs+Clock, Fs+Net, Net+Clock, Env+Clock,
  Random+Clock, plus the Fs+Env+Net triple. Four design-
  pattern CVE case studies in `examples/cve_*.capa` +
  `docs/cve_*.md` (PyYAML, Jinja2 SSTI, lxml XXE, pickle)
  continue to anchor the bug-class taxonomy side.
  Slice 1 landed 2026-05-26: study scaffold at
  [`evaluation/sbom_diff/`](evaluation/sbom_diff/) (README +
  harness.py + summary.py, stdlib-only). Three library pairs
  in the corpus: `config_loader/` (Fs+Env+Net, ported from
  `examples/empirical_config*`), `dotenv/` (Fs+Env,
  python-dotenv shape; surfaces a structural finding that
  Capa's read-only Env capability cannot mirror the naive
  Python's `os.environ` mutation, which is a stronger
  asymmetry than per-function attribution alone), `slugify/`
  (pure, asymmetry case where PURL would list `re` +
  `unicodedata` but Capa proves 4 of 5 functions hold zero
  authority). Harness extracts per-function
  `capa:declared_capability` properties via subprocess
  `capa --cyclonedx`, scans naive.py AST for top-level
  imports, intersects with a 30-entry capability-bearing
  module allowlist; emits `results.csv`. Summary renders a
  paper-ready table + asymmetry analysis. Aggregate metric
  `per_fn_info_bits` (count of (function, capability)
  declarations) sat at 13 across 3 pairs.
  Slice 2 landed 2026-05-26: five additional library pairs
  delegated in parallel to sub-agents and joined into the
  corpus. `tabulate/` (pure, ASCII-table formatter; PyPI
  ~50M downloads/month), `http_retry/` (Net + Clock, the
  exponential-backoff fetch pattern present in
  `urllib3.Retry`, `requests`, `tenacity`, `backoff`,
  `httpx`; first Clock-bearing pair), `ini_loader/` (Fs
  alone, `configparser` shape; first single-Fs pair),
  `short_uuid/` (Random; first Random-bearing pair, shortuuid
  shape ~3M downloads/month), `textwrap/` (pure, stdlib
  shape, cleanest 1:1 pure-case parity with no Unicode-
  normalisation gap). Corpus now at **8 pairs / 46 functions
  (26 pure / 20 with caps) / 6 distinct cap axes (Clock,
  Env, Fs, Net, Random, Stdio) / 25 per_fn_info_bits**.
  Asymmetry section now enumerates 6 pairs (every pair with
  non-empty naive imports).
  Slice 3 landed 2026-05-26: five more pairs delegated in
  parallel. `env_loader/` (Env alone, 12-factor settings
  pattern; first Env-only pair; surfaces an additional
  structural narrowing since Capa's Env has no full-iteration
  API so the Capa version takes an explicit `keys` list, an
  upper bound on what the function can ever read),
  `log_forwarder/` (Fs + Net, tail-log + POST pattern;
  Capa Net has no `post` so the version uses callback-URL
  GETs - itself a more disciplined wire shape than
  arbitrary-body POST), `rate_limiter/` (Clock alone, token-
  bucket pattern; first Clock-only pair; refill arithmetic
  is purely functional given an elapsed time so 3 of 6
  functions are compiler-verified pure), `glob_walker/` (Fs
  alone, recursive directory walk; second Fs-only pair but
  exercises `list_dir` + `is_dir` rather than `read`),
  `humanize/` (pure, byte/duration/count formatter; PyPI
  ~30M downloads/month). Corpus now at **13 pairs / 75
  functions (42 pure / 33 with caps) / 6 distinct cap axes /
  40 per_fn_info_bits**. Slice 3 surfaced a pre-existing
  Capa typer-vs-transpiler mismatch: analyzer types `Int /
  Int -> Int` (per `capa/analyzer/_expressions.py:489`) but
  the transpiler used to map `/` to Python true division
  (Float) per `capa/transpiler/__init__.py:143`. Fixed
  2026-05-26 in `capa/transpiler/_expressions.py`: BinOp
  emit now consults `self.types.get(id(e.left))` /
  `self.types.get(id(e.right))` and emits `//` when both
  are `TyName("Int")`. Wasm backend was already correct
  (`i64.div_s`). 6 regression tests in
  `tests/test_transpiler.py::TestIntegerDivision`. The
  `idiv` workaround was dropped from `humanize/capa.capa`
  (3 call sites + the helper) and replaced by direct `/`.
  Slice 4 landed 2026-05-26: five more pairs delegated in
  parallel, closing remaining cap-axes combinations.
  `url_fetch/` (Net alone, GET-and-JSON-parse pattern; first
  Net-only pair - completes the axis-alone coverage matrix
  alongside ini_loader Fs / env_loader Env / rate_limiter
  Clock / short_uuid Random), `disk_cache/` (Fs + Clock,
  memoise-with-TTL pattern; first Fs+Clock combination;
  surfaces another structural narrowing - Capa Fs has no
  `getmtime` so the version stores the timestamp inside the
  file, a more disciplined format than mutable filesystem
  metadata), `csv_parser/` (pure, stdlib csv shape;
  state-machine parser, exercises Capa's nested-collection
  handling), `pathspec/` (pure, gitignore matching via
  direct recursion since Capa has no regex; PyPI ~50M
  downloads/month), `colorama/` (pure, ANSI codes; first
  pair making the explicit point that a casually-Stdio-
  associated lib is actually pure - the colored strings
  are produced; printing is the caller's responsibility;
  Capa's per-function attribution makes this crisp).
  Corpus now at **18 pairs / 109 functions (67 pure / 42
  with caps) / 6 distinct cap axes / 51 per_fn_info_bits**.
  Axis-alone coverage matrix is now COMPLETE for the 5
  Capa-exposed-axes that can be transliterated (Clock, Env,
  Fs, Net, Random; Stdio is the universal demo-print
  surface; Db and Proc are out-of-scope by Capa design).
  Slice 4 surfaced a real Capa lexer bug: `\033` parsed
  silently as `\0` + literal `33` (greedy `\0` consumption
  followed by literal characters). Fixed 2026-05-26 in
  `capa/lexer/_literals.py` `_read_escape`: after consuming
  `\0`, peek at the next char; if it is a digit, raise
  `octal escape '\\0X...' is not supported; use '\\u{HEX}'
  for arbitrary code points, or '\\0' alone for NUL`. Bare
  `\0` (NUL) still works. 3 regression tests in
  `tests/test_lexer.py::TestStringLiterals`
  (`test_escape_nul`, `test_octal_escape_rejected`,
  `test_octal_escape_rejected_inside_string`). `colorama/`
  was already using `\u{1b}` so no update needed.
  Slice 5 landed 2026-05-26: closing 2 pairs to hit the
  upper target. `session_token/` (Random + Clock; first
  Random+Clock combination; shape of `itsdangerous`,
  `pyjwt`, `flask-login` core; 4 pure helpers + 2 cap-bearing
  composition functions), `secret_rotator/` (Env + Clock;
  first Env+Clock combination; shape of `python-keyring`,
  `aws-secretsmanager-caching`, `vaultenv` shape; 2 pure
  helpers + 2 cap-bearing functions). Corpus closes at
  **20 pairs / 122 functions (73 pure / 49 with caps) /
  6 distinct cap axes / 61 per_fn_info_bits**. Pair-
  combination matrix covers Fs+Env, Fs+Clock, Fs+Net,
  Net+Clock, Env+Clock, Random+Clock, plus the Fs+Env+Net
  triple. Reproduce via
  `.venv/Scripts/python -m evaluation.sbom_diff.harness &&
  .venv/Scripts/python -m evaluation.sbom_diff.summary`.

- [x] **Formatter v3, AST round-trip** (closed 2026-05-26).
  v1 (line-level) and v2 (intra-line spaces / comma fixup) are
  the safe textual fallback. v3 adds expression re-emission
  from the AST and `//` comment preservation through the AST
  round-trip. `format_source` defaults to v3 with graceful
  fallback to v1+v2 on lex / parse / emit failure.
  Phase 1 landed 2026-05-26: lexer sidecar for plain comments.
  `capa/tokens.py` gains `CommentKind` (LINE / BLOCK) and a
  frozen `Comment` dataclass (kind, start, end, text);
  `capa/lexer/__init__.py` gains `self.comments: list[Comment]`;
  `_skip_line_comment` and `_skip_block_comment` in
  `capa/lexer/_comments.py` now record into the sidecar before
  consuming. Token stream is unchanged, so parser / analyzer /
  transpiler / Wasm emitter see no difference. Full suite green
  at 1653 / 5 skipped / 0 fail (10 new tests in
  `TestCommentSidecar`).
  Phase 2 design locked in
  [`docs/formatter-v3-comment-map-design.md`](docs/formatter-v3-comment-map-design.md):
  CommentMap as a side-table keyed by `id(node)` (matches
  `analyzer.types` / `transpiler.types` convention); attachment
  rules for trailing / standalone / floating per category;
  separate slots `leading` / `trailing` / `trailing_header` /
  `interior`; O((T+N) + C log(T+N)) algorithm. Doc identifies
  the one real risk (interleaving with `///` doc comments
  before items) and prescribes a 9th test plus a one-helper
  adjustment to de-risk before Phase 3.
  Phase 2 landed 2026-05-26: `CommentMap` implementation at
  [`capa/formatter/_comments.py`](capa/formatter/_comments.py)
  (588 LOC). Implements the locked design verbatim: side-table
  keyed by `id(node)` with four slots (`leading`, `trailing`,
  `trailing_header`, `interior`); trailing-vs-standalone-vs-
  floating triage via the positional rule; section-divider regex
  + doc-comment-adjacency triage for the de-risk case from
  design 7. 10 unit tests in
  `tests/test_comment_map.py::TestCommentMap` cover every shape
  from the design. Invariant `len(cmap) == len(lexer.comments)`
  holds on 3 sampled corpora files (68 / 69 / 66 comments).
  Phase 3 landed 2026-05-26: AST pretty-printer at
  [`capa/formatter/_emit.py`](capa/formatter/_emit.py) (entry +
  `_Emitter`, 242 LOC) plus per-category emitters
  `_emit_items.py` (329), `_emit_stmts.py` (394),
  `_emit_exprs.py` (466). Total 1431 LOC. Handles all 50+ AST
  node types with precedence-based parenthesisation; emits all
  4 type expressions and all 7 patterns; escapes string
  literals canonically (including `\u{1b}` for ESC per the
  Capa lexer constraint). 66 tests in
  `tests/test_pretty_printer.py`: `TestPrettyPrinterStructure`
  (64 targeted snippets), `TestPrettyPrinterRoundtrip` (the
  key invariant: parse -> emit -> parse produces a structurally
  equivalent AST on 71 corpus files: 51 examples + 20
  sbom_diff), `TestPrettyPrinterIdempotence` (byte-exact
  `fmt(fmt(src)) == fmt(src)`). Package layout follows the
  design's split:
  `capa/formatter/{__init__,_lines,_comments,_emit,_emit_*}.py`.
  Phase 4 fully landed 2026-05-26: `format_source` defaults to
  the AST roundtrip pipeline, with graceful fallback to v1+v2
  on any lex / parse / emit failure (mid-edit sources, syntax
  errors, broken constructs all get the safe textual cleanup).
  Two CommentMap fixes shipped alongside the promotion:
  (1) block-aware file-header heuristic. A standalone comment
  attaches to `Module.leading` only when its contiguous comment
  block has no section divider AND is separated from the first
  item by at least one blank line. Without this, a section-
  divider-wrapped block above the first item was getting split
  (dividers on FunDecl, body on Module), reversing source order
  in the emitter's leading list. Block bookkeeping is
  precomputed in `build_comment_map` (single right-to-left
  pass per block). (2) Token-aware end offsets in
  `_build_node_index`. The old bottom-up `max(start, recursive
  max of children's ends)` underestimated leaf spans (IntLit /
  FloatLit / Ident leaves had end = start), so a `let x = 1
  // trailing` style comment's `_smallest_containing_node`
  lookup landed on the enclosing `Block` instead of the
  `LetStmt`, with every trailing comment in a function body
  bunching up on the `FunDecl`. The new pass refines each
  entry's end to the end offset of the last token whose start
  falls in `[entry.start, next_sibling_at_same_or_shallower_
  depth.start)`. Two small follow-ups (test_javadoc rename to
  reflect `/** */` -> `///` canonicalisation; init template
  drops blank line between doc and `fun main`; `format_source`
  guard against degenerate lone-`\` line-continuation sources
  that lex to empty token streams). Corpus idempotence is
  71/71 via the promoted `format_source` path. Full suite at
  1730 passed / 5 skipped / 0 fail. Downstream `sbom-watch`
  smoke verified.

- [~] **Test-coverage review**. Three passes landed:
  - 2026-05-25 (1): `capa/runtime/_wasm_component_host.py`
    lifted 0% → 74% via 4 `TestWasmComponentHost` cases.
  - 2026-05-25 (2): `capa/loader.py` lifted 60% → 65% via
    7 cases extending `TestQualifiedCallShadowing` plus
    `TestLoaderErrorFormat`.
  - 2026-05-24 (3): `capa/ir/_emit_wasm/_match.py` lifted
    43% → 86% via 13 `TestWasmMatchEmission` cases targeting
    the missing-line ranges directly (Bool catch-all branches,
    String-scrutinee match, every tuple-match shape including
    literal sub-patterns + Float / Bool / String element binds,
    variant payload Float / Bool binding). Surfaced and fixed
    two real soundness bugs in the process: top-level IdentPat
    catch-all on Bool / Tuple matches declared the binder local
    as i64 instead of i32 (analyser refinement gap, fixed in
    `_refine_pattern_binds`); and `$str_eq` was not auto-imported
    when the only String comparison came from a tuple-match
    sub-pattern (fixed in `_discovery._uses_map_ops`).
    `capa/loader.py` lifted 69% → 93% via 6
    `TestPrivateRenameWalkerCoverage` cases hitting every
    visit-* branch of `_PrivateRenameWalker` and `_Rewriter`
    in-process (the existing `TestPubVisibility` cases run
    `--run` via subprocess and don't register against the
    parent's coverage instance, which is why the gap had
    stayed open).
    Suite: 1299 → 1318.
  - 2026-05-24 (4): `capa/lsp/server.py` lifted 12% → 97% via
    27 new cases. `TestLspServerHandlersInProcess` builds the
    real LanguageServer, stubs the workspace + publish +
    show_message, then drives every `@server.feature(...)`
    handler directly via `server.protocol.fm.features[...]`
    (pygls 2.x's feature map). Handlers come back as
    `functools.partial` with the server pre-bound, so each
    call is just `handler(params)`. Covers did_open / did_change
    / did_save / did_close, hover, definition, references,
    document_symbol, code_action, semantic_tokens_full,
    completion, prepare_rename, rename, plus the small URI /
    Pos translation helpers and the `serve()` ImportError
    fallback. Final 5 missed lines are 3 trivial early-returns
    + the 2-line `start_io()` blocking loop -- not worth
    chasing. Suite: 1318 → 1345.
  - 2026-05-26 (5): `capa/repl.py` lifted 30% -> 87% via 32
    `TestReplInProcess` cases driving `serve()` through a
    monkey-patched `builtins.input` plus a captured
    stdout/stderr. Helper functions, `_ReplState`,
    `_try_compile_and_run`, `_typeof_expr`, `_find_probe_value`,
    and every dot-command branch (.exit / .quit / EOF / .help /
    .show / .reset / .types) are exercised, along with the
    bare-expression / let / top-level-fun / block-statement
    routing branches and the output-delta logic. Remaining
    misses are the KeyboardInterrupt arms (outer prompt + both
    continuation gathers) and the subprocess-timeout /
    runtime-failure paths inside `_try_compile_and_run`.
  - 2026-05-26 (6): `capa/cli.py` lifted 10% -> 77% via 56
    `TestCliInProcess` cases driving `main()` in-process with
    monkey-patched `sys.argv` + captured stdout/stderr.
    `--check` / `--transpile` / `--run` / `--manifest` /
    `--cyclonedx` / `--spdx` / `--vex` / `--provenance` /
    `--doc` / `--wit` / `--ir` / `--fmt` (+ `--fmt-check`,
    stdin path) / `init` subcommand / `--version` / `--help` /
    `--prefer-wasm` (both flag + env-var + forced-fallback
    paths) / `install` subcommand (success + InstallError +
    ImportError) / `CAPA_PATH` + `capa.toml` path-dep + broken
    `capa.toml` warning / `--ir` `UnsupportedInIR` legacy
    fallback / `--wit` exception path / `--run` SystemExit
    int + string code shapes / coloured token-dump branch
    (via `_TtyBuf(io.StringIO)`) / default token-dump + 
    `--no-layout` / `--watch` no-file error / unknown flag /
    `repl` + `lsp` subcommand dispatch all exercised.
    `--wasm` cases (`--transpile`, `-o` core, `-o --component`,
    `--run`, `--run --component`) skip when wasm-tools /
    wasmtime are missing. Remaining misses are mostly the
    `--watch` polling loop (intentionally skipped, ~88 lines)
    plus a handful of colour-branch error paths and the
    `--wasm` failure arms that need a synthetic CIR-rejection
    fixture. Suite: 1528 -> 1584.
  - 2026-05-26 (7): `capa/manifest/_strings.py` lifted 56% -> 100%
    via 50 `TestManifestStringHelpers` cases hitting every
    Expr-render and TypeExpr-render branch directly. Truncation,
    quote-string escape rules, and the _root_type_name fallback
    paths all exercised.

- [x] **CycloneDX / SPDX parsers, pending optional fields**
  (closed 2026-05-26). Three parser examples
  (`examples/spdx_parser.capa`, `examples/spdx_tag_parser.capa`,
  `examples/cyclonedx_parser.capa`) cover the JSON-schema
  surface of both SPDX 2.3 and CycloneDX 1.5 plus the
  alternative tag-value serialisation for SPDX. The
  "representation + validation" writeup tying them together is
  at [`docs/sbom-parsers.md`](docs/sbom-parsers.md), explaining
  the split between `parse_*` (typed AST) and `validate_*`
  (semantic checks on top of the AST), cataloguing every
  validator across the three parsers, and connecting them to
  the downstream `examples/sbom_capability_audit.capa`
  consumer. Sub-item progress journal below kept for reference.
  Progress 2026-05-25: SPDX `annotations[]` parsing landed at both
  document and package scope with a per-annotation
  `kind in {REVIEW, OTHER}` validator; locked by two new
  `assertIn` lines on `test_spdx_parser`.
  Progress 2026-05-25: CycloneDX `vulnerabilities[]` + VEX
  `analysis` subset parsing landed with severity / analysis-state
  enum validators and an affects-ref referential check; locked
  by four new `assertIn` lines on `test_cyclonedx_parser`.
  Progress 2026-05-25: CycloneDX services[] + data-flow validation landed; locked by five new assertIn lines on test_cyclonedx_parser.
  Progress 2026-05-25: SPDX hasExtractedLicensingInfos[] parsing landed with LicenseRef- prefix + non-empty extractedText validators; locked by four new assertIn lines on test_spdx_parser.
  Progress 2026-05-26: CycloneDX evidence (identity + occurrences + copyright) per-component landed with field / technique enum validators + confidence-bounds check; locked by five new assertIn lines on test_cyclonedx_parser.
  Progress 2026-05-26: SPDX snippets[] parsing landed with SPDXRef- prefix + non-empty-ranges + monotonic-offset validators (byte-offset pointer shape only; line-pointer pointer rejected at parse time); locked by five new assertIn lines on test_spdx_parser.
  Progress 2026-05-26: CycloneDX JSF signature parsing landed with algorithm enum + non-empty value validators; verification crypto stays out of scope. Locked by four new assertIn lines on test_cyclonedx_parser.
  Progress 2026-05-26: SPDX externalDocumentRefs[] parsing landed with DocumentRef- prefix + non-empty URI + complete-checksum validators; locked by four new assertIn lines on test_spdx_parser.
  Progress 2026-05-26: CycloneDX externalReferences[] per-component parsing landed with the 39-entry type enum + non-empty URL validator; locked by 5 new assertIn lines on test_cyclonedx_parser.
  Progress 2026-05-26: CycloneDX compositions[] parsing landed with 10-value aggregate enum + assembly/dependency/vulnerability ref-resolution validators; locked by five new assertIn lines on test_cyclonedx_parser.
  Progress 2026-05-26: SPDX tag-value (text format) parser landed as a new self-contained example examples/spdx_tag_parser.capa with state-machine line-by-line parsing covering document headers + creation info + packages (with checksums) + document-level annotations + relationships. Multi-line <text>...</text> blocks, snippets, extracted licenses, external doc refs, and per-package annotations are deferred to v2 with an explicit parse-time error. Locked by 9 assertIn lines on a new test_spdx_tag_parser.

- [x] **SBOM-capability audit example, structural policies**
  (closed 2026-05-25). `examples/sbom_capability_audit.capa`
  now carries a `Policy.structural: List<StructuralRule>`
  field alongside the existing per-function `rules` map. Each
  rule pins a capability to a list of allowed containers
  (impls / traits); every declared capability is checked
  against every matching structural rule independently of the
  per-function allow-list, so a single (fn, cap) pair can
  raise one per-function violation plus one structural
  violation. Missing `structural` in the JSON is treated as
  an empty list, keeping old policy files valid. Demo
  policy gains a `net-confined-to-NetClient` rule and the
  SBOM tags `fetch_user` with `capa:container=NetClient`;
  audit now reports 3 violations (notify_remote per-function
  + main and notify_remote structural). Locked by
  `tests/test_transpiler.py::TestTranspileExamples::test_sbom_capability_audit`.

- [~] **Workshop paper revision**. Draft v1 (~5000 words, all
  sections) is local-only. Iterate on revision; convert to
  LaTeX when targeting a specific venue submission. Target
  venues: PLAS, EuroS&P workshops, NDSS workshops. ⏱ 10-20h
  for a publishable revision; 20-40h for venue submission.
  Revision pass 2026-05-26: incorporated the now-closed
  20-pair SBOM-diff study (P1 #1) into the paper draft.
  Three surgical edits: (1) abstract phrase "an SBOM-diff
  case-study against an idiomatic Python equivalent" replaced
  with "a 20-library SBOM-diff study (122 transliterated
  functions across 6 capability axes; 61 (function,
  capability) attribution facts unrecoverable from a PURL-only
  SBOM)"; (2) §5.3 rewritten from a 45-line single-pair
  illustration to a 132-line / 989-word quantitative section
  with the per-pair table, the 6-axis aggregate, the two
  asymmetry shapes (PURL-narrowing via pure-function proof +
  PURL over-attribution), the axis-combination coverage
  matrix, and the three explicit honest-disclosure caveats
  surfaced from `summary.md`; (3) §8 future-work item 2
  (the "Empirical study at scale" item) removed since done,
  subsequent items renumbered. Side effect: 3 pre-existing
  em-dashes flagged and removed during the verification sweep.
  Paper now at v1.9 in `docs/paper-draft.md` (gitignored,
  local-only per commit 900318e). Remaining: targeted venue
  conversion to LaTeX when ready to submit.

- [x] **Wasm Float formatting: bit-identical with Python `str(float)`**
  (closed 2026-05-25). The legacy fixed-6-decimal `$ftoa` is
  replaced by a pure-WAT port of Grisu2 in
  [`capa/ir/_emit_wasm/_runtime.py`](capa/ir/_emit_wasm/_runtime.py).
  Five new helpers (`$grisu_mul_high` for the 64x64 -> 128-bit
  high product with round-half-up, `$grisu_cached_power` for the
  87-entry cached-powers-of-10 lookup, `$pow10_i32` for the
  digit-generation divisors, `$grisu2` for the main algorithm,
  and the rewritten `$ftoa` that handles NaN / +/-inf / +/-0
  and dispatches to either decimal or scientific spelling
  based on Python's `n = len(digits) + K` rule -- decimal when
  `-3 <= n <= 16`, scientific otherwise). The cached-powers
  table is reserved as a `(data ...)` block at a fresh offset
  between the string segment and the heap base whenever
  `_uses_float_format` is true; `_cached_powers_offset` tracks
  the slot so `$grisu_cached_power` can address it.
  Translation was kept faithful to the validated Python
  reference at `grisu2_ref.py` (21/21 curated cases pass);
  the WAT port adds five more curated cases for the
  scientific-notation boundaries and special values, plus the
  pre-existing `0.1 + 0.2` round-trip suite. Coverage: new
  31-case `TestWasmFtoaParity` class; `json_demo.capa`
  promoted from `_EXCLUDED` to `_PARITY_PROGRAMS` in
  `tests/test_ir_wasm_parity.py`. Bonus fix: `_emit_unaryop`
  for `-` on `Float` operands used to emit `i64.const 0 ;
  i64.sub` (an Int idiom), which the Wasm verifier rejected
  when the operand was `f64`. The branch is now type-aware:
  `f64.neg` for Float, `0 - x` for Int. Suite: 1432 tests
  total, 0 regressions.

- [x] **`JsonValue.as_int` parity** (closed 2026-05-25). Wasm
  `_emit_jv_as_int` now mirrors Python's
  [`JsonValue.as_int`](capa/runtime/_json.py): wrap an i64
  truncation only when `f64.trunc(v) == v`, else None. The
  fix uses a new `_alloc_tmp_f64` scratch local declared in
  the `has_json_method` block; three regression tests
  (integer-valued JNum, non-integer JNum, non-JNum variant)
  in `TestWasmJson` lock the parity in.

- [x] **Capability-discipline hole C: generic instantiation
  re-check** (closed 2026-05-25). New
  `_reject_cap_leak_via_substitution` in
  [`capa/analyzer/_discipline.py`](capa/analyzer/_discipline.py)
  fires when a capability appears in the substituted parameter
  or return type and was *not* there pre-substitution.
  `_check_call_with_inference` and `_check_method_dispatch` in
  [`capa/analyzer/_dispatch.py`](capa/analyzer/_dispatch.py)
  call it after unification, before committing the
  substitutions. `id(stdio)` and `wrap(stdio)` now fail with
  "argument N substitutes capability 'Stdio' into a generic
  type parameter"; explicit cap params (`fun use(s: Stdio)`
  with `use(stdio)`) keep working because the check skips when
  the pre-substitution form already names the capability.
  Coverage: 5 tests in `TestCapLeakViaGenericInstantiation`.

- [x] **Audit 2026-05-25 follow-up sweep** (closed 2026-05-25).
  Six findings from `security-audit.md` closed in sequence:
  - **C1** `b21dd73`: dependency-name path-traversal at install
    time. `[dependencies."../evil"]` now refused at manifest
    parse.
  - **H1** `022cb13`: capability hole D. `_mark_consumed_args`
    now canonicalises FieldAccess via `_path_of`;
    `consume(box.cap)` + `box.cap.use()` rejected.
  - **H2** `47bbdc4`: git tag / rev pin validation. Pins
    starting with `-`, containing whitespace or path separators
    refused before reaching git argv.
  - **H3** `0d57139`: lockfile pre-check via `git ls-remote`.
    Moved-tag mismatch raises before `vendor/<name>` is touched;
    the working tree no longer holds attacker content during
    the error.
  - **H4** `3752972`: 100-level depth cap on the bundled JSON
    parser. `[[[ ... ]]]` adversarial input fails cleanly with
    `Err("max nesting depth ...")` instead of trapping the
    Wasm stack.
  - **H5** `2570eec`: SPDX `licenseConcluded` /
    `licenseDeclared` / `copyrightText` and CycloneDX
    `supplier` / `licenses[]` now emitted on every package /
    component; strict validators accept the documents.

  C2 (Wasm `Fs.restrict_to` no-op) closed in commit `2a2f566`:
  compile-time inline checks via dataflow analysis. The lowerer
  now threads a per-function attenuation map (built by
  `capa.manifest._flow._build_attenuation_map`) into a new
  `MethodCall.attenuations` field; the Wasm emitter consumes the
  field on privileged ops (`Fs.read`, `Fs.write`, `Net.get`,
  `Net.post`, `Env.get`) and emits an inline check before the
  host import (`$str_starts_with` for Fs prefix,
  `$str_contains` for Net host, OR-chain of `$str_eq` for Env
  keys). Failure path materialises the canonical Err/None into
  the canonical-ABI return area and skips the host call. Scope:
  intra-function (matches `_flow`'s documented intra-function
  scope); cross-function chains still rely on the analyzer's
  static discipline check. The audit document records the
  limitation explicitly. 11 new `TestWasmAttenuationEnforcement`
  tests pin the contract; suite 1463 -> 1472.

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
  methods), semantic tokens.
  Polish pass landed 2026-05-26: three more LSP features added
  in parallel via sub-agents. (1) `textDocument/documentHighlight`
  at [`capa/lsp/document_highlight.py`](capa/lsp/document_highlight.py)
  (54 LOC): thin adapter over `compute_references` so the editor
  highlights every in-file occurrence of the identifier under
  the cursor; v1 emits `Text` kind only (read / write split
  deferred). (2) `textDocument/foldingRange` at
  [`capa/lsp/folding.py`](capa/lsp/folding.py) (153 LOC):
  AST walk emitting gutter +/- regions for FunDecl, TypeStruct,
  TypeSum, ImplBlock, TraitDecl, IfStmt, ForStmt, WhileStmt,
  MatchExpr, LambdaExpr bodies; returns empty on parse failure
  so a mid-edit file does not confuse the editor. (3)
  `textDocument/formatting` + `textDocument/rangeFormatting`
  at [`capa/lsp/formatting.py`](capa/lsp/formatting.py) (75
  LOC): hooks the v3 formatter (`capa.formatter.format_source`)
  to the editor's Format Document / Format Selection commands;
  rangeFormatting falls back to whole-document since v3 is
  parse-then-emit; never raises (the formatter has v1+v2
  textual fallback). 11 new compute-level tests + 4 new
  server-handler integration tests. Full suite 1770 / 5
  skipped / 0 fail (was 1734 + 36 new).
  Remaining v2 polish (not yet identified as user-blocking;
  re-evaluate after a real-user session): signatureHelp,
  inlayHint, workspace/symbol, codeLens, selectionRange.
  ⏱ depends on what surfaces.

- [x] **REPL v2** (closed 2026-05-27). MVP at `capa/repl.py`
  re-ran everything on each input (no incremental state). v2
  needed incremental state and readline / history. ⏱ 8-12h.
  Slices A + B landed 2026-05-26. Slice A: readline-style
  line editing + persistent history file at
  `~/.capa_repl_history` (1000-entry cap). Tries stdlib
  `readline` first, falls back to `pyreadline3` on Windows,
  silent skip if neither is present. All history-I/O errors
  swallowed so the REPL never crashes on a non-writable
  home dir. Slice B: in-process `exec()` replaces the
  `subprocess.run` path in `_try_compile_and_run`. New
  `_exec_in_process` builds a fresh namespace per turn
  (`__name__ = "__main__"` so the transpiler's bootstrap
  fires), captures stdout/stderr via
  `contextlib.redirect_stdout`, formats Python tracebacks
  into the error channel. POSIX gets a 10s hard timeout via
  `signal.SIGALRM`; Windows has no `SIGALRM` so the hard
  timeout is lost (Ctrl-C still works; documented in the
  function docstring and module-level v2 notes). Net win:
  per-turn time drops from ~30-200ms (subprocess fork+exec
  on Windows) to ~1.2ms in-process measured locally, a
  ~100x speedup. 4 new tests (`TestReplReadline` x 2,
  `TestReplInProcessExec` x 2) plus all 63 existing repl
  tests stay green. Full suite 1734 / 5 skipped / 0 fail.
  Slice C landed 2026-05-27: persistent namespace +
  incremental execution. New statements now exec at Python
  module scope into a kept `_ReplState.namespace` (so `let` /
  `var` bindings persist as globals and prior-`var` mutation
  works), executing only each turn's NEW items + statements
  via `transpile_repl` (`capa/transpiler`). Side effects now
  fire exactly once and the stdout-diffing hack is gone. The
  `?` operator routes through the `_capa_try` exception path
  (new `Transpiler.repl_toplevel` flag) and is caught at the
  exec boundary; `return` at the prompt is rejected. Full
  re-analysis is RETAINED each turn deliberately: it is
  microseconds and enforces the capability discipline, whereas
  true incremental analyzer state is high-risk for negligible
  gain, so it stays out of scope. 6 new incremental tests;
  full suite 1827 / 5 skipped / 0 fail.

- [ ] **VSCode marketplace publication**. Grammar lives in
  `vscode/`; install today is manual symlink/junction. Publish
  to Marketplace for one-click install. ⏱ 1-2h once the
  Marketplace account + publisher are set up.

- [~] **Migration path from Python** (slice 1 closed 2026-05-27).
  Interop is one-way via `Unsafe`; the gradual-hardening *pattern*
  already shipped (`examples/migrate_logfetcher_step{1,2,3}` +
  `docs/migration.md`). New `capa migrate <file>` tooling
  (`capa/migrate.py`) now reports progress: % Unsafe-free,
  removable-`Unsafe` detection (silenced-but-dead `_u: Unsafe`),
  and next-candidate ranking by bridge-call count; `--json` for
  CI. Deferred: warning/info diagnostic severity in analyzer+LSP
  for inline editor nudges, transitive call-graph analysis for
  removable detection, and a website "Migrating from Python"
  chapter.

- [x] **Package manager + minimal registry** (closed
  2026-05-27). Core install flow ships (`capa.toml` +
  `capa install` + `capa.lock` + SLSA L2 verify).
  `capa add <name> --git <url> [--tag | --rev | --branch]
  [--verify-key] [--force] [--no-install]` edits `capa.toml`
  to declare a `[dependencies.<name>]` block (comments +
  existing tables preserved verbatim), validates the git URL
  through the same `_validate_git_url` allow-list the install
  path uses (rejects `ext::`, leading-`-`, etc. at add time),
  then runs install unless `--no-install`. Core in
  `capa/pkg/_add.py` (~165 LOC), 10 tests.
  Minimal registry landed: dedicated public repo
  [nelsonduarte/capa-registry](https://github.com/nelsonduarte/capa-registry)
  with an `index.json` mapping `<name>` to git URL +
  `verify_key` + `latest` tag, seeded with the 4 seed libs
  (capa_cli / capa_datetime / capa_http / capa_log).
  `capa add <name>` WITHOUT `--git` now resolves via
  `capa/pkg/_registry.py::resolve_name` (stdlib urllib fetch
  of the index, `CAPA_REGISTRY_URL` override, `~/.capa/`
  cache with 1-hour TTL + stale-cache fallback on fetch
  failure, refuses an index whose `registry_version` exceeds
  the toolchain's, re-validates the resolved git URL through
  `_validate_git_url`). Defaults the pin to the index's
  `latest` tag and the `verify_key` to the index entry's
  when the user omits them. Unknown name gives an actionable
  error listing the known packages and suggesting `--git`.
  7 registry tests (file:// fetch + cache-fallback +
  future-version refusal + poisoned-URL rejection +
  malformed-index). Full suite 1805 / 5 skipped / 0 fail.
  The registry is a name-to-URL convenience; the three-layer
  trust model (lockfile SHA + GPG tag signature + SLSA L2
  provenance) is unchanged and the index carrying `verify_key`
  means resolving a name also pins the expected signer.
  Remaining (not blocking): `capa search`, a `capa publish`
  PR-to-registry flow, third-party-namespace governance - all
  ecosystem-growth work, not core mechanism.

- [~] **Debugger integration**. Statement-level source maps
  landed 2026-05-27. The transpiler records a
  `python_line -> Capa Pos` map at statement-emit boundaries
  (one `_mark(node)` hook at the top of `_emit_stmt`,
  rebased past the spliced `?` helper); `transpile()` fills
  an optional `out_line_map` dict. `capa --run` now rewrites
  a runtime traceback: the plain Python traceback still
  prints (power users keep it), followed by a `Capa
  traceback (most recent last)` summary mapping each
  `<transpiled>` frame to the originating `file:line`. New
  `capa/_debug.py` `_rewrite_traceback` helper; 7 tests in
  `tests/test_sourcemap.py`. Verified end-to-end: a
  divide-by-zero in a 4-line program now names the Capa
  line that threw.
  Caret snippets landed 2026-05-27: each Capa-traceback frame
  now renders `file:line:col` plus the offending Capa source
  line and a `^` caret, matching `errors.py` compile-error
  style (same gutter/caret math). `_rewrite_traceback` takes
  `sources` (multi-file map) + `default_source`; `capa --run`
  passes the linked sources. 4 new tests (suite 1831 / 5
  skipped / 0 fail). **Still pending**: per-expression
  granularity (the caret points at the statement start, not
  the failing sub-expression; true sub-expression mapping
  needs the expression emitter reworked to track generated-
  Python column ranges, deliberately deferred as high-effort /
  fragile); a real stepping debugger (DAP adapter) is a
  separate, larger arc. ⏱ remaining is open-ended.

- [x] **Analyzer performance benchmarks** (closed 2026-05-25).
  New runner at [`benchmarks/compile_bench.py`](benchmarks/compile_bench.py)
  measures lex / parse / analyse wallclock on three synthetic
  programs (10 / 100 / 1000 function definitions; the medium
  workload mixes capability calls and sum-variant match, the
  large adds structs + field access + sum + match). Each phase
  is timed in isolation across ``--repeat`` standalone trials.
  Output is plain text by default, ``--markdown`` for inclusion
  in docs. The benchmark itself doesn't gate CI; it exists as a
  reproducible bar so a future ``O(n^2)`` pass in the analyser
  surfaces in a manual run before it ships. Current baseline on
  Windows 11 / CPython 3.14: small ~3.5ms, medium ~55ms, large
  ~450ms (lex / parse roughly linear in LOC; analyse grows
  super-linearly with sum + match density but stays well within
  the regression bar). Benchmarks README updated to point at
  the new runner.

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

- [x] **"Fully functional Wasm" slice 14 - lift the last
  audit-P2 restriction (dynamic-arg `allows`)** (closed
  2026-05-29). Pre-slice the Wasm emitter rejected
  `if fs.allows(some_runtime_path)` with "requires a literal
  string argument" while Python accepted it; this last-remaining
  audit-P2 portability gap is now closed.
  - **Behavior**: literal-arg fast-path keeps the static collapse
    at emit time (push `i32.const 0/1`, zero runtime cost). The
    dynamic-arg path now emits a runtime check that mirrors the
    privileged-op machinery: stash the path / name in
    `$_atten_path_*`, AND-chain per-attenuation predicates into
    `$_atten_ok`, push the accumulator as the i32 result. Three
    capability paths covered:
    - `Fs.allows` / `Db.allows`: per-attenuation
      `_emit_path_prefix_check` (the boundary-aware
      `eq OR starts-with-slash` shape from slice 12)
    - `Env.allows`: per-attenuation OR-chain of `str_eq` against
      the keys in that `restrict_to_keys` list, AND-combined
      across the chain
    - Unrestricted cap (no attenuations) collapses to
      `i32.const 1` regardless of the arg shape
  - **Discovery + locals**: the locals walker flags
    `$_atten_path_*` / `$_atten_ok` when `Fs.allows` /
    `Env.allows` / `Db.allows` appears with a non-literal arg;
    the discovery walker registers `needs_starts_with` so the
    `$str_starts_with` (+ transitively `$str_eq`) helpers are
    emitted whenever any `Fs/Db.allows` source-level call
    exists (over-emits the helper once if the call turns out
    to be literal-only; <100 WAT bytes either way).
  - **Tests**: the two pre-slice canary tests
    (`test_fs_allows_dynamic_arg_rejected`,
    `test_env_allows_dynamic_arg_rejected`) flipped to positive
    assertions; added
    `test_fs_allows_dynamic_arg_attenuated_emits_runtime_check`
    to pin the runtime-check shape. New parity program
    `allows_dynamic.capa` covers Fs/Env/Db with let-bound
    args + the boundary case + the unrestricted shortcut.
    Suite 2040 -> 2042 / 5 skipped / 0 fail.

- [x] **"Fully functional Wasm" slice 13 - close the two
  audit-deferred findings (Clock.sleep + Db.ATTACH)** (closed
  2026-05-29). Slice 12 fixed two capability escapes but
  deferred two more findings; this slice closes both.
  - **Clock.sleep gate on Wasm.** Python silently no-ops
    `clock.sleep()` when the cap's `restrict_to_after(deadline)`
    deadline hasn't passed; Wasm pre-fix ran the host call
    regardless. Fix: `(Clock, sleep)` added to
    `_ATTENUATION_PRIVILEGED_OPS`;
    `_emit_clock_with_attenuation_check` extended to emit an
    inline `if (clock.now_secs() >= deadline) call
    $Clock_sleep` guard. Multiple chained `restrict_to_after`
    calls combine via `max(thresholds)` (matches Python). The
    `secs` arg is stashed in a new `$_clock_sleep_secs` f64
    scratch local so the if-arm doesn't re-evaluate it. The
    implicit `Clock.now_secs` host call is registered in both
    the Wasm discovery and the WIT
    `collect_used_capabilities` so the Component Model wrap
    doesn't fail at link time with "import interface is
    missing function now-secs".
  - **Db.ATTACH/DETACH block on both backends.** A Capa
    program holding a Db cap scoped to `/tmp/` could
    previously run `ATTACH DATABASE '/etc/secret.db' AS evil`
    to open a connection to a file outside the cap's prefix.
    Fix: every `sqlite3.connect` call (Python runtime + Wasm
    core host + CM host) now installs an authorizer via
    `conn.set_authorizer(...)` that returns `SQLITE_DENY` for
    `SQLITE_ATTACH` (24) and `SQLITE_DETACH` (25). Every
    other action stays allowed. Shared via a new module-
    level `_install_sqlite_authorizer(conn)` helper so the
    three call sites cannot drift. The `set_authorizer` API
    is available in Python 3.4+, so this is portable to the
    project's 3.10+ minimum (the earlier `setlimit` option
    needed 3.11).
  - **WIT collector fix surfaced by the Clock.sleep work**:
    `collect_used_capabilities` did not filter `restrict_to*`
    methods, so a program using `clock.restrict_to_after(...)`
    failed component generation with "capability method
    Clock.'restrict_to_after' has no WIT signature". The
    Wasm-side discovery already filtered them; mirrored
    that here.
  - Two new parity programs (`clock_sleep_attenuation.capa`,
    `db_attach_blocked.capa`) under both core + CM parity
    harnesses. Suite 2036 -> 2040 / 5 skipped / 0 fail.

- [x] **"Fully functional Wasm" slice 12 - audit-pass security
  hardening (capability escapes on Wasm)** (closed
  2026-05-29). Audit of slices 4-11 surfaced **two real
  capability escapes** in the Wasm backend that this slice
  closes. Both bugs let a program with a path-attenuated `Fs` /
  `Db` cap reach paths outside its allowed prefix. The Python
  runtime had always gated correctly; the Wasm host bridges
  trusted the guest entirely.
  - **P0: `Fs.{exists,is_dir,mkdir,list_dir}` bypassed
    attenuation on Wasm.** Pre-fix a `Fs.restrict_to("/tmp/")`
    cap could `fs.mkdir("/etc/foo")` / `fs.list_dir("/etc")`
    on Wasm and the host happily complied. Fix:
    - `mkdir` / `list_dir` (return `Result<...>`) added to
      `_ATTENUATION_PRIVILEGED_OPS`; routed through
      `_emit_indirect_with_attenuation_check` with the
      single-string-arg shape.
    - `exists` / `is_dir` (return `Bool`) get a new inline-
      wrapper helper `_emit_bool_query_with_attenuation_check`
      that calls the host on pass and pushes `i32.const 0`
      on deny (fail-closed-as-absent, matches Python's
      "denied paths report False so the cap doesn't leak
      out-of-prefix existence").
    - New `result_list_string_io_error` Err materialiser
      (was latent: missing branch would have crashed emit
      once `list_dir` got added to the privileged set).
  - **P1: path-prefix boundary bug.**
    `Fs.restrict_to("/tmp")` (no trailing slash) admitted
    `/tmproot/secret` on both Python and Wasm. Naive
    `str.startswith` / `$str_starts_with` doesn't respect
    component boundaries. Fix: new emit-time
    `_emit_path_prefix_check` helper that emits
    `path == prefix OR path.startswith(prefix + '/')` as a
    combined check; Python's `Db.allows` and the inline
    `_emit_atten_allows` for `Fs.allows` / `Db.allows`
    apply the same component-boundary rule. Python's
    `Fs.allows` already canonicalises via
    `Path.is_relative_to` (strictly stronger; resolves
    symlinks / `..`), so it was already correct; the
    boundary fix only adjusted `Db.allows` (which copied
    Fs's naive prefix shape) and the Wasm-side inline
    checks.
  - **Discovery walker**: `_uses_attenuation_check` now
    recognises all six `Fs` attenuated ops (read / write /
    exists / is_dir / mkdir / list_dir) so the
    `$str_starts_with` (and transitively `$str_eq`)
    helpers are emitted when any one of them fires.
  - **Audit findings NOT fixed this slice**, with
    rationale:
    - `Db.exec` accepts `ATTACH DATABASE 'foo.db'` to
      bypass path attenuation. Already documented as a v1
      limitation in the `Db` docstring; mitigations
      require Python 3.11+ (`setlimit(SQLITE_LIMIT_ATTACHED,
      0)`) or SQL-string parsing both of which are more
      involved than the audit-fix scope. Tracked for Db v2.
    - `Clock.sleep` on a `restrict_to_after(future)` cap is
      a silent no-op in Python but currently runs on Wasm
      (no inline check around the host call). Real
      divergence; fix needs either an inline
      `clock.allows()` call before `clock.sleep` or a
      widened WIT sig threading the deadline to the host.
      Both designs land in a follow-up; flagged but not
      blocked here.
    - `_emit_atten_allows` rejects non-literal `path` args
      at emit time (user-facing limitation, documented in
      the diagnostic message).
  - New parity program
    `examples/wasm/fs_attenuation_audit.capa` exercises every
    fixed surface (exists / is_dir / mkdir / list_dir on
    out-of-prefix paths, plus the `/tmp` vs `/tmproot/x`
    boundary). Would fail loudly on the pre-fix Wasm
    backend. Suite 2035 -> 2036 / 5 skipped / 0 fail.
  - **Performance profile** (informational, no code
    change): governance pack end-to-end Python 309ms /
    Wasm core 500ms / Wasm CM 560ms; pure execution with
    pre-built `.wasm` Python 8ms / Wasm 14-18ms (~2x
    overhead is acceptable for sandbox isolation).
    `wasm-tools parse` is ~150ms of the per-run overhead;
    cacheable via `--output app.wasm`.

- [x] **"Fully functional Wasm" slice 11 - `Db` capability v1
  (SQLite-backed, path-prefix attenuation)** (closed
  2026-05-29). The `Db` cap moves from documented-deferral
  stub to a fully functional capability across all three
  backends (Python, core Wasm, Component Model).
  - **Surface** (4 methods, mirrors Fs):
    - `restrict_to(prefix: String) -> Db` - intersect-style
      attenuation
    - `allows(path: String) -> Bool` - membership query
      (inline-attenuation at emit time, D4 Option B)
    - `exec(path: String, sql: String) -> Result<Unit,
      IoError>` - runs DDL / DML (SQLite `executescript`,
      so multiple `;`-separated statements work)
    - `query(path: String, sql: String) -> Result<String,
      IoError>` - runs SELECT and returns a JSON-encoded
      `[[col1, col2, ...], ...]` string with every cell
      stringified. Cross-backend wire shape is a single
      `result<string, io-error>` so no new canonical-ABI
      materialiser is needed; consumers use `parse_json`.
  - **Backend wiring**: Python runtime uses `sqlite3.connect`
    per call (cap is stateless). Wasm host bridge mirrors
    exactly. WIT signatures land alongside the existing
    `result<...>` shapes. `_emit_indirect_with_attenuation_check`
    gained a Db branch (two-string args, same shape as
    Fs.write / Net.post). `_emit_one_attenuation` gained a
    `cap == "Db"` branch that emits the same `$str_starts_with`
    prefix check as Fs.
  - **Component Model**: `_wasm_component_host._register_db`
    parallels the core bridge; the wire-level lift/lower goes
    through `result<string, io-error>` and `result<_, io-error>`
    which already had CM coverage in slice 10. Db works
    under `--component --run`.
  - **Verification**: new parity program `examples/wasm/db_demo.capa`
    (CREATE -> INSERT -> SELECT -> attenuation-deny) hits all
    four methods. Registered in `_PARITY_PROGRAMS` (core
    parity) and `_CM_HOST_BRIDGE_SUBSET` (CM parity). Suite
    2033 -> 2035 / 5 skipped / 0 fail. `db_demo` under
    `--component --run` also matches the Python backend
    byte-for-byte.
  - **Deferred**: `Db` v2 surface (typed result columns,
    persistent connection caching, transactions, prepared
    statements). v1 is the minimum useful surface; the
    JSON-encoded wire shape leaves room for typed-columns
    expansion without breaking source-level code (Capa
    consumers already parse `JArr<JStr>` rows).

- [x] **"Fully functional Wasm" slice 10 - Component Model
  parity harness + `Fs.allows` / `Env.allows` WIT-mismatch
  fix** (closed 2026-05-29). Two deliverables:
  - **CM parity harness**: new
    `TestPythonWasmComponentParity` class in
    `tests/test_ir_wasm_parity.py` that pivots the
    Python <-> Wasm parity assertion on the Component Model
    path (`wasm-tools component new` + `WasmComponentHost`)
    instead of the core `WasmHost`. Bound to a 7-program
    subset that exercises host-bridge data flow: `hello`,
    `env_demo` (option<T> regression net), `fs_demo`,
    `net_get`, `net_post`, `net_restrict`, `allows_inline`.
    Pure-guest programs (closures, sets, struct equality,
    etc.) trust the core-host parity test; the CM wrapping
    doesn't touch guest-only WAT, so re-running all 50+
    entries would waste CI time for zero new coverage. Also
    adds 4 new `TestWasmComponentHost` cases for the slice 1
    host bridges (`Fs.mkdir`, `Fs.list_dir`,
    `Stdio.read_line` EOF path, `Random` seeded sequence
    cross-checked against the core host).
  - **Second latent CM bug fixed**: `Fs.allows` and
    `Env.allows` were missing from `_GUEST_ONLY_METHODS`,
    so the WIT generator demanded a host signature for them
    even though the Wasm emitter inlines the check at emit
    time (D4 inline-attenuation Option B, slice 1).
    Core-host runs worked because no WIT generation
    happened; the `--component --run` path failed at
    `compile_wit` with `capability method 'allows' has no
    WIT signature`. Surfaced by the new CM parity test for
    `allows_inline.capa`. Fixed by adding `Fs` and `Env`
    `allows` entries to `_GUEST_ONLY_METHODS`;
    `Clock.allows` deliberately stays a host call (it needs
    the live wall clock against a `restrict_to_after`
    deadline, no static collapse possible).
  Suite 2022 -> 2033 / 5 skipped / 0 fail.
  `capa_governance_pack` on pure `--wasm --component --run`
  also matches Python byte-for-byte.

- [x] **"Fully functional Wasm" slice 9 - parity-list cleanup +
  Component Model `option<T>` discriminant bug-fix** (closed
  2026-05-29). Three deliverables in one slice:
  - `examples/wasm/fs_demo.capa` and
    `examples/wasm/env_demo.capa` promoted to the parity list.
    Both were excluded as "needs a fixture" but were actually
    parity-clean: fs_demo uses a single constant `/tmp/` path
    and prints only that path + the bridge's response, both
    backends routing through Python's `open(...)`; env_demo
    queries the same `os.environ` from within one Python
    process across two back-to-back runs. Suite gained 2
    parity tests.
  - **Component-host test coverage expanded**: `Net.post` happy-
    path against an in-process loopback `http.server`, full Fs
    round-trip (write + read + exists), and Env.get hit / miss
    with a known-value fixture. Caught the discriminant bug
    below; before this expansion the CM `option<T>` path had
    no in-tree coverage.
  - **Latent CM `option<T>` discriminant bug fixed**: the
    Component Model canonical ABI for `option<T>` puts `none`
    first (discriminant 0) and `some(T)` second (1). Capa's
    internal Option layout uses the inverse (`Some`=0,
    `None`=1). Pre-fix the core host happened to write Capa-
    convention tags directly into the ret_area which fake-
    matched the materialiser's naive byte-copy; the bug
    surfaced only under `--component --run` where the CM
    adapter writes WIT-convention bytes. Fix: core host now
    writes WIT-convention (none=0, some=1) and the materialiser
    XOR-flips the discriminant to Capa convention before
    storing in the Option record. The attenuation-deny Err
    writer was updated to match. Result<T, E> needs no change
    (Ok=0/Err=1 matches both conventions).
  Suite 2017 -> 2022 / 5 skipped / 0 fail. `capa_governance_pack`
  on pure `--wasm` still matches Python byte-for-byte.

- [x] **"Fully functional Wasm" slice 8 - `Net.post` end-to-end
  on Wasm** (closed 2026-05-29). Closes the deferred slice 3
  follow-up (D2 was deliberate to ship `Net.get` parity first).
  Surface: `Net.post(url: String, body: String) -> Result<String,
  IoError>`. Both backends call `urllib.request.urlopen(Request(
  url, data=body.encode("utf-8"), headers={"Content-Type":
  "application/octet-stream"}))` with a 10-second timeout and
  decode the response body UTF-8 with `errors="replace"`, so
  ASCII-only payloads round-trip byte-for-byte. WIT signature +
  io-error gating + `_CANONICAL_INDIRECT_RETURN` entry +
  `_cap_method_wasm_sig` pattern for `func(url, body) -> result
  <string, io-error>` all landed. Attenuation-path
  `_emit_indirect_with_attenuation_check` now stashes both
  String args (url + body) and re-pushes them in the host-call
  branch; the deny-arm short-circuits without touching the
  network. New parity program (`net_post.capa`, deny-only so the
  harness stays hermetic) + new execution test
  `test_net_post_round_trip_against_loopback` that spins up an
  in-process `http.server` whose handler echoes the request body
  verbatim, validates the happy path end-to-end (Wasm bridge
  reads body bytes from linear memory, builds urllib Request,
  loopback echoes, Ok arm carries the response). Suite 2015 ->
  2017 / 5 skipped / 0 fail. `capa_governance_pack` on pure
  `--wasm` still matches Python byte-for-byte.

- [x] **"Fully functional Wasm" slice 6.1 - free top-level
  functions usable as `Fun(...)` values on Wasm** (closed
  2026-05-29). Pre-fix `xs.map(double_int)` (where `double_int`
  is a top-level function rather than an inline lambda)
  rejected with `value kind 'global' not supported`; only
  inline `fun (...) => ...` lambdas worked. The fix is a
  per-(fn, sig) thunk synthesised at emit time: a tiny Wasm
  function whose sig matches the closure ABI
  (`(env_ptr, args...) -> result`), body drops the env and
  forwards to the underlying function. Thunks live in the
  closure function table immediately after the lifted lambdas
  so existing fn_idx values stay stable. Pre-emit discovery
  pass walks every IR instruction (including lambda bodies,
  match arms, all control-flow) to find global Fun references
  and pre-register the thunks before the table is sized, so
  `_push_value` can look up the fn_idx during body emission
  without growing the table on the fly. One new parity program
  (`fn_ref_as_closure.capa`, ~10 assertions covering
  apply-style HOFs, List.map / List.filter on free fns, the
  same fn passed twice with the same sig sharing a thunk,
  different sigs allocating distinct thunks, and Option.map
  with a free fn arg). Suite 2014 -> 2015 / 5 skipped / 0
  fail. `capa_governance_pack` on pure `--wasm` still
  matches Python byte-for-byte. Closes the "pre-existing gap"
  noted at the end of slice 6.

- [x] **"Fully functional Wasm" slices 6 + 7 - Option/Result HOFs
  + Unsafe rejection + stale docstrings + two discovery-walker
  bug-fixes** (closed 2026-05-29). Closes the master plan's
  remaining slices and brings the Wasm backend to the
  "fully functional" target.
  - **Slice 6 Option HOFs**: `map`, `and_then`, `filter`,
    `ok_or`, `or_else` lower to allocate-tag-and-payload + invoke
    closure via the existing `call_indirect` ABI. Fallback arm of
    `map` / `and_then` uses pointer pass-through (None record /
    Err(e) encoding doesn't change across the output type),
    avoiding a redundant 16-byte alloc per call.
  - **Slice 6 Result HOFs**: `map`, `map_err`, `and_then`,
    `or_else`, `ok`, `err`. `.ok()` and `.err()` are simple
    projections (alloc Option + copy 8-byte payload + flip tag).
    Closure-arity dispatch (Option.or_else takes a zero-arg
    closure, Result.or_else takes the Err payload) uses a
    dedicated `_emit_closure_call_no_payload` helper.
  - **Slice 7 Unsafe rejection (D5)**: discovery walker scans
    every function + impl method signature at emit-start and
    raises a single actionable diagnostic naming each offending
    site. Pre-slice-7 the rejection happened deep in cap-method
    dispatch with a message that read as "this is a backlog
    item"; now the user sees "Unsafe is intentionally not
    supported on the Wasm backend ... use the Python backend
    for these functions, or refactor".
  - **Bonus discovery-walker fixes** (caught while verifying the
    slice 6 parity program): BinOp `==` / `!=` on String
    operands now triggers `$str_eq` emission (used to slip
    through if the only String comparison was in a lifted
    lambda); `MakeLambda.body` is now recursed into by the
    `_uses_map_ops` walker so closure bodies contribute to the
    helper-emission decisions just like the parent function does
    (the lambda-lift happens AFTER discovery).
  - **Docstring polish**: `_emit_list_method_call` no longer
    references "Phase 6E" (HOFs landed); `_emit_map_method_call`
    docstring lists `keys` / `values` instead of saying they're
    deferred.
  Plus one new parity program (`option_result_hofs.capa`,
  ~25 assertions covering every method × {Int, String} payload).
  `test_option_result_hofs` added to the parity harness.
  Suite 2013 -> 2014 / 5 skipped / 0 fail. `capa_governance_pack`
  on pure `--wasm` still matches the Python backend byte-for-byte
  (no regression).

- [x] **"Fully functional Wasm" slice 5 - tuple arity > 2,
  Map.keys / Map.values, range iteration, and four IR / emit
  bug-fixes surfaced by `capa_governance_pack` on pure `--wasm`**
  (closed 2026-05-28). Verification: `capa --run --wasm
  governance.capa` (with and without `GOV_PACK_INCLUDE_CVE=1`)
  produces output byte-identical to the Python backend (modulo
  timestamps), where previously the program rejected on five
  separate gaps in sequence. Six landed:
  - **Tuple arity > 2**: the `arity != 2` cap in `_emit_make_tuple`
    was defensive only; the uniform 8-byte slot stride covers any
    arity. Comment relocated, check relaxed.
  - **Map.keys() / Map.values()**: walks the map's pair table
    into a fresh List<K> / List<V> with per-K / per-V slot
    encoding (mirrors how `_emit_make_list` writes the respective
    element shape). Shared header-setup + per-slot-emit loop
    factored out so a future Set.to_list could reuse it.
    `test_unsupported_phase_construct_raises` flipped to a
    success canary (`test_map_keys_and_values_now_supported`).
  - **Range iteration** (`for i in 0..N`, `for j in a..=b`): new
    `MakeRange` CIR node + 24-byte heap record { start_i64,
    end_i64, inclusive_i32 } + counted-loop fast-path in
    `_emit_for` that reads start / end / inclusive directly
    without materialising List<Int>. Depth-indexed scratch
    locals (`$_range_end_i64_N`, `$_range_incl_i32_N`) so
    nested `for o in 1..=3: for p in 0..o` doesn't have the
    inner loop's end-compare clobber the outer's (caught by the
    nested-pairs parity case: would've reported 1 pair instead
    of 6). Python emitter renders as `CapaRange(start, stop)`
    so parity is preserved.
  - **Wildcard let-pattern** (`let _ = expr`): the CIR lowerer
    rejected this with `UnsupportedInIR("let-pattern WildcardPat")`;
    now lowers as an evaluate-and-discard into a fresh `wild_*`
    local. Also handles `let (a, _) = pair` (tuple wildcard
    slot skipped during destructure). Surfaced via
    `render.capa:148` (`let _ = sbom // reserved placeholder`).
  - **String dst <- String param**: `_emit_string_assign` only
    handled `lit_str` / `local` / `lit_unit` / `global` sources
    but not `param`; a `let m = fallback` aliasing a String
    function parameter tripped `cannot bind String dst`. Added
    the `param` case routing through `${name}_ptr` / `${name}_len`.
  - **Tuple-element type-recovery in CIR Index**: the analyzer
    didn't always carry a precise type for `tuple[lit_int]`
    (arity > 2 in particular), so destructured slots landed as
    i64 locals in Wasm even for String / Bool elements,
    tripping the wasm verifier with i32-vs-i64 mismatches. The
    lowerer now parses the receiver's tuple-type string and
    picks the slot's authoritative element type when the
    receiver is `(T1, T2, ...)` and the index is a literal int.
  Bonus pre-existing bug fixed along the way: `_lower_stmt.py`,
  `_lower_expr.py`, `_lower_pattern.py` all raised
  `UnsupportedInIR(...)` without importing the class (since the
  audit P1 mixin split), so every legitimate rejection surfaced
  as `NameError: name 'UnsupportedInIR' is not defined`. The
  class moved to `_lower_helpers.py` (leaf module already
  imported by every mixin) and `_lower.py` re-exports it for
  the public `capa.ir.UnsupportedInIR` surface. Three new
  parity programs (`tuple_arity_n.capa`, `map_keys_values.capa`,
  `range_iter.capa`). Suite 2010 -> 2013 / 5 skipped / 0 fail.

- [x] **"Fully functional Wasm" slice 4 - String.replace /
  char_at / index_of + Stdio terminal-encoding robustness**
  (closed 2026-05-28). Per D3: `char_at(idx) -> Option<String>`
  (UTF-8 codepoint decode, multi-byte safe), `index_of(needle) ->
  Option<Int>` (byte offset, None on miss), `replace(old, new) ->
  String` (two-pass: count occurrences + copy with substitution).
  Empty-needle rule for both `replace` and the rest: receiver
  unchanged (avoids Python's `"abc".replace("", "X") -> "XaXbXcX"`
  empty-needle inf-loop trap; documented and applied identically
  on both backends via a small guard in the Python emitters).
  4 new tests (3 parity programs covering ASCII + multi-byte
  UTF-8 + edge cases + 1 pre-existing canary test repointed
  since the three methods are no longer deferred).
  Caught + fixed a real Windows-terminal robustness bug while
  verifying: `Stdio.print/println/eprintln` on both backends
  crashed (`UnicodeEncodeError`) when writing chars the terminal
  codec (e.g. cp1252) cannot encode (e.g. 🦊). Added a shared
  `_write_safe(stream, text)` helper in `capa/runtime/_capabilities.py`
  that catches `UnicodeEncodeError` and re-encodes with
  `errors="replace"` for the stream's declared encoding. Wired
  Python `Stdio` + Wasm host + Component host all through it so
  parity holds (both sides produce identical bytes on the same
  terminal). Pre-existing harness test was insensitive because
  `io.StringIO` has no codec limit; the bug only surfaced on real
  terminals. Full suite 2007 -> 2010 / 5 skipped / 0 fail.

- [x] **"Fully functional Wasm" slice 3 - Net.get end-to-end**
  (closed 2026-05-28). Per D2: urllib mirror, Net.post deferred.
  `Net.get(url: String) -> Result<String, IoError>` now works on
  Wasm with full parity to Python's `urllib.request.urlopen`.
  New `capa:host/net.get` WIT interface (reuses
  `result_string_io_error` materialiser, same shape as Fs.read).
  Host bridge wraps `urllib.request.urlopen(url, timeout=10)`,
  decodes with `errors="replace"`, lowers URLError/OSError/ValueError
  into the canonical IoError record. Attenuation pipeline was
  already half-wired; required only adding `("Net", "get")` to
  `_CANONICAL_INDIRECT_RETURN` and extending `_cap_method_wasm_sig`
  to recognise the `url:` arg name. 5 new tests: 2 parity programs
  (`net_get.capa` round-trips a tempfile via `fs.write` +
  `net.get("file:///...")` for deterministic oracle; `net_restrict.capa`
  exercises the attenuation-deny path with both backends
  short-circuiting to Err without touching the network), 2 direct
  Net execute tests (Windows-portable via `Path.as_uri()`), 1
  Component Model host test. Full suite 2002 -> 2007 / 5 skipped /
  0 fail. Net.post remains rejected by the analyzer (pre-wired in
  `_ATTENUATION_PRIVILEGED_OPS` but absent from `builtins.py`).
  Closes audit I1.

- [x] **"Fully functional Wasm" slice 2 - Random capability**
  (closed 2026-05-28). Per D1 = SplitMix64. Both backends use
  the same PRNG so seeded output is byte-identical. Python:
  replaced `random.Random` internals in
  `capa/runtime/_capabilities.py` with SplitMix64 (one-i64 state,
  unbiased rejection-sampling `int_range`, 53-bit mantissa
  `float_unit`, `os.urandom(8)` for unseeded entropy). Wasm: new
  `capa/ir/_emit_wasm/_random.py` (~290 LOC) with module-globals
  `$rand_state` + `$rand_state_inited` and helpers
  `$rand_next_u64`, `$rand_int_range`, `$rand_float_unit`, plus
  lazy init from a single `capa:host/random.system-seed -> u64`
  host call. New `capa:host/random` WIT interface (one host
  method); the three guest-only methods (`with_seed`, `int_range`,
  `float_unit`) are elided via a new `_GUEST_ONLY_METHODS`
  table in `_emit_wit.py`. `Random.choice` deferred (not in
  `builtins.py`).
  Subtle correctness fix during impl: the textbook Lemire
  rejection limit `(2^64 // bound) * bound` overflows in i64 for
  bounds that divide 2^64 (e.g. `int_range(0, 2)` -> infinite
  rejection loop). Replaced with `bias = (0 - bound) % bound`
  (unsigned arithmetic, never overflows). Mirrors Python's
  distribution exactly; documented inline + tested via the
  `int_range(0, 2)` x 8 section of the parity program.
  `with_seed` returns a fresh Random instance on Python; on
  Wasm it writes the per-module shared `$rand_state` global -
  observably equivalent for any well-formed Capa program (no
  source has two Randoms held in parallel), documented in
  `_random.py` module docstring. 6 new tests (5 wasm Random
  execution tests + 1 `random_seeded.capa` parity program
  exercising `int_range(0, 100)`, `int_range(-50, 50)`,
  `int_range(0, 2)` power-of-two bound, `with_seed` re-seed).
  All three backends (py / wasm core / wasm component) produce
  byte-identical `Random(42).int_range(0, 100)` sequence:
  `[13, 91, 58, 64, 50, 62, 25, 8, 5, 74]`. Full suite 1996 ->
  2002 / 5 skipped / 0 fail. No pre-existing tests adjusted
  (existing Random tests are relational not value-pinned).

- [x] **"Fully functional Wasm" slice 1 - host-bridge pile**
  (closed 2026-05-28). First slice of the multi-slice arc to close
  the "demos only" gap and let real programs run on Wasm. 9
  capability methods added: `Stdio.read_line` (canonical-ABI
  result<string, io-error>, EOF -> Err, UTF-8-bad -> Err),
  `Clock.sleep` (f64 -> unit, guards negative duration),
  `Clock.allows` (host-bridged; depends on wall clock so inline
  static-check would need attenuation state across the WIT boundary,
  deferred per locked D4 adjustment), `Fs.exists` / `Fs.is_dir`
  (bool, UTF-8-bad path -> false), `Fs.mkdir` (idempotent via
  `exist_ok=True`, `result_unit_io_error` shape), `Fs.list_dir`
  (NEW canonical-ABI shape `result_list_string_io_error`,
  20-byte indirect-return area, Ok arm allocates a List<String>
  header around the host-allocated data buffer, sorted entries),
  `Fs.allows` / `Env.allows` (inline-attenuation per D4: literal
  arg evaluated at emit time against the attenuation chain
  producing a static i32; non-literal arg raises
  `WasmEmissionError` with actionable diagnostic). 18 new tests
  (11 runtime host-bridge tests + 5 emit-time `allows` tests +
  1 `allows_inline.capa` parity program + 1 existing canary
  test repointed since `Stdio.read_line` is now supported). Full
  suite 1978 -> 1996 / 5 skipped / 0 fail. Files: `_emit_wit.py`
  (gated `_METHODS_NEEDING_IO_ERROR` so io-error injects only when
  needed), `_wasm_host.py`, `_wasm_component_host.py`, `_caps.py`
  (new `_emit_atten_allows` helper + new `result_list_string_io_error`
  materialiser), `_discovery.py` (elide `allows` from imports).
  Next: Random capability (slice 2, gated D1 = SplitMix64).

- [x] **Map and Set structural equality (`==`/`!=`)** (closed
  2026-05-28). Both deferred at slice 3 ("Map and Set are deferred";
  `_emit_leaf_compare` raised on reach). This slice ships both as
  order-independent structural equality (`{1:"a", 2:"b"} ==
  {2:"b", 1:"a"}` is True; `{1,2,3} == {3,2,1}` is True), matching
  Python `dict == dict` / `set == set` semantics. Reuses the slice-3
  `$eq_*` machinery for nested keys/values and the slice-6/7
  per-key-type Map dispatch (`_emit_compare_pair_key_to`,
  `_emit_push_map_key_canonical`).
  Algorithm (O(N*M), naive nested scan): length-mismatch fast-fail,
  outer loop over `a`'s pairs/elements, inner loop scans `b` for a
  match; on key match compare values via per-type decode + leaf
  compare; outer completes -> equal. Two new emitters in
  `capa/ir/_emit_wasm/_equality.py` (`_emit_map_eq`,
  `_emit_set_eq`) + three helpers (`_emit_map_stash_pair_key`,
  `_emit_map_pair_value_compare`, `_emit_set_stash_element_at`).
  Value-decode handles Int (raw i64), Float (`f64.reinterpret_i64`),
  Bool (`i32.wrap_i64`), String (packed-i64 unpack -> `$str_eq`),
  pointer-shape (`i32.wrap_i64` -> `$eq_<V>`, transitively).
  Also closed a latent Python-oracle gap: `CapaSet` had no `__eq__`
  (identity-only), so `CapaSet({1,2}) == CapaSet({2,1})` returned
  False on Python. Added `CapaSet.__eq__` that compares the
  underlying insertion-ordered dicts (which Python dict-equality
  already orders independently of insertion order) + `__hash__ =
  None` to mirror native `set`. Both backends now agree on Set
  structural equality. Same class of latent bug fix as the slice-4
  payloadless-variant identity issue.
  6 new tests: 2 parity programs (`map_eq.capa` covering Map<Int,Int>,
  Map<String,Int>, Map<Point,Int> all order-independent + mismatch
  cases; `set_eq.capa` covering Set<Int>, Set<String>, Set<Point>),
  4 CapaSet-equality runtime tests, plus 2 existing
  `test_map_equality_rejected` / `test_set_equality_rejected` tests
  flipped to positive `test_*_order_independent` cases. Full suite
  1972 -> 1978 / 5 skipped / 0 fail. With this slice the equality
  story is complete across all compound types (struct, sum, tuple,
  List, Map, Set, nested).

- [x] **Map<K, V> with Struct / Tuple / Sum keys on Wasm**
  (closed 2026-05-28). Continuation of the prior Int+Bool slice.
  Pointer-shape Map keys (Struct, Tuple, Sum incl. Option / Result,
  nested struct via transitive freeze) now work end to end via the
  slice-3 `$eq_*` structural-equality helpers and the slice-4 H2
  frozen rule, both of which were already in place. This slice is
  purely additive: lifts three analyzer rejections, adds four
  pointer-shape branches to the slice-6 `_maps.py` helpers, adds
  one branch to `_collect_eq_types`, and one new `$_alloc_tmp_key_ptr`
  scratch local. Pair layout uniform 16 bytes (key i32 @0, pad i32
  @4, value i64 @8) identical to Bool's layout; allocator + grow
  loop unchanged. H2 already covered struct keys, now starts firing
  in practice (`p.x = 5` after `Map<Point, Int>` is rejected with
  the locked diagnostic). Tuples and sums are immutable from Capa
  source (parser has no `t.0 = x` / `Some(x).value = y` surface),
  so they need no H2 extension. Latent bug fix: `_map_key_type` /
  `_map_value_type` were splitting `Map<(Int, String), V>` on the
  inner comma; replaced with depth-aware `_split_top_level_commas`.
  5 new tests (4 parity programs: `map_point_key`, `map_tuple_key`,
  `map_option_key`, `map_nested_struct_key`; 1 H2-interaction test).
  3 slice-6 rejection tests flipped to acceptance. Full suite
  1967 -> 1972 / 5 skipped / 0 fail. Accepted Map key set is now
  String, Int, Bool, Struct, Tuple, Sum (incl. Option / Result);
  rejected: Float (NaN), List / Map / Set (nested collection),
  Fun. Deferred: Map equality (`==`) - same machinery now available,
  next slice candidate.

- [x] **Map<K, V> with Int and Bool keys on Wasm** (closed
  2026-05-28). Map was String-key-only on the Wasm backend per the
  audit's M4 finding (analyzer accepted `Map<Int, V>`, Wasm
  silently miscompiled). This slice extends key types to **Int and
  Bool**, with the analyzer now loudly rejecting genuinely
  unsupported key types (`Float`, struct, sum, tuple, nested
  collections, functions) up-front with clear diagnostics. String
  keys unchanged.
  Locked design: **uniform 16-byte pair layout for all key types**
  (String: ptr/len/value; Int: i64/value; Bool: i32/pad/value), so
  the allocator + grow loop stay generic. Per-key-type dispatch
  factored into `_emit_push_map_key_canonical`,
  `_emit_compare_pair_key_to`, `_emit_store_pair_key`,
  `_emit_load_pair_key_for_tuple` in `_maps.py`; new
  `_map_key_type` companion to `_map_value_type` in `_layout.py`.
  `$str_eq` now only emitted when the module actually uses String
  keys (cleaner; existing benign-but-noisy unconditional emit
  removed). New `$_alloc_tmp_key_i64` scratch local for Int-key
  Maps so Int-key + String-value programs do not collide on
  `$_alloc_tmp_i64`. 18 new tests (6 Map parity programs covering
  Int->Int, Int->String, Int->Struct, Int->update/dedup,
  Bool->Int, String->Int regression; 13 analyzer-rejection tests
  for Float / List / Map / Set / Tuple / Fun / Struct / Sum keys
  + the three accepted scalar types). Full suite 1948 -> 1967 / 5
  skipped / 0 fail. Closes audit's M4 silent-divergence vector.
  Deferred to follow-ups: struct / tuple / sum keys (need
  integration with slice-3 `$eq_*` helpers; ride on the H2 frozen
  rule), Map equality (`==`).

- [x] **Security hardening pass 4 - H2 frozen struct types as Set
  / Map keys** (closed 2026-05-28). Final audit follow-up.
  Mutating a struct used as a Set element or Map key broke the
  data-structure invariant on both backends (Wasm linear-scan misses
  entries; Python `CapaSet` dict corrupts its hash bucket). Closed
  with a conservative type-level analyzer rule: **if a struct type
  T is referenced (transitively via fields, sum payloads, nested
  collections) from any `Set<...T...>` or `Map<...T..., V>` position
  anywhere in the program, then `p.field = value` on any value of
  type T is rejected at analysis time** with a clear diagnostic
  ("field 'x' of struct 'Point' cannot be assigned: type 'Point' is
  frozen (appears in Set or Map keys; mutating fields would break
  the structure)"). Map VALUES stay mutable (only keys need
  freezing). Whole-value rebinding (`p = Point{...}`) stays allowed;
  only post-construction field writes are rejected. Catches `=`,
  `+=`, `xs[i].x = y` and other indexed-receiver forms by walking
  the FieldAccess target uniformly. New
  `capa/analyzer/_frozen.py` mixin (~250 LOC) computes the
  frozen-type set via a module-walk + transitive closure pre-pass
  run after `_collect_globals`. One new branch (~10 LOC) in
  `_check_assign`. 9 new tests covering direct freeze, Map-key
  freeze, Map-value not frozen, transitive via struct field, nested
  collection, constructor still works, var rebinding still works,
  augmented assignment caught, indexed receiver caught. Zero
  existing test or example used a mutate-then-Set pattern, so the
  rule lands with zero corpus breakage. Full suite 1939 -> 1948 / 5
  skipped / 0 fail.
  **All audit follow-ups closed.** No known silent unsafety or
  parity divergence between the Python and Wasm backends today.

- [x] **Security hardening pass 3 - C4 + M1 + M4 + H1**
  (closed 2026-05-28). Four audit follow-ups closed in one slice.
  (C4) `to_int(huge_float)` now raises `OverflowError` on Python when
  the result is outside the signed i64 window (also on NaN / inf),
  matching the existing Wasm trap. Both backends fail loud at the
  same input.
  (M1) Env capability docs: prominent "leaks all host env vars
  by default; use restrict_to_keys to narrow" notes added to the
  Env runtime class, the WIT host bridges (`_wasm_host.py` /
  `_wasm_component_host.py`), and the `_register_env` docstrings.
  Documentation only.
  (M4) Capability manifest embedded in the `.wasm` artefact via a
  `capa-manifest` custom section. Schema v1: `{capa_manifest_version,
  capa_version, functions: [{name, declared_capabilities}]}`. Built
  from the existing `manifest.build_manifest` data, embedded via WAT
  `(@custom "capa-manifest" "...")` directive (no new wasm-tools
  version needed). New `capa.ir.read_wasm_manifest(blob) -> dict |
  None` is a tiny LEB128 parser so third-party auditors can inspect
  per-function capabilities directly from the artefact without
  wasmtime / wasm-tools.
  (H1) Memory budget cap: deterministic upper bound on Wasm linear
  memory at emit time, defaulting to 256 pages (16 MiB), exposed via
  the new `--wasm-memory-cap <pages>` CLI flag (`0` opts out).
  Out-of-budget allocations trap loud via the existing
  `memory.grow` -> `unreachable` path; the cap just makes the trap
  predictable across hosts.
  20 new tests; full suite 1919 -> 1939 / 5 skipped / 0 fail. Audit
  follow-ups remaining: **H2 effect tracking for "struct as Set
  element ⇒ fields read-only"** (design-heavy, own slice next).

- [x] **Security hardening pass 2 - C1 bounds checks on collection
  indexing** (closed 2026-05-28). The C1 audit finding turned out
  more serious than "defense in depth": `xs[i]` with `i >= len`
  raised `IndexError` on Python but silently read junk memory on
  Wasm (real silent divergence + data-leak vector). Same for
  negative indices (`xs[-1]`) and `String.substring(s, 0, 1000)`.
  Closed in the "both fail loud at same input" stance of pass 1.
  Wasm: `_emit_index` in `_lists.py` prepends `i >= len` unsigned
  compare + `unreachable` (one check catches negatives too because
  `i32.wrap_i64` of a negative i64 is a huge u32); `_emit_string_substring`
  in `_strings.py` adds equivalent `start > end OR end > len` guard.
  Python: new `_capa_list_get(xs, i)` and `_capa_substring(s, start, end)`
  in `capa/runtime/_safety.py` raise `IndexError` / `ValueError` on
  out-of-range, called by both transpilers via the Index / substring
  emit paths. Capa indices are now explicitly non-negative on both
  backends (matches the "fail loud, deterministic across backends"
  contract; no `xs[-1]` usage in tests / examples to migrate; one
  pre-existing `test_string_substring_clamps` renamed to
  `test_string_substring_raises_on_oob` since the clamp contract is
  replaced). `_emit_for` for-iter already structurally bounded
  (`for i in 0..len`); Map / Set linear scans already capped by the
  header `len`; tuple indices analyzer-verified at compile time. New
  scratch local `$_bounds_idx` (i32) gated by `has_list_index_bounds`
  flag. 10 new tests (5 wasm bounds-trap, 5 Python bounds-raise);
  parity program `safety_traps.capa` extended with positive cases.
  Full suite 1909 -> 1919 / 5 skipped / 0 fail. Audit followups
  remaining: H1 allocator GC, H2 Set/Map-key mutation effect tracking
  (own slice), C4 to_int out-of-range docs, M1-M4 supply-chain
  manifest in `.wasm`.

- [x] **Security hardening pass 1 - 5 critical safety gaps closed**
  (closed 2026-05-28). Five concrete unsafety / silent-divergence
  gaps surfaced by the backend security audit (also 2026-05-28), all
  fixed to "both backends fail loud at the same input" rather than
  silent miscompile. Capa is a security-focused language and the audit
  found these were the highest-leverage items to close before
  shipping more language features.
  (1) **C2 Int overflow** (i64 wrap was the one observable silent
  divergence today): `+` / `-` / `*` / `+=` / `-=` / `*=` on Int now
  trap on signed overflow on Wasm (overflow-detection emit:
  `((a^r) & (b^r)) < 0` for add, equivalent for sub, `b!=0 AND r/b!=a`
  for mul; gated by a new `has_int_overflow_check` flag in
  `_locals.py`) and raise `OverflowError` on Python via runtime
  helpers `_capa_iadd` / `_capa_isub` / `_capa_imul` (new
  `capa/runtime/_safety.py`). Both transpilers wrap Int+/-/\* into
  the helpers when types resolve to Int. (Acknowledged perf hit on
  the Python side, accepted for security correctness.)
  (2) **C3 Shift count** (`<<` / `>>` and `<<=` / `>>=`) now traps on
  Wasm when RHS not in `[0, 64)` (unsigned compare catches both
  negative and >=64), and raises `OverflowError` on Python via
  `_capa_shl` / `_capa_shr`. Same "both fail loud" contract.
  (3) **C5 parse_int overflow** now returns `None` instead of
  silently wrapping on both backends. Wasm `$parse_int` adds a
  pre-multiply threshold check (`acc > 922337203685477580` or `==`
  with next-digit `> '7'`); Python `parse_int` returns `None_` when
  the parsed value escapes the i64 window.
  (4) **C6 Float `%` by zero** now traps on Wasm via an explicit
  `f64.eqz` guard before the floored-modulo lowering (was silently
  producing NaN by the chain `a/0 = inf, floor(inf) = inf, inf*0 =
  nan, a - nan = nan`). Python already raised `ZeroDivisionError`.
  (5) **H3 UTF-8 host crash** - the host bridge previously crashed
  the Python process on malformed UTF-8 in guest-supplied strings.
  Stdio uses `errors="replace"` (no return channel to signal failure;
  prints U+FFFD); Env.get / Fs.read / Fs.write / json.parse return
  the appropriate Err / None variant via the WIT result types.
  21 new tests (8 wasm safety-trap tests, 4 host-bridge UTF-8 tests,
  8 Python-side trap-raise tests, 1 parity program covering all five
  fixes' valid inputs). One pre-existing test assertion adjusted
  (`tests/test_ir.py` arithmetic-emission text check now expects the
  `_capa_iadd` helper call instead of a bare `+`). Full suite 1888
  -> 1909 / 5 skipped / 0 fail. Audit findings deferred to follow-up:
  C1 bounds checks on collection indexing (defense in depth),
  C4 to_int out-of-range docs, H1 allocator GC, H2 Set/Map-key
  mutation effect tracking (design-heavy, own slice), M1-M4 supply-
  chain manifest in `.wasm`.

- [x] **Bitwise operators on Int** (closed 2026-05-28). `& | ^ << >>`
  now work end to end on `Int` with parity-clean output between the
  Python and Wasm backends; previously unsupported across the whole
  stack (no lexer tokens, no parser precedence, no analyzer rule,
  no emit-table entries). Five layers touched: lexer (new
  `AMPERSAND` / `CARET` / `LSHIFT` / `RSHIFT` tokens + `<<` / `>>`
  lookahead mirroring `<=` / `>=`), parser (4 new precedence
  methods + 4 op-set constants, rewired into the existing cascade),
  analyzer (one `_check_binop` branch requiring Int / Int -> Int,
  rejecting Float / String), and both emit tables (`_BINOP_MAP` /
  `_PY_BINOPS` / `_INT_BINOP`). Standard C / Rust / Python
  precedence: `or < and < not < cmp < range < | < ^ < & < + - < << >> < * / %`.
  `PIPE` token is reused: match-pattern or-patterns parse via a
  distinct entry point, no conflict. The `>>` lexer change broke
  `List<List<Int>>` (RSHIFT swallowed both closers); fix is the
  standard rustc/scalac in-place token split in
  `_parse_type_args._close_type_args` (RSHIFT rewritten to GT with
  position shifted by one column). 18 new tests (2 lexer, 7 parser,
  3 analyzer, 5 ir-wasm, 1 parity program covering all ops +
  precedence corners + a nested-generics regression check). Full
  suite 1870 -> 1888 / 5 skipped / 0 fail. Slice 6 of full language
  coverage. Note: `i64.shr_s` is the signed shift right (matches
  Python's sign-extending `>>` on int); Wasm masks shift amount to
  low 6 bits while Python raises on negative shift, but the analyzer
  enforces Int operands and well-typed non-negative shifts agree
  byte for byte. Bitwise on `Bool` deliberately rejected (`and` /
  `or` are the bool ops).

- [x] **Numeric + Bool interpolation parity** (closed 2026-05-28).
  Three small parity fixes that cleaned up known divergences /
  rejects between the Python and Wasm backends:
  (1) **Int `%` is now floored** on Wasm (matches Python): the raw
  `i64.rem_s` gives C-style truncated remainder (sign of dividend)
  while Python's `%` is floored (sign of divisor), so `-7 % 3` was
  Wasm `-1` / Python `2`; the emitter now corrects `r = a rem_s b`
  by adding `b` when `r != 0 and (r ^ b) < 0`. Gated by a new
  `has_int_modulo` flag in `_locals.py` that pulls in
  `$_alloc_tmp_i64`.
  (2) **Float `%` is implemented** on Wasm (was a hard reject): `a
  - floor(a/b) * b`, also floored to match Python.
  (3) **`${flag}` Bool interpolation is now lowercase on both
  backends** (`true`/`false`). Wasm already used lowercase; the two
  Python backends (`transpiler/_expressions.py` and
  `ir/_emit_python.py`) wrapped Bool interpolations as
  `('true' if x else 'false')`. One new parity program
  (`examples/wasm/numeric_parity.capa`) covers mixed-sign Int / Float
  modulo + Bool interpolation. Three pre-existing test assertions
  updated from `True` / `False` to `true` / `false`. Full suite 1869
  -> 1870 / 5 skipped / 0 fail. Slice 5 of full language coverage.
  Bitwise operators (`& | ^ << >>`) on `Int` are deliberately NOT in
  this slice: they have no lexer tokens today, so they are a
  frontend addition (lexer + parser + analyzer + both backends), not
  a Wasm-coverage gap.

- [x] **Set<T> on the Wasm backend, insertion-ordered both
  backends** (closed 2026-05-27). `Set<T>` (add / remove /
  contains / length / is_empty / to_list / for-iteration) now
  compiles on the Wasm backend; previously all Set methods were
  rejected. Decision: Set is now **insertion-ordered on both
  backends** (was a raw hash-ordered Python `set()`, which would
  diverge from a Wasm linear-scan array on `for` / `to_list`).
  Python side: new `capa/runtime/_set.py` `CapaSet` backed by an
  insertion-ordered dict (structural dedup via value `==`/hash;
  structs became `@dataclass(unsafe_hash=True)` so they hash while
  staying mutable for field assignment); wired into both Python
  emitters (`new_set()` -> `CapaSet()`). Wasm side: new
  `capa/ir/_emit_wasm/_sets.py` mirroring the List/Map emitters
  (16-byte header + `_size_of`-strided element array); add dedups
  and remove shifts the tail down (not swap-remove) to preserve
  insertion order; add/contains/remove dedup via slice-3 structural
  equality (`$eq_*` / `$str_eq` / scalar eq), discovered by
  extending `_collect_eq_types` for Set element types. 9 new tests
  (3 Python-vs-Wasm parity programs: Set<Int>/Set<String>/Set<Point>
  with dedup + ordered for/to_list). Full suite 1860 -> 1869 / 5
  skipped / 0 fail. Slice 4 of full language coverage.

- [x] **Structural equality on compound types** (closed
  2026-05-27). `==` / `!=` on struct / sum (incl. Option/Result) /
  tuple / `List<T>` now compile to deep, by-value comparison on the
  Wasm backend, matching the Python backend (dataclass / list /
  tuple `__eq__`); previously compound `==` fell through to an
  i64.eq on the heap pointers (reference compare / invalid wasm).
  Also unblocks `List.contains` on pointer-shape elements (rejected
  since the slice-1 guard). New `capa/ir/_emit_wasm/_equality.py`
  generates one `$eq_<Type>(a, b) -> i32` helper per compound type
  reached transitively under a `==` / pointer-shape `contains`;
  helpers mutually recurse by name (WAT resolves `call $name`
  module-wide, no ordering needed). Leaves reuse `i64.eq` / `f64.eq`
  / `i32.eq` / `$str_eq`; container-specific loads (struct two-i32
  String, sum/tuple/list packed-i64) feed a shared
  `_emit_leaf_compare`. Map/Set equality is rejected with a clear
  error (deferred). Also fixed a latent **both-backend** bug:
  payloadless variants (`Red == Red`) compared by identity (Python
  plain class -> False; Wasm invalid); now structural (`True`) via
  frozen-empty-dataclass on the Python side + variant-name->sum
  normalisation on the Wasm side. 16 new tests (6 Python-vs-Wasm
  parity programs: struct/sum/tuple/list/contains/nested, plus
  execution + Map/Set-reject tests). Full suite 1844 -> 1860 / 5
  skipped / 0 fail. Slice 3 of full language coverage. Note: bare
  Bool interpolation (`${flag}`) still diverges True/true between
  backends, orthogonal to equality, deferred.

- [x] **Int pattern matching** (closed 2026-05-27). `match` on an
  `Int` scrutinee (literal arms + wildcard/identifier-bind default
  + guards) now compiles on the Wasm backend; previously rejected
  in `_emit_match` ("Int match lands in a later phase"). Lowering,
  CIR, and analyzer were already complete (Int literal arms lower
  to `PatLiteral(kind="int")`; the analyzer enforces the default
  arm), so the change is confined to `capa/ir/_emit_wasm/_match.py`:
  a dispatch clause plus `_emit_int_match` (N-arm nested-if cascade,
  `i64.eq` per literal, scrutinee-bind tail) and
  `_emit_int_match_with_guards` (flat-block, reusing the generic
  guarded-arm helpers), modeled on the Bool/String emitters. The
  i64 scrutinee is stashed in a dedicated `$_m_scrut_i64` local
  (the shared `$_m_scrut` is i32) gated by a new `has_int_match`
  flag in `_locals.py`. 4 new tests (1 Python-vs-Wasm parity
  program `int_match.capa` + 3 execution/guard tests). Full suite
  1840 -> 1844 / 5 skipped / 0 fail. Slice 2 of full language
  coverage. Note: negative-literal patterns (`-1 -> ...`) are a
  separate parser-surface gap (`expected pattern, got MINUS`), not
  an emitter gap; negatives route through the catch-all today.

- [x] **Pointer-shape element types in collections + HOFs**
  (closed 2026-05-27). `List` / `Map` / the map / filter / fold
  HOFs now carry struct / tuple / sum (incl. Option/Result) /
  nested-collection elements on the Wasm backend, not just
  scalars + String. Root cause was a slot-size divergence: the
  base list path strides pointer-shape elements at 4 bytes (i32
  pointer, via `_layout._size_of`) but the HOF path
  (`_closures._hof_elem_slot_size`) hardcoded 8 for everything
  but Bool, so a `List<Point>` built at 4-byte stride was
  read/written at 8-byte stride and stomped neighbours. Fix:
  `_hof_elem_slot_size` now delegates to `_size_of` (single
  stride source for base + HOF), the closure-result store honours
  the 4-byte slot (`i32.store`, mirroring the Bool branch), the
  three pointer-shape HOF rejection guards (map/filter/fold) are
  removed, and the filter/fold raw-slot width branch is broadened
  from `elem_ty == "Bool"` to `stride == 4`. The base `List`
  path, the closure ABI (`_wasm_type` already returns i32 for
  pointer-shape), and `Map<String, pointer-shape V>` needed no
  change (verified by parity). `List.contains` on pointer-shape
  is rejected with a clear error (it would compare references,
  not values; structural equality is a separate piece). 8 new
  tests (7 Python-vs-Wasm parity programs in `examples/wasm/`:
  struct map/filter/fold, scalar<->struct both directions,
  `Map<String, Point>`, `List<List<Int>>`; plus 1 WAT slot-size
  pin). Full suite 1831 -> 1840 / 5 skipped / 0 fail. First slice
  of the broader "full language coverage" arc. Deferred:
  structural contains/equality, `Set<T>` of pointer-shape,
  `Map<Int, V>`, Float-bearing parity.

- [x] **List<T>.map / filter / fold for non-Int element types**
  (closed 2026-05-25). `List<Int>`, `List<String>`,
  `List<Float>`, and `List<Bool>` HOFs are now supported by
  the Wasm backend: the closure sig is built per-element-type
  via `_closure_sig_key_for` (String -> two i32s ptr/len,
  Float -> f64, Bool -> i32, Int -> i64); load uses
  `i64.load` + `f64.reinterpret_i64` for Float,
  `_emit_unpack_i64_to_string` for String, and
  `i32.load + i64.extend_i32_u` for Bool (4-byte slot widened
  into the shared `$_alloc_tmp_i64` scratch local); map's
  store path uses `f64.store` / `i64.store` /
  `i32.store` per the output type's stride; filter preserves
  the packed slot bytes byte-for-byte via
  `_emit_inline_packed_list_push` with `slot_size=4` on Bool;
  fold widens to handle String accumulators through
  `_set_string_dst`. Also fixes a pre-existing bug where
  `List<Float>` literal / indexing / for-iter used
  `i64.store/load` instead of `f64.store/load`, which made
  the literal `[1.0, 2.0]` fail to compile. The map loop now
  re-reads the dst data pointer from the list header each
  iteration so the Bool stash path's reuse of `$_alloc_tmp`
  doesn't clobber it. Remaining gap: pointer-shape element
  types (would need alloc-aware store); raises a clear
  `WasmEmissionError` pointing at the Python backend as
  workaround. Coverage: 4 new tests in `TestWasmListHofNonInt`
  (`test_list_bool_map`, `test_list_bool_filter`,
  `test_list_int_map_to_bool`, `test_list_bool_fold_to_int`)
  on top of the existing 8; pointer-shape skip stays.
  Suite: 1492 -> 1495.
- [x] **Lambdas-inside-lambdas (nested closures)** (closed
  2026-05-25). Lambda lifting with flat envs: each nested
  closure gets its own env record containing every name it
  references from any outer scope, with values copied straight
  into that env at MakeLambda emit time. No env-of-env chain at
  run time. The discovery walker now threads a scope stack
  (function at the bottom, each lifted lambda pushed when
  descending into its body); ``_register_lambda`` consults the
  immediate-outer scope's ``params`` / ``locals`` / ``captures``
  in priority order before falling through to the top-level
  function for capture-type resolution. The MakeLambda emit
  site routes per-capture stores through ``_push_value`` /
  ``_push_string_value_as_ptr_len`` so a name that is itself an
  outer capture loads from the outer's ``$env`` rather than a
  Wasm local that doesn't exist. Free-variable analysis
  recurses into nested MakeLambda bodies and subtracts the
  nested's own params + body-defined locals before propagating
  the remainder upward, so an outer that never references a
  name directly still captures it when an inner needs it. Works
  for arbitrary nesting depth (verified through triple nesting
  in interactive testing). Coverage: 4 new tests in
  ``TestWasmNestedClosures`` (simple nested closure spanning
  function + outer scopes; inner captures only outer's param;
  inner captures only function-scope variable; nested closure
  used as a HOF callback). Suite: 1488 -> 1492.
- [x] **`wasmtime` as optional dep + `--prefer-wasm` opt-in**
  (closed 2026-05-25). `pyproject.toml` now exposes a `[wasm]`
  extra (`pip install -e .[wasm]`) that brings in
  `wasmtime>=20`, so the host-bridge path no longer requires a
  separate manual install. `wasm-tools` still ships as a Rust
  binary and stays on PATH separately (Python cannot vendor a
  Rust toolchain). New CLI flag `--prefer-wasm` (also honoured
  via `CAPA_PREFER_WASM=1`) makes `capa --run` try the Wasm
  pipeline first and fall back silently to the Python pipeline
  when CIR lowering / Wasm emission / wasmtime trap. The
  fallback is intentionally silent so the default execution
  path stays predictable for users who opt in best-effort. The
  toolchain probe (`_wasm_tooling_available`) lazily checks
  both `shutil.which("wasm-tools")` and `import wasmtime`, so
  `capa --run` without the flag still pays nothing for the
  feature. Suite: 1492 tests, 0 regressions.
- [x] **Pure-Wasm JSON parser** (superseded 2026-05-25). The
  original motivation was to drop the ``capa:host/json``
  host bridge so ``--component --run`` worked without leaking
  the canonical-ABI boundary. That bridge no longer exists:
  ``_builtin_json.py`` splices a pure-Capa parser /
  serialiser (``__capa_parse_json`` / ``__capa_to_json``)
  into every IR module that touches ``parse_json`` /
  ``to_json``, so the JsonValue tree builds in the guest's
  own linear memory through the regular Capa allocator. A
  separate hand-written WAT parser would be ~500 lines for
  no measurable gain over the Capa source the compiler
  already lowers, so this item closes as superseded rather
  than implemented.

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
