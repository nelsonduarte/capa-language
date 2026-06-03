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

## P0: done for this milestone

No remaining work in this priority.

---

## P1: High-impact within positioning

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

## P2: Adoption-moving, not core

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

## P3: Research-grade, parked

None on the current plan. Each is a multi-month arc of its own.
Listed so the design space is explicit.

### Type-system extensions

- **Linear handles for resources** (must-call types). SHIPPED
  (S1): `linear type` + `consume self`, `_live_linear` tracking,
  `linear_obligations` in the SBOM. Closes a concrete bug class
  (resource leaks).
- **Information Flow Control (IFC)**. SHIPPED (S2): two-point
  `@public`/`@secret` lattice, join propagation, secret-by-default
  `env.get`, secret-to-sink enforcement (warn-then-enforce,
  `@strict_ifc`), `declassify(value, reason)` recorded in the SBOM as
  `declassification_sites`, implicit-flow under strict, and
  anti-laundering through aggregates + mutable containers
  (intra-procedural, whole-aggregate granularity). Remaining (v2):
  cross-function inference without explicit `@secret` params,
  per-field precision, a mechanised noninterference proof.
- **Typestate / session types**. SHIPPED (S3.1 + S3.2, Python
  backend): the state lives in the type (`typestate Name` +
  `Name[State]`), a value is linear, and the type checker enforces the
  protocol via state-exact compatibility. Construction `Name[State] {}`
  + transition `become(value, State)` make a full protocol type-check
  and run; the SBOM carries `typestates` + a `protocol_states` count.
  S3.3 added Wasm parity (a v1 typestate lowers as a zero-field struct /
  i32 token, construction is a fieldless MakeStruct, become is identity;
  `examples/wasm/typestate_door.capa` runs byte-identically on both
  backends). Remaining: state-specific receiver methods and typestate
  fields/payloads (v1 is fieldless).
- **Constant-time markers for crypto**. SHIPPED (S4, analyzer):
  `@constant_time()` rejects secret-dependent control flow (if /
  elif / while / if-expr / match) and secret-indexed memory access
  (`xs[secret]`, list/map/set lookups, `str.char_at`), reusing the S2
  labels; surfaced in the SBOM as a per-function `constant_time` flag.
  Mechanically prevents the CWE-208 examples in the CVE case studies.
  Remaining: defense-in-depth enforcement in the Wasm emitter, and
  variable-time arithmetic (e.g. division by a secret).
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

- [x] **Roadmap P3 (partial) - 2^63 residual closed; constant-fold
  deliberately skipped** (2026-06-02). The slice-26 residual (a bare
  ``9223372036854775808`` = 2**63 used positively) was a real silent
  divergence: Python printed the bignum, Wasm wrapped to i64::MIN. The
  lexer admits the magnitude (it can't see a preceding unary minus, and
  ``-9223372036854775808`` = i64::MIN must work), so the ANALYZER now
  rejects an ``IntLit == 2**63`` unless it's the immediate operand of
  unary ``-`` (``_check_unary`` marks the operand id; the ``IntLit``
  check consults it). Clean error, both backends. 4 new tests in
  ``TestIntLiteralRange``.
  - **Constant-fold NOT implemented (measured decision).** Benchmarked
    a fabricated program with 100 constant ops: full compile ~2ms,
    Cranelift already folds constants downstream -- no measurable gain.
    The fold would also have to preserve i64 trap-on-overflow (only
    fold when the result fits), subtle code with regression risk and no
    payoff. Skipped per the no-over-engineering principle; closure-dedup
    / DCE likewise parked until a benchmark shows the overhead matters.
  - Suite 2145 -> 2149.

- [x] **Roadmap S1 - linear (must-consume) types** (landed
  2026-06-01). Second roadmap phase
  (docs/design/roadmap-technical-detail.md). A
  ``linear type Foo { ... }`` value must be consumed before
  it leaves scope -- passed to a ``consume`` param /
  ``consume self`` method, or returned (transfers the
  obligation to the caller). Closes the resource-leak bug
  class (file never closed, transaction never resolved) at
  compile time. The dual of the existing capability
  ``consume`` discipline (that errors on use-after-consume;
  this errors on never-consumed).
  - **Syntax/AST (S1.1)**: new ``KW_LINEAR`` token;
    ``linear type Name { ... }`` (struct only -- ``linear``
    on a sum type is rejected); ``TypeStruct.is_linear``.
    ``consume self`` now parses (``consume`` accepted before
    the ``self`` special-case) so a method can release its
    receiver.
  - **Analyzer (S1.2/S1.3)**: new ``capa/analyzer/_linear.py``
    mixin. ``_linear_types`` collected per-analyze;
    ``_live_linear`` (name -> bind Pos) tracks outstanding
    obligations per function, save/restored like
    ``_consumed``. A ``let h = open()`` of a linear value
    opens an obligation; a ``consume`` arg / ``consume self``
    call / ``return h`` discharges it; anything still live at
    function exit is a leak error. Branch fork/merge mirrors
    the ``_consumed`` machinery but merges by UNION of
    surviving obligations (a value must be consumed on every
    path, so consume-on-some-branches-only is caught).
    Function ``consume`` params are the terminal owner and do
    NOT re-obligate the body.
  - **SBOM (S1.4)**: per-param ``is_linear``; per-function
    ``linear_obligations: {consumes: [...], produces_linear:
    bool}`` -- "this function takes ownership of handle X and
    must release it" / "produces a handle the caller must
    release". The regulator-facing must-consume surface.
  - **Known MVP limits (deferred, documented)**: a linear
    value dropped on a *diverging* branch (e.g. consumed in
    ``then``, ``return`` in ``else`` without consuming) is
    not caught -- diverging branches are excluded from the
    merge and there's no per-``return`` drop check yet;
    aliasing a linear value via ``let g = h`` is treated as
    the obligation staying on the original name (no
    move-tracking through plain idents); destructuring a
    linear value isn't tracked. None are soundness holes in
    the common path; all are extensions for a follow-up.
  - Runs end-to-end on both backends (linearity is
    compile-time only; the lowerer treats a linear struct as
    a plain struct). 12 new tests (analyzer + manifest).
    Suite 2133 -> 2145.

- [x] **Roadmap P1 - Wasm AOT (`capa build --release` +
  `capa run-aot`)** (landed 2026-06-01). First phase of the
  post-1.0 security+performance roadmap
  (docs/design/roadmap-technical-detail.md). Compile-once /
  run-many: serialise the wasmtime/Cranelift module instead
  of JIT-compiling the .wasm on every `--run`. Reuses the
  whole audited Wasm pipeline; no new backend.
  - **New `capa/runtime/_aot.py`**: a portable AOT container
    (`CPAO` magic + JSON header + serialized cwasm). The
    header carries (a) `main`'s param names -- the serialized
    cwasm drops the name section, so without this the host
    couldn't map cap slots to root handles; captured from the
    .wasm at build time instead -- and (b) the wasmtime
    version, so a cwasm from a mismatched wasmtime is refused
    (deserializing a mismatched blob is unsafe) rather than
    crashing.
  - **`WasmHost.run_main_aot`**: deserialize path, sharing a
    new `_invoke_main` helper with the JIT `run_main` (root-
    handle bootstrap + name->slot mapping extracted so both
    paths use one implementation). load_aot takes the host's
    engine (wasmtime refuses cross-Engine instantiation).
  - **CLI**: `capa build --release <file> [-o out.cwasm]`
    (multi-file aware via the loader; same memory-cap bounds
    as --wasm) and `capa run-aot <file.cwasm> [-- args]`.
  - **Verified**: build->run-aot output is byte-identical to
    `--run --wasm` on a plain program AND on one with
    attenuated Fs+Net params in (net, fs) order (proves the
    param-name->handle mapping survives serialization, the
    one thing that could silently break). Version-mismatch
    fails closed; bad-magic gives a clean error not a
    traceback; an analysis error refuses the build with no
    artifact written.
  - **Honest perf note**: module-load (the part AOT
    optimizes) is ~1.3x faster on a trivial module; the gain
    scales with module size (Cranelift compile cost grows,
    deserialize stays ~flat) and with run count. Wall-clock
    of a one-shot CLI run is dominated by Python interpreter
    startup (~150ms both paths), so the headline win is
    architectural (a distributable compile-once artifact),
    not a big one-shot speedup. A Rust launcher (roadmap
    P1.2b) would remove the Python startup floor; deferred.
  - 12 tests in `tests/test_aot.py` (container format unit +
    build/load + CLI e2e parity). Suite 2121 -> 2133.

- [x] **Slice 30 - CLI driver robustness audit** (closed
  2026-06-01). A fourteenth audit pass, on `capa/cli.py`
  (1328 LOC, the entry point). No P0 (the CLI doesn't gate
  the capability/regulatory claims); fixed two P1 crashes
  + one P2 corrupted-output, each verified before + after.
  - **P1-a - token dump crashed on redirect.** The default
    token dump uses a `->` arrow glyph (U+2192); on a
    cp1252 Windows console redirected to a file, printing
    any literal token (`let x = 42`) raised
    `UnicodeEncodeError` + traceback, exit 1 -- on the most
    basic `capa file.capa > out` invocation. Fix:
    `main()` reconfigures stdout/stderr to UTF-8 with
    `errors="replace"` at startup (guarded so the StringIO
    test harness, which has no `.reconfigure`, is
    unaffected). Closes the whole class (also unicode file
    names in error messages), not just the arrow.
  - **P1-b - non-UTF-8 file -> raw traceback.** Both
    `read_text(encoding="utf-8")` sites (main + migrate)
    caught only `OSError`; a binary file raises
    `UnicodeDecodeError` (a `ValueError`), so it escaped as
    a traceback, exit 1. Fix: catch `UnicodeDecodeError` at
    both sites, clean `not valid UTF-8` message, exit 2.
  - **P2-b - invalid .wasm written as success.**
    `--wasm-memory-cap` only guarded `<= 0`; a value above
    the wasm32 limit (65536 pages) was emitted verbatim,
    producing a module `wasm-tools validate` rejects, yet
    written to disk with a success message + exit 0. Fix:
    validate `1 <= cap <= 65536` (new `_WASM32_MAX_PAGES`);
    out-of-range -> clean error, exit 2, no artifact
    written.
  - **Deferred (documented, not fixed - UX-nicety, zero
    corruption risk):** conflicting output-format flags
    (`--manifest --cyclonedx`) silently pick the first;
    `--stdin` + positional file silently ignores the file;
    `--output` / `--component` / `--wasm-memory-cap` are
    silent no-ops with a non-matching action. All P2/P3,
    none crash or corrupt.
  - **CLEAN verified:** no ANSI color leak into redirected
    output; missing file / directory -> exit 2; empty stdin
    -> exit 0; `--run` runtime error -> clean rewritten
    traceback exit 1; subcommand argparse (missing arg /
    unknown flag / `--help`) consistent exit 2/0;
    non-integer `--wasm-memory-cap` rejected by argparse
    exit 2.
  - Regression tests in `TestCliRobustness` (4). Suite
    2116 -> 2120 passed / 8 skipped, 0 regressions.

- [x] **Slice 29 - documented-residual cleanup** (closed
  2026-06-01). Closed the three P3s left open by earlier
  slices, each verified before + after.
  - **Slice 26 P3-2** - `parser/_types.py:_close_type_args`
    mutated the shared `Token` object in place when
    splitting a `>>` in nested generics (`List<List<Int>>`),
    so re-parsing the same token stream a second time saw a
    single `>` and failed (latent footgun for an LSP token
    cache / comment sidecar / re-parse). Fix: `Parser`
    shallow-copies its token list (`__init__`), and the
    split writes a FRESH token via `dataclasses.replace`
    instead of mutating. Verified: re-parse of the same
    stream now succeeds and the original stream's RSHIFT
    tokens are untouched.
  - **Slice 26 P3-1** - `parser/_expressions.py:_parse_range`
    docstring claimed `a..b..c` was a dedicated syntax
    error; it actually parses `(a..b)` and leaves `..c` for
    the generic "expected newline" rejection. Docstring
    corrected to match (the behaviour is sound; only the
    claim was wrong).
  - **Slice 28 P3** - `lsp/semantic_tokens.py` emitted
    `deltaStart` / `length` in codepoint units while the
    LSP wire protocol counts UTF-16. Cosmetic (coloring
    offset after an astral char in a string on the same
    line, never corruption), but cleaned up: `_encode` now
    converts column + length to UTF-16 units via a
    dependency-free `_utf16_len` helper. ASCII is the
    identity, so existing output is unchanged.
  - Regression tests added (parser re-parse + chained-range;
    semantic-tokens UTF-16 columns). Suite 2113 -> 2116
    passed / 8 skipped, 0 regressions.

- [x] **Slice 28 - LSP robustness audit (UTF-16/codepoint
  positions + RecursionError)** (closed 2026-06-01). A
  thirteenth audit pass, on `capa/lsp/` (the editor surface,
  not the regulatory claim). Found one **P0 buffer-corrupting
  bug** + one **P1 crash-on-malformed-input**, both fixed.
  - **P0 - UTF-16 vs codepoint column mismatch.** The LSP
    server converted positions as raw codepoints
    (`col = character + 1` inbound, `character = col - 1`
    outbound) while pygls advertises UTF-16 position
    encoding, and `capa/lsp/` negotiated none. On any line
    with a supplementary-plane char (e.g. an emoji in a
    string) before an identifier, every returned range was
    off by the count of astral chars - and on **rename** the
    client overwrote the wrong columns, silently corrupting
    the user's buffer (the worst LSP outcome). Verified
    independently: `greeting` after an emoji resolved to
    codepoint col 18 but UTF-16 col 19; the server emitted
    18.
  - **The fix.** Route every inbound `params.position` and
    every outbound `Position`/`Range`/`TextEdit` through
    pygls's `PositionCodec` (default Utf16) at the
    `server.py` boundary, reusing the document's own
    `.position_codec`. The per-handler `compute_*` functions
    stay in codepoint space (consistent with the lexer's
    codepoint offsets); only the wire boundary converts. 11
    outbound sites converted (diagnostics, hover, definition,
    references, highlight, formatting, range-formatting,
    document-symbols, code-action, prepare-rename, rename);
    line-only ranges (folding) are encoding-safe and left.
    Verified ASCII is a no-op in both directions (the
    regression guard - all pre-existing tests pass with
    identical ranges).
  - **P1 - RecursionError escaped the parse guards.** The
    narrow `except (LexerError, ParserError)` in
    `context.py` / `folding.py` / `diagnostics.py` let a
    deeply-nested-expression `RecursionError` propagate
    (uncaught, though pygls contained it to a degraded
    feature + error toast); `analyze()` was also called
    outside the guard. Broadened the guards to catch
    `RecursionError` and wrapped the `analyze()` calls.
    Reproducer (`'('*600 ... ')'*600`) now degrades to
    empty diagnostics / folding / floor-completion instead
    of raising.
  - **Residual (P3, documented):** `semantic_tokens` emits
    delta-encoded `[deltaLine, deltaStart, length, ...]`
    integers in codepoint units, not `Range` objects, so it
    wasn't covered by the boundary fix. Impact is cosmetic
    only - token `length` is correct (Capa identifiers are
    ASCII), and `delta_start` shifts only when an astral char
    sits in a string before a token on the same line, giving
    slightly-offset coloring, never buffer corruption. Needs
    a different (delta-aware) conversion; deferred.
  - **CLEAN verified by the audit:** no single bad request
    kills the session (pygls 2.1.1 contains every handler
    exception); completion/hover/definition/references/
    highlight/folding/semantic-tokens all degrade gracefully
    on empty / unterminated-string / bad-char / missing-brace
    / undefined-name / type-error documents (11 handlers x 9
    malformed docs, none raised); `did_change` reads the
    already-patched document (no stale-read).
  - `tests/test_lsp.py` 174 -> 185; full suite 2102 -> 2113
    passed / 8 skipped, 0 regressions.

- [x] **Slice 27 - package-manager supply-chain audit
  (registry trust root)** (https + index-signing landed
  2026-05-31; ENFORCEMENT completed 2026-06-01). A twelfth
  audit pass, this one on the REAL
  package manager `capa/pkg/` (two prior audit briefs
  hallucinated nonexistent module paths `capa/package/`
  and stub `_signing.py` etc. - the real PM is a
  git-vendoring resolver: clone + commit-SHA + optional
  GPG tag verify + optional SLSA, NO artifact digest).
  - **No P0 found.** The GPG core (`_verify_signed_pin`)
    is sound (rejects non-zero, requires VALIDSIG,
    compares full 40-hex fingerprint); the lockfile
    defends moved tags (pre-clone ls-remote check);
    path-traversal / `ext::` / pin-injection are closed
    and tested. Verified by independent code-read + run.
  - **The genuine finding (P1).** The registry index is
    the trust root for the whole `capa add` flow: it
    supplies both the git URL AND the `verify_key` GPG
    fingerprint that anchors every downstream signature
    check. Pre-fix the index was fetched with `http://`
    permitted, `CAPA_REGISTRY_URL` env-overridable, and
    its on-disk cache trusted by mtime with no integrity
    check. A MITM (or cache writer, or env var) swaps URL
    + verify_key in one coherent entry; the GPG layer
    then "passes" against the attacker's own key.
  - **Fixes shipped this slice:**
    1. **https enforced for the index URL**
       (`_ALLOWED_INDEX_SCHEMES = (https, file)`, checked
       in `_load_packages` so it covers arg / env / default).
       `http://` for the index now rejected; git deps may
       still use http (a moved git dep is caught by the
       lock SHA, a swapped index is not caught below it).
       `file://` kept for tests + air-gapped mirrors.
    2. **Detached-GPG index signature verification**
       (`_verify_index_signature`), warn-then-enforce:
       root key unconfigured / signature absent / gpg
       missing -> warn once + continue (FAIL-OPEN);
       signature present but gpg-invalid / no-VALIDSIG /
       wrong-fingerprint -> RegistryError (FAIL-CLOSED).
       Verifies the RAW index bytes before JSON parse, on
       BOTH the network and cache paths, so the
       cache-poisoning vector is closed (a well-formed
       poisoned cache without a valid matching `.asc` is
       rejected - verified independently). Design in
       `docs/design/signed-registry-index.md`.
  - **Enforcement COMPLETED (2026-06-01).** The
    `capa-registry` repo now ships `index.json.asc` (signed
    with the root key `6C1D...A24B`, live on
    raw.githubusercontent.com), `_REGISTRY_ROOT_KEY` is
    baked with that fingerprint, and the missing-signature
    path is fail-closed. Final decision table: valid sig ->
    accept; invalid/mismatched sig -> fail-closed (opt-out
    never applies); missing sig -> fail-closed UNLESS
    `CAPA_REGISTRY_ALLOW_UNSIGNED=1` (explicit escape hatch
    for air-gapped / self-hosted mirrors, covers absence
    only); gpg-not-on-PATH -> warn (environment limit, not
    an attacker vector). Closes the downgrade attack
    (strip-the-.asc). Verified end-to-end against the LIVE
    signed index (real network fetch + signature verify),
    and independently that the opt-out never rescues an
    invalid signature. Registry-side commit:
    `capa-registry@761a58a` (sign index + document trust
    model). Tests updated: name-resolution / search tests
    opt out (they exercise resolution, not signing);
    `TestRegistryIndexSignature` rewritten for the enforced
    semantics (unsigned-with-root now fail-closed; new
    opt-out-resolves + opt-out-does-not-rescue-bad-sig
    cases). Suite 2120 -> 2121.
  - **Audit residuals deferred** (lower severity, in the
    sub-agent report): SLSA verifies a release tarball it
    then discards (not tied to the installed checkout) +
    `--owner`-only scoping; rev-pin lock entries are
    audit-only (silently healed, not enforced) since the
    rev IS the SHA; removing `verify_key` from capa.toml
    silently downgrades a previously-signed dep. All P2 /
    manifest-edit gaps, none remote-escalation.
  - **CLEAN verified**: GPG verify logic, moved-tag lock
    refusal + vendor-not-clobbered, git URL allow-list,
    pin/name option-injection guards, registry version
    gating, no tarball-extract / zip-slip surface (deps
    are git clones).
  - Suite 2098 -> 2102 passed / 8 skipped (3 new skips =
    ephemeral-gpg-keypair on Windows/MSYS, same fragility
    as the 2 pre-existing). `tests/test_pkg.py` 80 -> 84.

- [x] **Slice 26 - lexer/parser audit (integer literal
  overflow)** (closed 2026-05-30). An eleventh audit pass
  (lexer + parser) found one **P1 silent value corruption**
  plus two P3s, and positively verified a large CLEAN set
  (full precedence ladder, literal forms, indentation,
  comments, type grammar).
  - **The bug.** `capa/lexer/_literals.py:_lex_number` used
    Python's unbounded `int()` with no signed-64-bit range
    check. A literal like `9223372036854775808` (2**63) or
    `99999999999999999999999999` flowed untouched through
    the lexer, parser, and analyzer. The Python backend then
    printed it verbatim as an unbounded bignum (silently
    violating the i64 `Int` type) while the Wasm backend
    either wrapped it or failed `wasm-tools parse` with
    "constant out of range". The source said one number; the
    program produced another (or didn't compile on one
    backend only).
  - **The fix.** New `_check_int_magnitude` rejects any
    integer literal whose magnitude exceeds 2**63. The bound
    is 2**63 *inclusive* because the unary minus is a
    separate token, so `-9223372036854775808` (i64::MIN)
    must be reachable as `-(2**63)`. i64::MAX
    (`9223372036854775807`) and i64::MIN via negation both
    still lex cleanly; anything strictly past 2**63 is now a
    clean compile-time error on all four bases (dec/hex/oct/
    bin). Regression tests in `tests/test_lexer.py`.
  - **Residual.** The single value `9223372036854775808`
    used *positively* (not negated) is still accepted at lex
    time (the lexer can't see whether a unary minus
    follows). Narrow edge; a future analyzer-level
    constant-fold pass could catch the non-negated 2**63.
    Noted, not blocking.
  - **Audit P3s deferred.** (1) `_parse_range` docstring
    claims `a..b..c` is a syntax error; it actually parses
    `(a..b)` and leaves `..c` for a generic "expected
    newline" error - caught, but the docstring is
    inaccurate. (2) `_close_type_args` mutates the shared
    `>>` token in place when splitting nested generics
    (`List<List<Int>>`); harmless in the single-pass compile
    path but a latent footgun for any tool that re-parses a
    cached token stream (LSP/formatter/fuzzer).
  - **Test-hygiene note** (out of scope): `tests/test_lexer.py`
    has duplicate `test_int_literal_value` method names;
    Python keeps only the last, so some assertions silently
    never run. Cleanup for a future slice.
  - **CLEAN verified** (next audit can skip): full operator
    precedence + associativity ladder (arith/bit/shift/
    logical/unary/range/postfix-`?`), comparison
    non-associativity enforced, all literal forms
    (int/float/hex/oct/bin/underscore/exponent), string +
    char escapes incl `\u{...}`, interpolation boundary
    cases, indentation (tabs rejected, dedent-mismatch
    rejected, blank/comment lines, paren continuation, EOF
    in block), comments (nested block, EOF, in-string),
    type grammar (`>>` split, Fun types, tuple vs grouping,
    `Foo<>` rejected), assignment-target validation, token
    positions.

- [x] **"Fully functional Wasm" slice 25 - runtime cap-bridge
  audit + handle-table architecture** (foundation closed
  2026-05-30; rollout slices 25.1 - 25.9 all closed by
  2026-05-30). Tenth audit pass; found a **systemic P0** plus
  several lower-severity findings, all since fixed. The
  "fully functional Wasm" arc is complete: every capability,
  the full language surface, and sound cross-function
  attenuation run on both Wasm hosts with output byte-identical
  to Python (verified 2026-06-02).
  - **The systemic P0 (F1).** The Wasm backend's attenuation
    enforcement is **intra-function only**. The emitter
    inlines `restrict_to(...)` checks (`$str_contains`,
    path-prefix WAT) at the literal call site in the same
    function. The moment a restricted cap crosses any `fun`
    boundary, the receiving function sees a plain cap, no
    enforcement code is emitted, and the host bridge runs
    the syscall unconditionally. Verified across **5 caps**
    with cross-function reproducers (Fs, Db, Proc, Env,
    Clock); Net exploitable in principle. Component Model
    bridge has the identical bug. Python backend is sound.
    Downstream demos exposed: `audit-trail-reporter`,
    `policy-eval`, `sbom-watch` all do
    `let read_fs = fs.restrict_to("data/"); run(log, read_fs, ...)`.
    Reach: every regulator-facing `provably_excluded_capabilities`
    claim is **honest at the manifest layer but unsound on
    the Wasm runtime** for any program with cross-function
    attenuation.
  - **The architecture.** Capability values on Wasm become
    i32 handles into a host-side table. Every privileged
    host import takes the handle, looks up the
    Python-side `CapRestriction` object, enforces it, then
    performs the syscall. `main`'s cap params are root
    handles allocated by the host at instance init.
    Restriction-imports (e.g. `capa:host/fs.restrict-to`)
    take a handle, allocate a fresh restricted handle via
    the existing `Fs.restrict_to` etc., return the new
    i32. Full design in `docs/design/wasm-cap-handles.md`.
    Side benefit: closes **F2** (Wasm Net inline check
    uses `$str_contains(url, host)` substring match
    instead of parsed hostname) for free, since enforcement
    now goes through `Net.allows` which uses urlparse.
  - **What this slice (25.1) ships.**
    - `capa/runtime/_cap_handles.py` (NEW): `CapHandleTable`
      class, per-cap allocation helpers
      (`restrict_fs`/`restrict_net`/`restrict_db`/`restrict_proc`/`restrict_env`/`restrict_clock_after`),
      `bootstrap_root_handles` for the host-side root-
      handle setup, type-checked `lookup`. The table
      reuses the existing Python-side cap classes verbatim;
      restriction monotonicity + intersection semantics
      are inherited.
    - `tests/test_cap_handles.py` (NEW, 10 cases): handle
      allocation monotonicity, zero-sentinel rejection,
      type-mismatch rejection, intersection chains for Fs
      and Net, Env case-insensitive canonicalisation
      surviving the round trip, bootstrap_root_handles
      shape.
    - `docs/design/wasm-cap-handles.md` (NEW): full
      architecture + rollout plan + lifecycle.
  - **What slices 25.2 - 25.8 will ship** (each is one
    cap end-to-end against the foundation):
    - **25.2 Fs DONE** (2026-05-30): cross-function
      reproducer denies on both backends.
      `WasmHost` holds a `CapHandleTable`; Fs ops take
      `handle: u32` first param, host enforces
      `fs.allows(path)` before the syscall; new
      `fs.restrict_to(handle, prefix) -> u32` import
      allocates a child handle. Fs is no longer erased
      in CIR -> Wasm (un-erased in `_locals.py`,
      `_closures.py`, `_traits.py`, `_dispatch.py`,
      `_structs.py`, `_values.py`, `_emit_wasm/__init__.py`,
      `_discovery.py`, `_emit_wit.py`); cap-method
      lowering in `_caps.py` short-circuits ahead of
      the old inline-attenuation machinery. New parity
      program `examples/wasm/fs_cross_function_attenuation.capa`
      + `test_fs_cross_function_attenuation`. 7 Component
      Model tests parked with explicit slice-25.8 skip
      markers (CM wrapper still emits fixed
      `world { export main: func(); }` so wasm-tools
      rejects the new main signature).
    - **25.3 Net DONE** (2026-05-30): closes F1 + F2 together.
      Net is no longer erased in CIR -> Wasm (mirrors slice
      25.2 across `_locals.py`, `_closures.py`, `_traits.py`,
      `_dispatch.py`, `_structs.py`, `_values.py`,
      `_emit_wasm/__init__.py`, `_discovery.py`, `_emit_wit.py`);
      Net cap-method lowering in `_caps.py` short-circuits
      ahead of the now-dead inline `$str_contains` machinery
      (kept commented for slice-25.9 cleanup). Host bridge
      delegates to the Python `Net.get` / `Net.post` which
      use `urlparse(url).hostname` + `allows()`: closes F2
      by side effect. New `capa:host/net.restrict-to(handle,
      host) -> u32` import. Two new parity programs:
      `net_cross_function_attenuation.capa` (F1) and
      `net_substring_attack.capa` (F2). Notable: `run_main`
      now parses the wasm `name` custom section to recover
      source-level cap param identifiers (`$fs`, `$net`) so
      the right root handle is routed to each i32 slot;
      single-cap programs that lack a name section fall back
      to Fs. 4 more Component Model tests parked behind the
      same slice-25.8 skip marker.
    - **25.4-25.7 DONE** (Db, Proc, Env, Clock, batched
      2026-05-30): four caps wired through the handle
      table in one slice. Each follows the slice-25.2/25.3
      template verbatim; scope held at ~600 LOC across
      all four caps. Four new parity programs
      (`db_/proc_/env_/clock_cross_function_attenuation.capa`),
      one test method each, all deny on both backends.
      `_wasm_host` bootstraps `_root_db` / `_root_proc` /
      `_root_env` / `_root_clock` lazily; `run_main`'s
      name-section routing dict extended to all six caps.
      All inline-attenuation branches in
      `_emit_one_attenuation` for the now-six-handled caps
      sit dead-with-comment for slice-25.9 sweep. 6 more
      Component Model tests parked behind the
      `_SLICE_25_8_PENDING` marker. **F1 (slice-25 systemic
      P0) is now closed on the core wasm backend for
      every cap with attenuation surface; F2 closed by
      side effect in 25.3.** Component Model is the last
      gap; slice 25.8 unparks it.
    - **25.8 DONE** (2026-05-30): Component Model host
      reaches full parity with the core wasm host on
      cap-handle threading. `capa/ir/_emit_wit.py` now
      walks `main`'s cap-typed params and renders them
      as `export main: func(fs: u32, net: u32, ...)`
      (pure `fun main()` and Stdio-only programs keep
      the trivial `func()` shape). `capa/runtime/_wasm_component_host.py`
      grew its own `CapHandleTable` + lazy `_root_*` +
      handler rewrites: every Fs/Net/Db/Proc/Env/Clock
      handler takes `handle: u32` first, enforces
      `allows()` via the looked-up cap, and the missing
      `restrict-*` handlers were added (previously
      stubbed as no-ops). `run_main` inspects
      `main.type(store).params` from the WIT directly
      (no `name`-section parse needed on CM, the WIT is
      the source of truth). 17 previously-parked CM
      tests now pass; 7 new `_under_cm` parity tests
      cover the cross-function attenuation oracles on
      the Component Model path. Gov pack runs end-to-end
      on `capa --wasm --component --run`. F1/F2 are now
      closed on **both** wasm execution paths.
    - **25.9 DONE** (2026-05-30): swept the dead inline-
      attenuation emitter machinery. Net **-785 LOC**
      removed (~620 in `_caps.py`, ~125 in `_runtime.py`,
      ~90 in `_discovery.py`, ~80 in `_locals.py`). Fully
      gone: `_emit_indirect_with_attenuation_check`,
      `_emit_bool_query_with_attenuation_check`,
      `_emit_clock_with_attenuation_check`,
      `_emit_attenuation_err_into_ret_area`,
      `_ATTENUATION_PRIVILEGED_OPS`, runtime helper
      `$str_contains`, scratch locals
      `$_atten_content_*`/`$_clock_sleep_secs`, the dead
      `attenuations and priv_op` dispatch branches in
      `_emit_cap_method_call`. Stale "inline-check WAT
      present" test inverted to "handle path active, no
      inline check". Kept-because-still-live:
      `MethodCall.attenuations` (consumed by
      `_emit_atten_allows` for the Fs/Env/Db/Proc
      literal-arg `.allows(x)` fast path AND by the
      manifest's `args_flow` field via
      `_build_attenuation_map`); future slice could move
      `.allows()` to the host via per-handle imports,
      not blocking F1/F2.

- **Slice 25 CLOSED** (2026-05-30). Audit slice 25 found
  F1 (systemic cross-function attenuation bypass on
  wasm, all six attenuation-bearing caps) and F2 (Net
  inline check used substring match instead of parsed
  hostname). Both closed across slices 25.1-25.9:
  handle-table foundation + Env case-fix (25.1),
  Fs (25.2), Net (25.3, closes F2 by side effect),
  Db/Proc/Env/Clock batched (25.4-7), Component Model
  parity (25.8), cleanup (25.9). Suite 2061 (slice-25
  audit start) -> 2085 / 5 skipped / 0 fail. F4 (Env
  case-sensitivity) closed in 25.1. F3 / F5 / F6
  documented residuals. The wasm backends (core +
  Component Model) now match the Python backend on
  cap-discipline soundness; the regulator-facing
  ``provably_excluded_capabilities`` claim is honored
  at runtime on **both** wasm execution paths.
  - **F4 closed in this slice.** `Env.restrict_to_keys`
    now case-folds keys on Windows
    (`capa/runtime/_capabilities.py:_canon_key`) so a
    restriction `["NEVER_SET"]` actually denies a lookup
    `env.get("PATH")`: pre-fix the platform's case-
    insensitive `os.environ` was bypassing a
    case-sensitive Python-side allow-list.
  - **F3 (Random reseeding), F5 (Fs lexical vs realpath
    portability), F6 (TOCTOU)** stay as documented
    residuals; F3 is by design (`Random.with_seed`
    docstring acknowledges it), F5 is Wasm being
    stricter than Python (sound, just less portable), F6
    is in the documented threat model.
  - **CLEAN areas verified by the audit**: Fs intersection
    semantics, Net Python intersection, SQLite ATTACH
    blocked via `set_authorizer`, Proc basename+suffix
    check, Fs realpath canonicalisation, stdio
    replacement-char decoding, file-handle lifetimes
    (every Python + Wasm path uses `with open(...)`), db
    connection close, Unsafe trust boundary, wasmtime
    memory-read bounds check.
  - Suite 2061 -> 2071 / 5 skipped / 0 fail.

- [x] **"Fully functional Wasm" slice 24 - CIR lowerer
  audit (block-body lambda implicit-result tail)**
  (closed 2026-05-30). A ninth audit pass on
  `capa/ir/_lower_*` found one **P0 silent Python/Wasm
  divergence** plus several lower-severity findings.
  - **The bug.** A non-Unit lambda with a block body
    ending in an implicit-result expression returned
    `None` on Python and trapped on Wasm:
    ```capa
    let f = fun (x: Int) -> Int =>
        let y = x * 2
        y + 1
    stdio.println("f(3)=${f(3)}")
    ```
    Python: `f(3)=None`. Wasm: `unreachable` instruction
    executed. Two parallel bugs, no parity test caught
    them (both backends honored their respective IRs).
  - **The fix.** Mirror the `match`-arm implicit-result
    rule in both `capa/ir/_lower_expr.py:_lower_lambda`
    (Wasm path) and `capa/transpiler/_expressions.py:_emit_lambda`
    (Python path). New parity program
    `examples/wasm/lambda_block_implicit_result.capa`.
  - **Bonus fix.** `_lower_const_decl` was not resetting
    `self._attenuation_map` across function/const
    boundaries, latent today (consts can't carry caps)
    but broke the per-item state-isolation invariant.
  - **Findings deferred** (separate slices): Unit-
    returning block-body lambda trips Wasm emit "values
    remaining on stack" (pre-existing); tuple-destructure
    `for`-pattern + or-patterns + field-target assignment
    raise `UnsupportedInIR` on Wasm; `_monomorphise`
    Call-instance mutate-share footgun; analyzer
    `unify` infinite recursion when pushing typed-T
    into `var out: List<T>`.
  - **CLEAN verified**: short-circuit ops with side
    effects, `?` operator on Option/Result, interpolation
    eval order, tuple/list literal eval order,
    arithmetic/comparison, sum-match with mixed payload
    arities, alpha-renamed shadowing, lambda value-capture
    parity, monomorphisation, forward refs, map iteration.
  - Suite 2060 -> 2061 / 5 skipped / 0 fail.

- [x] **"Fully functional Wasm" slice 23 - SBOM exporter
  audit (transitive cap reach for CycloneDX + SPDX)**
  (closed 2026-05-29). An eighth audit pass on the
  `capa/manifest/_cyclonedx.py` + `_spdx.py` exporters
  found two **P0 regulator-facing under-disclosure bugs**
  plus several P2/P3s deferred.
  - **The finding.** Slice 21 added the
    `transitively_reachable_capabilities` field to every
    function record; the CycloneDX and SPDX exporters
    were never updated to consume it. The per-function
    `provably_excluded_capabilities` claim was sound at
    the manifest layer but the SBOM dependency graphs
    still showed only the signature-only
    `declared_capabilities` view. A regulator walking
    the dep graph from `main` to discover Stdio reach
    saw nothing for `use_logger(lg: FileLogger)` (the
    audit's slice-21 reproducer); the cap was reachable
    via the impl chain but the graph carried zero edges
    for it.
  - **The fix.** Both exporters now:
    1. synthesise a component/package per built-in cap
       any function in the program transitively reaches
       (`capa:builtin:<file>:Stdio` etc.) so dep edges
       can resolve;
    2. emit a `capa:transitively_reachable_capability`
       property/annotation per function alongside the
       unchanged `capa:declared_capability` (consumers
       can read either view);
    3. widen the per-function dep edges to walk the full
       transitive set, resolving to user-cap refs OR the
       new built-in-cap refs;
    4. extend program-level `dependsOn` to include the
       built-in cap refs.
  - **Regression tests** (`TestCycloneDX::test_transitively_reachable_cap_surfaces_in_cyclonedx`
    + `TestSPDX::test_transitively_reachable_cap_surfaces_in_spdx`)
    lock the FileLogger reproducer end-to-end. Three
    pre-existing tests updated to look up the function
    component by bom-ref/name rather than `components[0]`
    (built-in caps now share the components list).
  - **Audit findings deferred:**
    - **P2 / F4**: provenance attestation (`_provenance.py`)
      doesn't bind the manifest hash to the source hash,
      so a verifier with only the attestation can't tie
      capability claims back to the build. Add a
      `byproducts` entry with `name=capability-manifest`,
      `digest.sha256` of canonical manifest JSON. Future
      slice.
    - **P2 / F6**: schema version doc says "refuse
      unknown" but slice 21+23 added fields without
      bumping. Either bump to 2 or relax the doc to
      "additive fields ignored". Doc/policy call.
    - **P3 / F5**: UUIDv5 derived from basename only;
      two `main.capa` from different projects collide.
      Touch on a project-id story.
    - **P3 / F7**: VEX `@vex(...)` text not cross-checked
      against the post-slice-21 exclusion list, stale
      VEX statements survive into the SBOM. Add a
      cross-check.
    - **P3 / F8**: VEX `bom-ref` keyed on loader-mangled
      name for cross-module non-pub items in standalone
      `--vex` output. Mirror the CycloneDX
      `qualname_display` demangle.
  - **CLEAN areas verified:** `has_unsafe` aggregation
    under transitive Unsafe reach (slice 21 propagates
    correctly through both exporters), per-function
    `provably_excluded_capabilities` value-sequence,
    demangle through to exporters, CycloneDX
    `vulnerabilities[]` shape, SPDXID sanitisation,
    determinism (UUIDv5), strict-mode compliance fields.
  - Suite 2058 -> 2060 / 5 skipped / 0 fail; gov pack
    end-to-end on `--wasm` still works and its CycloneDX
    correctly synthesises the 5 built-in caps it
    reaches (Clock, Env, Fs, Net, Stdio).

- [x] **"Fully functional Wasm" slice 21 - analyzer audit
  + per-impl reachability closure** (audit opened audit-
  only, closed via the per-impl reachability machinery
  same day, 2026-05-29). A seventh audit pass found one
  **P0 manifest-soundness gap**; the closure implements
  the honest fix and updates the regulator-facing tests
  to honest semantics.

  **The closure (per-impl reachability):** new file
  `capa/manifest/_reachability.py` computes, for each
  user-cap and each cap-bearing struct, the set of
  built-in caps values of that type can transitively
  cause to be exercised. Closed-world fixpoint over (a)
  struct field types and (b) the union over all impls of
  each user-cap (impl's struct caps + impl method sig
  caps). A new manifest field
  `transitively_reachable_capabilities` surfaces this
  union (alongside the unchanged signature-only
  `declared_capabilities`); `provably_excluded_capabilities`
  is now computed against the transitive set, so an
  auditor reading the SBOM sees a sound exclusion claim.

  **Honest semantics, demo test updates.** The
  `agent_loop` / `process_request` / `run_chat` demos no
  longer claim Unsafe-exclusion when an in-scope impl
  holds Unsafe in a struct field (AnthropicLlmClient).
  Four tests updated to assert the honest shape: the
  signature surface is unchanged (declared = exactly the
  caps in the function signature), the transitive
  surface adds caps the impls bring along, and the
  exclusion is computed against the transitive set.
  Where Net is reachable through tool impls
  (StubSearch / StubMailer hold `net: Net`), tests no
  longer assert Net is excluded; they assert it's in
  the transitively-reachable set and that RunCode /
  Unsafe stay excluded because no impl in the function's
  reach carries them. The demos' positioning ("discipline
  contains Unsafe to where it lives") is retracted for
  the AnthropicLlmClient case; the honest reading is
  "Unsafe is in the LlmClient's reach via the Anthropic
  impl, surfaced explicitly in the manifest."

  **New regression tests** in `TestPerImplReachability`
  (5 cases) covering the audit reproducer
  (`use_logger(lg: FileLogger)` where
  `FileLogger { out: Stdio }`), the user-cap-trait
  variant, Unsafe-via-impl-field propagation,
  zero-impl-no-extras correctness, and the impl-method
  `self`-carries-wrapped-caps case.

  **Audit P2 closed** (slice 22, 2026-05-29). Analyzer
  now rejects `impl <BuiltinCap> for <UserStruct>` at
  `capa/analyzer/_items.py:_check_impl` with an
  actionable diagnostic pointing the user at the user-
  cap-wrapping pattern. Regression test
  `TestImpl::test_impl_builtin_capability_rejected`
  covers every built-in cap.

  **Audit CLEAN areas** (skip on future passes):
  consuming-cap match/loop merge logic, tuple/struct
  field laundering when struct does NOT impl a user-
  cap, generic instantiation cap-leakage (caught by
  `_reject_cap_leak_via_substitution`), aliasing within
  a call, `Option<Stdio>` construction
  (`_check_no_capability` on variant payloads), let-
  binding a cap from a bare Ident (vs MethodCall), free
  function declaring `-> BuiltinCap` (caught by
  `_check_no_builtin_capability` on return types).

  Suite 2051 -> 2057 / 5 skipped / 0 fail. Gov pack +
  audit-trail-reporter + sbom-watch all still run
  end-to-end on `--wasm`.

  --- Original audit-only entry (superseded by the
  closure above) follows; kept for the design rationale
  it captures. ---
  - **The finding.** A function whose signature includes a
    cap-bearing struct or a user-defined capability claims
    in its `provably_excluded_capabilities` that built-in
    caps not in its signature cannot be reached - but the
    user-cap's impl methods can call into any built-in cap
    the impl's struct holds. Audit reproducer
    `repro9b_factory_launder.capa`:
    ```capa
    type FileLogger { out: Stdio }
    impl Logger for FileLogger
        fun log(self, msg)
            self.out.println(msg)
    fun use_logger(lg: FileLogger)
        lg.log("through logger")  // exercises Stdio
    ```
    Manifest of `use_logger`: declared `[]`, excluded
    `[..., Stdio, ...]`. Runtime: prints "through logger"
    via real Stdio. The claim is false. Same shape with
    `lg: Logger` (the user-cap trait param) instead of the
    struct.
  - **Why no code change in this slice.** The conservative
    fix (downgrade `provably_excluded` to empty whenever
    any param/return touches a user-cap or cap-bearing
    struct) breaks 4 existing tests
    (`test_llm_agent_runner_manifest_agent_loop_excludes_net`
    and friends) because the LLM-agent demo's headline
    regulatory pitch is *exactly* this shape:
    `agent_loop(stdio: Stdio, llm: LlmClient,
    search: SearchWeb, mail: SendEmail)` claims to exclude
    Net/Fs/Env/Unsafe. Under the conservative rule, that
    claim is voided. The demo's claim is structurally
    identical to the audit reproducer - both rely on the
    same kind of reasoning that the audit shows is unsound
    under the current implementation.
  - **The honest fix** is per-impl reachability under
    closed-world reasoning: for each user-cap `T`,
    `reachable(T) = ∪ (caps directly used by impl's
    method bodies + caps held by the impl's struct fields
    + reachable of any user-cap referenced)` over all
    impls of `T` in the program. Then a function param
    `lg: T` implicitly declares `reachable(T)` as an upper
    bound on what the function can exercise; the
    exclusion list is sound if and only if it omits every
    cap in that union. This is **the** semantic that makes
    both the audit reproducer and the LLM demo sound: the
    LLM demo's impls (Mock + Anthropic) carry only Unsafe
    (via `AnthropicLlmClient.u`), and the demo would have
    to either drop the Unsafe-in-Anthropic field or accept
    that Unsafe is in reach (the test would update to
    assert Unsafe NOT in excluded, not Net). FileLogger
    holds Stdio, so `use_logger` would correctly drop
    Stdio from its exclusion list.
  - **Implementation scope** (estimated ~half-session):
    new `capa/manifest/_reachability.py` doing fixpoint
    over (impl-block, struct-field) graph. `_fun_record`
    expands each param's user-cap/cap-bearing-struct ref
    to its reachable set, unions into the declared-set
    used for the exclusion subtraction. Existing LLM demo
    tests update: `test_llm_agent_runner_manifest_agent_loop_excludes_net`
    drops Unsafe from the excluded assertion (Unsafe IS
    reachable via Anthropic impl); other 3 tests similarly
    adjust to the honest claim. New regression test from
    the audit reproducer.
  - **Audit P2 deferred** (not directly exploitable):
    `impl <BuiltinCap> for <UserStruct>` (e.g.
    `impl Stdio for FakeStdio`) is accepted by the
    analyzer. Method dispatch routes through the user
    impl so no actual built-in I/O happens, but it
    pollutes the trust model (Stdio should be a host-
    granted singleton, not user-inhabitable). Reject at
    `capa/analyzer/_items.py:_check_impl` when
    `item.trait_name in CAPABILITY_NAMES`.
  - **Audit CLEAN areas** (skip on future passes):
    consuming-cap match/loop merge logic, tuple/struct
    field laundering when struct does NOT impl a user-
    cap, generic instantiation cap-leakage (caught by
    `_reject_cap_leak_via_substitution`), aliasing within
    a call, `Option<Stdio>` construction
    (`_check_no_capability` on variant payloads), let-
    binding a cap from a bare Ident (vs MethodCall), free
    function declaring `-> BuiltinCap` (caught by
    `_check_no_builtin_capability` on return types).

- [x] **"Fully functional Wasm" slice 20 - loader audit
  (mangled cap names leaking into manifest)** (closed
  2026-05-29). A sixth audit pass (this one on
  `capa/loader.py` + the mangling pipeline) found one
  **P2 regulator-facing surface bug** plus four lower-
  severity issues, all deferred.
  - **The bug.** A non-pub capability defined in an
    imported module (e.g. `capability LocalCap` inside
    `mod_cap.capa`, imported from a root file) had its
    loader-time prefix leak through the manifest's
    regulator-facing fields: `user_defined_capabilities[].name`,
    `user_defined_capabilities[].implementors`, per-param
    `type`, `declared_capabilities`,
    `provably_excluded_capabilities`, and `return_type`
    all rendered as `_capa_m1__LocalCap` / `_capa_m1__LocalImpl`
    instead of the source-level identifier the user wrote.
    Internal fields (`name`, `container`) stay mangled by
    design - they're the stable collision-safe ids that
    bom-ref keying and call-resolution depend on - and a
    sibling `source_name` / `source_container` already
    surfaced the human-readable form. The leak was just
    the cap- and type-typed surfaces missing the same
    demangling treatment.
  - **The fix.** `capa/manifest/_funrec.py` grew a
    `_demangle_type_text` helper (regex sub on rendered
    `_ty_text` strings, anchored at a word boundary) and
    now demangles: every per-param `type` field, the
    return type, the implicit-cap entry, and the
    `provably_excluded_caps` computation (done by
    comparing demangled-cap-names against demangled-
    declared set so the subtraction lives in one
    namespace). The `_funkey.py` upstream collector for
    `user_defined_capabilities[].name` + `[].implementors`
    was demangled in the same slice.
  - **Audit findings deferred** (lower severity, none
    user-facing): same-alias collision when two imports
    share the exact same pub export set (diagnostic
    quality only); cyclic-import re-parses root file
    (wasted work + misleading cycle message); fall-through
    on `getattr(it, "is_pub", False)` for new item types
    (latent); discipline-across-imports CLEAN; path-
    traversal safety CLEAN.
  - New regression test
    `TestSourceNameDemangle.test_imported_non_pub_capability_is_demangled_in_user_surfaces`
    covers every regulator-facing field. Suite 2050 ->
    2051 / 6 skipped / 0 fail. `capa_governance_pack`
    still runs end-to-end on `--wasm`.

- [x] **"Fully functional Wasm" slice 19 - transpiler audit
  (Python closure-over-loop-var capture parity)** (closed
  2026-05-29). A fifth audit pass (this one on the
  `capa/transpiler/` Python emit path) found one **P1 silent
  parity divergence** that no parity test exercised. The
  audit also flagged 5 lower-severity P2 issues, none of
  which were reproducible from realistic source.
  - **The bug.** `for i in 0..N { handlers.push(fun () => i) }`
    on the Python backend produced lambdas that all returned
    the loop's final value (Python late-binding closure
    semantics, `lambda: i` looks up `i` at call time, after
    the loop has finished). The Wasm backend captured each
    iteration's `i` at `MakeLambda` time (the env record is
    allocated fresh per closure construction), so its
    lambdas returned `[0, 1, 2, ...]`. Two backends, two
    different wrong answers; no parity test ever exercised a
    captured loop variable. Caught by the audit.
  - **The fix.** Transpiler's `_emit_lambda` now walks the
    body to collect free variable references that resolve to
    enclosing-scope locals (PARAM / LOCAL / LOCAL_VAR symbol
    kinds, excluding names bound inside the body itself via
    let / var / for / match patterns + nested lambdas'
    params). Each is emitted as a Python default arg:
    `lambda i=i: i`. Default args bind values at lambda-
    creation time, matching Wasm's MakeLambda-time snapshot.
    Reference-typed captures (lists, strings) still share
    the same object, default args bind references, not deep
    copies, same as Wasm capturing the i32 heap pointer.
  - **Audit P2s deferred** (lower severity, all confirmed
    not exploitable from realistic source): `${...}`
    splicing in `_emit_string_lit` is dead code on parser-
    produced ASTs (no production path); Bool-format fallback
    only fires when types dict is missing (production paths
    pass it); inclusive-range Wasm overflow trap (edge case,
    deferred in slice 16); `?` on Option in Result-returning
    fn (analyzer rejects); `new_map` / `new_set` shadow
    (analyzer reserves).
  - **Structural finding**: the auditor noted that every
    per-method lowering in `_methods.py` is hand-written
    Python idiom with no static cross-link to the Wasm
    side; future slice-17-shaped silent divergences will
    keep slipping through unless each method gets a
    deliberate fuzz-style parity test. Flagged for a future
    slice.
  - New parity program `closure_loop_capture.capa` covers
    flat for-loop captures, let-bound captures, and nested
    for-loop captures (i*10 + j across 9 closures). Suite
    2050 -> 2051 / 5 skipped / 0 fail.
    `capa_governance_pack` still works end-to-end on
    `--wasm`.

- [x] **"Fully functional Wasm" slice 18 - manifest soundness
  fix (closure-laundering of capabilities)** (closed
  2026-05-29). A fourth audit (this one on the analyzer /
  manifest builder) surfaced one **P0 manifest-unsoundness
  bug** that directly contradicts Capa's headline regulatory
  claim.
  - **The bug.** Capa's pitch to auditors: "the manifest's
    `provably_excluded_capabilities` is a hard claim, this
    function CANNOT exercise the listed caps, by construction
    of the analyzer's discipline". A program with shape:
    ```
    fun b(f: Fun() -> Unit) { f() }
    fun a(stdio: Stdio) {
        let leak = fun () -> Unit => stdio.println("LEAKED")
        b(leak)
    }
    ```
    type-checks, runs, and prints "LEAKED". Pre-fix the
    manifest claimed `b` provably-excluded every cap including
    Stdio, but Stdio IS exercised through `b`. The type
    system does not track captured caps inside `Fun(...)` (a
    lambda + a plain function both have the same type), so
    the analyzer can't tell which caps a closure value
    carries; any function accepting / returning a `Fun(...)`
    could be invoked with a closure carrying any cap the
    caller has in scope.
  - **The fix.** New `_contains_fun_type(t)` helper in
    `capa/manifest/_strings.py` walks a `TypeExpr` recursively
    (through `TypeName` generics + `TupleType` + `FunType`
    itself) to detect embedded `Fun(...)`. The manifest
    builder downgrades `provably_excluded_capabilities` to
    `[]` whenever the function's signature (any parameter
    type OR return type, transitively) contains a `Fun(...)`.
    Same machinery `Unsafe` already used, both are "we can't
    honor the claim, so don't make it" cases.
  - **Audit triage (3 P0 claimed; only #1 confirmed real).**
    - **P0 #1 (closure laundering)**: confirmed, fixed this
      slice.
    - **P0 #2 (var of cap reassigned)**: NOT exploitable.
      Verified: `var alias: Stdio = stdio` is rejected at
      the `var` binding step ("capability cannot appear in
      a 'var' binding"); the factory path is also blocked
      ("capability cannot be constructed at a call site" +
      "capability cannot appear in return type"). The
      language-level guards block the path before the
      alias-reassignment code is reached.
    - **P0 #3 (struct cap-field smuggle via impl method)**:
      NOT exploitable. Verified: `let m = SmtpMailer { net:
      net }` is rejected ("capability 'SmtpMailer' cannot
      appear in a 'let' binding"). Without the let-binding
      there's no way to obtain a cap-bearing struct value
      to invoke `.send()` on (return is also blocked).
  - **Audit P1 / P2 deferred**: no transitive call-graph
    cap-flow check (P0 #1 above closes the most acute case);
    attenuation chain not tracked by analyzer (documented
    out-of-scope; runtime enforces); cap-field of cap-bearing
    struct can carry unrelated cap fields (would need
    analyzer rule); pattern-arm duplicate detection skips
    variants-with-payloads (no security impact).
  - 4 new regression tests in `TestIneligibilityProofs`:
    `test_fun_param_voids_proof`, `test_fun_return_voids_proof`,
    `test_nested_fun_voids_proof`, `test_no_fun_in_sig_still_proves`.
    Suite 2046 -> 2050 / 5 skipped / 0 fail.
    `capa_governance_pack` still works end-to-end on `--wasm`.

- [x] **"Fully functional Wasm" slice 17 - String.length +
  String.substring switched to code-point semantics on Wasm**
  (closed 2026-05-29). A third audit pass (this one on the
  Python runtime, `_safety.py` + older capability code)
  surfaced one **P0 silent-divergence bug** that the parity
  test suite had been masking because every parity program
  uses ASCII strings: Wasm's `String.length` returned the byte
  count, Python's returned the code-point count; same for
  `String.substring` indices (bytes vs code points). The two
  backends produced different output on any non-ASCII input
  but the parity tests never exercised one. A Capa program
  computing `"abcé".substring(0, 4)` returned `"abcé"` on
  Python and the broken UTF-8 `"abc\xC3"` on Wasm.
  - **Fix**: two new WAT runtime helpers in `_runtime.py`:
    - `$str_codepoint_count(p, l) -> i32` walks the byte
      slice counting non-continuation bytes.
    - `$str_cp_to_byte_offset(p, l, cp_idx) -> i32` returns
      the byte offset of the cp_idx-th code-point boundary
      (or `l` if past the end).
  - `_emit_string_length` calls `$str_codepoint_count`;
    `_emit_string_substring` translates both indices to byte
    offsets via `$str_cp_to_byte_offset` before the
    `memory.copy`. Bounds check now compares against the
    code-point count (not the byte length).
  - Discovery walker gains `_uses_string_codepoint_index`
    (recurses into `MakeLambda.body` and match-arm
    `guard_setup` so a closure-body or match-guard call to
    `.length()` still flips the gate). New `$_str_cp_count`
    scratch local declared with the other String scratch
    locals.
  - **Other audit findings deferred** (lower severity or
    documented intentional): `_capa_shl` overflow-trap policy
    difference with Wasm (P1, intentional fail-loud);
    `int_range(low > high)` Wasm-side handling (P1, separate
    Wasm-side fix); empty-frozenset fail-open in
    `Fs/Db/Proc.allows` (P2, only reachable via direct
    construction); `Clock._not_before = NaN` poisoning (P2,
    fail-closed so safe); `to_json` on NaN/Inf raises
    ValueError (P2, standard JSON doesn't support either);
    `Some.map` vs `and_then` semantic (?, intentional per
    Rust convention).
  - New parity program `string_unicode.capa` covers
    2/3/4-byte code points and every substring boundary;
    would silently diverge on the pre-fix Wasm backend.
    Suite 2045 -> 2046 / 5 skipped / 0 fail.
    `capa_governance_pack` still matches Python byte-for-byte.

- [x] **"Fully functional Wasm" slice 16 - older-Wasm-code audit
  pass (3 real bugs fixed)** (closed 2026-05-29). A second
  audit (slice 10 covered slices 4-11; this one covered
  Phase 6A-6E) surfaced three bugs in code that had been
  stable for months because no test exercised the exact
  shape. Two would have crashed the wasm verifier on first
  real use; the third was a security-shaped bounds-check
  bypass that Python's runtime caught but Wasm's did not.
  - **P1: Float captures in lifted lambdas crashed the wasm
    verifier.** `_emit_make_lambda` wrote Float env entries
    with `i64.store` (from `_store_op_for_size(8)`), the
    matching capture load in `_push_value` used `i64.load`,
    both type-mismatch the f64 operand. A program like
    `let factor = 1.5; let scale = fun (x: Float) -> Float
    => x * factor; scale(2.0)` failed compile on Wasm. Fix:
    Float-specific branches in both halves use `f64.store` /
    `f64.load`. Existing closure tests never captured a
    Float, which is how the bug survived.
  - **P1: `Set<Float>` crashed the wasm verifier.** The
    scalar-needle stash in `_emit_set_stash_needle` set the
    f64 push into the i64 scratch (`local.set
    $_alloc_tmp_i64`); the compare in `_emit_set_compare_at`
    used `i64.eq` on the bit pattern (which would have also
    given NaN-equal-to-NaN, opposite of Python). Fix: new
    `$_alloc_tmp_f64` scratch declared on `has_set_method`,
    Float-specific branch in both halves uses `f64.eq`. The
    NaN fix is a bonus: both backends now agree on
    `float('nan') != float('nan')`.
  - **P1 security: negative-i64 list indices whose low 32
    bits wrapped in-bounds silently returned `xs[0]`.** The
    bounds check in `_emit_index` / `_emit_list_get` wrapped
    the i64 to i32 before checking, so `-2**32 =
    0xFFFFFFFF_00000000` wrapped to 0, passed the unsigned
    compare, and returned the first element. Python's
    `_capa_list_get` raises `IndexError`. Fix: validate
    `0 <= idx < len` at i64 width BEFORE wrapping; only
    wrap once we know the value fits. New `$_bounds_idx_i64`
    scratch. The pre-fix comment ("the unsigned compare
    catches negative indices") was right for most negatives
    but missed the cases whose low 32 bits land in `[0,
    len)`. A real attacker-controlled index computation
    could trigger this; the trap-style `xs[i]` path now
    traps and the `List.get(i)` path returns `None` on the
    full range of negative i64s.
  - **Findings deferred** (lower severity, marked ? by the
    auditor): nested-tuple emit fallthrough (P2; no demo
    nests tuples this way), `String.replace` count*delta
    overflow (P2; needs attacker-controlled massive input),
    `String.split` empty-separator garbage read (P2; pre-
    existing low-value), `JsonValue.as_int` trap on large
    floats (P2; edge case), `for i in 0..=i64::MAX`
    infinite loop (P2; edge case), trait method stack leak
    on dst=None+non-Unit (P2; not reachable in current
    surface).
  - New parity program `audit_float_and_index.capa`
    exercises all three fixes; would crash compile or
    silently diverge on the pre-fix backend. Suite 2044 ->
    2045 / 5 skipped / 0 fail. `capa_governance_pack` on
    pure `--wasm` still matches Python byte-for-byte.

- [x] **"Fully functional Wasm" slice 15 - `Proc` capability v1
  (sandboxed subprocess, basename-prefix attenuation)** (closed
  2026-05-29). `Proc` moves from documented-stub
  (`_StubCapability("Proc")`) to a fully functional capability
  across all three backends (Python, core Wasm, Component Model).
  - **Surface** (3 methods, mirrors `Db` v1):
    - `restrict_to(cmd_prefix: String) -> Proc` - intersect-style
      attenuation
    - `allows(cmd: String) -> Bool` - membership query
      (inline-attenuation at emit time, D4 Option B)
    - `exec(cmd: String, args_json: String) -> Result<String,
      IoError>` - runs `subprocess.run(argv, capture_output=True,
      timeout=30, shell=False)` with `json.loads(args_json)` as
      the argv tail. Returns captured stdout in the Ok arm;
      non-zero exit / timeout / malformed argv JSON / denial
      surface as Err. Reuses the existing
      `result<string, io-error>` wire shape so no new
      canonical-ABI materialiser is needed.
  - **Attenuation rule**: basename + suffix-boundary check
    (not path-prefix like Fs/Db). `restrict_to("git")` admits
    `git` and `git-lfs` (a git plugin) but rejects `gitlab`;
    a fully-qualified `/usr/bin/git` still gates against
    `restrict_to("git")` because the basename normalisation
    (Python's `os.path.basename`, Wasm's `$proc_allows` helper)
    runs before the compare.
  - **Backend wiring**: Python runtime uses `subprocess.run`
    per call (cap is stateless). Wasm host bridge mirrors
    exactly (`_register_proc` in both core and CM hosts,
    self-contained `_alloc_utf8` / `_write_result_*` helpers).
    WIT signatures land alongside the existing
    `result<string, io-error>` shapes.
    `_emit_indirect_with_attenuation_check` gained a Proc
    branch (two-String args, same shape as Db.exec / Net.post).
    `_emit_one_attenuation` gained a `cap == "Proc"` branch
    that emits a call to the new `$proc_allows` runtime helper
    rather than reusing the path-prefix machinery.
  - **New runtime helper**: `$proc_allows(cp, cl, pp, pl) ->
    i32` in `_runtime.py`. Walks the command string from end
    to start to find the last `/`, extracts the basename, then
    AND-checks `basename == prefix OR
    basename.startswith(prefix + '-')`. Single helper covers
    both Proc.exec attenuation enforcement and Proc.allows
    dynamic-arg path. Gated on a new `needs_proc_allows` flag
    threaded out of `_uses_attenuation_check` as a third
    return value.
  - **Component Model**: `_wasm_component_host._register_proc`
    parallels the core bridge; the WIT signature uses
    `args-json` (kebab-case) per WIT identifier rules. Works
    under `--component --run`.
  - **Verification**: new parity program
    `examples/wasm/proc_demo.capa` shells out to `python -c
    "print('hello')"` (deterministic output, present on every
    CI matrix entry) and covers unrestricted exec, scoped
    pass, scoped deny, and Proc.allows on both arms.
    Registered in `_PARITY_PROGRAMS` (core parity) and
    `_CM_HOST_BRIDGE_SUBSET` (CM parity). Suite 2042 -> 2044 /
    5 skipped / 0 fail.

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
- 2026-05-15: **Tier 1 complete**: SBOM diff tool, SPDX 2.3
  emission, VEX integration, SLSA Build L1 provenance.
- 2026-05-15: **Tier 2 complete**: `docs/regulatory.md`
  covering CRA + NIS2 + DORA + NIST SSDF + OWASP SCVS.
- 2026-05-15: Tier 3, provenance signing workflow.
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
- 2026-05-25: **`capa_http` v0.1.3**: vendor-aware sys.path
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
