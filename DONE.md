# Capa, DONE (completed work)

> **Convention.** When an item in [`TODO.md`](TODO.md) is completed, it
> moves to the top of the matching section here with its completion date
> (`YYYY-MM-DD`). This file is the internal task record (distinct from
> [`CHANGELOG.md`](CHANGELOG.md), which records user-facing releases).
> [`TODO.md`](TODO.md) holds only what is still open; everything already
> shipped lives here.

This is the full historical record of completed work, organised by
category with dates, most-recent first within each section. The
[`CHANGELOG.md`](CHANGELOG.md) carries the per-release reasoning and the
advisories under [`docs/advisories/`](docs/advisories/) carry the
security detail.

Status legend (preserved from the original roadmap): `[x]` done ·
`[~]` partially shipped, with the remaining slice now tracked as a
pending item in [`TODO.md`](TODO.md).

---

## NLnet empirical study (2026-06-18)

The headline NLnet deliverable: a two-part empirical study of the
per-function capability SBOM, under
[`evaluation/empirical_study/`](evaluation/empirical_study/).

- **Breadth (head-to-head).** 25 hand-built Python / Capa pairs, four
  treatments (T1 dependency SBOM, T2 Semgrep, T2b CodeQL 2.25.6, T3 Capa),
  scored by one per-function `(function, capability)` fact across two
  questions. **Q1 (positive attribution): a clean three-way tie at the
  top** -- Capa and CodeQL both attribute 38/48, Semgrep 36/48; Capa does
  not see more than the best dataflow tool. **Q2 (false-clearance under
  closed-world SBOM semantics): Capa = 0/48**, against CodeQL 10/48,
  Semgrep 12/48, and the dependency SBOM 48/48. The separation is in Q2,
  it holds against the strongest real dataflow tool, and the ten
  dispatcher facts CodeQL silently clears are the ones Capa reports as
  *not-determined* rather than clearing.
- **Depth (richness + scale + concentration).** Two real enterprise Capa
  programs measured from their actual emitted manifest in
  [`evaluation/empirical_study/depth/`](evaluation/empirical_study/depth/):
  `capa_paymentguard` (PCI core, 70 functions) and `capa_claimdesk`
  (claims engine, 213 functions). No Python equivalent exists, so this is
  deliberately not a tool comparison. Measured: **88-94 % of functions
  provably pure**, no sensitive axis held by more than **4.3 %** of
  functions (data for the positioning-doc concentration claim), and
  **625 / 2,295 sound provably-excluded `(function, capability)` facts**
  that no dependency SBOM expresses. A genuine in-the-wild dynamic
  dispatch (`render_report` over a `Reporter` trait object) is present
  and typed soundly; it is benign here because all three reporter impls
  are pure. A v1.5.2 regeneration finding (claimdesk's app-side selective
  `import capa_csv.model` collides with the vendored library's
  whole-module import of the same module) is recorded honestly in the
  depth README.

Follow-up still open: consolidate both halves into the paper (paper
&sect;5). The depth harness reads only committed manifests, so it is
deterministic and CI-safe.

## Security arc (2026-06-16 .. 2026-06-18)

The deepest hardening window to date: a six-axis adversarial review
(~25 real findings) followed by four releases and an infrastructure
sweep.

### Consolidated supply-chain trust model page (2026-06-18)

- **Created [`docs/trust-model.md`](docs/trust-model.md)**, a single
  honest page for a sceptical supply-chain auditor that consolidates what
  was spread across `SECURITY.md`, `docs/packages.md`,
  `docs/regulatory.md`, and the advisories. It separates the
  **unconditional / fail-closed** guarantees (SBOM claims by construction
  with the conservative `provably_excluded` note, lockfile-SHA retag
  catch, GPG anchored on the primary key, PKG-1 vendor re-verification,
  signed registry index, byte-reproducible SBOMs) from the **best-effort
  / fail-open** SLSA L2 layer (graceful-skip on missing `gh` / tarball /
  non-GitHub host; M4 `verify_provenance="required"` not yet a default)
  from the **TCB premises** (committed `capa.lock`, local git state of
  `vendor/`, the toolchain itself, install.sh M3, operator-trusted
  `CAPA_PATH` / `./libraries`) from what is **outside the threat model**
  (`Unsafe` escape hatch, microarchitectural timing, trust-anchor
  compromise). Each line is checkable against the code. Linked from
  `README.md`, `SECURITY.md`, and `docs/packages.md`. Closes the
  short-term TODO consolidation item.

### Stalled-demo revalidation against v1.5.1 (2026-06-18)

- **Revalidated the three stalled downstream demos (`sbom-watch`,
  `policy-eval`, `audit-trail-reporter`) against compiler v1.5.1.** All
  three last ran on 2026-05-23, predating the four security releases
  (laundered-`Unsafe`-in-cap-bearing-struct rejection, secret-dependent
  compare in `@constant_time`, field-access through an abstract
  capability receiver, `@secret` var-reassign warning, and the PKG-1
  fail-closed vendor-vs-lock verification). All three came up clean with
  no changes required: each passes `capa --check` on its entrypoint
  (`watch.capa`, `policy_eval.capa`, `reporter.capa` respectively),
  runs end-to-end via `capa --run` on its bundled sample data, and is
  PKG-1-coherent (every vendored git-dep HEAD matches its `capa.lock`
  `commit` and every vendor working tree is clean). No security bit-rot:
  none of the demos used any of the now-rejected anti-patterns, so no
  honest-model rewrite was needed. No PKG-1 drift and no compiler
  regression surfaced. No demo commits were made (nothing to change);
  each repo's tree stayed clean (generated reports are gitignored).

### Documentation reconciliation (2026-06-18)

- **Reconciled the documentation with the real v1.5.1 state.** The
  compiler `README.md` advertised 2593 tests and four seed libraries; the
  real numbers are 3080 tests and eight published libraries
  (`capa_cli`, `capa_csv`, `capa_datetime`, `capa_hash`, `capa_http`,
  `capa_log`, `capa_sbom`, `capa_test`). Updated the README metrics and
  switched the volatile test count to durable round-down phrasing
  (`3000+ tests`) so it stays true across commits without per-release
  maintenance; the seed-library table now lists all eight. The website
  (separate repo) carried the same drift: the test count moved to
  `3000+` across `index.html`, `start.html`, `community.html`, and
  `roadmap.html`, and the stale `v1.2.0` current-state version was
  refreshed to `v1.5.1` (page colophons plus the index / roadmap /
  regulatory / compare narrative). This item also covered the original
  TODO/DONE split itself, the first practical application of the
  TODO->DONE convention those files declare.

### Security review (2026-06-16/17)

- **Six-axis adversarial security review.** A full review across six
  adversarial axes surfaced ~25 real findings spanning capability
  attenuation / enforcement, information-flow and constant-time,
  capability encapsulation, manifest / SBOM integrity, supply-chain
  trust roots, and build-time vendor verification. The findings drove
  v1.4.0, v1.4.1, v1.5.0, v1.5.1 and the infra sweep below. Advisory:
  [`docs/advisories/2026-06-17-security.md`](docs/advisories/2026-06-17-security.md).

### v1.4.0 (2026-06-16/17): 8 security findings fixed

- **Proc basename->identity RCE.** `Proc.restrict_to` now fixes the
  binary identity, not just the basename, closing the RCE vector.
- **Db `..`-traversal.** `Db.allows` canonicalises through `realpath`
  before the boundary check.
- **IFC variable-reassignment leak.** `x = secret` now joins the RHS
  label onto the target in the default tier too, closing the silent
  laundering hole.
- **`@constant_time` secret-compare.** A `@constant_time` function now
  rejects a short-circuiting secret string / list compare (CWE-208).
- **`Unsafe` hidden in a cap-bearing struct.** Rejected now; the
  `Unsafe` rejection walks parameter types recursively on Wasm.
- **`provably_excluded` under-declaring user caps.** No longer
  over-claims via a cap-bearing struct, a nested field, or a
  sum-variant payload (direct + nested + sum-variant payload).
- **Provenance / SBOM digest covered only the root file.** The
  provenance / SBOM digest now covers all modules and demangles
  `sel__`; single-file SBOM identifiers restored to historical values.
- **GPG verify anchored on the primary key**; `file://` traversal
  (literal + percent-encoded `%2e%2e`) rejected; the registry index
  fails closed when unverifiable; `Db` post-open TOCTOU re-validates the
  kernel true path (narrow residual recorded in `TODO.md`).
- Commits `1f645e0`, `dcf47af`, `77ee0c5`, `3cdb421`, `30e66e3`,
  `2b6ee0f`, `de16b21`, `9369f11`, `909959c`. Advisory:
  [`docs/advisories/2026-06-17-security.md`](docs/advisories/2026-06-17-security.md).
  Three new rejections under the security exception: `@constant_time`
  secret-compare, `Unsafe` in a cap-bearing struct, field access through
  an abstract-cap / trait receiver.
- **`parse_int` many-digit DoS** closed (commits `1f645e0`, `dcf47af`):
  screens significant-digit count and returns `None` before
  `int(body)`, matching the Wasm `$parse_int`.
- **`Random` documented as non-cryptographic** (commit `de16b21`):
  SplitMix64 documented as not cryptographically secure in
  `docs/stdlib.md` and the `Random` docstring; registry TOFU anchoring
  documented in `docs/packages.md`.

### v1.4.1 (2026-06-17): POSIX regression fix

- **Proc separator-detection POSIX fix.** Fixed a regression where
  `Proc`'s separator detection hit the `os.altsep is None` trap, which
  broke `restrict_to` on a bare command name on Linux/macOS.

### v1.5.0 (2026-06-17): PKG-1 build-time vendor verification

- **PKG-1: re-verify `vendor/` against `capa.lock` at build time.**
  `capa build` / `check` / `run` now re-verify vendored dependencies
  against the lockfile (HEAD == locked commit AND a clean working tree,
  plus in-place-edit detection), fail-closed by default with an explicit
  `CAPA_NO_VERIFY` opt-out. Closes the prior gap where only `capa
  install` verified vendored content.

### v1.5.1 (2026-06-18): package self-reference resolution

- **Package self-import resolution in `capa --check` / `--run`.** Brought
  to parity with `capa test` (commits `5c0a126`, `0d08acc`). A package
  that imports itself now resolves under `--check`/`--run` as it already
  did under `capa test`.

### Infrastructure hardening (2026-06-18)

- **GitHub Actions pinned by commit SHA across all 12 ecosystem repos.**
  Removed the floating-tag trust root from every workflow, including the
  release channel (compiler pinning commit `6c97187`).
- **CI GPG gate anchored on a pinned primary-key fingerprint** (validated
  on a real Ubuntu runner), with a template-appropriate variant
  (derived `fpr`) in `cra_template`.
- **Compiler pinned by SHA in the CRA / governance packs.**
- **PKG-1 Phase 0:** `capa.lock` committed in `capa_csv`, `capa_hash`,
  `capa_claimdesk`; `capa_showcase` converted from gitlinks to
  vendor+lock (local-only by design).

### Optional-dependency refresh (2026-06-18)

- **Refreshed optional Python deps** (pytest / hypothesis / matplotlib /
  wasmtime) and raised the `wasmtime` floor from `>=20` to `>=45`
  (commit `6c3f0fe`); ran `pip-audit` (0 CVEs in Capa's dependencies).

---

## June 2026 releases + six-axis bug hunt (v1.1.0 .. v1.4.0)

Concise record; full reasoning in [`CHANGELOG.md`](CHANGELOG.md) and the
advisories under [`docs/advisories/`](docs/advisories/).

**Releases (real tag dates).**
- **v1.1.0** (2026-06-14): first minor since 1.0. Byte-reproducible
  SBOMs / attestations via `SOURCE_DATE_EPOCH`, `String.bytes()`,
  builtin `panic(message)`, `capa test` (with `--both`), `capa migrate`,
  `[dev-dependencies]` + `capa add --dev`, Wasm tail-call optimisation,
  typestate completed.
- **v1.2.0** (2026-06-15): hardens the soundness core and closes parity
  gaps. New feature: selective import with renaming
  (`import foo (a, b as c)`), resolving `pub` name collisions between
  dependencies. Six soundness fixes (see the 2026-06-15 advisory).
- **v1.3.0** (2026-06-16): completes Python / Wasm parity, closes five
  more soundness holes, hardens the frontend and the package manager. No
  new language features (see the 2026-06-16 advisory). Includes Wasm
  `parse_float` scientific notation: `$parse_float` on Wasm became a
  correctly-rounded decimal-to-f64 conversion bit-identical to CPython
  `float()` (commit `782a0d2`), the last numeric cross-backend
  divergence.
- **v1.4.0** (2026-06-17): a window of localised audit findings across
  capability attenuation / enforcement, information-flow and
  constant-time, capability encapsulation, manifest / SBOM integrity,
  and supply chain (detailed in the Security arc section above). No new
  language features (see the 2026-06-17 advisory).

**New language / tooling features in this window.** Selective import
with renaming; `capa test` (`--both` for cross-backend parity) and
`capa migrate` subcommands; `[dev-dependencies]` + `capa add --dev`;
builtin `panic`; `String.bytes()`; byte-reproducible SBOMs via
`SOURCE_DATE_EPOCH`.

**The rigorous six-axis bug hunt and what it closed.**
- *Soundness (IFC).* `@secret` label now survives a `match` / `if`
  value and a capturing closure, intra-function and cross-function (a
  captured-secret closure invoked-and-sunk through a HOF).
- *Soundness (linear affinity).* Double-consume closed via alias
  (`let h2 = h`) and via a closure captured-and-reinvoked; the
  must-consume obligation now moves on an aliasing `let` / `var`.
- *Soundness (manifest).* `provably_excluded_capabilities` no longer
  over-claims when a `Fun` is hidden in a struct field or a sum-variant
  payload; `declassification_sites` counts only genuine secret
  declassifies.
- *Cross-backend parity, now complete.* Correctly-rounded
  decimal-to-f64 `parse_float` (oracle-first, `tools/float_ref.py`);
  `1 << 63` and any out-of-window left shift trap on Wasm; `String`
  order operators, a Unit-payload binder and Unit-returning bind on
  Wasm; `String.split("")` traps; ASCII-only `to_upper` / `to_lower`
  on both backends; canonical `parse_int` and `to_json` number forms.
- *Frontend robustness.* Clean diagnostics for over-long int literals,
  deep flat expression chains (no `RecursionError`), and extra / leading
  whitespace tokens inside `${...}`.
- *Package-manager quality (7 fixes).* `capa add --force` over an
  inline dep, git-URL host option-injection, escaping path deps,
  divergent re-import of a module, loader-mangled names in diagnostics,
  `@vex` soft-validation against the CycloneDX vocabulary.

Three soundness / security advisories published:
[`docs/advisories/2026-06-15-soundness.md`](docs/advisories/2026-06-15-soundness.md),
[`docs/advisories/2026-06-16-soundness.md`](docs/advisories/2026-06-16-soundness.md),
and
[`docs/advisories/2026-06-17-security.md`](docs/advisories/2026-06-17-security.md).

**Ecosystem.** 8 seed libraries published on the signed registry
(`capa_cli`, `capa_datetime`, `capa_http`, `capa_log`, `capa_sbom`,
`capa_test`, `capa_csv`, `capa_hash`); the enterprise showcase
`capa_claimdesk` published (exercises the whole language, with its
guarantees proved in the SBOM); `capa_paymentguard` and
`capa_cra_template` carry byte-for-byte reproducibility.

---

## High-impact within positioning (P1)

- [x] **Wasm float-to-string byte-exact via Dragon4 fallback**
  (closed 2026-06-10, commit `a1a4abd`). A stdlib-parity audit
  found the Grisu shortest-digit path could diverge from Python
  `repr` on the rare inputs where Grisu cannot prove the result
  is shortest. Closed by porting a Dragon4 limb-bignum fallback
  to WAT that runs whenever Grisu declines, so Wasm float
  formatting is now BYTE-EXACT with Python `repr` across the
  curated corpus. Validated against the Python reference at
  `tools/float_ref.py` (oracle-first). A follow-up
  (`233304d`) fixed two further Wasm silent-divergence bugs the
  same audit surfaced.

- [x] **Loud-error Wasm stdlib gaps closed** (closed 2026-06-10,
  commit `83777cb`). The same parity audit found a set of stdlib
  methods that raised on the Wasm backend while working on
  Python. All now implemented with Python parity: `List.first` /
  `last` / `find` / `find_index` / `sorted_by` (stable merge
  sort), `Range.length` / `contains` / `is_empty` / `to_list`,
  and `Net.allows`. With this batch and the Dragon4 fix above,
  the Wasm backend has NO known silent divergences from the
  Python reference.

- [x] **Security audit medium / low / informational hardening**
  (closed 2026-06-10). The 2026-05-25 audit's remaining
  medium / low / informational findings were triaged and either
  hardened or honestly documented. SECURITY.md was refreshed to
  1.0 and the 2026-05-25 audit marked as remediated (`7846b4b`);
  the medium / low findings were hardened (`2ea7740`), with two
  parser depth-cap fixes alongside (`a0fc2f0`, `0cba6f7`). An
  em-dash / en-dash cleanup of the Python source landed in the
  same window (`7780006`). Two findings are deferred by design:
  M3 (install.sh same-channel SHA) and M4
  (`verify_provenance="required"` default).

- [x] **Feasibility studies: async/await + native LLVM backend,
  both DEFERRED** (closed 2026-06-10, commit `2934da4`). Wrote
  `docs/design/async-feasibility.md` and
  `docs/design/llvm-backend-feasibility.md`. Both are DEFERRED
  with a concrete trigger rather than left as vague far-future
  items. LLVM trigger: a perf-bound consumer the Wasm-AOT
  sandbox provably cannot serve, or a native-FFI requirement.
  async trigger: a real I/O-bound workload plus GC, with the
  explicit caveat that async reopens the mechanised
  noninterference proof. Do NOT re-propose starting either
  without such a driver.

- [x] **Wasm generics + traits parity (2026-06-08)** (closed
  2026-06-08). A completion arc that takes the Wasm backend
  from demo-surface generics/traits to full parity with the
  Python backend across the parity corpus. Suite went from
  ~2350 to 2372 passed / 8 skipped / 9 subtests, CI green.
  Landed in order:
  - `a5bc5ac` - top-level non-i64 consts now pushed in the
    correct calling shape (a String const is pushed as
    ptr/len, including String struct-field initializers).
    Aggregate consts stay a loud error rather than silently
    miscompiling.
  - `e43e112` - trait-typed receiver method calls resolve the
    method's declared return type for both the `capability`
    and the `trait` keyword receivers, so non-i64 returns are
    stored in the correct shape. Multi-impl traits raised a
    precise loud error at this point (lifted by `7688c0d`).
  - `7abd609` - generic methods on generic types: impl blocks
    are specialised per instantiation for generic structs AND
    generic sums.
  - `af2fe1c` - generic struct/sum literals are monomorphised
    inside control-flow blocks (if/else, for, while, and match
    arms), not just at top level.
  - `d3dda27` - refactor: the monomorphiser is split into a
    package (`_typestr` / `_functions` / `_types` / `_calls`).
    Pure structural move, public API unchanged.
  - `24b0825` - core generics gaps closed: generic struct
    literal types are annotated before call-site inference so
    generic free functions over generic structs resolve their
    monomorphised callee; full rewrite of nested generic sum
    payload types and inner match-arm binders.
  - `7688c0d` - multi-impl trait dynamic dispatch via a
    per-concrete-type type-id header plus an if-chain (struct
    impl targets). The trait value stays a single i32 pointer
    (no fat pointer).
  - `7927ad2` - SUM types usable as multi-impl trait targets;
    the type-id moved to a uniform offset (4) shared by struct
    and sum participants.
  - `0938d16` - trait-typed values usable as Option/Result
    payloads, Map values, List elements, tuple components, and
    struct fields (recognised as i32 pointer-shape in the
    uniform-slot encoders).
  - `3236fbe` - structural equality of trait values dispatched
    by runtime type-id (`==`/`!=`, and trait-as-value equality
    inside List/Option/Result/Map/tuple/struct). Also hardened
    the parity inventory gate to require an executing test per
    parity program, which recovered 3 latent untested programs.
  Remaining honest limit: a trait used as a Map KEY or a Set
  ELEMENT stays a precise loud error. This mirrors a Python
  hashability divergence (a struct dynamic type is hashable but
  a sum dynamic type is not), so it is a by-design boundary
  rather than a gap. The website was updated to reflect this arc
  and the test count bumped to 2372 (commit `aed6a32` in that
  repo).

- [x] **Compiler bugs surfaced by capa_governance_pack stress
  test 2026-05-26** (closed 2026-05-27). All five findings
  from writing the first real-world ~900-LOC downstream
  Capa program
  ([nelsonduarte/capa_governance_pack](https://github.com/nelsonduarte/capa_governance_pack)):
  1. **MEDIUM. Variant name collision shadows built-in
     `Result::Ok`.** Fix: hard-ban `Ok` / `Err` / `Some` /
     `None` as user-declared variant names with an actionable
     diagnostic suggesting alternatives. New
     `_RESERVED_VARIANT_NAMES` constant + small if-block in
     `capa/analyzer/_declarations.py`. Five regression tests in
     `TestReservedVariantNames`. Full suite 1775 / 5 skipped /
     0 fail.
  2. **LOW (cosmetic). Formatter v3 orphans trailing `//` on
     `match` arm body.** Root cause: `MatchArm` is an `A.Node`
     but not `A.Stmt` / `A.Item`. Fix: new
     `_enclosing_match_arm_on_line` short-circuit in
     `_attach_trailing`; `_emit_match_arm` now calls
     `_emit_trailing(arm)` for both single-line arm shapes.
  3. **LOW (cosmetic). Formatter v3 glues `// =====` divider
     to `///` doc block.** Fix: `_emit_item` inserts one blank
     line whenever the item has BOTH a non-empty leading
     comment block AND a `///` doc string, via a generic
     `_item_doc(item)` helper.
  4. **LOW (diagnostic clarity). Top-of-file `///`
     diagnostic.** Three "doc comments are not valid on X"
     messages (`import`, `const`, `impl`) in
     `capa/parser/_items.py` rewritten to name the `///` syntax
     and suggest the `//` alternative.
  5. **OBSERVATION. `--cyclonedx` emits mangled cross-module
     non-pub names.** Fix: new `_demangle` helper in
     `capa/manifest/_funrec.py`; the function record now carries
     `source_name`, `source_container`, and
     `source_module_index` alongside the loader-time `name` /
     `container`. The CycloneDX and SPDX emitters display
     `source_name` and surface the import index as a property /
     annotation. Verified end-to-end on capa_governance_pack
     (`still-mangled: 0` across 40 components). 5 regression
     tests. Full suite 1783 / 5 skipped / 0 fail.

- [x] **Wasm backend: FormatStr on arbitrary user struct types**
  (closed 2026-05-24). Design decision: opt-in Display protocol
  rather than auto-derive. A struct that declares
  `fun to_string(self) -> String` in an impl block opts in; both
  backends honour the method consistently (`${value}` ->
  `value.to_string()` rewrite at emit time). Structs without it
  keep prior behaviour: `--python` falls through to dataclass
  repr; the Wasm emitter raises a `WasmEmissionError` pointing
  the user at the protocol or at field-specific interpolation.
  Auto-derive rejected (reproducing Python's dataclass repr
  byte-for-byte would be months of brittle work). 4 new
  `TestWasmStructToStringDisplay` cases. Suite 1345 -> 1349.

- [x] **CIR coverage gap** (closed 2026-05-24, Wasm-side guards
  2026-05-25). CIR now lowers 46 of 46 analysable examples.
  Match-arm guards landed for the IR + Python side (captured ANF
  prelude into `MatchArm.guard_setup`, inlined back into a single
  `case PAT if EXPR:` clause; inlineable shapes: `FieldAccess`,
  `Index`, `UnaryOp`, `BinOp`; non-inlineable shapes raise
  `UnsupportedInIR` and fall back to the legacy transpiler). The
  Wasm emitter supports guards via a flat-block-with-labeled-exit
  restructure (Bool / String / sum / tuple scrutinees; nested-
  variant + guard arms raise a precise WasmEmissionError). Suite
  1296 -> 1299 (IR) -> 1488 (Wasm).

- [x] **Property-based testing for the Wasm backend** (closed
  2026-05-24). `tests/test_properties.py` Phase 4 mirrors Phase
  3's split: a basic strategy plus an advanced-flavours strategy
  exercising plain / attenuated / via_helper / consumed call
  shapes through the lowerer and Wasm emitter. Citable invariant:
  `wasm_runtime_classes ⊆ manifest_classes`. Suite 1295 -> 1296.

- [x] **Empirical study at scale** (closed 2026-05-26). Target
  reached at the upper bound: 20 library pairs, all `--check`
  + `--cyclonedx` + `--run` green, end-to-end harness +
  summary at [`evaluation/sbom_diff/`](evaluation/sbom_diff/).
  Final aggregates: **122 total functions (73 pure / 49 with
  caps); 6 distinct cap axes (Clock, Env, Fs, Net, Random,
  Stdio); 61 per_fn_info_bits** ((function, capability)
  declaration facts that have no counterpart in a PURL SBOM).
  Axis-alone coverage matrix complete for the 5 Capa-exposed
  transliterable axes; pair-combination matrix covers Fs+Env,
  Fs+Clock, Fs+Net, Net+Clock, Env+Clock, Random+Clock, plus the
  Fs+Env+Net triple. Four design-pattern CVE case studies in
  `examples/cve_*.capa` + `docs/cve_*.md` (PyYAML, Jinja2 SSTI,
  lxml XXE, pickle) anchor the bug-class taxonomy.
  Slices 1-5 (all 2026-05-26) built the corpus incrementally:
  Slice 1 scaffold (config_loader, dotenv, slugify); Slice 2
  (tabulate, http_retry, ini_loader, short_uuid, textwrap);
  Slice 3 (env_loader, log_forwarder, rate_limiter, glob_walker,
  humanize) which also surfaced + fixed a typer-vs-transpiler
  Int-division mismatch (`/` now emits `//` when both operands
  are Int; 6 regression tests in `TestIntegerDivision`); Slice 4
  (url_fetch, disk_cache, csv_parser, pathspec, colorama) which
  completed the axis-alone matrix and surfaced + fixed a lexer
  bug (`\033` octal escape now rejected with an actionable
  message; 3 regression tests); Slice 5 (session_token,
  secret_rotator) to hit the upper target. Reproduce via
  `.venv/Scripts/python -m evaluation.sbom_diff.harness &&
  .venv/Scripts/python -m evaluation.sbom_diff.summary`.

- [x] **Formatter v3, AST round-trip** (closed 2026-05-26).
  v1 (line-level) and v2 (intra-line spaces / comma fixup) are
  the safe textual fallback. v3 adds expression re-emission from
  the AST and `//` comment preservation through the AST
  round-trip. `format_source` defaults to v3 with graceful
  fallback to v1+v2 on lex / parse / emit failure.
  Phase 1: lexer sidecar for plain comments (`CommentKind`,
  frozen `Comment` dataclass, `lexer.comments`). Phase 2:
  `CommentMap` side-table keyed by `id(node)` at
  `capa/formatter/_comments.py` with four slots; design locked in
  `docs/formatter-v3-comment-map-design.md`. Phase 3: AST
  pretty-printer at `capa/formatter/_emit.py` + per-category
  emitters (1431 LOC total), 66 tests in
  `tests/test_pretty_printer.py` covering structure, the
  parse->emit->parse roundtrip invariant on 71 corpus files, and
  byte-exact idempotence. Phase 4: `format_source` defaults to
  the AST roundtrip with two CommentMap fixes (block-aware
  file-header heuristic; token-aware end offsets in
  `_build_node_index`). Corpus idempotence 71/71. Full suite
  1730 passed / 5 skipped / 0 fail. Downstream `sbom-watch`
  smoke verified.

- [~] **Test-coverage review.** Stays incremental; the June 2026
  bug hunt added many targeted cases as it closed soundness /
  parity holes (suite reached 2965 passed / 15 skipped / 1
  xfailed / 1658 subtests during that window). The per-module
  passes:
  - 2026-05-25 (1): `capa/runtime/_wasm_component_host.py`
    0% -> 74% via 4 `TestWasmComponentHost` cases.
  - 2026-05-25 (2): `capa/loader.py` 60% -> 65% via 7 cases
    (`TestQualifiedCallShadowing` + `TestLoaderErrorFormat`).
  - 2026-05-24 (3): `capa/ir/_emit_wasm/_match.py` 43% -> 86% via
    13 `TestWasmMatchEmission` cases; surfaced and fixed two
    soundness bugs (top-level IdentPat catch-all on Bool / Tuple
    declared the binder i64 instead of i32; `$str_eq` not
    auto-imported for a tuple-match sub-pattern String compare).
    `capa/loader.py` 69% -> 93% via 6
    `TestPrivateRenameWalkerCoverage` cases. Suite 1299 -> 1318.
  - 2026-05-24 (4): `capa/lsp/server.py` 12% -> 97% via 27 cases
    (`TestLspServerHandlersInProcess` drives every feature handler
    via the pygls feature map). Suite 1318 -> 1345.
  - 2026-05-26 (5): `capa/repl.py` 30% -> 87% via 32
    `TestReplInProcess` cases.
  - 2026-05-26 (6): `capa/cli.py` 10% -> 77% via 56
    `TestCliInProcess` cases driving `main()` in-process. Suite
    1528 -> 1584.
  - 2026-05-26 (7): `capa/manifest/_strings.py` 56% -> 100% via 50
    `TestManifestStringHelpers` cases.
  (The remaining incremental coverage work continues organically
  alongside feature/bug work; not tracked as a discrete pending
  item.)

- [x] **CycloneDX / SPDX parsers, pending optional fields**
  (closed 2026-05-26). Three parser examples
  (`examples/spdx_parser.capa`, `examples/spdx_tag_parser.capa`,
  `examples/cyclonedx_parser.capa`) cover the JSON-schema surface
  of SPDX 2.3 and CycloneDX 1.5 plus the SPDX tag-value
  serialisation. Writeup at
  [`docs/sbom-parsers.md`](docs/sbom-parsers.md) explaining the
  `parse_*` (typed AST) vs `validate_*` (semantic checks) split.
  Progress journal (all 2026-05-25/26): SPDX `annotations[]`;
  CycloneDX `vulnerabilities[]` + VEX `analysis` subset;
  CycloneDX `services[]` + data-flow; SPDX
  `hasExtractedLicensingInfos[]`; CycloneDX evidence; SPDX
  `snippets[]`; CycloneDX JSF signature; SPDX
  `externalDocumentRefs[]`; CycloneDX `externalReferences[]`
  (39-entry type enum); CycloneDX `compositions[]`; the SPDX
  tag-value text-format parser as a new self-contained example.
  Each locked by new `assertIn` lines on the parser tests.

- [x] **SBOM-capability audit example, structural policies**
  (closed 2026-05-25). `examples/sbom_capability_audit.capa`
  carries a `Policy.structural: List<StructuralRule>` field
  alongside the per-function `rules` map. Each rule pins a
  capability to a list of allowed containers; every declared
  capability is checked against every matching structural rule
  independently of the per-function allow-list. Missing
  `structural` is treated as an empty list. Locked by
  `TestTranspileExamples::test_sbom_capability_audit`.

- [~] **Workshop paper revision.** Draft v1 (~5000 words) is
  local-only. Revision pass 2026-05-26 incorporated the closed
  20-pair SBOM-diff study (abstract phrase, §5.3 rewritten to a
  132-line quantitative section, §8 future-work item removed).
  Paper now at v1.9 in `docs/paper-draft.md` (gitignored,
  local-only per commit `900318e`). Remaining (now in
  [`TODO.md`](TODO.md)): LaTeX conversion on venue submission,
  2027 work.

- [x] **Wasm Float formatting: bit-identical with Python
  `str(float)`** (closed 2026-05-25). The legacy fixed-6-decimal
  `$ftoa` replaced by a pure-WAT port of Grisu2 in
  `capa/ir/_emit_wasm/_runtime.py` (five new helpers +
  rewritten `$ftoa` handling NaN / inf / -0 and dispatching
  decimal vs scientific per Python's `n = len(digits) + K` rule).
  Faithful to the validated Python reference `grisu2_ref.py`
  (21/21 curated). Bonus fix: `_emit_unaryop` for `-` on Float
  now emits `f64.neg`. New 31-case `TestWasmFtoaParity`;
  `json_demo.capa` promoted to `_PARITY_PROGRAMS`. Suite 1432, 0
  regressions.

- [x] **`JsonValue.as_int` parity** (closed 2026-05-25). Wasm
  `_emit_jv_as_int` mirrors Python's `JsonValue.as_int`: wrap an
  i64 truncation only when `f64.trunc(v) == v`, else None. New
  `_alloc_tmp_f64` scratch; 3 regression tests in `TestWasmJson`.

- [x] **Capability-discipline hole C: generic instantiation
  re-check** (closed 2026-05-25). New
  `_reject_cap_leak_via_substitution` in
  `capa/analyzer/_discipline.py` fires when a capability appears
  in the substituted parameter or return type and was not there
  pre-substitution. `id(stdio)` and `wrap(stdio)` now fail;
  explicit cap params keep working. 5 tests in
  `TestCapLeakViaGenericInstantiation`.

- [x] **Audit 2026-05-25 follow-up sweep** (closed 2026-05-25).
  Six findings from `security-audit.md` closed: C1 dependency-name
  path-traversal at install time (`b21dd73`); H1 capability hole D
  (`022cb13`, `consume(box.cap)` + `box.cap.use()` rejected); H2
  git tag/rev pin validation (`47bbdc4`); H3 lockfile pre-check via
  `git ls-remote` (`0d57139`); H4 100-level depth cap on the
  bundled JSON parser (`3752972`); H5 SPDX/CycloneDX required
  license/copyright fields (`2570eec`). C2 (Wasm `Fs.restrict_to`
  no-op) closed in `2a2f566` via compile-time inline checks
  (intra-function scope; cross-function chains rely on the
  analyzer's static discipline check). 11 new
  `TestWasmAttenuationEnforcement` tests; suite 1463 -> 1472.

---

## Adoption-moving (P2)

- [x] **LLM tool-use demo** (2026-05-23 landed at
  [nelsonduarte/capa_agent_demo](https://github.com/nelsonduarte/capa_agent_demo)
  v0.1.0). Four-tool agent harness in ~400 lines of Capa, talking
  to the real Anthropic Messages API. Attenuated capability
  wrappers (`ReadOnlyFs`, `GetOnlyHttp`) keep the LLM's blast
  radius statically bounded; even total prompt-injection cannot
  escape because the compiler refuses the call. Live-verified
  against `claude-haiku-4-5`. Tagged v0.1.0 with the full
  three-layer supply-chain stack (signed tag + SLSA L2
  attestation in Sigstore Rekor).

- [x] **LSP server v2 polish** (closed 2026-06-10). v1 covers
  diagnostics, hover, go-to-definition, find-references,
  documentSymbol, code actions, rename, completion, semantic
  tokens. Polish pass 2026-05-26 added documentHighlight,
  foldingRange, and formatting / rangeFormatting. The remaining
  v2 surface landed 2026-06-10: signatureHelp, inlayHint,
  workspace/symbol (`473b367`), codeLens (capability surface per
  function, shown inline) and selectionRange (`4cd4844`). The
  full LSP feature set is shipped.

- [x] **REPL v2** (closed 2026-05-27). MVP re-ran everything per
  input; v2 adds incremental state + readline / history.
  Slice A: readline-style editing + persistent history at
  `~/.capa_repl_history` (pyreadline3 fallback on Windows). Slice
  B: in-process `exec()` replaces the subprocess path (~100x
  speedup, ~1.2ms/turn; POSIX gets a SIGALRM hard timeout,
  Windows does not). Slice C: persistent namespace + incremental
  execution via `transpile_repl`; full re-analysis retained each
  turn deliberately (microseconds, enforces capability
  discipline). Suite 1827 / 5 skipped / 0 fail.

- [x] **VSCode marketplace publication** (published + live
  2026-06-03). `nelsonduarte.capa-language` v0.8.0 is live on the
  VS Code Marketplace. Grammar covers the full current surface
  (typestate / IFC / linear / constant-time). A first-party
  bundled LSP client remains a follow-up.

- [~] **Migration path from Python** (slice 1 closed 2026-05-27,
  slices 2 + 3 closed 2026-06-10). Interop is one-way via
  `Unsafe`; the gradual-hardening pattern shipped
  (`examples/migrate_logfetcher_step{1,2,3}` +
  `docs/migration.md`). `capa migrate <file>` (`capa/migrate.py`)
  reports % Unsafe-free, removable-`Unsafe` detection, and
  next-candidate ranking; `--json` for CI. Slice 2: transitive
  removable detection over the module call graph + a first-class
  non-fatal warnings channel (the dead-Unsafe nudge as its first
  lint). Slice 3: multi-file aware report (per-file totals +
  file_ranking); surfaced + fixed a manifest bug (an imported
  function's `pos` stamped the root file's name). The `capa
  migrate` subcommand shipped in v1.1.0; all three slices done.
  Remaining (the deferred website "Migrating from Python"
  chapter) is website work, tracked in the website repo.

- [x] **Package manager + minimal registry** (closed 2026-05-27).
  Core install flow ships (`capa.toml` + `capa install` +
  `capa.lock` + SLSA L2 verify). `capa add <name> --git <url>
  [...]` edits `capa.toml`, validates the git URL through the
  install-path allow-list, then installs unless `--no-install`
  (`capa/pkg/_add.py`, 10 tests). Minimal registry landed:
  [nelsonduarte/capa-registry](https://github.com/nelsonduarte/capa-registry)
  with an `index.json` mapping `<name>` to git URL + `verify_key`
  + `latest`. `capa add <name>` without `--git` resolves via
  `capa/pkg/_registry.py::resolve_name` (urllib fetch,
  `CAPA_REGISTRY_URL` override, `~/.capa/` cache with 1-hour TTL +
  stale-cache fallback, version gating, URL re-validation). 7
  registry tests. Full suite 1805 / 5 skipped / 0 fail. The
  three-layer trust model is unchanged. Remaining (not blocking,
  ecosystem-growth): `capa search`, `capa publish`, third-party-
  namespace governance.

- [~] **Debugger integration.** Statement-level source maps landed
  2026-05-27 (transpiler records a `python_line -> Capa Pos` map;
  `capa --run` rewrites a runtime traceback with a `Capa
  traceback` summary; `capa/_debug.py` `_rewrite_traceback`, 7
  tests). Caret snippets landed 2026-05-27 (`file:line:col` + the
  offending source line + a `^` caret). **Still pending** (now in
  [`TODO.md`](TODO.md)): per-expression granularity and a real
  stepping DAP adapter.

- [x] **Analyzer performance benchmarks** (closed 2026-05-25). New
  runner at `benchmarks/compile_bench.py` measures lex / parse /
  analyse wallclock on three synthetic programs (10 / 100 / 1000
  functions). Plain text by default, `--markdown` for docs.
  Baseline on Windows 11 / CPython 3.14: small ~3.5ms, medium
  ~55ms, large ~450ms. Does not gate CI; a reproducible bar so a
  future O(n^2) pass surfaces in a manual run.

---

## Type-system extensions (shipped)

- **Linear handles for resources** (must-call types). SHIPPED
  (S1): `linear type` + `consume self`, `_live_linear` tracking,
  `linear_obligations` in the SBOM. Closes the resource-leak bug
  class.
- **Information Flow Control (IFC).** SHIPPED (S2): two-point
  `@public`/`@secret` lattice, join propagation, secret-by-default
  `env.get`, secret-to-sink enforcement (warn-then-enforce,
  `@strict_ifc`), `declassify(value, reason)` recorded as
  `declassification_sites`, implicit-flow under strict, and
  anti-laundering through aggregates + mutable containers.
  Cross-function inference SHIPPED (modular sink-reaching-parameter
  inference to a fixpoint over the call graph). Per-field precision
  SHIPPED (per-struct-field label maps with a conservative
  escape/alias boundary). Mechanised noninterference SHIPPED: an
  Agda proof of termination-insensitive noninterference for the
  `lambda_if` core calculus (declassify-free fragment) -
  `proofs/CapaIF.agda` + `proofs/CapaNoninterference.agda`, checked
  under `--safe`. Per-field follow-ups SHIPPED (cross-function
  field-write effect summaries; embed-then-mutate staleness closed
  via alias-group linkage). Remaining (v2): the fidelity gap
  between the model and the Python analyzer is argued informally; a
  differential fidelity harness is planned.
- **Typestate / session types.** SHIPPED (S3.1-S3.5, both
  backends): state in the type (`typestate Name` + `Name[State]`),
  linear value, state-exact compatibility; construction +
  `become(value, State)`; SBOM `typestates` + `protocol_states`
  count; Wasm parity (S3.3); fields/payload (S3.4); state-specific
  methods `impl Type[State]` (S3.5). **S3 COMPLETE.**
- **Constant-time markers for crypto.** SHIPPED (S4, analyzer):
  `@constant_time()` rejects secret-dependent control flow,
  secret-indexed memory access, and variable-time arithmetic;
  surfaced as a per-function `constant_time` SBOM flag. COMPLETE
  (a Wasm-emitter check was considered and dropped: the analyzer is
  the single inescapable enforcement point).
- **Tail-call optimisation.** SHIPPED (Wasm backend): `return f(x)`
  lowers to `return_call` via an emitter peephole; constant-stack
  recursion (1M-deep verified). Not optimised: the expression form
  `return match n { ... }`.

---

## Wasm-specific gaps closed (not P0)

- [x] **GAP-2b: dynamic-prefix `.allows()` attenuation parity via the
  host-route** (2026-06-19; shipped in v1.6.0). The `.allows(arg)` query
  on `Fs` / `Db` / `Net` / `Proc` / `Env` now routes through the
  authoritative host function (the `Clock.allows` pattern) instead of a
  guest-side inline check. The inline check crashed on a dynamic
  (non-literal) `restrict_to` prefix/key for `Fs` / `Db` / `Net` /
  `Proc` and diverged silently for `Env`; routing through the host
  restores Python/Wasm parity for attenuation with a dynamic argument
  and aligns the query with the binding enforcement (`realpath` for
  `Fs` / `Db`), closing the lexical-query divergences for `Proc` / `Db`
  / `Net` from the 2026-06-17 security audit. The three orphaned
  guest-side runtime helpers (`$str_starts_with`, `$str_has_slash`,
  `$proc_allows`) were dropped. Parity fixture
  `examples/wasm/allows_dynamic_prefix_parity.capa`. The companion
  `self`-in-lambda gap was already closed in v1.5.2 (below); broader
  parity beyond the `_PARITY_PROGRAMS` subset remains open in `TODO.md`.

- [x] **`self`-in-lambda field parity inside an impl method**
  (2026-06-18). A lambda defined inside an `impl` method that captures
  `self` and reads or writes one of its fields used to fail loud on
  the Wasm backend ("FieldAccess on receiver of type 'Unknown': no
  struct layout known") while the Python backend ran it correctly: the
  lifted lambda's `self` capture carried its concrete type only in the
  lift's env layout, which the field emitter never consulted. The Wasm
  emitter now resolves the captured receiver's struct layout from that
  env layout, restoring byte-identical output; the read and write
  paths share one receiver-layout resolver. Covers field read and
  in-place mutation (`self.n = self.n + 100`), multiple fields,
  self+local capture, a doubly-nested lambda, and an Int field. Parity
  fixture `examples/wasm/self_in_impl_lambda.capa`; shipped in v1.5.2.

- [x] **Bug-hunt batch: cross-backend parity, soundness, Wasm
  patterns** (2026-06-03). Integer `/` now floors on both backends
  and both trap on `MIN / -1`; unary integer negation traps on
  `i64::MIN`; float division by zero traps on Wasm; a value `match`
  must be exhaustive; `break` / `continue` inside a lambda rejected;
  `String.index_of` returns a code-point offset on Wasm; `Set<Float>`
  equality no longer crashes Wasm; a user `parse_int` / `parse_float`
  shadows the builtin on both backends; a `Bool` reached through a
  tuple index interpolates as `true` / `false`. Wasm match patterns
  gained identifier-binding catch-alls in sum matches, float-literal
  patterns, binding-free or-patterns, and struct patterns.

- [x] **Tuple indexing typed at the root** (2026-06-03). A constant
  tuple index `t[k]` resolves to the k-th element type; a constant
  out-of-range index is now a compile-time error; a nested tuple
  index `t[0][1]` no longer emits invalid Wasm. Parity program
  `examples/wasm/tuple_nested_index.capa`.

- [x] **Char type on the Wasm backend** (2026-06-03). A Capa Char is
  a single-codepoint String; the Wasm path normalises the Char type
  token to String in the lowered CIR before emission, reusing all
  String machinery. Wasm-only normalisation: the manifest still
  reports Char and the analyzer keeps Char and String distinct.
  Parity examples `char_basics.capa`, `match_char_lit.capa`.

- [x] **Generic struct/sum monomorphisation on the Wasm backend**
  (2026-06-03). A generic field whose type is the type parameter
  mis-decoded when the instance crossed a function boundary. The
  Wasm path now specialises each generic struct/sum per concrete
  instantiation before emission. Parity program
  `examples/wasm/generic_struct_field.capa`.

- [x] **Or-patterns that BIND on the Wasm backend** (2026-06-03).
  `Pos(n) | Neg(n) -> n` now works with Python parity (OR-of-tags
  predicate then per-alternative tag dispatch into shared bind
  locals). Still loudly unsupported: an alternative whose payload is
  a nested non-identifier pattern. Parity program
  `examples/wasm/match_or_bind.capa`.

- [x] **Security: capability-leak hole D closed** (2026-06-03). The
  hole-C cap-leak guard was not applied to the struct-literal path
  (`Box { value: stdio }`) or the variant-constructor path
  (`Wrap(stdio)`). The analyzer now runs the same substitution check
  after both; legitimate generic code is unaffected.

- [x] **One-command reproduction harness for the paper's §5
  numbers** (2026-06-03). New `evaluation/reproduce.py` regenerates
  the section-5 measurements in a single command; §5 baselines
  re-anchored to current measurements.

- [x] **Roadmap P3 (partial) - 2^63 residual closed; constant-fold
  deliberately skipped** (2026-06-02). A bare `9223372036854775808`
  (2**63) used positively was a real silent divergence; the analyzer
  now rejects `IntLit == 2**63` unless it is the immediate operand of
  unary `-`. Constant-fold NOT implemented (measured decision:
  Cranelift already folds downstream, no measurable gain). Suite
  2145 -> 2149.

- [x] **Roadmap S1 - linear (must-consume) types** (landed
  2026-06-01). A `linear type Foo { ... }` value must be consumed
  before it leaves scope. New `KW_LINEAR` token; `consume self`
  parses; new `capa/analyzer/_linear.py` mixin (`_live_linear`
  tracking, branch fork/merge by UNION of surviving obligations);
  SBOM per-param `is_linear` + per-function `linear_obligations`.
  Known MVP limits documented (diverging-branch drop, plain-ident
  aliasing, destructuring). 12 new tests. Suite 2133 -> 2145.

- [x] **Roadmap P1 - Wasm AOT (`capa build --release` +
  `capa run-aot`)** (landed 2026-06-01). Serialise the
  wasmtime/Cranelift module instead of JIT-compiling on every
  `--run`. New `capa/runtime/_aot.py` (CPAO container: magic + JSON
  header carrying `main`'s param names + wasmtime version + the
  cwasm). `WasmHost.run_main_aot` deserialize path sharing
  `_invoke_main` with `run_main`. CLI `capa build --release` +
  `capa run-aot`. Build->run-aot output byte-identical to
  `--run --wasm` (verified with attenuated Fs+Net params).
  Version-mismatch fails closed. 12 tests in `tests/test_aot.py`.
  Suite 2121 -> 2133.

- [x] **Slice 30 - CLI driver robustness audit** (closed
  2026-06-01). Fourteenth audit pass on `capa/cli.py`. P1-a: token
  dump crashed on redirect (cp1252 console) - `main()` reconfigures
  stdout/stderr to UTF-8 with `errors="replace"`. P1-b: non-UTF-8
  file raised a raw traceback - now caught, clean message, exit 2.
  P2-b: an out-of-range `--wasm-memory-cap` wrote an invalid `.wasm`
  as success - now validated `1 <= cap <= 65536`. Regression tests
  in `TestCliRobustness`. Suite 2116 -> 2120.

- [x] **Slice 29 - documented-residual cleanup** (closed
  2026-06-01). Closed three P3s: `_close_type_args` mutated the
  shared `>>` token in place (now copies + `dataclasses.replace`);
  `_parse_range` docstring corrected; `lsp/semantic_tokens.py`
  emitted codepoint units where the protocol wants UTF-16 (now
  `_utf16_len`). Suite 2113 -> 2116.

- [x] **Slice 28 - LSP robustness audit** (closed 2026-06-01).
  Thirteenth audit pass on `capa/lsp/`. P0: UTF-16 vs codepoint
  column mismatch corrupted the buffer on rename - now routes every
  inbound position and outbound Position/Range/TextEdit through
  pygls's `PositionCodec`. P1: `RecursionError` escaped the parse
  guards - guards broadened. Residual (P3, documented):
  `semantic_tokens` codepoint deltas. `tests/test_lsp.py` 174 ->
  185; suite 2102 -> 2113.

- [x] **Slice 27 - package-manager supply-chain audit (registry
  trust root)** (https + index-signing 2026-05-31; enforcement
  2026-06-01). Twelfth audit pass on `capa/pkg/`. No P0 found. P1:
  the registry index is the trust root (supplies git URL +
  `verify_key`); pre-fix it allowed `http://`, was env-overridable,
  and its cache was trusted by mtime. Fixes: https enforced for the
  index URL; detached-GPG index signature verification on both
  network and cache paths (cache-poisoning closed). Enforcement
  completed: the registry ships `index.json.asc`, the root key is
  baked, missing-signature is fail-closed unless
  `CAPA_REGISTRY_ALLOW_UNSIGNED=1`. Verified end-to-end against the
  live signed index. Registry commit `capa-registry@761a58a`.
  `tests/test_pkg.py` 80 -> 84; suite 2098 -> 2121 across the slice.

- [x] **Slice 26 - lexer/parser audit (integer literal overflow)**
  (closed 2026-05-30). Eleventh audit pass. P1: `_lex_number` used
  Python's unbounded `int()` with no i64 range check, so
  `9223372036854775808` flowed through and the backends diverged.
  Fix: `_check_int_magnitude` rejects magnitude > 2**63 (inclusive
  bound so `-(2**63)` = i64::MIN is reachable). Residual: positive
  bare 2**63 still accepted at lex time (closed later, 2026-06-02).
  Two P3s deferred (later closed in slice 29). CLEAN set verified
  (precedence ladder, literal forms, indentation, comments, type
  grammar).

- [x] **"Fully functional Wasm" slice 25 - runtime cap-bridge audit
  + handle-table architecture** (foundation 2026-05-30; rollout
  25.1-25.9 all closed by 2026-05-30; CLOSED 2026-05-30). Tenth
  audit pass; found a systemic P0 (F1: cross-function attenuation
  bypass on Wasm across all six attenuation-bearing caps) and F2
  (Net inline check used substring match instead of parsed
  hostname). The architecture: capability values on Wasm become i32
  handles into a host-side table; every privileged host import
  looks up the `CapRestriction` object, enforces it, then performs
  the syscall. New `capa/runtime/_cap_handles.py` (`CapHandleTable`)
  + `docs/design/wasm-cap-handles.md`. Rollout:
  - 25.1 foundation + Env case-fix (F4: `Env.restrict_to_keys`
    case-folds on Windows).
  - 25.2 Fs, 25.3 Net (closes F2 by side effect; `run_main` parses
    the wasm `name` section to recover cap param identifiers),
    25.4-25.7 Db/Proc/Env/Clock batched.
  - 25.8 Component Model parity (`_emit_wit.py` renders cap params
    as `export main: func(fs: u32, ...)`; the CM host grew its own
    `CapHandleTable`; 17 previously-parked CM tests now pass).
  - 25.9 cleanup: swept the dead inline-attenuation machinery
    (-785 LOC). F1/F2 now closed on BOTH wasm execution paths. F3
    (Random reseeding), F5 (lexical vs realpath), F6 (TOCTOU) stay
    as documented residuals. Suite 2061 -> 2085 across the slice.

- [x] **"Fully functional Wasm" slice 24 - CIR lowerer audit
  (block-body lambda implicit-result tail)** (closed 2026-05-30).
  Ninth audit pass. P0: a non-Unit lambda with a block body ending
  in an implicit-result expression returned `None` on Python and
  trapped on Wasm. Fix mirrors the match-arm implicit-result rule in
  both `_lower_lambda` and `_emit_lambda`. Bonus: `_lower_const_decl`
  now resets `_attenuation_map` across boundaries. Parity program
  `lambda_block_implicit_result.capa`. Suite 2060 -> 2061.

- [x] **"Fully functional Wasm" slice 23 - SBOM exporter audit
  (transitive cap reach for CycloneDX + SPDX)** (closed
  2026-05-29). Eighth audit pass. P0: the slice-21
  `transitively_reachable_capabilities` field was never consumed by
  the CycloneDX/SPDX exporters, so the dep graphs showed only the
  signature-only view. Both exporters now synthesise a
  component/package per reachable built-in cap, emit a
  `capa:transitively_reachable_capability` property/annotation, and
  widen the per-function + program-level dep edges. Regression tests
  lock the FileLogger reproducer. Several P2/P3 deferred (provenance
  manifest-hash binding, schema-version policy, UUIDv5 basename
  collision, VEX cross-check + bom-ref demangle). Suite 2058 ->
  2060.

- [x] **"Fully functional Wasm" slice 21 - analyzer audit + per-impl
  reachability closure** (closed 2026-05-29). Seventh audit pass.
  P0 manifest-soundness gap: a function whose signature includes a
  cap-bearing struct or user-cap claimed exclusions for built-in
  caps the user-cap's impl methods can actually reach. Closure: new
  `capa/manifest/_reachability.py` computes, for each user-cap and
  cap-bearing struct, the transitive built-in caps it can exercise
  (closed-world fixpoint); a new
  `transitively_reachable_capabilities` field surfaces the union and
  `provably_excluded_capabilities` is computed against it. Demo tests
  updated to honest semantics (the AnthropicLlmClient Unsafe case is
  retracted). 5 cases in `TestPerImplReachability`. Audit P2 closed
  (slice 22): `impl <BuiltinCap> for <UserStruct>` now rejected.
  Suite 2051 -> 2057.

- [x] **"Fully functional Wasm" slice 20 - loader audit (mangled cap
  names leaking into manifest)** (closed 2026-05-29). Sixth audit
  pass. P2: a non-pub capability defined in an imported module had
  its loader-time prefix leak through the regulator-facing manifest
  fields. Fix: `_demangle_type_text` helper in
  `capa/manifest/_funrec.py` demangles every per-param `type`,
  return type, implicit-cap entry, and the `provably_excluded_caps`
  computation; `_funkey.py` demangled in the same slice. Regression
  test covers every regulator-facing field. Suite 2050 -> 2051.

- [x] **"Fully functional Wasm" slice 19 - transpiler audit (Python
  closure-over-loop-var capture parity)** (closed 2026-05-29). Fifth
  audit pass. P1: `for i in 0..N { handlers.push(fun () => i) }`
  produced late-binding lambdas on Python (all return the final
  value) but per-iteration captures on Wasm. Fix: `_emit_lambda`
  collects free-variable captures and emits each as a Python default
  arg (`lambda i=i: i`), matching Wasm's MakeLambda-time snapshot.
  Parity program `closure_loop_capture.capa`. Suite 2050 -> 2051.

- [x] **"Fully functional Wasm" slice 18 - manifest soundness fix
  (closure-laundering of capabilities)** (closed 2026-05-29). Fourth
  audit pass. P0: `b(f: Fun() -> Unit)` called with a closure
  capturing `stdio` exercised Stdio while the manifest claimed `b`
  excluded it. Fix: new `_contains_fun_type` helper walks a
  `TypeExpr` recursively; the manifest downgrades
  `provably_excluded_capabilities` to `[]` whenever the signature
  contains a `Fun(...)`. P0 #2 (var-of-cap reassign) and P0 #3
  (struct cap-field smuggle) verified NOT exploitable (blocked by
  language-level guards). 4 tests in `TestIneligibilityProofs`.
  Suite 2046 -> 2050.

- [x] **"Fully functional Wasm" slice 17 - String.length +
  String.substring code-point semantics on Wasm** (closed
  2026-05-29). Third audit pass. P0: Wasm's `String.length` returned
  bytes while Python returned code points (same for `substring`
  indices); ASCII parity tests masked it. Fix: two new WAT helpers
  (`$str_codepoint_count`, `$str_cp_to_byte_offset`); `length` and
  `substring` now use code-point semantics with bounds against the
  code-point count. Parity program `string_unicode.capa`. Suite 2045
  -> 2046.

- [x] **"Fully functional Wasm" slice 16 - older-Wasm-code audit
  pass (3 real bugs fixed)** (closed 2026-05-29). Second audit
  (Phase 6A-6E). P1: Float captures in lifted lambdas crashed the
  verifier (`i64.store`/`load` vs f64) - now `f64.store`/`load`. P1:
  `Set<Float>` crashed the verifier - new `$_alloc_tmp_f64` + `f64.eq`
  (NaN fix as bonus). P1 security: negative-i64 list indices whose
  low 32 bits wrapped in-bounds silently returned `xs[0]` - now
  validated at i64 width before wrapping (`$_bounds_idx_i64`). Parity
  program `audit_float_and_index.capa`. Suite 2044 -> 2045.

- [x] **"Fully functional Wasm" slice 15 - `Proc` capability v1**
  (closed 2026-05-29). `Proc` moves from documented-stub to a fully
  functional capability across all three backends. Surface (mirrors
  Db v1): `restrict_to(cmd_prefix)`, `allows(cmd)`, `exec(cmd,
  args_json) -> Result<String, IoError>` (runs `subprocess.run` with
  `shell=False`, 30s timeout). Attenuation: basename + suffix-boundary
  check (`restrict_to("git")` admits `git` and `git-lfs` but rejects
  `gitlab`). New `$proc_allows` runtime helper. Component Model
  parallel. Parity program `examples/wasm/proc_demo.capa`. Suite
  2042 -> 2044.

- [x] **"Fully functional Wasm" slice 14 - lift the last audit-P2
  restriction (dynamic-arg `allows`)** (closed 2026-05-29). The Wasm
  emitter rejected `if fs.allows(some_runtime_path)` while Python
  accepted it. The dynamic-arg path now emits a runtime check
  (`Fs.allows` / `Db.allows` path-prefix, `Env.allows` OR-chain;
  unrestricted collapses to `i32.const 1`). Two canary tests flipped
  to positive assertions; parity program `allows_dynamic.capa`.
  Suite 2040 -> 2042.

- [x] **"Fully functional Wasm" slice 13 - close two audit-deferred
  findings (Clock.sleep + Db.ATTACH)** (closed 2026-05-29). Clock.sleep
  gate on Wasm: `(Clock, sleep)` added to
  `_ATTENUATION_PRIVILEGED_OPS` with an inline
  `if (now_secs >= deadline)` guard (multiple `restrict_to_after`
  combine via `max`). Db.ATTACH/DETACH blocked on both backends:
  every `sqlite3.connect` installs an authorizer returning
  `SQLITE_DENY` for ATTACH (24) / DETACH (25). WIT collector fix for
  `restrict_to*` surfaced by the Clock work. Two parity programs.
  Suite 2036 -> 2040.

- [x] **"Fully functional Wasm" slice 12 - audit-pass security
  hardening (capability escapes on Wasm)** (closed 2026-05-29). Two
  real capability escapes. P0: `Fs.{exists,is_dir,mkdir,list_dir}`
  bypassed attenuation on Wasm - now routed through the
  attenuation-check machinery (new `_emit_bool_query_with_attenuation_check`
  for the bool queries, new `result_list_string_io_error` Err
  materialiser). P1: `Fs.restrict_to("/tmp")` (no trailing slash)
  admitted `/tmproot/secret` - new `_emit_path_prefix_check`
  (`path == prefix OR path.startswith(prefix + '/')`). Parity program
  `fs_attenuation_audit.capa`. Suite 2035 -> 2036.

- [x] **"Fully functional Wasm" slice 11 - `Db` capability v1**
  (closed 2026-05-29). SQLite-backed, path-prefix attenuation. Surface
  (mirrors Fs): `restrict_to(prefix)`, `allows(path)`, `exec(path,
  sql) -> Result<Unit, IoError>` (executescript), `query(path, sql) ->
  Result<String, IoError>` (JSON-encoded rows). Wire shape is a single
  `result<string, io-error>` so no new materialiser. Component Model
  works under `--component --run`. Parity program
  `examples/wasm/db_demo.capa`. Suite 2033 -> 2035. v2 (typed columns,
  connection caching, transactions) deferred.

- [x] **"Fully functional Wasm" slice 10 - Component Model parity
  harness + `Fs.allows` / `Env.allows` WIT-mismatch fix** (closed
  2026-05-29). New `TestPythonWasmComponentParity` pivots the parity
  assertion on the CM path (bound to a 7-program host-bridge subset)
  + 4 new `TestWasmComponentHost` cases. Latent CM bug: `Fs.allows` /
  `Env.allows` missing from `_GUEST_ONLY_METHODS`, so WIT generation
  demanded a host signature for an emit-time-inlined check. Suite
  2022 -> 2033.

- [x] **"Fully functional Wasm" slice 9 - parity-list cleanup +
  Component Model `option<T>` discriminant bug-fix** (closed
  2026-05-29). `fs_demo.capa` and `env_demo.capa` promoted to the
  parity list. Expanded CM host coverage. Latent CM `option<T>`
  discriminant bug: the CM ABI puts `none` first (0), `some(T)`
  second (1); Capa's internal layout is the inverse. Core host now
  writes WIT-convention and the materialiser XOR-flips to Capa
  convention. Suite 2017 -> 2022.

- [x] **"Fully functional Wasm" slice 8 - `Net.post` end-to-end on
  Wasm** (closed 2026-05-29). `Net.post(url, body) -> Result<String,
  IoError>`. Both backends use `urllib.request.urlopen(Request(...))`
  with a 10s timeout and `errors="replace"` decode. New execution
  test against an in-process `http.server` echo. Suite 2015 -> 2017.

- [x] **"Fully functional Wasm" slice 6.1 - free top-level functions
  usable as `Fun(...)` values on Wasm** (closed 2026-05-29).
  `xs.map(double_int)` (a top-level function rather than an inline
  lambda) rejected with `value kind 'global' not supported`. Fix: a
  per-(fn, sig) thunk synthesised at emit time (drops the env,
  forwards). Parity program `fn_ref_as_closure.capa`. Suite 2014 ->
  2015.

- [x] **"Fully functional Wasm" slices 6 + 7 - Option/Result HOFs +
  Unsafe rejection + discovery-walker fixes** (closed 2026-05-29).
  Slice 6: Option HOFs (`map`, `and_then`, `filter`, `ok_or`,
  `or_else`) and Result HOFs (`map`, `map_err`, `and_then`, `or_else`,
  `ok`, `err`). Slice 7: Unsafe rejection (D5) with an actionable
  diagnostic at emit-start. Bonus discovery-walker fixes (String `==`
  in a lifted lambda triggers `$str_eq`; `MakeLambda.body` recursed by
  `_uses_map_ops`). Parity program `option_result_hofs.capa`. Suite
  2013 -> 2014.

- [x] **"Fully functional Wasm" slice 5 - tuple arity > 2, Map.keys /
  Map.values, range iteration + four bug-fixes** (closed 2026-05-28).
  Surfaced by `capa_governance_pack` on pure `--wasm`. Tuple arity > 2
  (uniform 8-byte stride); Map.keys() / Map.values(); range iteration
  (new `MakeRange` CIR node + counted-loop fast-path, depth-indexed
  scratch locals); wildcard let-pattern (`let _ = expr`); String dst
  <- String param; tuple-element type-recovery in CIR Index. Bonus:
  `UnsupportedInIR` moved to `_lower_helpers.py` (the mixins raised it
  without importing it). Three parity programs. Suite 2010 -> 2013.

- [x] **"Fully functional Wasm" slice 4 - String.replace / char_at /
  index_of + Stdio terminal-encoding robustness** (closed
  2026-05-28). `char_at -> Option<String>`, `index_of -> Option<Int>`,
  `replace -> String` (empty-needle leaves the receiver unchanged on
  both backends). Bonus: `Stdio.print/println/eprintln` crashed
  (`UnicodeEncodeError`) on chars the terminal codec cannot encode;
  new shared `_write_safe(stream, text)` re-encodes with
  `errors="replace"`. Suite 2007 -> 2010.

- [x] **"Fully functional Wasm" slice 3 - Net.get end-to-end** (closed
  2026-05-28). `Net.get(url) -> Result<String, IoError>` with full
  parity to `urllib.request.urlopen`. New `capa:host/net.get` WIT
  interface. Two parity programs (`net_get.capa`, `net_restrict.capa`)
  + 2 direct Net execute tests + 1 CM host test. Net.post remains
  rejected by the analyzer at this point. Suite 2002 -> 2007.

- [x] **"Fully functional Wasm" slice 2 - Random capability** (closed
  2026-05-28). SplitMix64 on both backends so seeded output is
  byte-identical. Python: replaced `random.Random` internals with
  SplitMix64. Wasm: new `capa/ir/_emit_wasm/_random.py` (~290 LOC) +
  `capa:host/random.system-seed` host call; the three guest-only
  methods elided via `_GUEST_ONLY_METHODS`. Subtle fix: the Lemire
  rejection limit overflows i64 for bounds dividing 2^64; replaced
  with `bias = (0 - bound) % bound`. All three backends produce
  identical `Random(42).int_range(0, 100)`:
  `[13, 91, 58, 64, 50, 62, 25, 8, 5, 74]`. Suite 1996 -> 2002.

- [x] **"Fully functional Wasm" slice 1 - host-bridge pile** (closed
  2026-05-28). 9 capability methods: `Stdio.read_line`, `Clock.sleep`,
  `Clock.allows`, `Fs.exists` / `Fs.is_dir`, `Fs.mkdir`,
  `Fs.list_dir` (new `result_list_string_io_error` shape),
  `Fs.allows` / `Env.allows` (inline-attenuation per D4). 18 new
  tests. Suite 1978 -> 1996.

- [x] **Map and Set structural equality (`==`/`!=`)** (closed
  2026-05-28). Order-independent structural equality matching Python
  `dict == dict` / `set == set`. New `_emit_map_eq`, `_emit_set_eq` in
  `capa/ir/_emit_wasm/_equality.py`. Closed a latent Python-oracle gap
  (`CapaSet` had no `__eq__`). 6 new tests. Suite 1972 -> 1978. The
  equality story is now complete across all compound types.

- [x] **Map<K, V> with Struct / Tuple / Sum keys on Wasm** (closed
  2026-05-28). Pointer-shape Map keys now work via the slice-3 `$eq_*`
  helpers + the slice-4 H2 frozen rule. Latent fix: `_map_key_type` /
  `_map_value_type` split `Map<(Int, String), V>` on the inner comma;
  replaced with `_split_top_level_commas`. 5 new tests. Suite 1967 ->
  1972. Accepted key set: String, Int, Bool, Struct, Tuple, Sum;
  rejected: Float (NaN), nested collections, Fun.

- [x] **Map<K, V> with Int and Bool keys on Wasm** (closed
  2026-05-28). Uniform 16-byte pair layout for all key types so the
  allocator stays generic. Per-key-type dispatch factored into
  `_maps.py`; new `_map_key_type` in `_layout.py`. 18 new tests. Suite
  1948 -> 1967. Closes the audit's M4 silent-divergence vector.

- [x] **Security hardening pass 4 - H2 frozen struct types as Set /
  Map keys** (closed 2026-05-28). Final audit follow-up. Mutating a
  struct used as a Set element or Map key broke the data-structure
  invariant on both backends. Closed with a conservative type-level
  rule: if a struct type T is referenced (transitively) from any
  `Set<...T...>` or `Map<...T..., V>` position anywhere, `p.field =
  value` on any T is rejected at analysis time. Map values stay
  mutable; whole-value rebinding stays allowed. New
  `capa/analyzer/_frozen.py` mixin. 9 new tests; zero corpus breakage.
  Suite 1939 -> 1948. **All audit follow-ups closed.**

- [x] **Security hardening pass 3 - C4 + M1 + M4 + H1** (closed
  2026-05-28). C4: `to_int(huge_float)` raises `OverflowError` on
  Python outside the i64 window (matches the Wasm trap). M1: Env "leaks
  all host env vars by default" docs added. M4: capability manifest
  embedded in the `.wasm` via a `capa-manifest` custom section + a
  `capa.ir.read_wasm_manifest` LEB128 parser. H1: memory budget cap
  (default 256 pages / 16 MiB) via `--wasm-memory-cap`. 20 new tests.
  Suite 1919 -> 1939.

- [x] **Security hardening pass 2 - C1 bounds checks on collection
  indexing** (closed 2026-05-28). `xs[i]` with `i >= len` raised
  `IndexError` on Python but silently read junk on Wasm (data-leak
  vector); same for negative indices and over-long `substring`. Closed
  in the "both fail loud at same input" stance: Wasm `_emit_index`
  prepends an unsigned `i >= len` compare + `unreachable`; Python
  `_capa_list_get` / `_capa_substring` raise. New `$_bounds_idx`. 10
  new tests. Suite 1909 -> 1919.

- [x] **Security hardening pass 1 - 5 critical safety gaps closed**
  (closed 2026-05-28). C2 Int overflow (`+` `-` `*` and augmented
  forms trap on Wasm, raise `OverflowError` on Python via
  `_capa_iadd` / `_capa_isub` / `_capa_imul`); C3 shift count out of
  `[0, 64)` traps / raises; C5 `parse_int` overflow returns `None`
  instead of wrapping; C6 Float `%` by zero traps on Wasm; H3 UTF-8
  host crash (Stdio uses `errors="replace"`, Env/Fs/json return the
  Err / None variant). 21 new tests. Suite 1888 -> 1909.

- [x] **Bitwise operators on Int** (closed 2026-05-28). `& | ^ << >>`
  end to end with parity-clean output, previously unsupported across
  the whole stack. Five layers touched (lexer / parser / analyzer /
  both emit tables). Standard C/Rust/Python precedence. The `>>` lexer
  change broke `List<List<Int>>`; fixed via the in-place token split
  in `_close_type_args`. 18 new tests. Suite 1870 -> 1888.

- [x] **Numeric + Bool interpolation parity** (closed 2026-05-28). Int
  `%` now floored on Wasm (matches Python); Float `%` implemented on
  Wasm; `${flag}` Bool interpolation lowercase on both backends. Parity
  program `numeric_parity.capa`. Suite 1869 -> 1870.

- [x] **Set<T> on the Wasm backend, insertion-ordered both backends**
  (closed 2026-05-27). `Set<T>` (add / remove / contains / length /
  is_empty / to_list / for-iteration) now compiles on Wasm. Set is now
  insertion-ordered on both backends (Python `CapaSet` backed by an
  insertion-ordered dict; structs became `@dataclass(unsafe_hash=True)`).
  New `capa/runtime/_set.py` + `capa/ir/_emit_wasm/_sets.py`. 9 new
  tests. Suite 1860 -> 1869.

- [x] **Structural equality on compound types** (closed 2026-05-27).
  `==` / `!=` on struct / sum / tuple / `List<T>` compile to deep
  by-value comparison on Wasm (previously a pointer compare). New
  `capa/ir/_emit_wasm/_equality.py` generates one `$eq_<Type>` helper
  per compound type. Also fixed a latent both-backend bug: payloadless
  variants (`Red == Red`) compared by identity. Map/Set equality
  rejected (deferred, later closed). 16 new tests. Suite 1844 -> 1860.

- [x] **Int pattern matching** (closed 2026-05-27). `match` on an Int
  scrutinee (literal arms + default + guards) compiles on Wasm. Change
  confined to `capa/ir/_emit_wasm/_match.py` (`_emit_int_match` +
  `_emit_int_match_with_guards`); new `$_m_scrut_i64`. 4 new tests.
  Suite 1840 -> 1844. Negative-literal patterns route through the
  catch-all (a separate parser-surface gap).

- [x] **Pointer-shape element types in collections + HOFs** (closed
  2026-05-27). `List` / `Map` / map / filter / fold HOFs now carry
  struct / tuple / sum / nested-collection elements on Wasm, not just
  scalars + String. Root cause: a slot-size divergence (HOF path
  hardcoded 8 bytes); `_hof_elem_slot_size` now delegates to
  `_size_of`. `List.contains` on pointer-shape rejected (would compare
  references). 8 new tests. Suite 1831 -> 1840.

- [x] **List<T>.map / filter / fold for non-Int element types**
  (closed 2026-05-25). `List<Int/String/Float/Bool>` HOFs now
  supported on Wasm; per-element-type closure sig via
  `_closure_sig_key_for`. Also fixed a pre-existing `List<Float>`
  literal / index / for-iter bug (`i64` instead of `f64`
  store/load). Pointer-shape elements still raise a clear error
  (closed later). 4 new tests. Suite 1492 -> 1495.

- [x] **Lambdas-inside-lambdas (nested closures)** (closed
  2026-05-25). Lambda lifting with flat envs: each nested closure
  gets its own env record with every name it references from any
  outer scope, copied in at MakeLambda emit time. The discovery
  walker threads a scope stack; free-variable analysis recurses into
  nested MakeLambda bodies. Arbitrary nesting depth. 4 new tests in
  `TestWasmNestedClosures`. Suite 1488 -> 1492.

- [x] **`wasmtime` as optional dep + `--prefer-wasm` opt-in** (closed
  2026-05-25). `pyproject.toml` exposes a `[wasm]` extra
  (`wasmtime>=20` at the time). New `--prefer-wasm` flag (also
  `CAPA_PREFER_WASM=1`) makes `capa --run` try the Wasm pipeline
  first and fall back silently. The toolchain probe is lazy. Suite
  1492, 0 regressions.

- [x] **Pure-Wasm JSON parser** (superseded 2026-05-25). The original
  motivation (drop the `capa:host/json` bridge) no longer applies:
  `_builtin_json.py` splices a pure-Capa parser / serialiser into
  every IR module that touches `parse_json` / `to_json`, so the tree
  builds in the guest's own linear memory. A hand-written WAT parser
  would be ~500 lines for no gain; closes as superseded.

---

## Wasm CM backend (foundation, May 2026)

- 2026-05-23: **Milestone (May goal closed).** `audit-trail-reporter`,
  `policy-eval`, and `sbom-watch` all run end-to-end via both
  `capa --wasm --run` and `capa --wasm --component --run`, output
  bit-identical to the Python reference. `capa --wasm --component
  --output app.wasm` produces a standalone Component Model `.wasm`.
  Sessions 2026-05-22 and 2026-05-23 closed: pattern-binder shadowing
  (alpha-rename in the lowerer), for-loop `continue` skipping the index
  increment, Float-typed struct fields, the bump allocator never
  growing memory (`memory.grow` in `$alloc`), nested for-loops sharing
  scratch locals, `List<String>.contains`, kebab-case WIT identifiers,
  `io-error` record declaration, the canonical-ABI rework for
  `list<string>` / `option<string>` / `result<...>` / `string`
  returns + the `cabi_realloc` export, the `export main: func();` WIT
  entry point, an external Component Model runtime
  (`capa/runtime/_wasm_component_host.py`) wired as `--component
  --run`, and a pure-Capa JSON parser at `capa/ir/_builtin_json.capa`
  that replaces the `capa:host/json` host bridge (closing the handle
  leak that blocked the three demos under `--component --run`).
- 2026-05-22: **Phase 6E-6I** all landed in a single multi-hour
  session: closures + HOFs, Bool/`()`/`?` follow-ups, JsonValue +
  `capa:host/json` host bridge, `String.split` + List<String>
  baseline, Option/Result method dispatch
  (`is_some/none/ok/err/unwrap_or`), lowerer fix for parametric type
  rendering, List.get + Map<String,String>, String-scrutinee match,
  multi-value String returns. 92 Wasm tests green.
- 2026-05-22: **Wasm emitter modularised.** `_emit_wasm/` package with
  7 focused mixins (closures 888, strings 756, maps 450, runtime 432,
  lists 417, layout 242, match 149, json 245, option 174); main
  `__init__.py` 1506 lines (was 4628).

---

## Frontend / analyzer (May 2026)

- 2026-05-20: NLL-style consume tracking around divergent branches.
- 2026-05-20: Block-scope shadowing rejection.
- 2026-05-20: All four Agda soundness theorems mechanised (Stages 1-4
  of `proofs/`).
- 2026-05-19: `?` soundness fix (analyzer rejects `?` whose enclosing
  function/lambda doesn't return Result/Option).
- 2026-05-15: `pub` visibility enforcement via per-module name
  mangling.
- 2026-05-15: Stdlib paths via `CAPA_PATH`.

---

## Wasm showcase-driven fixes (late May 2026)

- 2026-05-27: **Milestone: every downstream demo runs end-to-end under
  `--wasm --run`.** Cross-demo smoke on the four downstream consumers
  (capa_showcase, policy-eval, audit-trail-reporter, sbom-watch) all
  produce Python-equivalent output under the Wasm CM backend. Zero new
  compiler gaps surfaced beyond the 8 showcase-driven fixes.
- 2026-05-27: **`${io}` interpolation for `IoError` values.**
  `_emit_format_part_stash` reads the `message` field and pushes (ptr,
  len), mirroring Python's `__str__`; the `cause` field is skipped to
  match Python.
- 2026-05-27: **Monomorphiser: `Fun(T) -> R` unification.** The
  string-based unifier treated closure types as opaque atoms, so the
  showcase's `count_by<T>(items, key: Fun(T) -> String)` never
  monomorphised. Fix: decompose `Fun(P, ...) -> R` into a pseudo-head.
  `capa_showcase` now runs end-to-end under `--wasm --run`
  byte-identical to Python.
- 2026-05-27: **Lowerer: tag cap_used on built-in cap method calls
  reached via field access.** `self.fs.read(...)` left `cap_used`
  None, so the canonical-ABI detector missed the call and `$_ret_area`
  went undeclared. Fix: tag `cap_used` by `receiver.ty` when it
  resolves to a built-in cap.
- 2026-05-27: **Top-level String const support end-to-end.** Three
  sites had no `global` case; plus the constant's UTF-8 bytes were
  never interned (the discovery pass walks function bodies, not
  ConstDecl). Fix: pre-intern every String-typed top-level constant at
  module-emit init.
- 2026-05-26: **Analyzer: propagate user-capability method return
  types.** `_check_method_call` gated the cap-method-table consult on
  built-ins only; user-defined caps fell through to `TyUnknown`. Fix:
  broaden to any `SymbolKind.CAPABILITY` symbol. Bonus tuple-type fix.
- 2026-05-26: **Multi-value lowering for String in lambda params +
  returns.** The lifted-lambda signature now emits two i32s `(ptr,
  len)` per String param and a multi-value `(result i32 i32)` for a
  String return.
- 2026-05-26: **Generic-function monomorphisation.** New IR pass at
  `capa/ir/_monomorphise.py` walks the module, infers each call's
  type-parameter substitution by string-unifying arg types, and
  synthesises a specialised clone per substitution (`first__Int` /
  `first__String`). Free functions only at this point.
- 2026-05-25: **Analyzer: propagate return type of calls through
  Fun-typed callees.** `_check_call` returned `TyUnknown` for a callee
  typed `Fun(P...) -> R`; now returns `R` with an arity-mismatch error
  when applicable.
- 2026-05-25: **Loader: scope-aware qualified-call rewrite.** The
  `mod.fn() -> fn()` pass now consults a per-function set of
  local-binding names before rewriting, so a name that shadows a module
  alias is left intact. 5 new tests in `TestQualifiedCallShadowing`.
- 2026-05-25: **`capa_http` v0.1.3:** vendor-aware sys.path in
  `make_urllib_client` (probes `./vendor/` and `./libraries/`). Closes
  the loose end from `capa_agent_demo` v0.1.0; demo bumped to v0.1.3.

---

## Supply-chain artefacts (May 2026)

- 2026-05-15: **Tier 1 complete**: SBOM diff tool, SPDX 2.3 emission,
  VEX integration, SLSA Build L1 provenance.
- 2026-05-15: **Tier 2 complete**: `docs/regulatory.md` covering CRA +
  NIS2 + DORA + NIST SSDF + OWASP SCVS.
- 2026-05-15: Tier 3, provenance signing workflow.
- 2026-05-15: Ineligibility proofs as SBOM enrichment
  (`provably_excluded_capabilities` in CycloneDX + SPDX).
- 2026-05-23: **Package-manager supply-chain hardening, three stacked
  layers** in `capa_cli` / `capa_datetime` / `capa_log` / `capa_http`:
  (1) lockfile SHA enforcement (catches tag retag); (2) GPG tag
  signatures + `verify_key` pinning (catches account compromise that
  moves a tag); (3) SLSA L2 build provenance via Sigstore (each seed
  library's release workflow fires on `v*`, builds a tarball, generates
  a SLSA L2 attestation via `actions/attest-build-provenance@v1`,
  publishes to Rekor). v0.1.2 is the first attested release.
- 2026-05-23: **Consumer-side SLSA L2 auto-verify.** `capa install`
  runs `gh attestation verify` implicitly when a dep declares
  `verify_key` and is GitHub-hosted; refuses on mismatch,
  graceful-skips on missing-tarball / missing-`gh` / non-GitHub. 10 new
  unit tests.
- 2026-05-23: **Website extracted to standalone repo** at
  [nelsonduarte/capa-language-website](https://github.com/nelsonduarte/capa-language-website).
  `git filter-repo` preserved per-file history; GitHub Pages
  custom-domain cut-over completed in the same session. `docs/` in this
  repo now contains only the Markdown source the website links to.

---

## LLM tool-use demo (May 2026)

- 2026-05-23: **LLM tool-use demo** shipped at
  [nelsonduarte/capa_agent_demo](https://github.com/nelsonduarte/capa_agent_demo)
  v0.1.0, the last P2 item from the alignment plan. Capability
  discipline as the right shape for sandboxing tool-calling LLM agents;
  the `run_agent_loop` capability signature bounds the blast radius of
  any prompt injection. Live-verified against `claude-haiku-4-5`. First
  downstream demo that surfaced two real Capa-side bugs (capa_http
  vendor-path, codegen method shadow).

---

## CVE case studies (6 landed)

- event-stream 2018, eslint-scope 2018, node-ipc 2022, xz-utils 2024,
  torchtriton 2022, ua-parser-js 2021. Four clean wins + two honest
  partial losses. Plus four design-pattern CVE studies (PyYAML, Jinja2
  SSTI, lxml XXE, pickle).

---

## Tooling (May 2026)

- 2026-05-15: LSP v1 (diagnostics, hover, go-to-definition,
  find-references, documentSymbol, code actions, rename, completion
  incl. receiver-method completion after `.`, semantic tokens).
- 2026-05-15: Formatter v2 (line-level + intra-line spaces / comma
  fixup).
- 2026-05-15: REPL MVP.
- 2026-05-15: `capa init` project scaffolding.
- 2026-05-15: Property-based testing through Phase 3.7 (multi-capability
  strategies, 50k+ generated programs stress-tested).
- 2026-05-15: Watch mode (`capa --watch`).
- 2026-05-15: Doc comments (`///`, `/**`), raw strings, named arguments.

---

## Strategic / governance

- All public-readiness items landed; repo flipped public, tagged
  `v0.2.0-alpha`. Security policy, code of conduct, contributing guide,
  issue / PR templates, Dependabot, secret scanning, CodeQL workflow.

---

## Closed soundness/security holes (reconciliation, June 2026)

These were tracked as "remaining open items" and then closed in v1.3.0 /
v1.4.0; recorded here so the full closure history is visible.

- **Capability attenuation / enforcement holes** - CLOSED in v1.4.0.
  `Proc.restrict_to` fixes the binary identity not the basename (RCE);
  `Db.allows` canonicalises through `realpath` (`..`-traversal); a `Db`
  open re-validates the kernel true path (symlink TOCTOU, narrow
  residual recorded in `TODO.md`). Commits `1f645e0`, `dcf47af`,
  `77ee0c5`.
- **IFC / constant-time holes** - CLOSED in v1.4.0. Default-tier secret
  reassignment warns; `@constant_time` rejects a short-circuiting secret
  compare (CWE-208); an early return inside a secret branch under
  `@strict_ifc` keeps the pc elevated. Commits `1f645e0`, `dcf47af`.
- **Capability encapsulation holes** - CLOSED in v1.4.0. Field access
  through an abstract-cap / trait receiver and `Unsafe` hidden in a
  cap-bearing struct both rejected (the `Unsafe` rejection walks
  parameter types recursively on Wasm). Commit `3cdb421`.
- **Manifest / SBOM false exclusions and digest gaps** - CLOSED in
  v1.4.0. `provably_excluded_capabilities` no longer over-claims via a
  cap-bearing struct / nested field / sum-variant payload; the
  provenance / SBOM digest covers all modules and demangles `sel__`;
  single-file SBOM identifiers restored. Commits `3cdb421`, `30e66e3`,
  `2b6ee0f`.
- **Supply-chain trust-root weaknesses** - CLOSED in v1.4.0. GPG verify
  anchored on the primary key; `file://` traversal (incl. `%2e%2e`)
  rejected; the registry index fails closed when unverifiable. Commits
  `de16b21`, `9369f11`.
- **Wasm `parse_float` has no scientific notation** - CLOSED in v1.3.0
  (commit `782a0d2`). The last numeric cross-backend divergence.
- **Website Tier 2 (and Tier 3) leftovers** (separate repo) - CLOSED.
  Updated to v1.3.0; the old test-count note is obsolete.

Resolved earlier: **typestate** is full (S3.1-S3.5); the **package
manager + registry** ship (`capa.toml` + `capa install` + `capa.lock` +
the `capa-registry` index); the **REPL** is v2.

---

## Known restrictions (documented, not bugs)

These shipped as conscious design boundaries, kept here for the record.

- **Indent-based `match` inside parentheses** fails because parens
  suppress NEWLINE / INDENT / DEDENT. Workaround: the braced inline form
  (`match x { P1 -> e1, ... }`) works inside call expressions.
- **Block-body lambdas in deep expression contexts.** Same root cause.
  The parser emits a targeted error pointing at the workaround.

---

## Things explicitly NOT planned for v1 (scope control)

- LLVM backend (far future)
- Self-hosting (very far future)
- Full async/await (reserved keywords, no implementation)
- Tail-call optimisation (since SHIPPED on the Wasm backend; was listed
  here as out-of-scope before it landed)
- Garbage collection beyond CPython's
- Custom syntax extensions / macros
