# 29. The capability manifest and composition

> **What this chapter covers.** The supply-chain artefacts born from
> the authority graph the analyzer already computes: the per-program
> manifest (`--manifest`), its signable canonical envelope
> (`--manifest-digest`), the composed SBOM of the whole PRODUCT
> (`--compose-sbom`) with the dependency DAG and the
> authority-UNKNOWN element, the authority changelog
> (`--capability-diff` / `--fail-on-widening`), and the two CI gates
> that rest on composition (`--check-capabilities` over each package's
> `[capabilities]` ceiling, and `--check-policies` /
> `--conformance-report` over the organization's `capa-policy.toml`).
> Source: the [`capa/manifest/`](../capa/manifest/__init__.py)
> package. The external SBOM formats (CycloneDX, SPDX) are
> [30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md)'s subject;
> the dependency model (`capa.toml`, `vendor/`, `capa.lock`,
> signatures) is documented in [`docs/packages.md`](../docs/packages.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification; invocations ran from a scratch folder (minimal programs
and a two-dependency product tree built for the purpose); no absolute
personal path appears in the outputs.

Depends on: [10-capability-model.md](10-capability-model.md),
[11-builtin-capabilities.md](11-builtin-capabilities.md).

---

## 1. The subsystem: an authority graph turned artefact

The `capa/manifest/` package turns the analyzer's result into a set of
machine-checkable artefacts. The central idea, in the package's own
docstring: "Other languages cannot emit this because the authority
graph is not in their type system; in Capa, it falls out of the
analyser for free". The capability discipline makes
`declared_capabilities` an UPPER bound on what a function can exercise
(no cap a callee touches can exist without being in scope here to be
passed); the manifest reads that bound and records it.

The subsystem is layered. Each layer rests on the previous one and has
its own independent `schema_version`, so a consumer can refuse a shape
it does not recognize:

| Layer | Module | Produces | `schema_version` |
|---|---|---|---|
| Per-program manifest | `_funrec.py` | the per-function record (`--manifest`) | `SCHEMA_VERSION = 3` (line 54) |
| Canonical substrate (S1) | `_canonical.py` | the `content_integrity` envelope (`--manifest-digest`) | scheme `capa-jcs-sorted-v1` (line 65) |
| Composed SBOM (S2/S3) | `_compose.py` | the whole product (`--compose-sbom`, `--check-capabilities`) | `COMPOSED_SCHEMA_VERSION = 6` (line 104) |
| Authority changelog | `_diff.py` | the signable delta (`--capability-diff`) | `DIFF_SCHEMA_VERSION = 1` (line 122) |
| Organization policies | `_policy.py` | the conformance report (`--check-policies` / `--conformance-report`) | `POLICY_SCHEMA_VERSION = 1` (line 85) |

The external-format wrappers (`_cyclonedx.py`, `_spdx.py`) and the
attestations (`_provenance.py`, `_vex.py`) depart from the same
internal manifest ([30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md)).

**The 10 built-in capabilities are the manifest's source of truth.**
The builder imports `CAPABILITY_NAMES` from `capa.typesys`, the same
set as [11-builtin-capabilities.md](11-builtin-capabilities.md). A
function's `provably_excluded_capabilities` is literally
`{all capability names} - {reachable}`, so any new built-in capability
automatically enters the exclusion proof.

---

## 2. `--manifest`: the per-function record

`--manifest` builds the per-program manifest (`build_manifest`,
[`capa/manifest/_funrec.py`](../capa/manifest/_funrec.py)) and prints
it with `json.dumps(..., indent=2)`, human-readable, WITHOUT
`sort_keys`. For a `Stdio`-only program (measured; trimmed to the
`greet` record):

```
$ python -m capa --manifest hello.capa
{
  "capa_version": "1.32.0",
  "schema_version": 3,
  ...
      "name": "greet",
      "declared_capabilities": [ "Stdio" ],
      "transitively_reachable_capabilities": [ "Stdio" ],
      "provably_excluded_capabilities": [
        "Clock", "Db", "Env", "Fs", "Net", "Proc", "Random", "Serve", "Unsafe"
      ],
      "linear_obligations": { "consumes": [], "produces_linear": false },
      "has_unsafe": false,
      "authority_provable_from_types": true,
      "ceiling_authority_provable": true,
      "constant_time": false,
  ...
  "summary": {
    "total_functions": 2, "functions_with_capabilities": 2,
    "functions_with_attributes": 0, "functions_crossing_unsafe": 0,
    "declassification_sites": 0, "protocol_states": 0,
    "foreign_components": 0, "functions_calling_foreign_components": 0
  }
}
```

### 2.1 The four capability fields per function

The regulatory core of each record is four capability views:

- **`declared_capabilities`**: the capabilities NAMED in the signature
  (plus the trait's cap when a method implements a user capability
  through `self`).
- **`transitively_reachable_capabilities`**: `declared` plus the caps
  the signature reaches TRANSITIVELY through user-capability impls and
  cap-bearing struct fields, UNIONED with the authority the BODY mints
  (`caps_reachable_via_body`,
  [`capa/manifest/_reachability.py`](../capa/manifest/_reachability.py)):
  a construction of a cap-bearing type, or a call to a factory whose
  declared return type names one. Measured through the CLI: in a
  `pub fun trigger_factory()` with an EMPTY signature whose body does
  `let b = make_bomb(); b.boom()`, the user capability `Danger`
  appears in `transitively_reachable_capabilities` and leaves
  `provably_excluded_capabilities`, while an unrelated cap, `Net`,
  REMAINS provably excluded: the minted authority is NAMED, it does
  not void the whole list the way a `Fun` / `Unsafe` in the signature
  does. The INLINE mint form `let b = Bomb {}` is rejected by the
  analyzer itself
  (`error: capability 'Bomb' cannot appear in a 'let' binding`), so
  through the CLI only the factory shape reaches the manifest. Pinned
  in [`tests/test_manifest_ceiling_user_caps.py`](../tests/test_manifest_ceiling_user_caps.py).
- **`provably_excluded_capabilities`**: `{all caps} - {reachable}`,
  the capabilities the function PROVABLY cannot use. This is the
  strong-guarantee field regulatory tooling consumes.
- **`has_unsafe`**: whether the function crosses the `Unsafe` hatch.

**The exclusion proof degrades to empty when it cannot be honoured.**
`provably_excluded_capabilities` is only filled when
`authority_provable_from_types` is true; that signal is
`not (has_unsafe or has_fun_in_sig or sig_unprovable)`. The proof is
VOIDED (empty list, never a false exclusion) in three documented
cases: (1) `Unsafe` in scope, which can bypass the discipline; (2) a
`Fun(...)` type in the signature (parameter, return, or nested
generic), because the caller injects authority the types never named
by passing a closure that captures a capability; (3) a signature type
that reaches a `Fun` through an impl. JUDGEMENT: this is a fail-safe
choice, the opposite of over-claiming.

### 2.2 What else the record carries

Besides capabilities, each function records: the demangled signature
(`params` with `type`, `consuming`, `borrowing`, `is_capability`,
`is_linear`; `return_type`); `linear_obligations`; the `attributes`;
`constant_time`; the `calls` list with the attenuation `args_flow`;
the audited `declassifications` (the `@secret -> @public` bridges);
and the `unaudited_secret_sinks` (raw warn-tier secret-to-sink flows
the IFC analysis surfaced; see
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md)).

**What `constant_time` attests.** Replicated from the public register
([`docs/trust-model.md`](../docs/trust-model.md), "Outside the threat
model", and the B2 scope addendum in
[`docs/advisories/2026-06-17-security.md`](../docs/advisories/2026-06-17-security.md)):
the per-function `constant_time` boolean reports the **PRESENCE of the
`@constant_time` attribute on the function**, NOT an analysis outcome.
Measured in the code:
[`capa/manifest/_funrec.py`](../capa/manifest/_funrec.py) line 1154
computes literally
`any(a.name == "constant_time" for a in fn.attributes)`, and
`build_manifest` receives no result of that analysis. A consumer must
read the field as "the author marked this function `@constant_time`"
(and the analyzer imposed on it the ENUMERATED rejection set of
[16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md) section
7, a SOURCE-level discipline, opt-in per function), not as "the
toolchain verified the function is constant-time". The other security
fields of the SBOM (`declared`, `provably_excluded_capabilities`,
`declassification_sites`, `has_unsafe`) remain analysis-derived, as
`docs/trust-model.md` lists.

**Carriers and typestates on the obligation surface.** The
must-consume predicate is single-sourced in
[`capa/_owned_obligation.py`](../capa/_owned_obligation.py), consulted
by the analyzer and by `_funrec.py`, so a struct that transitively
owns a linear field (a CARRIER) and a typestate count toward
`is_linear` / `consumes` / `produces_linear`. Measured through the
CLI, with `linear type Handle` and `type Box { h: Handle }`:
`fun mk() -> Box` reports
`"linear_obligations": {"consumes": [], "produces_linear": true}`, and
`fun sink(consume b: Box)` reports the parameter with
`"is_linear": true` and `"consumes": ["b"]` (transcript in
[14-linearity-consume-typestates.md](14-linearity-consume-typestates.md)
section 10.2).

At module level the manifest also records
`user_defined_capabilities` (the trait-capability declarations and
their `implementors`, see
[13-user-defined-capabilities.md](13-user-defined-capabilities.md)),
`typestates`, `foreign_components` (typed FFI boundaries, with
`"authority": "unproven-top"`), `module_declassifications`, and two
blocks of OPPOSITE trust level introduced by WASI (see
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)):

- **`operator_declared_grants`** (`trust_level:
  "operator-declared"`): the authority the OPERATOR declared
  (`--preopen`, `--allow-host`), which a regulator must read as
  deployment trust, NOT as program-proven.
- **`compiler_derived_path_arg_surface`** (`trust_level:
  "compiler-derived"`): the argv-to-sink surface the compiler PROVED
  by sound static analysis, the opposite trust level. It is the same
  surface `--wasi-surface` prints.

The explicit distinction between DERIVED/proven authority and
operator-DECLARED authority is intentional and each block is
labelled.

---

## 3. `--manifest-digest`: the signable canonical envelope (S1)

The readable `--manifest` output is NOT content-hashable: it is
emitted without `sort_keys`, so two semantically equal manifests built
with different key-insertion orders serialize to different bytes.
`--manifest-digest` fixes this without touching the pretty output: it
adds a canonical byte form and a digest over those bytes.

**The canonicalization scheme.** `canonical_json`
([`capa/manifest/_canonical.py`](../capa/manifest/_canonical.py) line
78) is `json.dumps(obj, sort_keys=True, separators=(",",":"),
ensure_ascii=False, allow_nan=False)`. `sort_keys` orders member names
at EVERY nesting depth, making the result byte-identical for
semantically equal manifests; array order is preserved because it is
semantic (the builder already sorts the lists whose order is not).
`allow_nan=False` fails loudly on NaN/Infinity. The scheme is
versioned as `CANONICALIZATION_SCHEME = "capa-jcs-sorted-v1"` (line
65), so a future move to strict RFC 8785 is visible.

**The digest is self-reference-free.** `manifest_digest` (line 116) is
`sha256` over the manifest's canonical bytes WITH the
`content_integrity` envelope removed, so attaching the digest never
changes the digest, and the operation is idempotent.

`--manifest-digest` prints the canonical bytes verbatim, with the
envelope attached. The envelope, measured:

```
$ python -m capa --manifest-digest hello.capa   # content_integrity
{
  "canonicalization": "capa-jcs-sorted-v1",
  "digest": {
    "algorithm": "sha256",
    "value": "aefa282de4e2565a1f900e33568f0d7180b2c72f84d58da10b45c07562391ef9"
  },
  "note": "content_integrity is computed over the canonical bytes of this manifest with the content_integrity key removed. To verify: drop content_integrity, re-serialise with the named canonicalization, sha256, and compare to digest.value. To sign: sign digest.value and fill the signature slot; the compiler holds no keys and never signs (SLSA-L1).",
  "signature": { "algorithm": null, "key_id": null, "value": null }
}
```

**Determinism.** Two invocations produce the same digest (measured:
`aefa282d...` twice).

**The detached signature slot.** `signature` is all `null`: consistent
with the SLSA-L1 posture, the compiler holds NO keys and never signs.
An external signer fills `signature.algorithm` / `.value` / `.key_id`
over `digest.value`; key custody is out of scope. This same envelope
wraps the composed artefacts, the changelog and the conformance
report: it is the shared content-addressable substrate.

**PUBLIC limitation (documented in the code).** The
`capa-jcs-sorted-v1` scheme is UNICODE-NORMALIZATION-AGNOSTIC: it
canonicalizes strings as written (their bytes), so two strings
differing only in NFC versus NFD give different canonical bytes and
digests. A known, accepted limitation, to weigh in a future RFC 8785
decision.

---

## 4. `--compose-sbom`: the whole product (S2)

The per-program manifest describes ONE binary. `--compose-sbom`
reintroduces the package boundary the loader flattens and produces a
capability SBOM per PRODUCT: it attributes each function to its owning
package, walks the dependency DAG, and rolls the capability surface up
bottom-up (`build_composed_sbom`,
[`capa/manifest/_compose.py`](../capa/manifest/_compose.py) line
1449). It requires a root `capa.toml`, found by ancestor walk.

The three pieces, in the module docstring's order:

1. **Per-package attribution (post-flattening).** The whole-program
   manifest is built as `--manifest` builds it; then each function is
   attributed to its owning package by source file. A file under
   `vendor/<dep>` belongs to that dependency; the DEEPEST package wins.
   `caps(P)` is the union of the transitively-reachable caps of the
   functions attributed to `P`, and it is REACHABILITY-SCOPED: it
   comes from the flattened manifest, which only has the source the
   loader LINKED, so a declared-and-vendored but never-IMPORTED
   dependency shows an empty attributed set (dead code is not
   shipped).
2. **The package DAG.** Built by reading the root `capa.toml`'s
   declared `[dependencies]` and RECURSIVELY each resolvable
   dependency's own `capa.toml` under `vendor/<name>`.
   `[dev-dependencies]` are excluded: test/tooling-only, never part of
   the shipped product.
3. **The bottom-up join** over a lattice whose carrier is {capability
   set} PLUS a distinguished TOP element, "authority unknown / trusted
   boundary".

### 4.1 The authority-UNKNOWN element (the non-negotiable piece)

The composition lattice is `Authority` (`_compose.py` line 134):
`caps` (the known set), `unknown` (the TOP flag) and `reasons` (WHY,
always labelled). The `join` (line 157) unions the cap sets, ORs the
unknown flags, and unions the reasons. TOP is absorbing for the
`unknown` component while still accumulating every proven concrete
capability, so a composed value with a TOP child is never SMALLER
than its analysable part.

**The resolvability rule** (`_classify_dependency`, line 297) decides
what makes a dependency a TOP node. A dependency is resolved
(analysable) only when ALL hold: a candidate directory exists
(`vendor/<name>` for a git dep, the target for a path dep); it has a
`capa.toml`; that `capa.toml` parses; and the directory has at least
one `.capa`. Any failure composes as TOP: a never-vendored git dep, a
native/non-Capa dependency, a corrupt manifest. A package whose
attributed functions cross `Unsafe` is also TOP (`_own_authority`,
line 1116). TOP DOMINATES every join and is VISIBLY LABELLED, never
silently treated as the empty set: an unanalysable subtree makes the
PRODUCT authority-unknown, not dishonestly clean, which is what
separates the composed SBOM from a scanner.

Measured over a product tree `app` with one resolvable path
dependency (`logger`, exposing `pub fun log_line(s: Stdio, ...)`) and
one NATIVE path dependency (`extcrypto`, a directory without a
`capa.toml`); the authority-UNKNOWN element appears and dominates
(trimmed):

```
$ python -m capa --compose-sbom main.capa
...
  "edges": [
    { "dependency": "extcrypto", "from": "app", "resolved": false,
      "to_package": null,
      "reason": "package directory has no capa.toml (native / non-Capa dependency; its authority cannot be derived)" },
    { "dependency": "logger", "from": "app", "resolved": true,
      "to_package": "logger", "reason": null }
  ],
  "composed": {
    "authority_unknown": true,
    "authority_unknown_reasons": [
      { "declared_in": "app", "dependency": "extcrypto",
        "reason": "package directory has no capa.toml (native / non-Capa dependency; its authority cannot be derived)" }
    ],
    "capabilities": [ "Net", "Stdio" ],
    "note": "... TOP dominates the join and is NEVER treated as the empty set: the capabilities shown are a floor, not a ceiling, whenever authority_unknown is true."
  }
```

Each package in the `packages` array carries
`attributed_capabilities`, `composed_capabilities`,
`authority_unknown` / `composed_authority_unknown`, and its
`dependencies`. The `logger` package of the product above, measured:

```
  { "name": "logger", "version": "0.2.0", "path": "vendor/logger",
    "attributed_capabilities": [ "Stdio" ],
    "composed_capabilities": [ "Stdio" ],
    "composed_authority_unknown": false,
    "declared_ceiling": [ "Stdio" ], "dependencies": [], ... }
```

**The join is cycle-safe.** `_compose_node` (line 1035) does an
explicit closure walk (`seen`), not a recursive fold, precisely so a
dependency CYCLE never undercounts caps or drops a TOP flag; because
the join is commutative and associative, the result is
visit-order-independent.

**The composed artefact is itself content-addressable.** It reuses
the S1 canonical form, carries no timestamps, and records each path
root-relative in POSIX form. Two invocations of the same product from
the same folder gave an identical digest (measured:
`486beb77...` twice). The `enforcement_posture` is `"none"` by
default (backend-agnostic/Python: a foreign-component call composes
as TOP) and `"wasm-sandbox"` under `--wasm` (the Wasm host enforces
the child's declared cap set, so the boundary composes as a BOUNDED
node; see
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)).

---

## 5. `--check-capabilities`: the per-package ceiling gate (S3)

Each package may DECLARE its own ceiling in the `[capabilities]`
section of its `capa.toml` (`max = [...]`, or `pure = true` as sugar
for `max = []`). `--check-capabilities` composes the SBOM and checks
that each package's COMPOSED capability set is a subset of its
ceiling (`_ceiling_violations`, `_compose.py` line 1297). It exits
NON-ZERO on violation: a CI gate.

**Fails closed over authority-UNKNOWN.** A package that declares a
ceiling but whose composed authority is TOP cannot be PROVEN within
any bound, so it FAILS CLOSED, unless it sets `allow_unknown = true`.
On the section-4 tree (`app` declares `max = ["Stdio", "Net"]` and
depends on the native `extcrypto`):

```
$ python -m capa --check-capabilities main.capa ; echo "exit=$?"
capa: --check-capabilities: FAILED - 1 ceiling violation(s):
  - package 'app' declares a capability ceiling but its composed authority is UNKNOWN: dependency 'extcrypto' of 'app' is not analyzable (package directory has no capa.toml (native / non-Capa dependency; its authority cannot be derived)) (via app); an unanalyzable subtree cannot be proven within any ceiling
exit=1
```

With `allow_unknown = true` in `app`'s ceiling, the TOP failure is
waived (a positive concrete violation would still fail):

```
$ python -m capa --check-capabilities main.capa ; echo "exit=$?"
capa: --check-capabilities: OK - every declared capability ceiling holds.
exit=0
```

**The ceiling check is SELF-SCOPED and stricter than the roll-up.**
The product roll-up's TOP trigger is `has_unsafe` ONLY
(`_own_authority`): a closure's authority is accounted for in the
package where the closure is CREATED, so a package that merely TAKES a
`Fun(...)` and invokes it gains no authority of its own. The ceiling
check is DIFFERENT: a ceiling is a claim about the declaring package's
subtree, into which a caller can inject authority the types never
named through an exposed higher-order function; so the check
additionally requires the declaring package's own authority to be
provable from the types, reading the per-function
`ceiling_authority_provable` signal. This tighter rule lives only in
the ceiling check; feeding it into the roll-up value would corrupt
the product join.

**Fails closed on stale evidence.** `build_composed_sbom` refuses a
per-program manifest with `schema_version` below
`_MIN_MANIFEST_SCHEMA_FOR_CEILING = 2` (`_compose.py` lines 116 and
1490), because an older manifest does not carry the
`authority_provable_from_types` signal the self-scoped check needs.
(NOT VERIFIED by execution: the whole CLI path builds a CURRENT
manifest, so this guard is unreachable from the CLI; it is read code,
reachable by library callers or stale artefacts.)

---

## 6. `--capability-diff` and `--fail-on-widening`: the authority changelog

`--capability-diff <old.json> <new.json>` produces a first-class
authority changelog between version N and N+1 of a program: which
capabilities each exported function (and the product) GAINED
(widening) or LOST (narrowing) (`build_capability_diff`,
[`capa/manifest/_diff.py`](../capa/manifest/_diff.py) line 470). It
operates on two JSON files that
`--manifest`/`--manifest-digest`/`--compose-sbom` already emit; it
does NOT take `.capa`.

**The critical decision: stable identity.** Functions are matched
between the two versions by the stable key `(container, name)`, NEVER
by `pos`: `file:line:col` changes every release, and a function that
only MOVED LINES is not an authority change. The diff is
POSITION-INDEPENDENT: two manifests identical except for line numbers
produce an EMPTY diff.

**How widening versus narrowing is decided** (module docstring): a
cap that ENTERED `transitively_reachable` = ADDED = widening; a cap
that LEFT `provably_excluded` = GUARANTEE LOST = widening (the subtle,
high-value signal: it fires even when the cap is not named in the new
signature, for example when the function gained an `Unsafe` /
higher-order parameter that voids the whole exclusion proof; a
scanner does not see this); the inverses are narrowings. Only
EXPORTED (`pub`) functions appear per function; a private widening
contributes to the product's COMPOSED set delta (subject to set-union
cancellation). A product transition authority-KNOWN -> UNKNOWN (a new
native dep: a TOP appeared) is a high-severity widening.

Over a version that gains `Net` (`fetch(s: Stdio)` ->
`fetch(s: Stdio, n: Net)`), measured (trimmed):

```
$ python -m capa --capability-diff old.json new.json
  "functions": [
    { "name": "fetch", "container": null, "classification": "widening",
      "added": [ "Net" ], "removed": [],
      "guarantee_lost": [ "Net" ], "guarantee_gained": [] }
  ],
  "product": { "composed_added": [ "Net" ], "composed_removed": [],
    "authority_unknown_transition": null, ... },
  "summary": { "widenings": 1, "narrowings": 0,
    "authority_unknown_regression": false }
```

The changelog is itself wrapped in the S1 envelope and records
`from_digest` / `to_digest` (the S1 digests of the two exact inputs),
so it is content-addressable, signable, and provably about those two
manifests (measured: both digests present in the output).

**`--fail-on-widening` is the gate.** It exits NON-ZERO when the
changelog has any widening or an authority-UNKNOWN transition; pure
narrowing / no change exits 0:

```
$ python -m capa --capability-diff old.json new.json --fail-on-widening ; echo "exit=$?"
capa: --capability-diff: FAILED --fail-on-widening: 1 widening(s)
exit=1
$ python -m capa --capability-diff new.json old.json --fail-on-widening ; echo "exit=$?"
exit=0
```

**Diff soundness guards.** Both inputs must be of the SAME shape
(manifest versus manifest, or composed SBOM versus composed SBOM);
mixing them is a category error refused with `DiffError`. PUBLIC
limitation (documented in the module): `guarantee_lost` /
`guarantee_gained` compare exclusion sets that may come from compiler
versions with a different capability UNIVERSE, which can fabricate a
spurious entry; this FAILS SAFE (a false widening BLOCKS the gate,
never passes falsely).

---

## 7. `--check-policies` and `--conformance-report`: organization policies

S2 produced the composed graph;
[`capa/manifest/_policy.py`](../capa/manifest/_policy.py) turns it
into an ORGANIZATION compliance layer. An auditor writes a
`capa-policy.toml` (`POLICY_FILENAME`, line 81) at the product root,
DISTINCT from any per-package `[capabilities]` ceiling, declaring
rules over a FIXED, enumerated set of predicate kinds
(`_POLICY_KINDS`, line 89):

| `kind` | What it requires |
|---|---|
| `exclusion` | no package may hold capabilities X and Y at once |
| `product-subset` | the product's composed authority must be a subset of a declared set |
| `purity` | a named package (or all) must be pure (reach no capability) |
| `forbid-capability` | no package (or a named one) may hold a given capability |
| `forbid-dependency` | a named package may not depend (directly or transitively) on another |
| `no-unresolved-dependencies` | the product may have no unresolved dependency |
| `no-declassification` | a named package (or the product) must have ZERO audited `@secret -> @public` declassifies |
| `no-secret-egress` | no secret value may reach a declared egress capability (via audited declassify+egress co-residence OR a raw unaudited secret-to-sink flow the IFC analysis proved) |

The parser is strict/closed: an unknown `kind` or a key outside the
allowed union for that kind is a hard error, never a silently ignored
policy. The evaluator (`evaluate_policies`) is PURE over what the
composed SBOM already emits (`packages` / `edges` /
`unresolved_dependencies` / `composed`): no new manifest data, no
type-system change.

**Fails closed over authority-UNKNOWN, with a distinct verdict.** A
predicate that quantifies over a package (or the product) whose
composed authority is TOP cannot be PROVEN (an unanalysable subtree
could hold any capability), so it FAILS CLOSED with the
`authority_unknown` verdict (distinct from a positively observed
violation), unless the policy sets `allow_unknown = true`.
`no-unresolved-dependencies` is the exception: it reports the
unresolved edges directly (verdict `violation`). On the section-4 tree
with three policies (`forbid-capability` of `Proc`, `exclusion` of
`Net`+`Fs`, `no-unresolved-dependencies`):

```
$ python -m capa --check-policies main.capa ; echo "exit=$?"
capa: --check-policies: FAILED - 3 policy(ies), 3 violation(s):
  policy 'no-proc' (kind forbid-capability):
    - [authority_unknown] policy 'no-proc' (forbid-capability 'Proc') cannot be verified over package 'app': its composed authority is UNKNOWN (an unresolvable / native / Unsafe-crossing dependency in its subtree), so an unanalyzable subtree cannot be proven to satisfy the policy. Set allow_unknown = true to waive.
  policy 'net-fs-exclusive' (kind exclusion):
    - [authority_unknown] policy 'net-fs-exclusive' (exclusion of ['Fs', 'Net']) cannot be verified over package 'app': its composed authority is UNKNOWN (...). Set allow_unknown = true to waive.
  policy 'all-deps-resolved' (kind no-unresolved-dependencies):
    - [violation] package 'app' has an unresolved dependency 'extcrypto' (package directory has no capa.toml (native / non-Capa dependency; its authority cannot be derived)), which policy 'all-deps-resolved' forbids
exit=1
```

Both verdicts are visible: `authority_unknown` (cannot be PROVEN over
a TOP subtree) versus `violation` (a positive concrete violation).

**`--conformance-report` is the signable evidence, not the gate.** It
evaluates the same policies and prints the report wrapped in the SAME
S1 content-integrity envelope (measured: `content_integrity` present;
with `capa-policy.toml` absent the report is empty). Measured
structure (trimmed):

```
$ python -m capa --conformance-report main.capa   # results
  "results": [
    { "policy": "no-proc", "kind": "forbid-capability", "pass": false,
      "violations": [ { "verdict": "authority_unknown", ... } ] },
    ...
    { "policy": "all-deps-resolved", "kind": "no-unresolved-dependencies",
      "pass": false, "violations": [ { "verdict": "violation", ... } ] }
  ],
  "pass": false
```

`--check-policies` is the CI gate (same evaluation, non-zero exit on
failure); `--conformance-report` is the same computation wrapped as a
content-addressable artefact.

---

## 8. Notes

- **Scope of the measurements.** The pasted outputs come from: a
  minimal `Stdio`-only program (`hello.capa`); the H-F1 factory
  program (`hf1.capa`); two versions of a `fetch` program for the
  diff; and ONE product tree built for the purpose, with a root
  package `app`, a resolvable path dependency `logger` (Capa source
  linked by `import`), and a NATIVE path dependency `extcrypto`
  (no `capa.toml`) exercising the authority-UNKNOWN element. All at
  `8e2c609`, from a scratch folder. Composition was exercised on a
  real multi-package product (DAG, per-package attribution, TOP,
  ceiling, policies), not just a single program.
- **MEASURED versus JUDGEMENT.** MEASURED: the outputs of
  `--manifest`, `--manifest-digest` (envelope plus determinism),
  `--compose-sbom` (DAG, attribution, TOP, stable digest),
  `--check-capabilities` (fail-closed and the `allow_unknown`
  waiver), `--capability-diff` plus `--fail-on-widening` (both
  directions), and `--check-policies` / `--conformance-report`; the
  line numbers and schema values in `capa/manifest/`. JUDGEMENT: the
  characterizations of WHY a choice is sound (the `has_unsafe`-only
  roll-up versus the self-scoped ceiling check; the voided exclusion
  proof instead of over-claiming; the diff's capability-universe
  fail-safe) are readings of the cited docstrings and comments, not
  theorems re-proved here.
- **Relation to the formal proofs.** `--manifest` corresponds to
  Theorem 2 (Manifest Completeness) of
  [`proofs/README.md`](../proofs/README.md), proved for the core
  `lambda_cap` calculus: the manifest declares exactly the capability
  footprint a term can exercise. The gated variant
  `CapaManifestExact.agda` does NOT yet prove surface exactness, and
  `proofs/README.md` says so. Composition (S2/S3), the diff and the
  policies have NO mechanized proof; they are constructions over the
  manifest, verified by test and execution.
- **NOT VERIFIED by execution.** (1) The fail-closed guard over
  manifest `schema_version < 2` in `build_composed_sbom` is read
  code, unreachable from the CLI. (2) The
  `enforcement_posture = "wasm-sandbox"` posture (a BOUNDED instead
  of TOP node for a foreign boundary under `--wasm`) was not
  exercised here; all pasted outputs carry
  `enforcement_posture: "none"`. (3) Cross-directory reproducibility
  of `--compose-sbom` was not confirmed by execution: digest
  stability was verified between two invocations from the SAME
  folder.

---

## Links

- [11-builtin-capabilities.md](11-builtin-capabilities.md): the 10
  built-in capabilities (`CAPABILITY_NAMES`) the manifest reads as its
  source of truth.
- [12-attenuation.md](12-attenuation.md): the attenuation the
  manifest's `args_flow` records, and the `[capabilities]` ceiling
  `--check-capabilities` verifies.
- [13-user-defined-capabilities.md](13-user-defined-capabilities.md):
  the `user_defined_capabilities` and their `implementors`.
- [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md): the
  audited `declassifications`, the `unaudited_secret_sinks`, and what
  `constant_time` attests.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  `operator_declared_grants` (`--preopen` / `--allow-host`), the
  `compiler_derived_path_arg_surface`, and the `wasm-sandbox`
  enforcement posture.
- [30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md): the external
  format wrappers (CycloneDX, SPDX) over the same internal manifest.
- [`docs/packages.md`](../docs/packages.md): the dependency model
  (`capa.toml`, path versus git, `vendor/`, `capa.lock`, signatures)
  that feeds the composed SBOM's DAG.
- [`proofs/README.md`](../proofs/README.md): Theorem 2 (Manifest
  Completeness) and the core-versus-implementation gap
  (`CapaManifestExact.agda`).
