# The field-qualified cross-function return channel (IFC)

Status: Landed on `main`, post-1.31.0, NOT yet in a released version.
Date: 2026-08-16.

State of the record: the last published version is 1.31.0. The work
described here is a run of commits on `main` with NO version bump, NO
advisory, and NO GHSA / CWE / CVE identifier (Capa's release cadence:
soundness fixes land as commits, and the version, CHANGELOG entry and
security advisory are cut at the next STABLE release). This record
captures the design, the mechanism, the verification and the residuals
now, while fresh, so the eventual release advisory is accurate. It is
the in-repo analogue of the per-release website design records
(`design_1_30_0.html` .. `design_1_31_0.html`); it should be lifted to a
per-version page plus an advisory when the release that ships it is cut.

Every claim below is labelled MEASURED (read from the tree at the commit
named, or run and its output pasted) or JUDGEMENT (reasoned inference).

Tree under description: `git rev-parse HEAD` is
`14ff2ab599635abdcb0ba8c3f738bf6e666292a1` (MEASURED). All file and line
references are into that tree. Before/after runs use two `git archive`
extracts (base `a095eef`, the commit immediately before this work line;
after `14ff2ab`), each run with its own extract as CWD so that
`capa.__file__` resolves inside the extract (verified below).

---

## 1. Summary

This is one information-flow (IFC) soundness work line delivered as two
merges. It makes the analyzer's cross-function RETURN channel
FIELD-QUALIFIED, so a `@secret` value that reaches a public sink THROUGH
A RETURNED FIELD (a field stored into a returned local struct, or a
nested declared-`@secret` field returned directly) is no longer laundered
public. Before it, both shapes were `capa --check`-clean at the default
tier AND under `@strict_ifc`, and the secret printed at run time on both
the Python interpreter and the Wasm Component Model backend.

The two merges are one channel, not two unrelated fixes: both close a
`@secret` that a callee delivers to the caller AS PART OF a returned
struct, and both are made possible by the same schema change to
`return_effects` (a flat source set could not distinguish which field of
a returned value carried the taint).

- Merge `a31fccc` ("field-qualified return channel"): `d28ab67`
  (field-qualify the summary pass-to-callee sink gate, a no-op guard that
  is the prerequisite), `b26aefd` (migrate `return_effects` from a flat
  `frozenset(sources)` to a per-path field map `{field_path -> sources}`,
  behaviour-preserving, everything recorded at `()`), `ffee175` (close
  the local field-store return laundering, field-precisely, using the new
  schema and a per-path content channel).
- Merge `14ff2ab` ("deep field-access return channel"): `89bbcd7` (close
  the cross-function deep, >=2-hop, field-access return leak: recognise
  `return t.f2.f3.v`, not only depth-1 `return t.f`), `c2aecc5` (correct a
  Fun-result docstring scope, text only), `c359914` (complete the
  residual disclosure, text only).

Severity is confidentiality-only, a silent false negative in the IFC
noninterference property. There is no integrity, availability, or
capability-discipline impact. (JUDGEMENT, consistent with the framing of
the prior IFC advisories; the noninterference guarantee is claimed only
under `@strict_ifc`, where the flow is a hard error, and by default it is
a warning.)

---

## 2. Problem and threat

Property at stake (MEASURED framing, unchanged from the 1.31.0 record): a
`@secret` value must not reach a public sink (`Stdio.println` /
`eprintln`, `Net.post`, `panic`, a sink-reaching parameter of a further
function) without an explicit `declassify(value, reason: "...")`. The
cross-function analyzer proves this across function boundaries by
computing, per callable, three summaries used here: `sink_summaries`
(which parameters reach a sink), `field_effects` (what a callee writes
into a parameter-rooted object) and `return_effects` (what flows into the
callee's RETURNED value). A caller consults `return_effects` to decide
whether a call RESULT is `@secret`.

Threat model: a silent false negative. The author writes `@secret`,
believes they are protected, and a build that gates noninterference on
`@strict_ifc` passes while the secret escapes at run time on both
backends.

Two concrete pre-fix leaks (both MEASURED, see section 6):

- Local field-store return (`ffee175`). A callee reads a
  declared-`@secret` field, stores it into a FRESH LOCAL struct, and
  returns the local; the caller sinks the stored field. The direct field
  store recorded only a cross-function mutation EFFECT, which needs a
  PARAMETER-rooted target, so a fresh local recorded nothing, and the
  local's return content was never raised. `return_effects` for the
  callee carried no `@secret` source, so the caller judged the result
  public.

- Deep field-access return (`89bbcd7`). A callee returns a NESTED
  declared-`@secret` leaf of a struct parameter (`return t.f2.f3.v`, leaf
  `v` labelled `@secret`). The summary recognised a declared-`@secret`
  field read only when the receiver was an `Ident` (depth 1,
  `return e.iban`); a chain whose receiver is itself a `FieldAccess`
  attributed no `INTERNAL_SECRET`, so the return effect at `()` carried
  only the harmless param index.

Both are the sibling of an already-closed shape: the deep-access leak is
the read-side sibling of the field-store leak, and both are downstream of
the fact that the pre-migration `return_effects` was a flat source set
that could not say WHICH FIELD of a returned struct carried the source.

---

## 3. Model and prior art

Cross-function summary-based IFC. The analyzer is a whole-program,
summary-based information-flow analysis: each callable is reduced to a
fixed set of finite summaries (sink-reaching parameters, field-write
effects, return effects), computed to a monotone fixpoint, and callers
compose the summaries of their callees rather than re-analyzing bodies.
This is the standard shape of a modular / summary-based taint analysis
(JUDGEMENT: the design follows the general summary-based dataflow
tradition; no specific paper is cited in the commits, and none is
re-derived here). The underlying security property is noninterference
(Goguen and Meseguer, 1982): a public observation must not depend on a
secret input; `declassify` is the endorsed, audited downgrade (principled
declassification, Sabelfeld and Sands, 2005). These frame the mechanism;
they are not re-derived here (JUDGEMENT).

Novelty of this work line: the return summary becomes ACCESS-PATH
QUALIFIED. Instead of "this call result carries source s", the summary
records "this FIELD PATH of the call result carries source s". This is
the return-channel mirror of the field-precise `(root, field-path)`
container / field-store channel the intra-procedural pass already used
(the 1.30.1 access-path channel). The k-bounded field path with a
whole-value fallback (`_MAX_FIELD_PATH = 5`, over-long or unkeyable paths
collapse to a sentinel) is the standard finiteness device that keeps the
summary lattice finite so the fixpoint terminates (MEASURED: the bound is
declared and used, section 4; JUDGEMENT: that this is the reason is the
documented rationale in `_return_path_key`).

---

## 4. Mechanism

All references are into `capa/analyzer/_ifc_summary.py` and
`capa/analyzer/_ifc.py` at `14ff2ab` (MEASURED). The work is
ANALYZER-ONLY: no code-generation or runtime file is touched, so both
backends stay byte-identical and only the `--check` verdict changes (see
the commit bodies of `ffee175` and `89bbcd7`, and section 6).

### 4.1 The `return_effects` schema migration (`b26aefd`)

`return_effects` changed from `{callable_key: frozenset(sources)}` to
`{callable_key: {field_path -> frozenset(sources)}}`
(`_ifc_summary.py:269`), carried on the SAME monotone fixpoint via
`_merge_effects` (`_ifc_summary.py:858`), which merges a map of
target-key to source-set and returns whether the accumulator grew
(`_ifc_summary.py:823` merges `returns` into `self.return_effects[key]`).
In this commit every source is recorded at the whole-value sentinel `()`
and every reader unions over all paths, so the migration is
behaviour-preserving (MEASURED: the commit body states "no verdict
changes, no test moves"; the readers at `_ifc_summary.py:2243`,
`_ifc.py:676`, `_ifc.py:3001` and `_ifc.py:3023` all iterate
`sources.items()` and union the per-path source sets).

Why a flat source set laundered a returned field: a flat
`frozenset(sources)` records THAT a source reaches the return, not WHICH
FIELD of the returned value carries it. The field-store closure
(`ffee175`) needs to record a source at a SPECIFIC returned field path so
that a disjoint public sibling of the returned struct stays clean; a flat
set cannot express that, so without the migration the field-store closure
would have had to taint the WHOLE returned value unconditionally
(regressing precision) or not at all (the leak). The migration is the
schema those two later commits key onto (MEASURED: commit body of
`b26aefd`, "the schema Part 3 needs").

The migration also fixed a latent crash in a reader. The independent
design contest of this schema caught that `_method_call_return_label`
(`_ifc.py:2937`) previously iterated the flat source set with a scalar
`0 <= s` test; against a per-path map that test would run on a TUPLE path
key and raise `TypeError: '<=' not supported between instances of 'int'
and 'tuple'`. The reader now iterates the per-path source SETS
(`_ifc.py:3001`, with the comment at `_ifc.py:2997` recording exactly
this hazard) (MEASURED: read at those lines; the `int <= tuple` shape is
why the readers iterate `sources.items()` rather than the map directly).

### 4.2 The field-qualified pass-to-callee sink gate (`d28ab67`)

`_sink_reaching_arg` (`_ifc_summary.py:2083`) is the prerequisite guard.
When a caller argument binds to a callee's sink-reaching parameter, the
caller previously marked the whole argument taint sink-reaching, which for
an Ident-rooted chain folds in the CONTENT channel read at the WHOLE
value. `d28ab67` splits that: the whole-value BASE taint of the argument
always reaches (the false-negative-safety floor, via
`_base_taint_of` at `_ifc_summary.py:2113`), while the CONTENT channel is
observed only at the callee's SUNK paths, composed with the caller's
access prefix (`_content_at` over `prefix + sp` at
`_ifc_summary.py:2114`). It is wired at the free-call, method-self and
method-explicit gates (MEASURED: the free-call site is
`_ifc_summary.py:2197`). This is a NO-OP on the corpus at the time
(MEASURED: commit body; the content channel then carried only
container-mutation taint keyed at `()`, prefix-compatible with every sunk
path). It is the guard so that when `ffee175` later writes a field-store
CONTENT taint on a disjoint sibling, that taint does not reach a callee
that sinks only a clean path.

### 4.3 The local field-store return closure (`ffee175`)

Three pieces in the summary CONTENT channel (MEASURED, commit body and
code):

- A direct field store `obj.f = v` now content-writes the root at the
  STORED field's path (`_walk_stmt` AssignStmt / FieldAccess branch,
  `_ifc_summary.py:1294`, seeding via `_seed_content_value` at
  `_ifc_summary.py:1206`), so a same-body read-back of that path, a whole
  read, or a return of the LOCAL observes it, while a disjoint public
  sibling stays clean.
- A struct-literal RHS is LEAF-SEEDED per leaf path
  (`_seed_content_value` recurses on `A.StructLit`,
  `_ifc_summary.py:1222`), so a clean leaf of a stored sub-struct stays
  clean.
- The return-read records a returned LOCAL's content per path, bounded by
  `_MAX_FIELD_PATH` with a `()` fallback (`_record_return`,
  `_ifc_summary.py:1232`; a bare-Ident LOCAL copies its content bucket
  through `_return_path_key` at `_ifc_summary.py:1255` plus its
  whole-value base at `()`; every OTHER return shape, a `return o.sub`,
  a call, a literal, an unwrap, a param, records the whole-value carrier
  `()` at `_ifc_summary.py:1261`).

Why the non-local return shapes fall back to `()` (MEASURED, commit body
and `_record_return` docstring): for a `return o.sub` the returned value
is a SUB-object; recording a SOURCE-relative path there would misplace
the taint relative to the caller's view of the result and DROP it. That
is the `G_subreturn` trap, so those shapes deliberately keep the
whole-value carrier and stay flagged (an accepted over-approximation).

The return channel therefore stays WHOLE-VALUE at the boundary (a sink of
ANY field of a returned struct that received an inside-callee secret
flags); the per-field precision is delivered INTRA-BODY (a store into one
local field taints only that field's read-back, not a disjoint sibling).

### 4.4 The deep field-access chain walk (`89bbcd7`)

`_field_read_is_secret` (`_ifc_summary.py:1520`) is the recogniser
consumed by `_base_taint_of` (`_ifc_summary.py:1181`, which adds
`INTERNAL_SECRET` (= -1, `_ifc_summary.py:213`) to the read's taint when
it returns True). It was extended from a depth-1 Ident-receiver check to
a type-precise, root-rooted CHAIN WALK:

- `_collect_secret_fields` (`_ifc_summary.py:466`) now also builds
  `struct_field_type_names` (`{struct type -> field name -> declared type
  name}`, populated at `_ifc_summary.py:489`) from the SAME
  `fld.type_expr.name` the label walk reads.
- `_field_read_is_secret` resolves the chain ROOT's type from a
  per-callable value-type map `_cur_value_types` (`_ifc_summary.py:1586`),
  walks the declared field types hop by hop through
  `struct_field_type_names` down to the leaf's owning struct
  (`_ifc_summary.py:1590`), and tests the leaf's declared label
  (`_ifc_summary.py:1594`). Depth-1 is the same walk with an empty prefix.
- Each hop follows the ACTUAL declared field type, never a field-name
  match (`_ifc_summary.py:1591`), so a same-named public field of an
  UNRELATED struct is not flagged (no by-name false positive; verified in
  section 6).
- `_cur_value_types` is seeded with the parameter types
  (`_ifc_summary.py:990`) and grown ONLY by a `let` / `var` binding whose
  pattern is a bare `IdentPat` and whose RHS statically denotes a struct
  (`_record_value_type` at `_ifc_summary.py:1650`, driven from
  `_walk_stmt` at `_ifc_summary.py:1274` for `let` and
  `_ifc_summary.py:1284` for `var`; `_static_struct_type` at
  `_ifc_summary.py:1623` recognises a param copy `let u = t`, a
  param/local field chain `let u = t.f2`, and a struct literal). So
  `let u = t; return u.f2.f3.v` and `let u = t.f2; return u.f3.v` are
  covered too.

The recovered `INTERNAL_SECRET` is recorded at the `()` key by the
existing `_record_return` whole-value path, so this commit needs no
further schema change and `_MAX_FIELD_PATH` never truncates it (MEASURED,
commit body).

### 4.5 Two guards that neutralise the flat value-type map's conflation
risk

`_cur_value_types` is a FLAT map keyed by NAME. If a name were bound twice
to different struct types in one body, or an annotation disagreed with the
RHS type, the root-type resolution could be wrong. Two pre-existing
guards make that unreachable (both MEASURED, section 6): the analyzer
hard-rejects a duplicate binding of the same name in a scope (exit 1), and
the type checker enforces that a `let`/`var` annotation equals the RHS
type (exit 1). So a name in `_cur_value_types` cannot silently denote a
struct type other than the one it actually holds.

---

## 5. Alternatives considered and why rejected

- Keep `return_effects` a flat source set and taint the whole returned
  value whenever a callee stores an inside-callee secret into a returned
  local (rejected, `b26aefd` + `ffee175`). This closes the leak but
  regresses the intra-body field precision (a disjoint public sibling of
  the returned struct would over-report). The per-path map plus a per-path
  content channel keeps the leak closed AND the sibling clean (verified in
  section 6, `sibling_clean`).

- Record a SOURCE-relative field path for every return shape, including
  `return o.sub` (rejected, `ffee175`). Recording a source-relative path
  on a sub-object return misplaces the taint relative to the caller's view
  and DROPS it (the `G_subreturn` false negative). The closure records a
  per-path key only for a bare-Ident LOCAL return and falls back to the
  whole-value `()` carrier for every other shape, which keeps those shapes
  flagged.

- Match a returned deep field by FIELD NAME (rejected by design,
  `89bbcd7` / `c359914`). A by-name match would flag a public field that
  merely shares a name with an `@secret` field of an UNRELATED struct (a
  false positive). The walk follows the declared field TYPE at each hop
  instead, resolved from `struct_field_type_names`, so only the genuine
  `@secret` leaf on the genuine type is flagged (verified: `same_name`,
  section 6).

- Seed `_cur_value_types` for every local binding shape (rejected,
  `c359914`). Only a bare-`IdentPat` binding whose RHS statically denotes
  a struct is seeded, because a call/index-rooted RHS, a for-loop binder,
  and a struct-destructuring field-name binder cannot be resolved to one
  certain struct type without a heavier analysis. These three are left as
  disclosed whole-value fallback residuals (section 7) rather than guessed
  at.

---

## 6. Verification

### 6.1 Before/after runs (MEASURED)

Two `git archive` extracts, base `a095eef` (immediately before this work
line) and after `14ff2ab` (HEAD), each run with its own extract as CWD.
`capa.__file__` was confirmed to resolve inside each extract before
trusting output:

```
before: ...\scratchpad\before\capa\__init__.py
after : ...\scratchpad\after\capa\__init__.py
```

Deep field-access return, `deep3.capa`:

```
type Inner { v: @secret String, note: String }
type Mid { f3: Inner }
type Outer { f2: Mid }
fun leak(t: Outer) -> String
    return t.f2.f3.v
fun main(stdio: Stdio)
    let o = Outer { f2: Mid { f3: Inner { v: "s3cr3t", note: "pub" } } }
    stdio.println(leak(o))
```

BEFORE (`a095eef`): `--check` clean at the default tier, leaks on both
backends.

```
$ python -m capa --check deep3.capa
deep3.capa: ok (5 items, 13 expressions typed, 4 bindings)     # exit 0
$ python -m capa --run deep3.capa
s3cr3t                                                          # exit 0
$ python -m capa --run --wasm deep3.capa
s3cr3t                                                          # exit 0
```

AFTER (`14ff2ab`): warns at the default tier, hard error under
`@strict_ifc` (exit 1); still prints at run time because a warning does
not block, on both backends.

```
$ python -m capa --check deep3.capa
deep3.capa:8:19: warning: information-flow: a @secret value reaches
  Stdio.println (argument 1), a public sink that sends data out of the
  program. Route it through declassify(value, reason: "...") ...
deep3.capa: ok (5 items, 13 expressions typed, 4 bindings)     # exit 0

$ python -m capa --check deep3_strict.capa    # @strict_ifc() on main
deep3_strict.capa:9:19: error: information-flow: a @secret value reaches
  Stdio.println (argument 1), a public sink ...
deep3_strict.capa: 1 error                                     # exit 1

$ python -m capa --run deep3.capa             # warning, then leaks
s3cr3t                                                          # exit 0
$ python -m capa --run --wasm deep3.capa      # warning, then leaks
s3cr3t                                                          # exit 0
```

The runtime leak is backend-independent (`s3cr3t` printed on both
backends on both commits); the analyzer is what should reject it, and
after `14ff2ab` it does. This is the byte-identical-both-backends parity
claim for this shape (MEASURED).

Local field-store return, `l2field.capa` (callee reads a
declared-`@secret` field, stores it into a fresh local `Box`, returns the
local; caller sinks the stored field):

```
BEFORE (a095eef):  l2field.capa: ok (...)            # clean, leak
AFTER  (14ff2ab):  l2field.capa:10:19: warning: information-flow ...
```

Precision negatives, AFTER (`14ff2ab`), each `ok` with ZERO
information-flow diagnostics (MEASURED):

- `sibling_clean.capa`: store a secret into `box.a`, sink the disjoint
  sibling `box.b`. Clean; runs and prints `public`. (Intra-body field
  precision preserved.)
- `samename.capa`: return `t.f2.f3.v` where `v` is public on `BInner`,
  though an UNRELATED `AInner` declares `v: @secret`. Clean (0
  information-flow lines). (Type-precise walk, no by-name false positive.)

Conflation guards, AFTER (`14ff2ab`) (MEASURED):

- Duplicate binding: `let u = a` then `let u = b` (different struct types)
  is rejected: `error: duplicate binding 'u' ...`, exit 1.
- Annotation vs RHS type: `let u: B = a` where `a: A` is rejected:
  `error: let binding: expected B, got A`, exit 1.

Call-rooted deep chain residual (section 7 (a)), AFTER (`14ff2ab`)
(MEASURED): `return id(t).f2.f3.v` stays `--check`-clean and leaks
`s3cr3t` at run time. Confirmed open.

### 6.2 Tests that pin it (MEASURED)

Running the three test files added / touched by this work line at
`14ff2ab`:

```
$ python -m pytest tests/test_ifc_deep_field_return.py \
    tests/test_ifc_local_field_store_return.py \
    tests/test_ifc_param_carried_readback.py -q
48 passed, 135 subtests passed in 2.07s
```

Pinned shapes: `test_ifc_deep_field_return.py` pins the flagged deep
shapes (`3hop`, `reentry`, `local_copy`, `local_field`, `self`,
`struct_built`, `2hop`) at both tiers on both backends
(`TestDeepFieldReturnLeak`), the type-precise no-false-positive negatives
(`public_leaf`, `never_sunk`, `same_name`,
`TestDeepFieldReturnNoFalsePositive`), and the call/index-rooted residual.
`test_ifc_local_field_store_return.py` pins the flagged local field-store
returns (`L2_field`, `C_nested`, `E_opaque`,
`TestLocalFieldStoreReturnLeak`), the intra-body field precision
(`I_barelocal`, `TestBareLocalFieldPrecision`), the returned-but-not-sunk
clean dual (`TestReturnedButNotSunkIsClean`), and the `G_subreturn` /
`H_alias` anti-false-negative shapes. `test_ifc_param_carried_readback.py`
gains the deep param-carried tainted-chain / public-twin acceptance test
from `d28ab67`.

Scope of the suite figure (honest): the `48 passed, 135 subtests` figure
is MEASURED by this record on the current tree. The full repository suite
figure is NOT re-run or cited here (the working tree carries unrelated
uncommitted changes, `deploy/install.ps1.sha256` and `envprobe/`, left
untouched). What is measured here is the three pinning files, the
before/after on both backends, and the file/line references in section 4.

### 6.3 Independent review (folded in, not re-derived)

MEASURED that these were established before the record: the design
contest caught the `int <= tuple` crash in `_method_call_return_label`
during the migration, which is why the readers iterate `sources.items()`
(confirmed in the code at `_ifc.py:2997`-`3001`). The reviewer diff-review
SHIP'd merge `14ff2ab` with 0 new false negatives / false positives across
the fleet, and the pentester found no new false negative, no new false
positive, and no new cross-backend divergence, with the flat value-type
map's conflation risk neutralised by the two guards re-confirmed above.
JUDGEMENT: this record independently re-ran the closed leaks, the two
precision negatives, the two guards, and one residual; it did not re-run
the whole fleet.

---

## 7. Scope and residuals

MEASURED framing of what is CLOSED: a `@secret` reaching a public sink
through a RETURNED value of a free function or self-method is now caught
when (a) the callee reads a declared-`@secret` field (at any depth of a
type-resolvable, Ident-rooted or seeded-local-rooted chain) and returns
it directly, or (b) the callee field-stores an inside-callee secret (a
declared-`@secret` field read, or an opaque call returning one) into a
bare-Ident LOCAL struct and returns that local. Intra-body field
precision is delivered (a disjoint public sibling stays clean); the return
boundary itself is whole-value (a sink of any field of a returned struct
that received an inside-callee secret flags, an accepted
over-approximation).

Open false-negative residuals (each a tested / measured leak that runs
UNFLAGGED at both tiers on both backends). Whole-value `()` fallback,
pre-existing, out of scope:

- (a) A CALL / INDEX-rooted deep chain (`return id(t).f2.f3.v`): the chain
  has no ident root (`_chain_root_name` returns `None`,
  `_ifc_summary.py:1598`), so no root type resolves. MEASURED open in
  section 6. Same class as `G_subreturn` / `H_alias`.
- (b) A FOR-LOOP binder (`for u in secs` with body `return u.f2.f3.v`):
  `ForStmt` binds `u` but never calls `_record_value_type`, so `u` is
  unseeded in `_cur_value_types`. Disclosed in `_field_read_is_secret`
  (`_ifc_summary.py:1564`); not re-run in this record (JUDGEMENT: covered
  by the same unseeded-root mechanism as (a)).
- (c) A struct-DESTRUCTURING field-name binder
  (`let Outer { f2 } = t; return f2.f3.v`) when the `@secret` leaf is
  nested BELOW the destructured field: only a bare `IdentPat` binding is
  recorded, so `f2` is unseeded. Disclosed at `_ifc_summary.py:1568`; not
  re-run here.

Inherited field-store `(root, field-path)` points-to residuals (the same
channel the container / field-store fixes use, so this inherits its
points-to gaps; pre-existing, out of scope):

- A container renamed out of the struct
  (`var lst = bag.items; lst.push(secret)`).
- A mutator rooted at a call or an index
  (`get_items(bag).push(secret)`, `arr[0].items.push(secret)`).
- A struct reached through a container VALUE or ELEMENT read.

(JUDGEMENT: these mirror the residuals disclosed in the 1.30.1 / 1.31.0
records for the same `(root, field-path)` channel; not independently
re-run here.)

Sound over-approximation (flags though nothing secret escapes, never the
reverse): the return BOUNDARY is whole-value, so a sink of a CLEAN sibling
field of a returned struct that received an inside-callee secret into a
DIFFERENT field flags. This over-reports, never under-reports (MEASURED
framing from the `ffee175` commit body; the accepted counterpart of the
`C_nested` / `E_opaque` closes).

One pre-existing Wasm code-generation residual, disclosed so silence does
not imply the shape is clean on Wasm (MEASURED, reproduced). A zero-arg
lambda assigned to a local and then called, whose body returns a captured
struct's DEPTH-3 field, crashes the Wasm backend at compile time while the
Python backend prints the secret. Exact program (`wasmcrash_exact.capa`):

```
type Inner { v: @secret String, note: String }
type Mid { f3: Inner }
type Outer { f2: Mid }
fun main(stdio: Stdio)
    let o = Outer { f2: Mid { f3: Inner { v: "s3cr3t", note: "pub" } } }
    let f = fun () => o.f2.f3.v
    stdio.println(f())
```

On `14ff2ab` (capa.__file__ confirmed inside the extract):

```
$ python -m capa --check wasmcrash_exact.capa
wasmcrash_exact.capa: ok (4 items, 13 expressions typed, 3 bindings)   # exit 0
$ python -m capa --run wasmcrash_exact.capa
s3cr3t                                                                 # exit 0
$ python -m capa --run --wasm wasmcrash_exact.capa
wasmtime._error.WasmtimeError: failed to compile: wasm[0]::function[3]::lambda_0
Caused by:
    0: WebAssembly translation error
    1: Invalid input WebAssembly code at offset 344: type mismatch:
       expected i64, found i32                                        # exit 1
```

Pre-existing (MEASURED): the SAME crash, byte-identical text and offset,
occurs on the base extract `a095eef` (immediately before this work line),
so it is NOT introduced here. Two facts of note. First, this crash is a
code-generation defect, a Wasm/Python DIVERGENCE (Python prints, Wasm
fails to compile), distinct from the IFC guarantee and out of scope for
this analyzer work line; it belongs on the codegen backlog. Second,
`--check` is CLEAN on `14ff2ab` (exit 0, no information-flow diagnostic):
this shape is a CAPTURE-INTERNAL sink through a locally-resolved zero-arg
lambda reading a captured deep field, which is a lambda-capture residual
of the kind disclosed in the 1.31.0 record (nested/deep capture reads),
NOT part of the cross-function RETURN channel this work line closes. So on
this exact program the secret would leak on Python and the analyzer does
not flag it; only the Wasm codegen defect (accidentally) stops execution.
Both are pre-existing and both are out of scope for this record; they are
recorded here only so that Wasm silence is not mistaken for cleanliness on
this shape. (MEASURED: the reproduction and the pre-existing confirmation
above; JUDGEMENT: the capture-internal-sink classification of the clean
`--check`.)

---

## 8. Cross-references

- Version. Not yet released. Last published version is 1.31.0. This work
  line is on `main` at `14ff2ab` with no version bump and no advisory. The
  next STABLE release cuts the version, CHANGELOG entry and advisory.
- Commits. `d28ab67` (field-qualify the pass-to-callee sink gate, no-op
  prerequisite), `b26aefd` (per-path `return_effects` migration,
  behaviour-preserving), `ffee175` (local field-store return closure),
  merge `a31fccc`; `89bbcd7` (deep field-access return closure), `c2aecc5`
  (Fun-result docstring scope, text only), `c359914` (residual disclosure,
  text only), merge `14ff2ab`.
- Tests. `tests/test_ifc_deep_field_return.py`,
  `tests/test_ifc_local_field_store_return.py`,
  `tests/test_ifc_param_carried_readback.py`.
- Related records. The 1.31.0 capture-internal-sink record
  (`design_1_31_0.html`) and the 1.30.1 field-store `(root, field-path)`
  access-path channel this return channel is the boundary mirror of; the
  broader IFC laundering line (the 2026-08 advisories for 1.26.0 through
  1.31.0, and `2026-06-16-soundness.md`, `2026-07-03-soundness.md`). When
  this work line ships, this file should be lifted to a per-version
  website design record plus a dated advisory, and a GHSA / CWE assigned
  at that time (none exists now).
