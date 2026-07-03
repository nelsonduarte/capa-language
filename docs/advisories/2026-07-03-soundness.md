# Capa security advisory, 2026-07-03: information-flow, formatter, and provenance-integrity fixes

> **Status.** Published with the `1.15.0` release. All findings below
> were remediated in the hardening window between `v1.14.0` (2026-06-29)
> and `v1.15.0` (2026-07-03). Each fix tightens the static
> information-flow analysis so a `@secret` value that previously reached
> a public sink with no diagnostic is now flagged (a warning by default,
> a hard error under `@strict_ifc`), restores a security label the
> formatter was silently discarding, or restores the integrity of the
> version the toolchain stamps into its provenance; every such change is
> claimed here under the [`STABILITY.md`](../../STABILITY.md) **security
> exception** (the same soundness-fix carve-out Rust and Python follow),
> and is therefore shipped as a **MINOR** bump, not a MAJOR one. The
> rationale is stated per finding below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: `1.14.0` and earlier on the `1.x` line.
Fixed in: `1.15.0`.
Reporter / process: internal hardening pass for the `1.15.0` release,
driven by adversarial dogfooding of the information-flow control.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.15.0` `CHANGELOG.md` entry.

## Why these are security fixes, not breaking changes

Every finding below is a case where the compiler (the cross-function
information-flow summary, the intra-procedural IFC pass, the AST
pretty-printer, or the version stamp) **dropped**, **ignored**, or
**mis-reported** something that a first-class, machine-checked Capa
security property depends on: information-flow control over `@secret`
data, and the integrity of the version stamped into the provenance /
SBOM. Both are in scope per [`SECURITY.md`](../../SECURITY.md)
("Compilation accepts a program where a `@secret` value reaches a public
sink that the analyzer should reject", and the integrity of the
published manifest / supply-chain artefacts). The prior behaviour was a
soundness or integrity bug, so tightening it falls squarely under the
`STABILITY.md` security exception and does not force a major bump. Every
information-flow fix is verified adversarially and fails closed under
`@strict_ifc`; the direction of every change is flag-more (or
report-truthfully), and only programs that were already unsound, or
artefacts that already carried the wrong version, are affected.

## A. Information-flow control: cross-boundary secret laundering (4 findings)

Capa's information-flow control is a first-class, machine-checked
security property: a `@secret` value must not reach a public sink
without an explicit `declassify`. The following four gaps let a
`@secret` be laundered across a boundary the analysis did not follow,
each a silent false negative (the worst kind of hole: the author writes
`@secret`, believes they are protected, and are not). All four are
verified adversarially and fail closed under `@strict_ifc`; each keeps
its precision (a `declassify`, a public value, and a non-capturing
closure stay clean, so no false positive is introduced).

### A1. A free-function call result did not follow the callee's return effects

**What changed.** The cross-function IFC summary already carried a
**method** call's result label from the callee's `return_effects` (so a
method returning a declared-`@secret` field of its receiver taints the
call result), but the **free-function** call path only joined the
argument taints and never consulted the callee's `return_effects`. A
free function that reads a declared-`@secret` field of a struct
parameter (or otherwise produces an internal secret) and **returns** it
therefore dropped the `INTERNAL_SECRET` sentinel: a caller whose own
return or public sink (`Stdio.println` / `eprintln`, `Net.post`,
`panic`, a sink-reaching parameter of a further function, ...) depended
on that call result was **not** flagged. The free-function-call result
now follows the callee's `return_effects` mapped back to the call's
taint, exactly like the method path (`INTERNAL_SECRET` maps to the
sentinel; a real parameter source maps to the taint of the bound
argument). Because a free-function name resolves to exactly one
callable, the mapping is precise: it closes the laundering (widening in
the secret direction, never under-marking) and removes the previous
unconditional argument join, so a parameter whose value does not flow
into the return no longer over-taints the result.

**Security impact.** A silent secret-disclosure path: a `@secret` (PII,
a token) returned by a free function and routed to a public sink, with
no diagnostic under either tier.

**Exception rationale.** Exactly the in-scope IFC class `SECURITY.md`
names. The accepted programs were already unsound. Security exception,
MINOR.

### A2. A `@secret` label on a module-level `const` was silently ignored

**What changed.** A `const K: @secret String = "..."` is accepted by the
parser, but the const handler only type-checked the value and never
stamped the declared label onto the global symbol, so a reference to the
const came out `@public`. A secret const forwarded to a public sink was
therefore **not** flagged: the annotation was accepted but not enforced.
Module consts now behave like the `let` / `var` path, which already
honoured the declared label: the const handler joins (lattice join,
never lowers) the declared `@secret` / `@public` label with the value's
label and records it on the global symbol. The cross-function summary
walk (an independent pass that does not consult the global scope) now
also recognises a reference to a `@secret` const as an internal secret
source, symmetric to a declared-`@secret` field read, so the leak is
caught not only intra-procedurally but also across a free-function
return or a callee field-write to a public sink. The summary walk's
const-vs-local decision respects **real lexical scope** (Capa lets a
`let` shadow a module const): a `let K = ...` inside a loop body, an
`if` branch, or a `match` arm masks the const only within that
sub-scope, saved / restored per block, so a genuine reference to the
secret const in a sibling or later block is still caught. Coverage: a
secret const reaching a public sink is flagged directly, through
intermediary bindings, through a call argument, through a free-function
return (including embedded in a returned struct field), through a callee
field-write, and across multi-hop return chains.

**Security impact.** Silent laundering of a declared-`@secret` module
constant to a public sink, the worst false-negative shape because the
author annotated the const and was not told the annotation had no
effect.

**Exception rationale.** Same in-scope IFC class as A1; enforcing an
annotation that was accepted but ignored restores the documented
discipline. Security exception, MINOR.

### A3. A secret captured by an escaping lambda laundered cross-function

**What changed.** A free function returning `fun () => K` (a `@secret`
const), `fun () => e.iban` (a declared-`@secret` field of a struct
parameter) or `fun () => token` (a `@secret` parameter), or hiding such
a closure in a returned struct field, produced a closure **value** that
carried none of the captured secret's taint: the caller could invoke it
and route the result to a public sink with no diagnostic. The cause was
that the cross-function summary pass did not walk lambda bodies, so a
`LambdaExpr` yielded the empty taint set and the function's
return-effect never recorded the captured source. The summary now
returns the taint a lambda's **invocation** would produce: the source
set of the value its body returns (its `return` statements plus its
trailing bare expression / expression body). The lambda's own parameters
are treated as fresh locals, not captures (masked in an isolated copy of
the taint env and registered as const shadows), so the walk never
corrupts the enclosing function's flat, monotone env and nested lambdas
compose.

**Security impact.** The same silent `@secret`-laundering class as A1 /
A2, reached by returning a secret-capturing closure across a function
boundary instead of returning the secret directly.

**Exception rationale.** Same in-scope IFC class as A1. The accepted
programs were already unsound; closing the closure-value leak is a
soundness fix under the security exception. MINOR.

### A4. Two-hop closure-by-name: a named secret closure passed to an invoker laundered

**What changed.** A closure that closes over a secret, bound to a name
(`let f = fun () => secret`) and then handed to a distinct callee that
invokes it and sinks the result (`invoke(f)` where `invoke` does `f()`
into a public sink), produced no diagnostic. Only the **inline** form
(`invoke(fun () => secret)`) was caught: the invoke-sink boundary check
consulted the closure's precise **result** label for an inline lambda
but skipped any `Fun` argument that was not a literal, because the only
label then to hand was the whole-value **capture** label, which cannot
see through an in-body `declassify` and would raise a false positive on
a declassifying let-bound closure. The check now recovers the **precise
result label** of a closure passed by name when the argument is an
identifier resolvable to a binding that denotes **one certain lambda
literal**: a `let` bound to a lambda literal, or a `var` bound to a
lambda literal at its declaration and never reassigned. So
`let f = fun () => secret; invoke(f)` is now flagged, while
`let f = fun () => declassify(secret); invoke(f)` stays public and is
**not** a false positive: the result label sees through the declassify
exactly as the inline case does.

**Known residual.** Documented false **negatives**, never degraded into
a false positive by a capture-label fallback: a closure borne in a
struct field, a `Fun` parameter of the enclosing function re-passed
onward, a binding whose RHS is not a lambda literal (e.g. a call
result), and any `var` that is ever reassigned (even to another lambda
literal). A reassigned `var` makes the denotation ambiguous; rather than
join over the candidates (which would reintroduce a false positive, and
turn a hard error under `@strict_ifc` in safe code) the check keeps the
documented skip. The posture is "a false positive is the worst
outcome", so only the inline and the single-assignment `let` / `var`
lambda-literal shapes are covered.

**Security impact.** The same silent `@secret`-laundering class as A1 /
A2 / A3, reached through a named closure handed to a higher-order
invoker: the last of the four hop-by-name gaps.

**Exception rationale.** Same in-scope IFC class as A1, closed
fail-positive-free. The accepted programs were already unsound. Security
exception, MINOR.

## B. Formatter dropped information-flow labels (1 finding)

The formatter (`capa --fmt`) rewrites a file in place. A formatter that
silently removes a security annotation weakens the very property the
annotation exists to enforce.

### B1. `capa --fmt` silently stripped `@secret` / `@public` labels

**What changed.** The AST pretty-printer's type emitter never re-emitted
the `TypeExpr.label`, so formatting a struct field
(`field: @secret String`), a parameter, a return type, a `let` / `var`
binding, a `const`, or a generic / tuple / `Fun(...)` type argument
**dropped** the `@secret` / `@public` label with no warning and exit 0.
Because a formatted file is written back in place, a user who ran the
formatter lost the label and the analyzer stopped protecting the value:
a program that leaked the field to a public sink, rejected before
formatting, was accepted after. The label lives on the `TypeExpr` base,
so it is now emitted once, centrally, covering every type position
uniformly. The typestate index `Name[State]`, dropped by the same
emitter, is preserved too. Formatting is idempotent and never emits
empty output for a valid, non-empty source.

**Security impact.** Silent disarming of information-flow control: a
single run of the formatter could delete a `@secret` label and,
downstream, turn a previously-rejected leak into an accepted one, with
no diagnostic.

**Known residual (operational).** Code formatted with an affected
release (`1.14.0` or earlier) may already have lost a `@secret` /
`@public` label. Re-run the analyzer (`capa --check`) against
version-control history, or re-audit type annotations, to confirm no
label was silently dropped before upgrading.

**Exception rationale.** The formatter must round-trip a security
annotation, not delete it; restoring the label in every type position
restores the documented behaviour. This is a soundness fix under the
security exception. MINOR.

## C. Provenance integrity (1 finding)

The `capa_version` the toolchain stamps into the provenance, the AOT
artefact, and the SBOM is the compiler identity a downstream consumer
verifies against. Reporting the wrong version misattributes every
artefact built by the affected binaries.

### C1. The stamped compiler version was a stale hard-coded literal

**What changed.** `capa.__version__` was a hard-coded literal
(`1.13.0`) that the release process never bumped alongside
`pyproject.toml`, so the shipped `v1.14.0` and `v1.15.0` binaries
reported `capa 1.13.0` and the AOT / provenance / SBOM stamped the wrong
compiler version, a real correctness problem for a language whose
headline is machine-verifiable SBOMs. The version is now single-sourced:
`capa.__version__` derives from `[project].version` in `pyproject.toml`
when running from a source checkout, and from installed distribution
metadata (`importlib.metadata`) for a `pip install` or the PyInstaller
binary (the release spec bundles Capa's own dist-info metadata so the
frozen binary resolves the correct version). There is no longer a second
place to bump at release time, and a new test locks `capa.__version__`
to the pyproject version so the two can never diverge again. Every
version-stamping consumer (`capa --version`, the `.capa-version` project
stamp, the manifest / provenance / AOT builders, the LSP server) follows
automatically.

**Security impact.** A provenance / SBOM integrity gap: an artefact
built by an affected binary attested to the wrong compiler version, so a
consumer verifying the toolchain identity in the attestation was
misled.

**Exception rationale.** The stamped version is part of a published,
machine-verified supply-chain artefact; single-sourcing it from
`pyproject.toml` restores its integrity. Security exception, MINOR.

## Precision (no over-tainting, no false rejection)

For the information-flow fixes, precision is preserved: a `declassify`
(intra- and cross-function) still closes the flow, a lambda that
captures a secret but returns a public value carries no taint, a
non-capturing closure stays public, a genuine local shadow of a module
const is not flagged, an unannotated (public) const at a sink is clean,
and a declassifying let-bound closure passed by name is not a false
positive. For the formatter fix, formatting stays idempotent and never
empties a valid source. The changes flag (or report truthfully) only the
programs that were already unsound or the artefacts that already carried
the wrong version.

## Credit

Found and fixed during the internal hardening pass for the `1.15.0`
release, driven by adversarial dogfooding of the information-flow
control.
