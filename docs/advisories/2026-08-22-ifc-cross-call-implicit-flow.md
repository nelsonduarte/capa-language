# Capa security advisory, 2026-08-22: information-flow and constant-time checks did not compose across a function call

> **Status.** Published with the `1.32.0` release. The two findings below are
> silent soundness gaps in the cross-function pass of the information-flow
> analysis: an implicit flow (finding IFC-1) and a constant-time timing channel
> (finding IFC-2) were each caught INLINE but not across a call, so a public sink
> or a variable-time operation reached through a helper was certified clean. Both
> are claimed under the [`STABILITY.md`](../../STABILITY.md) **security
> exception** (the soundness-fix carve-out Rust and Python follow) and are
> therefore shipped as a **MINOR** bump, not a MAJOR one. The rationale is stated
> below.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Low to moderate. Confidentiality impact only (a silent soundness
gap in a static verifier), no integrity, availability, code-execution, or
memory-safety impact, and no bypass of the capability discipline itself.

- IFC-1 is scoped down to builds that opt into `@strict_ifc`: the implicit-flow
  (pc) noninterference guarantee is claimed **only under `@strict_ifc`** (the
  default tier does not track implicit flows at all, per finding B1 of
  [`2026-06-17-security.md`](2026-06-17-security.md)), so the missed check
  affected only a build that gates noninterference on `@strict_ifc`.
- IFC-2 is not tier-gated: the `@constant_time` checks are hard errors at every
  tier, so the missed check affected any `@constant_time` function.

**CVSS-style vectors (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3) for IFC-1 (a specific
secret-conditioned-branch-around-a-call shape plus `@strict_ifc` must be
present), and `CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3) for IFC-2 (a
`@secret` value must flow into a variable-time operation inside an un-annotated
helper). CVSS is an imperfect fit here: both flaws are soundness gaps in a static
verifier. The scores reflect a confidentiality-only break, observable at run
time, with no integrity, availability, or memory-safety impact.

**CWE:** CWE-200 (exposure of sensitive information) for IFC-1; CWE-208
(observable timing discrepancy) for IFC-2, the same class as the intra-procedural
`@constant_time` finding B2 of [`2026-06-17-security.md`](2026-06-17-security.md).

**Affected versions:** `< 1.32.0` on the `1.x` line. Both gaps are cross-function
extensions of checks that existed only intra-procedurally in every prior release;
the leaking shapes were reproduced on the current `main` before the fix. The
exact earliest affected release was not bisected by executing each historical
binary.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-hcq6-x556-7r23.

**Reporter / process:** internal hardening pass for the `1.32.0` release,
following the audit of the whole compiler. Fix commits: IFC-1 in `6aae42e` (the
per-callable `sink_reaching_pc` summary bit and the two call-site checks),
tightened by `a9a6644`, `ccba795`, and `081c789` (three precision fixes that
narrow the method-call pc-union to the receiver's real dispatch targets so a
built-in container / capability getter and an unrelated same-named user method no
longer over-reject); IFC-2 in `4ba89b3` (the `ct_sensitive` summary output and
the two call-site checks, reusing IFC-1's dispatch-target machinery).

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why these are security fixes, not breaking changes

The analyzer's information-flow pass **failed to follow** a first-class,
machine-checked Capa security property across a function call: implicit-flow
noninterference under `@strict_ifc`, and the `@constant_time` no-secret-timing
discipline, both in scope per [`SECURITY.md`](../../SECURITY.md). The prior
behaviour was a soundness bug, so tightening it falls under the `STABILITY.md`
security exception and does not force a major bump. The direction of both changes
is reject-more: only programs that were already unsound (an implicit flow to a
public sink under `@strict_ifc`, or a secret reaching a variable-time operation
under `@constant_time`) are affected. Both ship as a **MINOR** bump, matching
every prior static-analysis-tightening IFC soundness fix.

## IFC-1. `@strict_ifc` implicit-flow noninterference did not compose across a call

Under `@strict_ifc`, the intra-procedural implicit-flow rule caught a public sink
placed **inline** inside a secret-conditioned branch (the pc-label is elevated
inside the branch, so a sink there leaks the predicate bit and is flagged). But
the same public sink reached through a **helper call** inside the secret branch
was certified clean, because the analysis did not know the callee reaches a sink:

```capa
fun sink(stdio: Stdio) -> Unit
    stdio.println("reached")           # a public sink

@strict_ifc()
fun leak(stdio: Stdio, s: @secret Bool) -> Unit
    if s then
        sink(stdio)                    # leaks the branch bit; not flagged before 1.32.0
```

Reaching `sink` at all depends on the secret predicate `s`, so an observer of the
program's output learns the bit. This held for every sink capability, at any call
depth, and for every branch form (`if` / `elif`, `while`, `for`, and a
secret-conditioned `match`, once finding C-F1 is also considered).

### The fix

`6aae42e` adds a per-callable boolean `sink_reaching_pc` to the cross-function
IFC summary (`capa/analyzer/_ifc_summary.py:413`, documented at
`capa/analyzer/_ifc_summary.py:333`): `True` iff the body can execute a real
built-in public sink (a `_PUBLIC_SINKS` method whose RECEIVER resolves,
type-awarely, to a built-in sink capability, or a built-in `panic`), directly or
transitively through a resolved call. It is grown on the same monotone least
fixpoint the existing summaries use, so self and mutual recursion converge. The
direct-sink recognition is receiver-capability TYPE-resolved, not by-name, so
`xs.get(i)` on a `List` receiver is never mistaken for `Net.get` (the sink
capabilities share the `get` / `write` / `send` method names). At each free-call
site `_check_ifc_call_pc` (`capa/analyzer/_ifc.py:3215`) and at each method-call
site `_check_ifc_method_call_pc` (`capa/analyzer/_ifc.py:3237`) hard-error under
`@strict_ifc` when the resolved callee's bit is set and the caller's pc is secret.
The bit is a static callee property from the summary pre-pass, so no live pc of
the callee is consulted; the rule composes additively with the intra-procedural
one.

Three follow-up commits narrow the method-call pc-union so it never over-rejects
a clean program: `a9a6644` drops the built-in container `get` / `Net.get`
collision, `ccba795` extends that to built-in capability receivers
(`env.get`, `fs.read`), and `081c789` restricts the by-name union to the
receiver's real dispatch targets via `_dispatch_target_keys`
(`capa/analyzer/_ifc.py:3324`), so a clean dynamic call is no longer rejected
because an unrelated same-named method sinks. Each is reject-only in the safe
direction and pinned by must-compile and must-reject tests.

**Disclosed residual (still open).** A sink whose receiver capability is reached
through a value the analysis cannot type-resolve to a built-in sink capability (a
higher-order or capability-alias route) is not caught; the summary recognises
only type-resolvable built-in sink receivers and resolved callees.

## IFC-2. `@constant_time` did not compose across a call

The constant-time side-channel checks were intra-procedural in the same way: a
`@secret` value passed to an un-annotated helper that performs the variable-time
operation ON THAT VALUE was certified clean.

```capa
fun divide(x: Int, y: Int) -> Int
    x / y                              # variable-time on y

@constant_time()
fun f(s: @secret Int) -> Int
    divide(100, s)                     # secret-dependent timing; not flagged before 1.32.0
```

Only the inline `100 / s` was caught; routing it through `divide` hid the
data-dependent division. This is the timing-side-channel twin of IFC-1.

### The fix

`4ba89b3` adds an 8th summary output, `ct_sensitive`
(`capa/analyzer/_ifc_summary.py:428`): `{callable_key: frozenset(param_idx)}`,
the value parameters whose value flows, directly or transitively, into a
variable-time operation inside the body (division or modulo, a data-dependent
branch condition or scrutinee, a variable-time `String` / `List` compare, or a
data-dependent index or lookup). It is annotation-blind, parameter-indexed, and
computed to the same monotone least fixpoint, recognising the five operation
sites on the existing body walk and composing transitively through the callee's
own `ct_sensitive` set. `capa/analyzer/_ifc.py` adds `_check_ct_call`
(`:2343`), `_check_ct_method_call` (`:2386`, resolving the callee ct-set with
IFC-1's dispatch-target-restricted `_dispatch_target_keys`), and
`_emit_ct_call_leak` (`:2451`), hooked at the two call seams right after the
IFC-1 pc hooks and guarded on `@constant_time`. A public argument, a
non-ct-sensitive parameter, a literal, and a declassified argument all still
compile. The leak is a **hard error at every tier**, matching the inline CT
checks (unlike IFC-1's strict-only gate).

**Disclosed residuals (still open, inherited).** The summary's nested-local-lambda
opacity, the local-bound-container element typing, and the non-`Ident`-operand
compare typing residuals are inherited unchanged from the intra-procedural CT
checks.

## Remediation

**Upgrade to `1.32.0`.** On affected versions there is no analyzer-configuration
workaround for either finding: IFC-1 was silent even under `@strict_ifc` (that
silence is the vulnerability), and IFC-2 was silent even though the CT checks
already error at every tier. After upgrading, IFC-1 is a hard error under
`@strict_ifc` and IFC-2 is a hard error at every tier. `declassify(value, reason:
"...")` remains for an intended disclosure, not a mitigation for these gaps.

## Verification

Both fixes are analyzer-only and reject-only, with no runtime or codegen change,
so the emitted output of every previously-accepted program is byte-identical on
the legacy transpiler, the CIR Python backend, and the Wasm Component Model
backend. IFC-1 is pinned by `TestImplicitCrossCallIFC1` (the leak shapes across
sink capability, depth, and branch form; the built-in container / capability
collision must-compile controls; the dynamic trait-receiver must-reject controls)
and IFC-2 by `TestConstantTimeCrossCall` (the leak shapes plus the over-reject
controls) in the information-flow test suite.

## Credit

Found and fixed during the internal hardening pass for the `1.32.0` release.
