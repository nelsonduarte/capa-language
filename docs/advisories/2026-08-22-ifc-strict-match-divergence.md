# Capa security advisory, 2026-08-22: `@strict_ifc` did not raise the block pc after a secret-conditioned `match` divergence

> **Status.** Published with the `1.32.0` release. The finding below is a silent
> implicit-flow false negative under `@strict_ifc`: a divergence inside a
> secret-conditioned `match` arm did not raise the enclosing block's pc-label, so
> a following public sink leaked the secret predicate bit. It **completes an
> incomplete fix**: finding B3 of the shipped
> [`2026-06-17-security.md`](2026-06-17-security.md) advisory raised the block pc
> after a secret-conditioned divergence for `if` / `while` / `for`, but the
> `match` form was overlooked. It is claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** and is therefore
> shipped as a **MINOR** bump, not a MAJOR one.

This advisory satisfies the `STABILITY.md` requirement that a security fix
changing observable behaviour without a major bump "ships with a security
advisory ... [that] states explicitly what changed and why the change is not
subject to the major-bump rule."

**Severity:** Low to moderate. Confidentiality impact only (a silent
implicit-flow false negative), and scoped to builds that opt into `@strict_ifc`:
the implicit-flow (pc) noninterference guarantee is claimed **only under
`@strict_ifc`**, so the missed check affected only a build that gates
noninterference on `@strict_ifc`. What leaks is one bit of the secret predicate
per reachable sink, not the secret value directly. No integrity, availability,
code-execution, or memory-safety impact.

**CVSS-style vector (illustrative):**
`CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` (~5.3). CVSS is an imperfect fit:
the flaw is a soundness gap in a static verifier. `AC:H` reflects that a
secret-conditioned `match` with a diverging arm and a following public sink, plus
`@strict_ifc`, must all be present.

**CWE:** CWE-200 (exposure of sensitive information) through an implicit flow,
the same class as finding B3 of [`2026-06-17-security.md`](2026-06-17-security.md).

**Affected versions:** `< 1.32.0` on the `1.x` line. This is an **incomplete
prior fix**, not a novel channel: `2026-06-17-security.md` finding B3 (shipped
with `1.4.0`) closed the `if` / `while` / `for` divergence-pc leak but did not
cover `match`, so the `match` shape has leaked under `@strict_ifc` since B3
shipped. The leaking shape was reproduced on the current `main` before the fix.

**Fixed in:** `1.32.0`.

**GHSA:** GHSA-w9m5-7pcc-mq3p.

**Reporter / process:** internal hardening pass for the `1.32.0` release. Fix
commit `88e2a30` (extend the B3 block-pc-raise mechanism to `match`), with a
follow-up disclosure correction in `3783939` (the divergence detector recognises
only syntactically-recognised forms, so an arm that diverges via the `?` / `Try`
operator or an always-panicking helper is a disclosed-open residual, symmetric
with the `if` / `while` / `for` path).

**Channel:** this advisory; cross-referenced from the `1.32.0` `CHANGELOG.md`
entry.

## Why this is a security fix, not a breaking change

The analyzer failed to elevate the pc after a control-flow divergence guarded by a
`@secret`, an implicit-flow property in scope per [`SECURITY.md`](../../SECURITY.md)
and already enforced for the other control forms since `1.4.0`. The prior
behaviour was a soundness bug, so tightening it falls under the `STABILITY.md`
security exception. The change is strict-only and reject-only, and only a program
that was already leaking the predicate bit under `@strict_ifc` is affected. It
ships as a **MINOR** bump.

## Details

Under `@strict_ifc`, a divergence (`return`, `break`, `continue`, `panic`) inside
a secret-conditioned branch elevates the enclosing block's pc for the rest of the
block, so a sink placed AFTER the branch (reaching which depends on the secret
predicate) is flagged. Finding B3 of `2026-06-17-security.md` implemented this for
`if` / `while` / `for`. The `match` form was overlooked: a divergence inside a
`match` arm, guarded by a secret scrutinee or a secret arm-guard, did not raise
the block pc, so a following public sink leaked silently under `@strict_ifc`.

```capa
@strict_ifc()
fun leak(stdio: Stdio, s: @secret Int) -> Unit
    match s
        0 -> return
        _ -> {}
    stdio.println("reached")           # reaching here reveals s == 0; not flagged before 1.32.0
```

## The fix

`88e2a30` extends the single existing mechanism to `match`, in
`capa/analyzer/_statements.py`:

- `_secret_conditioned_divergence` (`capa/analyzer/_statements.py:71`) now
  inspects a directly-carried `MatchExpr` (in statement position, or as the
  value of a `let` / `var` / assign / `return`): it joins the scrutinee label
  with every arm-guard label and, when that upper bound is secret and any arm may
  diverge, raises the block pc exactly as the `if` / `while` / `for` path does.
- `_block_has_divergence` (`capa/analyzer/_statements.py:166`) treats a diverging
  `match` (statement or value position) as a divergence, so a `match` nested
  inside an `if` / `while` / `for` body is caught.
- A new `_expr_may_diverge` (`capa/analyzer/_statements.py:236`) walks nested
  `match` and `if`-expressions on a MAY-diverge (some-path) basis, the sound
  direction. An all-paths formulation was **rejected as unsound** because it
  misses a partial-divergence nested arm.

The join is an upper bound on the true control label, inherited verbatim from the
shipped `if` / `elif` path. The change is strict-only and reject-only: no codegen,
AST, or default-tier behaviour changes, and no previously-accepted program's
output can move.

## Scope and known residuals

The fix inspects a directly-carried `match`. The following stay disclosed-open,
each symmetric with a limitation the shipped `if` / `while` / `for` path already
has:

- A `MatchExpr` nested deeper than the directly-carried value (`f(match ...)`,
  `match ... + 1`) is not inspected, consistent with the top-level-only inspection
  the `if` / `elif` path already uses.
- An arm that diverges via the `?` / `Try` operator is not recognised by the
  syntactic divergence detector (corrected in `3783939`; the `if` / `while` /
  `for` path does not recognise `Try` either, so this is pre-existing, not a
  regression).
- An arm that calls a void helper which always panics is interprocedural
  divergence the strict analysis does not track.

Each residual is pinned by a currently-accepted test that flips when the extension
lands.

## Remediation

**Upgrade to `1.32.0`.** On affected versions the leak was silent even under
`@strict_ifc` (that silence is the vulnerability). After upgrading, a
secret-conditioned `match` divergence followed by a public sink is a hard error
under `@strict_ifc`.

## Verification

Analyzer-only, strict-only, reject-only. Pinned in
[`tests/test_ifc_noninterference.py`](../../tests/test_ifc_noninterference.py),
which extends the implicit-leak noninterference generator with seven `match`
divergence shapes (statement / value / assign position, scrutinee-secret and
guard-secret, `return` / `break` / `continue` arms), adds deterministic panic and
nested-divergence rejections, two accept controls that run to a fixed public
output, and the residual pins.

## Credit

Found and fixed during the internal hardening pass for the `1.32.0` release.
