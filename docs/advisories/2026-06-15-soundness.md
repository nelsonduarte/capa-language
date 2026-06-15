# Capa security advisory, 2026-06-15: linear-affinity and IFC soundness fixes

> **Status.** Published with the `1.2.0` release. All six findings below
> were remediated in the hardening window between `v1.1.0` (2026-06-14)
> and `v1.2.0` (2026-06-15). Each fix tightens the static analysis so a
> program that previously compiled now produces an error; every such
> change is claimed here under the [`STABILITY.md`](../../STABILITY.md)
> **security exception** (the same soundness-fix carve-out Rust and
> Python follow), and is therefore shipped as a **MINOR** bump, not a
> MAJOR one. The rationale is stated per finding below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: `1.1.0` and earlier on the `1.x` line.
Fixed in: `1.2.0`.
Reporter / process: internal hardening pass for the `1.2.0` release.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.2.0` `CHANGELOG.md` entry.

## Why these are security fixes, not breaking changes

Every finding below is a case where the analyzer **accepted** a program
that violates a first-class, machine-checked Capa security property:
either the linear / typestate use-once discipline or information-flow
control over `@secret` data. Both are in scope per
[`SECURITY.md`](../../SECURITY.md) ("The `consume` qualifier is bypassed
(a value is used after consumption)" and "Compilation accepts a program
where a `@secret` value reaches a public sink that the analyzer should
reject"). The prior acceptance was a soundness bug, so tightening it
falls squarely under the `STABILITY.md` security exception and does not
force a major bump. No previously-rejected program is now accepted; the
direction of every change is reject-more, and only programs that were
already unsound are affected.

## Linear / typestate affinity (4 findings)

The linear / typestate discipline gives a value an **affine, use-once**
obligation: a `linear type` value (and every typestate value, which is
linear by nature) must be consumed exactly once, and must not be used
after it is consumed. This is what makes a non-duplicable token, for
example a payment authorization that may settle only once, actually
non-duplicable. The following four gaps let the obligation be evaded.

### A1. Use-after-consume of a linear / typestate value

**What changed.** A value that had already been consumed (passed to a
`consume` parameter or `consume self` method, transitioned with
`become`, or returned) could be used a second time: passed to another
consuming call, have a field read off it, or be transitioned again. All
of these type-checked and ran. A consume now poisons the binding, so
any later use is a compile error (`linear value 'x' was consumed earlier
and cannot be used again`).

**Security impact.** Double-spend / use-after-consume. The use-once
guarantee was not enforced: the same authorization token could be
settled twice. The compiler advertised non-duplicability it did not
deliver.

**Exception rationale.** The accepted programs were exactly the class
`SECURITY.md` lists as in scope ("the `consume` qualifier is bypassed").
Rejecting them restores the documented discipline; security exception,
MINOR.

### A2. Anonymous drop of a linear / typestate value

**What changed.** A linear / typestate value dropped into an anonymous
slot, a wildcard binding (`let _ = open()`) or a bare expression
statement (`open()`, or a `become(c, State)` whose result is discarded),
escaped the must-consume check, which only tracked obligations by
binding name. Such a drop is now rejected (`linear value is dropped
without being consumed`), exactly as a named drop already was.

**Security impact.** A dropped authorization / leaked resource: the
must-consume obligation could be silently discarded at these sites,
defeating the leak check that guarantees the token is accounted for.

**Exception rationale.** The use-once obligation is the documented
discipline; closing an evasion of it is a soundness fix under the
security exception. MINOR.

### A3. `var` and re-assignment of a linear / typestate value

**What changed.** A `var` binding never registered the must-consume
obligation its `let` counterpart does, and a re-assignment
(`h = open()`) never touched the live set, so a linear value bound with
`var` or re-assigned escaped both the leak check and the double-consume
check. A `var` of a linear value now carries the same obligation as a
`let`, and re-assigning a name whose current value is still live is
rejected as a drop. Re-assigning a name whose value was already consumed
re-arms a fresh obligation, so the legitimate
`close(h); h = open(); close(h)` pattern keeps compiling.

**Security impact.** Same double-spend / dropped-token class as A1 / A2,
reachable purely by choosing `var` over `let` or by re-assigning the
slot. The obligation was waived by a syntactic choice that should not
affect it.

**Exception rationale.** Soundness hole in the use-once discipline;
security exception, MINOR.

### A4. Partial consume of a linear / typestate value in a `match`

**What changed.** A `match` in statement position merged the consumed
set across arms like an `if` but never snapshotted or merged the live
linear obligations, so consuming a value in a single arm removed its
obligation permanently and masked the leak on the other arms. A linear
value live at the entry of a `match` must now be consumed on **every**
non-diverging arm or on **none**: the post-match live set is the union
of each reachable arm's survivors (diverging arms excluded). Consuming
it in all arms and then using it after the match is reported as
use-after-consume; consuming it in none and once after the match keeps
compiling.

**Security impact.** Control-flow-dependent evasion: a token could be
consumed on one branch and silently leaked (or, after the match,
double-consumed) on another. The obligation tracking did not survive the
join.

**Exception rationale.** Closes the `match`-shaped hole in the use-once
discipline; security exception, MINOR.

## Information-flow control over `@secret` fields (2 findings)

Capa's information-flow control is a first-class, machine-checked
security property: a `@secret` value must not reach a public sink
without an explicit `declassify`. The following two gaps dropped the
`@secret` label off a struct field, allowing silent laundering of PII to
public sinks.

### I1. Reading a declared-`@secret` struct field dropped the label

**What changed.** A field declared `@secret` in a type
(`type Emp { iban: @secret String }`) lost its label on READ: `e.iban`
produced a `@public` value, so `stdio.println(e.iban)` compiled clean
with no warning. The declared field label was parsed but discarded (only
the field's TYPE was recorded). Reading a declared-`@secret` field now
yields a `@secret` value, propagating exactly like a `@secret`
parameter: through a same-function sink (warn by default, hard error
under `@strict_ifc`), through a callee that reads and sinks the field,
and through a callee that reads the field and RETURNS it.

**Security impact.** Silent laundering of PII through a struct field,
directly undermining the core guarantee that the compiler proves
`@secret` data does not reach public sinks. No diagnostic fired.

**Exception rationale.** Exactly the in-scope IFC class `SECURITY.md`
names ("Compilation accepts a program where a `@secret` value reaches a
public sink that the analyzer should reject"). Security exception,
MINOR.

### I2. Destructuring a declared-`@secret` struct field dropped the label

**What changed.** Pulling the same field out by a pattern bind still
dropped its label after I1 caught the direct read. `let Emp { id, iban }
= e` (and the `match` form `Emp { id, iban } -> ...`) bound `iban` as
`@public`, so `stdio.println(iban)` compiled clean. The pattern-bind
label propagation carried only the scrutinee's whole-value label and
never consulted the struct's declared field labels. A name bound to a
field declared `@secret` now receives the `@secret` label, on both the
`let` and `match` paths, intra-procedurally and cross-function.

**Security impact.** The same silent PII-laundering class as I1, reached
by destructuring instead of a direct field read; an attacker-equivalent
bypass of the field-read fix had it shipped alone.

**Exception rationale.** Same in-scope IFC class as I1; completes the
closure of the field-laundering hole. Security exception, MINOR.

## Precision (no over-tainting, no false rejection)

For both IFC fixes, precision is preserved: a PUBLIC sibling field stays
public, a same-named field of an UNRELATED struct is never tainted, a
nested destructure taints only the declared-secret sub-field, and
`declassify` of the bound value clears the flow. For the linear fixes,
every legitimate use-once pattern (consume-once, re-arm after consume,
consume-in-all-arms) keeps compiling. The changes reject only the
programs that were already unsound.

## Credit

Found and fixed during the internal hardening pass for the `1.2.0`
release.
