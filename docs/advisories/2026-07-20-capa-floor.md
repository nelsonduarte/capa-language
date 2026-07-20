# Capa security advisory, 2026-07-20: the declared compiler floor was never enforced

> **Status.** Published with the `1.19.0` release. The `capa = ">=X.Y.Z"`
> field of `capa.toml` is now enforced at build time. A project whose
> root manifest declares a floor above the running compiler previously
> built without a word of complaint and now fails; that is an observable
> behaviour change, and it is claimed here under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** (the same
> carve-out Rust and Python use for soundness fixes), and therefore
> shipped as a **MINOR** bump, not a MAJOR one. The argument is made
> below rather than asserted.

This advisory satisfies the `STABILITY.md` requirement that a fix
changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: `1.18.1` and earlier on the `1.x` line, and the whole
`0.x` line.
Fixed in: `1.19.0`.
Reporter / process: internal audit of the release-guard surface, after
`tools/capa_floor.sh` was written for release guard 2 and the guard's own
header had to disclose that nothing enforced the field it read.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.19.0` `CHANGELOG.md` entry.

## What changed

`capa/pkg/_manifest.py` parsed `[package].capa` into
`Manifest.capa_requirement` and **no code read it back**. A package
declaring `capa = ">=1.18.1"` installed, compiled, ran, and emitted a
manifest / SBOM / provenance record on `1.2.0`, silently.

Since `1.19.0`:

- the **root** manifest's floor is a **hard error**;
- a **dependency**'s floor is a **warning**, once per offending package,
  naming it;
- a **missing** `capa` key stays unconstrained (absence is not a
  violation);
- `CAPA_IGNORE_CAPA_FLOOR=1` downgrades the refusal to a warning that
  prints, in full, the refusal it overrode.

The grammar accepted by the compiler is identical to the one
`tools/capa_floor.sh` accepts, whitespace included, so a manifest that
passes release guard 2 can never be one the compiler refuses. Both sides
were tightened in the same change to reject `1.17`, `1.2.3.4` and
`1..2`, which the guard's old `[0-9][0-9.]*[0-9]` pattern accepted.

## Why this is a security fix and not a breaking change

The argument has four steps. It is spelled out because the third step is
the one a reviewer should push on, and it is answered with a named
instance rather than a category.

### 1. The field is a distributed integrity claim, not documentation

`[package].capa` is not a comment. It is a machine-readable assertion,
published inside a signed artefact, about what is required for the
package's other published assertions to hold. It is already **consumed
as true** by automation on the producing side:

- [`tools/capa_floor.sh`](../../tools/capa_floor.sh) reads it to decide
  which released compiler **release guard 2** builds the published
  artefact with. That guard exists precisely so the artefact is built by
  a compiler a consumer is actually obliged to have, and the floor is
  where it gets that number from.

So the project already treats the field as authoritative when producing
artefacts. What it did not do was treat it as authoritative when
consuming them.

### 2. Unenforced, the claim was unfalsifiable at the point of use

A claim that nothing checks does not decay noisily; it decays silently.
The evidence is in the fleet. `capa_hex` shipped `capa = ">=1.1.0"`, and
`1.1.0` cannot compile `capa_hex`'s own example. The floor was wrong from
the day the library was published, and there was no mechanism anywhere
that could have discovered it, because the only party in a position to
falsify a floor is the compiler being asked to build below it. Every
other floor in the ecosystem was in the same unverified state for the
same reason.

### 3. The failure mode is a silently under-analysed build, not a crash

This is the step that matters. If building below the floor produced a
syntax error or a missing-symbol failure, the field would be a
convenience and enforcement would be a nicety. It does not. The build
**succeeds**, and emits an SBOM, a provenance record and a set of
capability claims that were derived by a compiler lacking the fix the
floor existed to require.

**The named instance.** Advisory
[`2026-06-17-security.md`](2026-06-17-security.md), finding **D1**,
fixed in `1.4.0`: `provably_excluded_capabilities` **falsely excluded** a
user-defined capability reachable through a capability-bearing struct. A
holder of `S` where `impl C for S` can exercise `C`, so a function whose
signature touches `S` can reach `C`; the reachability walk did not
propagate the user-cap through the struct, so `C` stayed in the
**exclusion** list while a method call exercised it. Finding **D2**
extended the same false exclusion to a capability nested in a struct
field or reachable only through a sum-variant payload.

Now compose that with an unenforced floor. A package that raises its
floor to `>=1.4.0` because it holds capabilities in exactly that shape,
built on `1.3.0`, compiles cleanly and publishes a manifest asserting
that a capability it can in fact reach is **provably excluded**. The
package is signed. The provenance is valid. The SBOM is well-formed. And
the central claim in it is false, with no diagnostic anywhere in the
pipeline, because the one component that knew the floor existed was not
consulting it.

That is the shape of every capability-claim fix in the `1.x` line, not a
property peculiar to D1: each one moved the boundary of what the analysis
can see, and each one therefore made every SBOM emitted before it
potentially over-claiming for programs of the affected shape. The floor
is how a package says which of those boundaries it is standing on. D1 is
cited because it is concrete, published, and has an explicit
"**Security impact.** A manifest that over-claims ... A downstream
consumer trusting the SBOM's exclusion claim would be misled about the
function's authority."

### 4. Therefore it is in scope for the security exception

[`SECURITY.md`](../../SECURITY.md) puts the integrity of the published
manifest and supply-chain artefacts in scope, and advisory
`2026-06-17-security.md` section D already treats a false
`provably_excluded_capabilities` claim as a supply-chain soundness bug.
Enforcing the floor is what stops that class of false claim from being
produced by a compiler that the package itself said was too old to
produce it. The prior behaviour, accepting a build whose own manifest
said the compiler was insufficient, was the vulnerability; declining it
is the fix. `STABILITY.md` L131-139 applies directly. **MINOR.**

## Why the root / dependency split, and not a warning-then-error cycle

The obvious alternative is `STABILITY.md`'s ordinary deprecation window:
warn in `1.19`, error in `2.0`. It was rejected, and the split is by
**root versus transitive** instead of by time.

- The **root** floor is the project's own declaration about the machine
  doing the build. It is maximally evidenced (the manifest, the compiler
  and the user are all right there), and the user can act on it two
  different ways: upgrade the compiler, or edit a floor they own. A
  warning in that position is a warning nobody reads, and the thing it
  is warning about is a build artefact that will be published and
  trusted.
- A **dependency**'s floor is someone else's declaration, and the
  consumer **cannot** satisfy it by editing their own manifest. It is
  therefore the case most likely to be a false stop: an upstream floor
  that was copied from a template, or never re-checked, would take down
  builds that are entirely fine. So it warns, once per package, naming
  the package, which is enough to get the floor fixed upstream without
  holding anyone's build hostage to a number they do not control.

A time-based split would have given both cases the weak treatment for a
release, including the one case where the evidence is complete and the
remediation is one command.

## Fail-open branches, stated explicitly

Two, and both are announced whenever they fire:

1. **A missing `capa` key.** Unconstrained, silently. Absence is not a
   violation. This is the opposite of `tools/capa_floor.sh`, which fails
   closed on a missing key; the divergence is intentional and documented
   in [`docs/packages.md`](../packages.md) and in `capa/pkg/_floor.py`.
   The two are answering different questions: the guard must choose a
   released compiler and cannot guess one, while the compiler is only
   ever asking whether a *stated* requirement is violated.
2. **An unknown running version.** `capa.__version__` falls back to the
   `0+unknown` sentinel when neither the adjacent `pyproject.toml` nor
   the installed distribution metadata can be read (reachable when a
   frozen build's `copy_metadata` fails; see `deploy/capa.spec`). The
   floor then **warns and continues** rather than refusing. A hard stop
   there would punish a packaging defect in the compiler itself, not
   anything about the manifest, and the remediation menu would be empty:
   the user can neither upgrade to satisfy a comparison that was never
   made nor fix it by editing their own floor. The sentinel is already
   fail-closed where it *can* be fixed, in
   `deploy/binary_smoke_test.py`, which asserts that official builds
   never reach it. `capa init` refuses outright on the sentinel rather
   than writing a `capa = ">=0+unknown"` manifest that the compiler
   which wrote it could not then parse.

## Not fixed here

`capa/cli.py`'s root-manifest read degrades **any** broken `capa.toml`
to a one-line warning and then continues with `./vendor` dropped from
the module search path. That is a larger fail-open than this one, and it
is deliberately not bundled into this change so it can be reverted
independently. The floor error is routed around it by an explicit
re-raise arm.

## Credit

Internal audit, `1.19.0` release preparation.
