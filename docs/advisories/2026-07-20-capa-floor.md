# Capa security advisory, 2026-07-20: the root `capa.toml` was advisory, not authoritative

> **Status.** Published with the `1.19.0` release. Two behaviour changes,
> one defect class: **the root manifest is a security-relevant input that
> was being discarded rather than enforced.**
>
> 1. A **malformed root `capa.toml`** now exits non-zero everywhere. It
>    previously printed `warning: ignoring capa.toml` and built anyway,
>    and "ignoring" it meant compiling a **different source file**.
> 2. A **violated root compiler floor** (`capa = ">=X.Y.Z"`) now exits
>    non-zero. It previously built without a word of complaint.
>    `CAPA_IGNORE_CAPA_FLOOR=1` downgrades this one, and only this one,
>    to a warning that prints the refusal it overrode in full.
>
> Both are observable behaviour changes, and both are claimed under the
> single [`STABILITY.md`](../../STABILITY.md) **security exception** (the
> same carve-out Rust and Python use for soundness fixes) invoked once
> below, and therefore shipped as a **MINOR** bump, not a MAJOR one. The
> argument is made rather than asserted.

This advisory satisfies the `STABILITY.md` requirement that a fix
changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: `1.18.1` and earlier on the `1.x` line, and the whole
`0.x` line.
Fixed in: `1.19.0`.
Reporter / process: internal audit of the release-guard surface, after
`tools/capa_floor.sh` was written for release guard 2 and the guard's own
header had to disclose that nothing enforced the field it read. The
malformed-manifest instance was found while reviewing that fix, by
noticing that the fix's own gate could be switched off by a typo.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.19.0` `CHANGELOG.md` entry.

## Instance 1: a malformed root manifest silently swapped the source file

This is the more serious of the two, and it fits the security exception
more squarely than the floor does: the previous behaviour is a confirmed
"the security control disappears" repro, not a missing check.

`capa/cli.py`'s root-manifest read caught bare `Exception` and degraded
**any** parse failure to `warning: ignoring capa.toml`, then continued.
Ignoring the manifest discards `_capa_dependency_roots`'s
name-to-directory mapping, which is what makes a declared
`path` dependency authoritative. Without it the loader falls back to the
module search path, where a directory whose **name** matches the
dependency shadows the declared directory.

The repro, reproduced on the released `1.18.1` binary. A project declares
`[dependencies.mylib] path = "vendor/real"` (the `path` maps the
dependency NAME to a directory that CONTAINS the modules, so `import
mylib.util` resolves to `vendor/real/util.capa`). A decoy `./mylib/`
holds a same-named module:

```
GOOD manifest    -> INTENDED: vendor/real (audited)   EXIT=0
BROKEN manifest  -> DECOY: ./mylib (unaudited)        EXIT=0
capa --check     -> main.capa: ok                     EXIT=0
```

**The BROKEN manifest differs by exactly one lowercase letter**:
`max = ["stdio"]` instead of `["Stdio"]`, in the `[capabilities]` table,
which has nothing to do with dependencies. A typo silently changed which
code ran, and the compiler reported success. For a language whose whole
claim is provenance, that is the thesis inverted.

The failure surface was one seam, not four. Measured across a bad
capability name, an unknown `[package]` key, a non-string `capa` value
and malformed TOML, the behaviour was identical: `--check`, `--run` and
`--manifest` exited 0 (fail-open), while `--check-capabilities`,
`--compose-sbom`, `capa test` and `capa install` failed closed. The last
two already had the right behaviour and the right wording; the fix is to
make the rest of the CLI match them rather than the other way round.

**Since `1.19.0`** every root-manifest read goes through one seam,
`capa.pkg.read_root_manifest`, which raises `BrokenRootManifestError`.
The CLI prints `capa: broken capa.toml: <path>: <reason>` and exits
**2** (this CLI's code for a configuration problem, which is what
`capa test` already returned for exactly this input).

### There is no escape hatch for a malformed manifest, deliberately

The floor has `CAPA_IGNORE_CAPA_FLOOR=1`; this does not, and the
asymmetry is the point. A floor violation may be genuinely unfixable by
whoever hits it, because "upgrade the compiler" is not always available
to them, and an escape is the difference between a gate and a wall. A
malformed manifest is always fixable by the person who hit it, by editing
the file. An env var restoring "ignore the manifest and build anyway"
would restore the source substitution along with it, so it does not
exist.

The one legitimate flow the old comment named, `capa --check` on a file
outside the project, is not lost: it is refused only when the *cwd*
holds a broken `capa.toml`, which is a defect the user owns and can fix,
and the existing test suite never actually exercised that flow.

## Instance 2: the compiler floor was never enforced

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

## Why the two instances ship together

They were originally scoped apart, so that the larger fail-open could be
reverted independently of the floor. That was wrong, and the reason is
mechanical rather than editorial: **instance 1 disables instance 2's
fix.**

```
[package] capa=">=99.0.0"                    -> EXIT=1, refused
same + [capabilities] max = ["stdio"]        -> EXIT=0, builds and runs
```

The floor gate read the manifest, the read failed, the failure was
swallowed, and the gate found nothing to enforce. So the same one-letter
typo that swapped the source file also switched the new floor off.
Reverting instance 1 alone would silently reopen the floor bypass, which
makes them one defect class and not two: the root manifest is a
security-relevant input that was being discarded rather than enforced.
`tests/test_capa_floor.py::BrokenManifestDisablesTheFloorTests` is the
end-to-end proof, so the coupling cannot regress unnoticed.

## Why this is a security fix and not a breaking change

The argument has four steps. It is spelled out because the third step is
the one a reviewer should push on, and it is answered with a named
instance rather than a category. It is made once and covers both
instances; instance 1 needs less of it, since its previous behaviour is a
demonstrated source substitution rather than an absent check.

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

Two remain, both about the floor (a malformed manifest has none), and
both are announced whenever they fire:

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

## The gate must answer for the root the command acts on

A third defect in the same family, fixed here. The gate resolved the
project root as `Path.cwd()`, while `--compose-sbom`,
`--check-capabilities`, `--check-policies` and `--conformance-report`
resolve theirs by walking up from the **file** (`find_package_root`).
From a subdirectory the two disagreed:

```
from project root:  capa --compose-sbom sub/main.capa  -> EXIT=1, floor enforced
from sub/:          capa --compose-sbom main.capa      -> EXIT=0, floor NOT enforced
```

The subdirectory run was not a no-op. It emitted a real composed SBOM
for the parent project and applied the parent's capability ceiling,
which is precisely the artefact the floor exists to protect.
`--manifest` was a lesser version of the same.

The gate now walks up from the cwd the same way, and the four
file-rooted commands re-check the root they actually resolved, which
also closes the residual case of a file **outside** the cwd's project
tree. The re-check is skipped when the two roots are the same directory,
so `CAPA_IGNORE_CAPA_FLOOR` still prints exactly once per invocation.

One consequence is worth stating plainly: `--check` and `--run` from a
subdirectory previously did not consult the manifest at all. That was
internally consistent rather than a bypass, but they are gated now
anyway, because the gate resolves the project root the same way for
every command.

`capa test` was never a bypass: each test runs in a subprocess whose cwd
is the project root, so it failed closed already. Under
`CAPA_IGNORE_CAPA_FLOOR=1` it prints one warning per subprocess plus one
for the parent, since each subprocess is a separate build.

## Credit

Internal audit, `1.19.0` release preparation.
