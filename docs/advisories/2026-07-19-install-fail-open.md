# Capa security advisory, 2026-07-19: `capa install` verified nothing when `gh` was absent

> **Status.** Published with the `1.18.1` release. A machine without the
> GitHub CLI on its PATH installed every dependency with its SLSA
> build-provenance layer switched off, printing one warning per
> dependency and continuing. The fix turns that warning into a refusal
> for any dependency whose `capa.toml` entry declares `verify_key`,
> which makes a previously-succeeding `capa install` fail. That is a
> change to the documented behaviour of a covered surface (the
> package-manager manifest semantics), claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** and
> therefore shipping as a **PATCH**, not a MAJOR bump. The rationale is
> below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: every `1.x` release up to and including `1.18.0`. The
missing-`gh` skip has existed since the SLSA layer first shipped
(pre-1.0); `1.7.0` made it print a warning instead of skipping in
silence, which is where it stopped and where this advisory picks up.
Fixed in: `1.18.1`.
Reporter / process: found internally, by running `capa install` in a
clean room that happened not to have `gh` installed.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.18.1` `CHANGELOG.md`
entry.

## The finding

`capa install` describes three independent supply-chain layers: the
lockfile SHA, the GPG signature against a `verify_key` fingerprint, and
SLSA L2 build provenance verified through Sigstore Rekor. The third
layer is implemented by shelling out to `gh attestation verify`.

When `gh` was not on PATH, that layer treated the situation as a
graceful skip. At the default `verify_provenance = "warn"` level it
printed:

```
capa: warning: SLSA provenance not verified for 'capa_jwt': gh not found in PATH
```

and installed the dependency. In a clean room, that is one line per
dependency and then a successful install; seven dependencies produced
seven identical warnings and seven unverified checkouts.

The problem is not that the layer degraded. It is **what** degraded it:
the absence of a tool on the consumer's own machine. Every other skip
path in that function describes the dependency or the network (a rev
pin, a non-GitHub host, an unreachable endpoint, a release with no
tarball). Those are conditions an install genuinely cannot do anything
about. A missing `gh` is a condition that anybody, including an
attacker who can influence a build image, can arrange, and arranging it
silently disables a verification layer while the install still reports
success.

A warning does not compensate for this. It is emitted once per
dependency on the most routine command in the package manager, in the
same stream as ordinary progress output, on a run that exits 0.

## Why this is a security fix and not a breaking change

The prior behaviour is a **fail-open in a security control**, in the
sense [`SECURITY.md`](../../SECURITY.md) already scopes: the integrity
of what a build links and of the supply-chain claims made about it.

`verify_key` is the consumer's own written statement, in their own
manifest, that a given dependency is meant to be verified. Honouring
that statement only when a helper binary happens to be installed makes
the strength of the check a property of the machine rather than of the
project, which is exactly the "verification that ran where we are,
proving nothing about where the user is" failure this project has been
correcting release by release.

The direction of the change is strictly **narrowing**: an install that
previously succeeded may now fail, and no install that previously
failed now succeeds. Nothing about the manifest format changed; no
field was removed, renamed or retyped. A project that never declared
`verify_key` is entirely unaffected.

## What changed

- A dependency that declares `verify_key` and finds no `gh` on PATH is
  **refused** with a `VerificationError` naming the dependency, instead
  of warned about.
- `verify_provenance = "off"` still short-circuits before the check.
  That is an explicit, reviewable opt-out recorded in `capa.toml`, and
  the refusal does not second-guess it.
- `CAPA_ALLOW_MISSING_GH=1` is the escape for anyone who genuinely must
  install without a verifier. It is loud by construction: it prints a
  stderr warning naming **every** dependency it lets through and stating
  that only the GPG layer ran. It follows the pattern already used for
  `CAPA_NO_VERIFY` and `CAPA_REGISTRY_ALLOW_UNSIGNED`, and the same
  read convention (only the exact value `1` counts).
- Deliberately unchanged: the other graceful-skip paths (rev pin,
  non-GitHub host, download failure, absent tarball) keep their existing
  per-level `verify_provenance` treatment, and a dependency with no
  `verify_key` keeps warning as before. Widening the refusal to those
  would refuse installs for reasons the consumer stated nothing about.

## Who is affected, and what to do

You are affected if you install dependencies that declare `verify_key`
on a machine without the GitHub CLI. Every package in the Capa registry
declares one, so this is the normal case for registry users.

After upgrading, such an install fails with:

```
capa install: cannot verify the SLSA build provenance of 'capa_jwt':
the 'gh' CLI is not on PATH.
```

In order of preference:

1. **Install the GitHub CLI** (<https://cli.github.com>) and re-run
   `capa install`. The verification then actually happens, which is the
   outcome the manifest asked for.
2. **Set `verify_provenance = "off"`** on that dependency in
   `capa.toml`, if you have decided you do not want the provenance layer
   for it. This is a decision that lives with the project and shows up
   in a diff.
3. **Set `CAPA_ALLOW_MISSING_GH=1`** for a single run you cannot
   otherwise complete. It prints what it let through. Do not put it in
   a CI image: an escape that is always set is not an escape.

If you have previously installed dependencies on a machine without
`gh`, those checkouts were never provenance-verified. Re-run
`capa install` on a machine that has it, and treat any dependency whose
attestation then fails as a finding rather than as a tooling problem.

## Related, in the same release, not a Capa behaviour change

The copy-paste example in the reusable release-guard workflow
(`.github/workflows/release-guards.yml`, the `HOW TO CALL IT` block)
omitted a `permissions:` block on the calling job. A caller who copied
it verbatim into a release workflow gave the guards the caller's
workflow-level grant, which in a release workflow includes
`id-token: write`: the token that signs Sigstore attestations. The
guard jobs inside the workflow correctly declare `contents: read` and
say in a comment that a guard "has no business holding a credential that
can sign anything"; the example contradicted them.

If you adopted those guards by copying that example, add to your
`guards:` job:

```yaml
    permissions:
      contents: read
```

The corrected example ships in `1.18.1`. Note that this bounds a
credential the guards never used; there is no indication of misuse, and
nothing in the guard scripts signs anything.
