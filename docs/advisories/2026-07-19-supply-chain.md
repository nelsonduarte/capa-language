# Capa security advisory, 2026-07-19: the module resolver satisfied imports from outside the project

> **Status.** Published with the `1.18.0` release. The module loader's
> project-root fallback could satisfy an import from a directory the
> supply-chain machinery had never seen: never fetched, never verified
> against `capa.lock`, never pinned, and absent from every SBOM the
> build emitted. The fix narrows the fallback, which changes the
> observable resolution order, a surface
> [`STABILITY.md`](../../STABILITY.md) lists as covered by SemVer. The
> change is claimed under the **security exception** (the same
> soundness-fix carve-out Rust and Python follow) and therefore ships
> as a **MINOR** bump, not a MAJOR one. The rationale is stated below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: `1.17.0` and earlier on the `1.x` line. The fallback
has been present since the package manager shipped.
Fixed in: `1.18.0` (PR #85).
Reporter / process: found internally while investigating why
`capa_authgate` `v0.1.0` passed CI and did not compile for anyone who
downloaded it.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.18.0` `CHANGELOG.md`
entry.

## The finding

Whenever a `capa.toml` existed in the working directory, the **parent of
the project root** was an open module search root, and `capa test`
injected that same parent into each test subprocess's `CAPA_PATH`.

Two existing mitigations kept the parent from **shadowing** a verified
dependency: it was appended after `./vendor` and after the declared
path dependencies, and the search path was de-duplicated. Neither
mitigation addressed the actual hazard, which is not shadowing but
**satisfying**. Nothing stopped the parent from resolving an import
that `./vendor` could not.

The consequence is precise. An **undeclared** transitive dependency
resolved against whatever same-named sibling directory happened to sit
next to the project. Those sources were:

- never fetched by `capa install`,
- never verified against `capa.lock`,
- never GPG-verified,
- never version-pinned,
- and never recorded in the manifest, the CycloneDX / SPDX SBOM, or the
  provenance attestation.

The build linked code the provenance machinery never saw, reported
success, and emitted a supply-chain description of itself that was
incomplete. For a language whose central claim is machine-verifiable
supply-chain integrity, a build that silently links unrecorded sources
is the one outcome that cannot be tolerated.

## Why this is a security fix and not a breaking change

The prior behaviour is an **integrity** bug in the sense
[`SECURITY.md`](../../SECURITY.md) already scopes: the integrity of the
published manifest and supply-chain artefacts. A manifest that omits a
linked dependency is not a smaller manifest, it is a wrong one, and
every downstream consumer of that SBOM inherits the error.

It also **failed open**. A missing dependency is supposed to fail
loudly and closed: `cannot resolve 'import x.y'`, at compile time,
before anything is published. Instead it succeeded on the one machine
whose directory layout happened to supply the missing piece, which is
by construction the maintainer's machine and never the user's. The
failure mode is therefore invisible exactly where it matters and
guaranteed where it does most damage.

It **masked a real defect for months**, which is the concrete proof
that the hazard is not theoretical. `capa_authgate` `v0.1.0` was
published without its transitive `capa_hash` dependency and its
published tarball does not compile. The development tree compiled
cleanly throughout, because a `capa_hash` checkout sat beside it.

The direction of the change is strictly **narrowing**: a program that
compiled only because of the fallback now fails at compile time with a
resolution error naming the unresolved import. No program that declared
its dependencies is affected, and no previously-rejected program is now
accepted.

## What changed

The documented justification for the fallback was always narrower than
the fallback itself: it existed so that a package could import **its
own name**, as a seed library whose repository directory *is* the
package does. The fix serves exactly that case and nothing more.

- `[package].name` from `capa.toml` now maps to the project root in the
  dependency-root table, alongside the declared `path` dependencies.
- The **parent directory is no longer a search root**, in either the
  CLI or the test runner.
- A declared dependency of the same name still wins, so the self-entry
  can never displace a resolved dependency.
- Keying on the **manifest name** rather than the directory basename
  makes the self-reference work in a working copy checked out under a
  different directory name.

Unchanged: `verify_vendored_deps` still fails closed before `./vendor`
joins the search path, and `./vendor` and the declared path
dependencies keep their existing precedence.

## Who is affected, and what to do

You are affected if a project of yours compiled by resolving an import
against a **sibling directory** rather than against a declared
dependency. After upgrading, that build fails with `cannot resolve
'import x.y'`.

That error is correct and it is telling you something true: the
dependency was never declared, so it was never in your lockfile and
never in your SBOM. The fix is to declare it.

1. Add the dependency to `capa.toml`, either from the registry or as an
   explicit `path` dependency if it really is a local checkout.
2. Run `capa install` so it is fetched, verified and written to
   `capa.lock`.
3. Re-emit any published SBOM or provenance artefact for the affected
   release. The previous one under-reported the dependency set.

If your project imports **its own** package name, nothing changes: that
case is still resolved, and now resolves by manifest name rather than
by directory layout.

## Defence in depth shipped alongside

Two release guards ship in the same version and exist to catch this
class of defect before an artefact reaches a user rather than after
(PR #86, `.github/workflows/release-guards.yml`):

- `tools/clean_room_build.sh` extracts a release artefact into a
  directory **with no siblings** and runs the consumer flow there using
  a released compiler, never the working tree. Verified against the
  real artefacts: the published `capa_authgate` `v0.1.0` tarball fails
  at `import capa_hash.hmac`, and `v0.2.1` passes the full flow.
- `tools/check_tag_version.sh` requires the tag to equal the manifest
  version, closing a separate case where a package was published tagged
  `v0.2.0` with its manifest still declaring `0.1.0`.

Both are reusable via `workflow_call` and fetched at
`github.job_workflow_sha`, so a caller runs exactly the revision it
pinned rather than N drifting copies.

## Known limitation, disclosed rather than fixed

`capa.toml`'s `capa = ">=X.Y.Z"` is parsed into
`Manifest.capa_requirement` and never read back, so **nothing in the
compiler enforces a package's declared compiler floor**. The clean-room
guard is currently the only thing that tests that claim, and it tests
it only at release time. This is disclosed here rather than left for a
user to discover.
