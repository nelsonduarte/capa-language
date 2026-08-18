# Trust model

This page consolidates, in one place, exactly what the Capa toolchain
verifies about a build and its dependencies, and what it does not. It is
written for a sceptical supply-chain auditor: every line here is meant to
be checkable against the code, and where a guarantee has an edge the edge
is stated rather than rounded up.

Four tiers, in decreasing order of strength:

1. **Unconditional (fail-closed)** the build is refused, or the claim is
   true by construction.
2. **Best-effort (fail-open)** an extra layer that runs when it can and
   silently steps aside when it cannot. It never downgrades trust on its
   own; it is backed by the unconditional tier underneath it.
3. **Premises / TCB boundary** things the toolchain trusts rather than
   verifies.
4. **Outside the threat model** explicitly not defended here.

The detailed mechanics live in
[`SECURITY.md`](../SECURITY.md) (threat model + advisories),
[`docs/packages.md`](packages.md) (`capa.toml` / `capa install` /
lockfile), and
[`docs/regulatory.md`](regulatory.md) (reproducibility, regulatory
mapping). This page references them rather than restating them.

## 1. Unconditional guarantees (fail-closed)

These are either true by construction or cause the build / install to be
refused on failure.

- **SBOM capability claims are derived from the source, not guessed.**
  The `capabilities`, `provably_excluded_capabilities`,
  `declassification_sites`, `has_unsafe`, and `constant_time` fields in
  the manifest / CycloneDX / SPDX output are computed by the analyzer
  from the same signatures and flow analysis it uses to accept or reject
  the program (`capa/manifest/`). They are not a heuristic scan layered
  on afterwards: if the code exercises a capability, the type system
  already required it to be declared, and the SBOM reads it off that.
  - `provably_excluded_capabilities` is **conservative**: it is a sound
    over-approximation of what a value's type can transitively reach,
    closed-world over all impls in the program
    (`capa/manifest/_reachability.py`). A capability is listed as
    provably excluded only when no reachable impl, struct field,
    sum-variant payload, or captured closure can reach it. It will under-
    claim before it over-claims.
  - `has_unsafe` is true whenever `Unsafe` is reachable. The escape hatch
    always surfaces in the SBOM (see tier 4).

- **Lockfile SHA enforcement catches a moved tag (retag).** When
  `capa.lock` already pins a commit for a tag dependency, `capa install`
  checks the remote tag still resolves to that commit via
  `git ls-remote` **before** touching `vendor/<name>`, so a force-pushed
  upstream tag is refused (`LockMismatchError`) without ever overwriting
  the vendored sources. Rev pins are re-checked after clone. See
  `capa/pkg/_install.py`.

- **GPG tag/commit signature verification is anchored on the primary
  key.** When a dependency declares `verify_key` (a 40-char fingerprint),
  `capa install` runs `git verify-tag` / `verify-commit` and matches the
  **primary-key** fingerprint from the GPG `VALIDSIG` line (the last
  field) against the declared key. Anchoring on the primary accepts a
  valid signing subkey under it (GPG has already proved the subkey-to-
  primary binding) and refuses an unsigned ref, an unknown key, or a
  different key. See `_verify_signed_pin` in `capa/pkg/_install.py`.

- **Build-time vendor re-verification (PKG-1).** Before the loader reads
  `./vendor`, every git dependency is re-checked against `capa.lock` on
  every build path (`capa --check` / `--run` / `--transpile`,
  `capa migrate`, `capa test`). Two conditions must both hold,
  fail-closed: the vendored HEAD must equal the locked commit **and** the
  working tree must be clean at that commit (`git status --porcelain`).
  The working-tree half is what catches an in-place edit of a checked-out
  file, which leaves HEAD matching the lock while changing the code that
  actually runs. See `capa/pkg/_verify.py`. Opt-out: `CAPA_NO_VERIFY=1`
  (annuls the guarantee, by design; see tier 3 for the premise it rests
  on).

- **The registry index is signature-verified, fail-closed.** When
  `capa add <name>` resolves a name through the registry, the index JSON
  is verified against a root-key fingerprint baked into the toolchain
  (not shipped with the index). A missing, invalid, mismatched, or
  unverifiable-because-tampered signature is refused. See
  `capa/pkg/_registry.py` and
  [`docs/design/signed-registry-index.md`](design/signed-registry-index.md).
  Opt-out for a missing signature only (air-gapped / self-hosted
  mirrors): `CAPA_REGISTRY_ALLOW_UNSIGNED=1`. A present-but-invalid
  signature is **always** refused, env var or not.

- **SLSA L2 provenance is fail-closed under `verify_provenance =
  "required"` (M4).** When a git dependency sets `verify_provenance =
  "required"` (or `CAPA_REQUIRE_PROVENANCE=1` is set, which raises every
  dependency's effective level to `required`), every path the `warn`
  default would skip becomes a refused install: `gh` missing, no release
  tarball, non-GitHub host, offline, or a rev pin all raise a
  `VerificationError` naming the dependency and the reason. The check is
  reached independently of `verify_key`, so a dependency can require
  provenance without also pinning a GPG key, and the attestation is
  scoped to `--repo {owner}/{repo}` (M4 closed the prior owner-only
  weakness, where any attestation under the same owner satisfied it).
  `CAPA_REQUIRE_PROVENANCE` only **tightens**: it never lowers a
  dependency below its `capa.toml` level. See `_verify_slsa_provenance`
  in `capa/pkg/_install.py`.

- **A missing `gh` is fail-closed for a `verify_key` dependency
  (1.18.1).** `verify_key` in a consumer's own manifest is a written
  statement that this dependency is to be verified, so `capa install`
  refuses it when the verifier is absent, at every level except an
  explicit `verify_provenance = "off"`. Previously this printed one
  warning per dependency and installed anyway: in a clean room without
  the GitHub CLI, all seven dependencies of a project installed
  unverified. A supply-chain check that opens because a tool is missing
  is one that anybody can switch off by not installing something. The
  escape is `CAPA_ALLOW_MISSING_GH=1`, which installs and names every
  dependency it let through on stderr. Deliberately narrow: it covers
  the missing-TOOL case only, since a rev pin, a non-GitHub host, an
  absent tarball and an unreachable network are facts about the
  dependency rather than about the consumer's machine, and those stay
  in tier 2 below. See `_refuse_or_allow_missing_gh` in
  `capa/pkg/_install.py`.

- **A malformed root `capa.toml` is refused (1.19.0).** It used to be
  degraded to `warning: ignoring capa.toml` and the build continued.
  Ignoring the manifest discards the declared dependency `path`
  mapping, so `import mylib.util` stopped resolving to the declared
  directory and fell through to whatever same-named directory was on
  the module search path: a **different source file compiled and ran**,
  exit 0. One lowercase letter in the unrelated `[capabilities]` table
  was enough to trigger it. Every file-based invocation now exits
  non-zero with `capa: broken capa.toml: <path>: <reason>`, as do
  `test`, `build`, `install`, `migrate` and `repl`. Six invocations are
  exempt by design, none of which can produce a build: `--help`,
  `--version`, a bare `capa`, `search`, `init` and `lsp`. `capa add` is
  exempt from that gate too, so it stays available to repair the file,
  but it refuses on its own read with the different prefix
  `capa add: <path>: <reason>`, also at exit 2 and without writing to
  `capa.toml`. There is **no escape
  hatch**, because the remediation (fix the file) is always available to
  whoever hit it, and an env var restoring "ignore it and build anyway"
  would restore the source substitution with it. See
  `capa/pkg/_manifest.py`'s `read_root_manifest` and
  [advisory 2026-07-20](advisories/2026-07-20-capa-floor.md).

- **The declared compiler floor is enforced (1.19.0).**
  `capa = ">=X.Y.Z"` in `[package]` is the package's statement of the
  oldest compiler it can be built with. It used to be parsed and never
  read back, so a package declaring `>=1.18.1` built silently on 1.2.0.
  Building below the floor does not fail loudly: it succeeds and emits
  an SBOM, provenance and capability claims derived by a compiler
  missing the fix the floor existed to require. The **root** manifest's
  floor is now a hard error, under the same six exemptions as the bullet
  above plus `capa add`; a **dependency**'s warns, once, naming the
  package, because the consumer cannot fix someone else's floor by
  editing their own manifest. A missing `capa` key is unconstrained.
  The escape is `CAPA_IGNORE_CAPA_FLOOR=1`, which builds anyway and
  prints the refusal it overrode in full. See `capa/pkg/_floor.py` and
  [advisory 2026-07-20](advisories/2026-07-20-capa-floor.md).

- **SBOMs are byte-reproducible.** With `SOURCE_DATE_EPOCH` set, the
  CycloneDX / SPDX / VEX / SLSA artefacts are byte-for-byte identical
  across runs and machines, so an auditor can rebuild and diff. See
  `capa/manifest/_timestamp.py` and
  [the reproducible-artefacts section of the regulatory note](regulatory.md#reproducible-sboms-rebuild-and-diff-byte-for-byte).

## 2. Best-effort (fail-open)

These run when they can and step aside when they cannot. They add
defence in depth but do **not**, on their own, make or break the
trust decision: the unconditional tier above stands underneath them.

- **SLSA L2 build-provenance attestation of dependencies (`warn`
  default).** For a GitHub-hosted git dependency pinned to a tag, `capa
  install` runs `gh attestation verify` against the release source
  tarball, checking the Sigstore Rekor log, scoped to `--repo
  {owner}/{repo}` (an attestation from a different repo under the same
  owner does not satisfy it). The per-dep `verify_provenance` field (M4)
  decides what a *missing precondition* does. At the default level
  `warn`, the layer is **best-effort but visible**: when the release has
  no matching tarball, the host is not GitHub, the endpoint is
  unreachable, or the pin is a rev, it prints a clear stderr warning
  naming the dependency and the reason, then continues. (A missing `gh`
  no longer belongs in that list for a dependency that declares
  `verify_key`; it moved to tier 1 in 1.18.1.) It
  **always fail-closes** when the tarball IS present and
  `gh attestation verify` returns non-zero. The honest consequence under
  `warn`: an attacker who removes the release tarball, or serves the
  dependency from a non-GitHub host, downgrades this layer, but the
  downgrade is now printed rather than silent, and the build is still
  defended by the unconditional lockfile-SHA and GPG layers beneath it.
  Set `verify_provenance = "off"` to silence the warning deliberately.
  See `_verify_slsa_provenance` in `capa/pkg/_install.py`. For the
  fail-closed mode, see tier 1's `verify_provenance = "required"` entry.

## 3. Premises / TCB boundary

These are trusted, not verified. An auditor must account for them
separately.

- **`capa.lock` is part of the trusted computing base.** PKG-1 verifies
  that `vendor/<name>` matches the **committed lock**; it does not verify
  the authenticity of the lock itself. An attacker who adulterates
  `vendor/<name>`, commits the change so HEAD moves, **and** rewrites
  `capa.lock` to match the new commit coherently is not caught by the
  build-time check: rewriting the committed lock already breaches the TCB
  boundary. The lock's commit was GPG / SLSA-verified at install time;
  re-running `capa install` is what re-establishes that anchor.

- **The local git state of `./vendor` is part of the TCB.** PKG-1 reads
  `git status --porcelain`. An attacker with local write access who runs
  `git update-index --assume-unchanged` / `--skip-worktree` on a vendor
  file (or leaves a vendored submodule uninitialised) can make `status`
  report clean over an edit. This is the same class as a coherently
  rewritten lock: it requires an attacker who already has local git
  write access, which is inside the TCB boundary, not a new gap.

- **The compiler and toolchain themselves.** The analyzer is not formally
  verified; the Agda `lambda_if` / `lambda_cap` proofs are over the model,
  so a soundness gap between the analyzer and that model is in scope as a
  *vulnerability* (see [`SECURITY.md`](../SECURITY.md)) but the running
  Python toolchain is trusted to execute.

- **The compiled Wasm artifact, on the Wasm backends.** Capability
  confinement and attenuation on `capa --wasm` (core module and Component
  Model) are enforced by the trusted Capa compiler / emitter together
  with the host handle table, not by an operator-supplied policy. The
  per-instance handle table is now bootstrapped with a root ONLY for the
  capabilities the artifact declares in its `capa:main-cap-types`
  binding, so the declared cap set is a runtime-enforced UPPER BOUND on
  the authority the artifact can exercise, on all three hosts (the core
  `WasmHost`, the AOT `capa run-aot` path, and the Component host). The
  linker still defines every `capa:host/*` import, but a hand-written or
  edited module that declares only `net` and forges the small integer an
  undeclared cap's root would have held now finds no entry (or a
  wrong-type entry) at the typed handle-table lookup, and the privileged
  op denies: cross-capability forgery, where an artifact declares one cap
  and exercises a different, undeclared one, is closed. See
  `capa/runtime/_cap_handles.py`.

  Three things remain trusted rather than verified, and this is not a
  sandbox for arbitrary artifacts:

  - The `capa:main-cap-types` binding is the artifact's OWN,
    freely-editable self-declaration, and there is no operator-supplied
    cap allowlist on `run-aot`. A malicious artifact may simply declare
    all six handle-bearing caps and receive all six roots. What the fix
    restores is the honesty of the declared / SBOM cap set (imports can
    no longer exceed the declaration), not a confinement decided by the
    operator. Operator cap-allowlisting is a separate, open question.
  - Within a cap it DID declare, root handles and their `restrict_to`
    children are still small predictable integers, so a guest can name
    the unrestricted root of that cap. This is not a cross-cap
    escalation, it is authority the artifact already holds by declaring
    the cap, and on the single-artifact core path there is no in-instance
    trust boundary to cross; but full handle unforgeability is deferred,
    tracked work.
  - The guarantee holds at *interface granularity* for a component the
    Capa compiler produced; intra-artifact attenuation still relies on
    the emitter.

  Consequently the executed `.wasm` / `.cwasm` stays part of the TCB:
  running a third-party-supplied artifact trusts that artifact's declared
  cap set as its authority ceiling. The fix makes that ceiling ENFORCED
  rather than advisory; it does not remove the artifact from the TCB. See
  [`docs/design/wasm-cap-handles.md`](design/wasm-cap-handles.md).

- **`install.sh` channel integrity (M3).** Same-channel SHA pinning for
  the one-line installer is **deferred by design** and tracked
  internally as M3. Until it lands, the installer trusts its
  download channel.

- **Operator-trusted source roots.** `CAPA_PATH` directories and the
  `./libraries/` fallback are read on the operator's trust: they are not
  vendored, not pinned in `capa.lock`, and not covered by the per-SHA
  verification. Code reached through them is the operator's
  responsibility. See the source-resolution section of
  [`docs/packages.md`](packages.md).

## 4. Outside the threat model

- **`Unsafe` / Python interop.** `Unsafe` is the declared escape hatch
  out of the capability discipline. It is not a vulnerability, but it
  **always** appears in the SBOM (`has_unsafe`, plus reachability), so a
  build that uses it cannot hide that fact from an auditor. Attacks that
  require `Unsafe` or `py_import` are out of scope by design
  ([`SECURITY.md`](../SECURITY.md)).

- **Microarchitectural / cache timing.** The `@constant_time` marker is a
  **language-level** check: it forbids data-dependent branching and
  short-circuiting on secret values in the marked function. It does not,
  and cannot, certify the absence of cache-, port-, or
  microarchitecture-level timing leaks below the language.

- **Compromise of the GitHub release channel or a signing key.** The
  registry root key and a dependency's `verify_key` are trust anchors: an
  attacker who holds the corresponding private key can produce signatures
  that verify. CI release-action pinning by SHA reduces the surface, but
  a compromised trust anchor is outside what per-build verification can
  detect.

## Where to go next

- [`SECURITY.md`](../SECURITY.md) the declared threat model, what counts
  as a vulnerability, and the published advisories under
  [`docs/advisories/`](advisories/).
- [`docs/packages.md`](packages.md) `capa.toml`, `capa install`, the
  lockfile, and source resolution.
- [`docs/regulatory.md`](regulatory.md) reproducibility and the
  regulatory mapping (EU CRA, NIS2, DORA, NIST SSDF, OWASP SCVS).
