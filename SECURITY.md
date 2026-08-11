# Security policy

Capa is a programming language whose design centres on security
properties. If you find a way that the language fails to deliver on
those properties, a way to bypass the capability discipline, escape
attenuation, or compromise the analyzer, please report it.

For a consolidated map of what the toolchain verifies unconditionally
(fail-closed), what is best-effort (fail-open), what it trusts as a
premise, and what is outside the threat model, see
[`docs/trust-model.md`](docs/trust-model.md).

## Reporting a vulnerability

**Please do not open a public GitHub issue for security reports.**

Use GitHub's private vulnerability reporting channel:

1. Go to <https://github.com/nelsonduarte/capa-language/security/advisories/new>
2. Describe the issue in as much detail as you can:
   - Affected version (`git rev-parse HEAD`)
   - A minimal `.capa` reproduction, if applicable
   - Expected behaviour vs. what actually happens
   - Why you believe it is a security issue (which property is broken)
3. Submit. Only repository maintainers will see the report.

You can also email **security@capa-language.com** with the subject line
`[capa security]`. PGP is not currently set up.

I aim to acknowledge reports within **7 days** and to provide a
detailed response within **30 days**. Capa is a personal project; I
will be transparent if a fix takes longer.

## What counts as a security issue

In scope:

- Compilation succeeds for a program that violates the capability
  discipline (e.g., a function performs IO without declaring the
  required capability, or aliases a capability across two arguments).
- Attenuation is bypassed at runtime: a capability constrained with
  `restrict_to(host)` reaches a host it should not.
- The `consume` qualifier is bypassed (a value is used after consumption).
- A way to obtain a built-in capability without it being a function
  parameter (other than through `Unsafe` / Python interop, which is
  explicitly out of scope of the discipline by design).
- Compilation accepts a program where a `@secret` value reaches a
  public sink that the analyzer should reject: an information-flow /
  noninterference violation (for example under `@strict_ifc`). Capa's
  information-flow control is a first-class, machine-checked security
  property (cross-function and per-field IFC, implicit-flow
  enforcement under `@strict_ifc`), backed by the Agda `lambda_if`
  noninterference proof. The analyzer itself is not formally verified;
  the proof is over the `lambda_if` model, so a soundness gap between
  the analyzer and that model is in scope.
- Crash or arbitrary code execution in the analyzer / transpiler when
  given a malformed `.capa` input. While Capa is not yet positioned
  as a sandbox for untrusted source, defensible behaviour matters.
- A vendored dependency under `./vendor/` whose code no longer matches
  the commit `capa.lock` froze is read and built without detection.
  Both ends are verified: `capa install` enforces the locked SHA (and
  GPG / SLSA when a `verify_key` is set), and the build path
  (`capa --check` / `--run` / `--transpile`, `capa migrate`,
  `capa test`) re-verifies each git dep before reading `vendor/<name>`,
  fail-closed, on two conditions: its HEAD must equal the locked commit
  *and* its working tree must be clean at that commit. The working-tree
  check matters because an in-place edit of a checked-out file leaves
  HEAD matching the lock while changing the code the build reads. What
  this does not catch, by stated premise, is an attacker who adulterates
  `vendor/<name>`, commits the change, and rewrites the committed
  `capa.lock` to match: the lockfile is part of the project's trusted
  computing base. The build-time check is the post-install tamper guard;
  it is bypassed only by the explicit `CAPA_NO_VERIFY=1` opt-out, which
  annuls the guarantee by design and is therefore not a vulnerability.

Out of scope:

- A program that legitimately receives a capability and uses it
  maliciously. Capa narrows where authority *can* hide; it does not
  audit *what holders of authority choose to do*.
- Attacks that require uses of the `Unsafe` capability or `py_import`.
  The Python interop boundary deliberately exits the discipline.
- Issues with third-party Python packages used at build time. CI does
  gate on known advisories in the packaged dependency set: a `pip-audit`
  job runs on every pull request over the package plus its `[lsp,wasm,test]`
  extras and fails the build on any known vulnerability.
- Theoretical issues in the type system that have no concrete attack.

## Supported versions

Capa is on the `1.x` line (latest `1.30.1`) and is a one-person
project. Only the latest tagged release is supported for security fixes.
I may publish patch releases for the latest minor when a fix is
significant.

| Version | Supported |
| ------- | --------- |
| 1.30.1 (latest) | yes |
| < 1.30.1 | no, please upgrade |

## Published advisories

Dated advisories are kept in [`docs/advisories/`](docs/advisories/).
The 2026-05-25 audit record lives at the repository root in
[`security-audit.md`](security-audit.md).

- [`docs/advisories/2026-06-15-soundness.md`](docs/advisories/2026-06-15-soundness.md):
  four linear / typestate affinity fixes (use-after-consume, anonymous
  drop, `var` / re-assignment, partial consume in `match`) and two
  information-flow fixes (`@secret` field read and destructure both
  dropped the label), shipped in `1.2.0` under the security exception.
- [`docs/advisories/2026-06-16-soundness.md`](docs/advisories/2026-06-16-soundness.md):
  two information-flow fixes (a `@secret` laundered through a `match` /
  `if` value or a capturing closure, and a captured-secret closure passed
  to a higher-order function that invokes it and sinks the result), one
  linear-affinity fix (double-consume via alias or captured closure), and
  two manifest fixes (`provably_excluded_capabilities` falsely excluded a
  capability reachable through a closure hidden in a struct field or a
  sum-variant payload), shipped in `1.3.0` under the security exception.
- [`docs/advisories/2026-06-17-security.md`](docs/advisories/2026-06-17-security.md):
  capability-attenuation and enforcement fixes (`Proc.restrict_to` fixed
  the binary identity not just the basename, `Db.allows` canonicalises
  through `realpath`, and a `Db` open re-validates the kernel true path
  to close a symlink TOCTOU), information-flow and constant-time fixes (a
  reassignment laundered a `@secret` in the default tier, a
  `@constant_time` function admitted a short-circuiting secret string /
  list compare, and an early return under `@strict_ifc` leaked the
  predicate bit and across a function boundary), encapsulation fixes
  (field access through an abstract-capability / trait receiver, and
  `Unsafe` hidden in a capability-bearing struct), manifest fixes
  (`provably_excluded_capabilities` falsely excluded a capability
  reachable through a cap-bearing struct, a nested field, or a
  sum-variant payload, plus a multi-module provenance / SBOM digest and
  stable single-file identifiers), and supply-chain fixes (GPG anchored
  on the primary key, `file://` traversal incl. percent-encoding,
  fail-closed registry index) plus a `parse_int` DoS, shipped in `1.4.0`
  under the security exception.
- [`docs/advisories/2026-07-03-soundness.md`](docs/advisories/2026-07-03-soundness.md):
  a family of cross-boundary `@secret`-laundering false negatives closed
  in the information-flow control (a free-function call result now follows
  the callee's return effects, a `@secret` label on a module `const` is
  now enforced with correct lexical scoping, a secret captured by an
  escaping lambda is caught cross-function, and the two-hop
  closure-by-name is flagged fail-positive-free), all verified
  adversarially and fail-closed under `@strict_ifc`; a formatter fix
  (`capa --fmt` silently stripped `@secret` / `@public` labels and the
  typestate index from every type position, disarming the IFC); and a
  provenance-integrity fix (the stamped `capa_version` was a stale
  hard-coded literal, now single-sourced from `pyproject.toml`), shipped
  in `1.15.0` under the security exception.
- [`docs/advisories/2026-07-19-supply-chain.md`](docs/advisories/2026-07-19-supply-chain.md):
  the module loader's project-root fallback made the parent of the
  project root an open search root, so an undeclared transitive
  dependency could be satisfied by a same-named sibling directory that
  was never fetched, never verified against `capa.lock`, never pinned
  and absent from every emitted SBOM. The build linked sources the
  provenance machinery never saw and reported success. The fallback is
  now scoped to the package's own name, which narrows the SemVer-covered
  module resolution order, shipped in `1.18.0` under the security
  exception.
- [`docs/advisories/2026-07-19-install-fail-open.md`](docs/advisories/2026-07-19-install-fail-open.md):
  `capa install` skipped the SLSA build-provenance layer entirely when
  the `gh` CLI was not on PATH, printing one warning per dependency and
  installing all of them, so a fail-closed supply-chain check could be
  switched off by not installing a tool. A dependency that declares
  `verify_key` is now refused when no verifier is available, with
  `CAPA_ALLOW_MISSING_GH=1` as a loud, per-dependency-traced escape.
  This makes a previously-succeeding install fail, shipped in `1.18.1`
  under the security exception. The same advisory records that the
  reusable release-guard workflow's copy-paste example omitted
  `permissions:` on the calling job, so a verbatim copy handed the
  guards the caller's `id-token: write`.
- [`docs/advisories/2026-07-20-capa-floor.md`](docs/advisories/2026-07-20-capa-floor.md):
  the root `capa.toml` was advisory rather than authoritative, in two
  ways that turned out to be one defect. A **malformed** root manifest
  was degraded to `warning: ignoring capa.toml` and the build continued;
  ignoring it discards the declared dependency `path` mapping, so a
  same-named directory shadowed the audited source and a **different
  source file was compiled**, exit 0. One lowercase letter in the
  unrelated `[capabilities]` table was enough. Separately, the
  `capa = ">=X.Y.Z"` field, a package's declaration of the oldest
  compiler it can be built with, was parsed and never read back, so a
  package declaring `>=1.18.1` built silently on `1.2.0`; building below
  the floor does not fail loudly, it succeeds and emits an SBOM,
  provenance and capability claims derived by a compiler lacking the fix
  the floor existed to require (the advisory names the `1.4.0`
  `provably_excluded_capabilities` false-exclusion fix as the instance).
  The first defect disabled the fix for the second, which is why they
  ship together. A malformed root manifest is now a hard error on every
  path that builds, with no escape hatch; the root manifest's floor is
  now a hard error and a dependency's a warning, with
  `CAPA_IGNORE_CAPA_FLOOR=1` as a loud escape for the floor only.
  Neither check is universal across the CLI, deliberately, and the
  exempt set is small enough to state here: `--help` (anywhere in the
  compiler's arguments), `--version`, a bare `capa`, `search`, `init`
  and `lsp` skip both, each for a reason recorded beside
  `_FLOOR_EXEMPT_COMMANDS` in [`capa/cli.py`](capa/cli.py); `capa add`
  additionally skips the floor, so that a floor you cannot satisfy
  never blocks you from editing the manifest that declared it. `capa add`
  still refuses a malformed manifest, on its own read, with
  `capa add: <path>: <reason>` at exit 2 and without writing to
  `capa.toml`. Everything else refuses, including `test`, `build`,
  `install`, `migrate`, `repl` and every file-based invocation. Both
  shipped in `1.19.0` under a single invocation of the security
  exception.
- [`docs/advisories/2026-07-24-net-scheme-confinement.md`](docs/advisories/2026-07-24-net-scheme-confinement.md):
  an unrestricted `Net` capability could read local files and reach
  non-HTTP schemes, because `Net.get` / `Net.post` handed the URL to
  Python's default `urllib` opener, which registers `FileHandler`,
  `DataHandler` and `FTPHandler`. A program holding only `Net`, with no
  `Fs` parameter, read a local file over `file://` and returned its
  contents while `--manifest` certified `Fs` in
  `provably_excluded_capabilities`; `data:` returned its decoded payload
  and `ftp:` opened a control connection. Separately, an HTTP redirect
  could steer a request to a host the capability did not permit, because
  the host check ran only on the initial URL. This is a
  capability-confinement bypass: one capability exercised another's
  authority (filesystem read and arbitrary-scheme egress). `Net` now
  speaks `http` / `https` only, on the first request and every redirect
  hop, with the opener built without the file/data/ftp handlers, which
  refuses schemes a previous version accepted. Affected `v0.2.0-alpha`
  through `v1.19.0`, shipped in `1.20.0` under the security exception.
- [`docs/advisories/2026-08-01-wasm-cap-forge.md`](docs/advisories/2026-08-01-wasm-cap-forge.md):
  on the Wasm backends the per-instance capability handle table was
  bootstrapped with a root for every handle-bearing capability (Fs, Net,
  Db, Proc, Env, Clock) regardless of what the artifact declared, and
  those roots are small predictable integers, so a hand-crafted `.wasm` /
  `.cwasm` whose `capa:main-cap-types` binding named only one capability
  could forge the integer of an undeclared capability's root, call that
  capability's `capa:host/*` import, and exercise authority it never
  declared. Reachable through the shipped `capa run-aot` verb (exit 0, no
  diagnostic) and on the core `--run --wasm` and Component hosts. The
  table is now bootstrapped with a root only for the declared
  capabilities, so a forged integer for an undeclared capability fails
  the typed handle-table lookup and the operation denies; the linker is
  unchanged, the gate is the missing root. This restores the honesty of
  the declared / SBOM capability set (imports can no longer exceed the
  declaration) on all three hosts; it does not make `run-aot` a sandbox
  for arbitrary artifacts, and the intra-capability widening residual and
  full handle unforgeability remain deferred. The default Python backend
  was never affected. Affected all releases with the Wasm capability
  backend, through `1.25.0`, shipped in `1.25.1` under the security
  exception.
- [`docs/advisories/2026-08-08-ifc-param-carried-readback.md`](docs/advisories/2026-08-08-ifc-param-carried-readback.md):
  a cross-function information-flow false negative. A `@secret` value
  arriving as a plain parameter of a caller, pushed by a user callee (or a
  side-effecting `match`-arm guard) into a fresh caller-local, then read
  back and sent to a public sink in that caller, produced no diagnostic:
  the summary recorded the callee's write against the caller's own
  parameters (the mutation-target channel) but never on the local's
  read-back, so no default warning and no `@strict_ifc` error fired and the
  secret reached the sink at runtime on both backends (reproduced on the
  released `1.25.1` binary). The cross-function summary now carries a
  distinct, additive content channel, scoped uniformly per branch, so the
  callee's write raises the local's content label and the read-back leak
  warns by default and is a hard error under `@strict_ifc`. Closes the
  fresh, unaliased, param-carried read-back shape uniformly across
  control-flow positions; the general aliasing / escape case, a
  loop-carried read-before-write, and a whole-value-rebind
  over-approximation stay open and are documented. Affected `1.25.1` and
  earlier on the `1.x` line, shipped in `1.26.0` under the security
  exception.
- [`docs/advisories/2026-08-08-ifc-match-arm-container-leak.md`](docs/advisories/2026-08-08-ifc-match-arm-container-leak.md):
  the `match`-arm analogue of the read-back false negative above. A
  `@secret` value arriving as a plain parameter of a caller, pushed inline
  into a fresh caller-local **inside a `match` arm** (`xs.push(secret)`),
  then read after the `match` or stored into one of the caller's own
  parameters and sunk, produced no diagnostic: the cross-function summary
  copied each `match` arm's environment in isolation and discarded it, so
  the arm's mutation never reached the read-back. No default warning, no
  `@strict_ifc` error, and the secret reached the sink at runtime on both
  backends (reproduced on the released `1.26.0` binary); the identical `if`
  shape was flagged. The container-mutation taint is now recorded in a
  separate, branch-scoped channel (intra and summary), isolated per branch
  and deferred-unioned back across `if` / `elif` / `else`, `if ... then
  ... else`, and `match`, so the arm's push reaches a read after the
  construct and the leak warns by default and is a hard error under
  `@strict_ifc`. The same change also closed an unrelated precision false
  positive (a sibling-branch read of a leak-free push). Loop bodies are a
  disclosed sound over-approximation (not branch-isolated); the assignment
  sibling-branch false positive, the general list-aliasing false negatives,
  and the cross-function loop-carried read-before-write stay open and are
  documented. Affected `1.26.0` and earlier on the `1.x` line, shipped in
  `1.27.0` under the security exception.
- [`docs/advisories/2026-08-09-ifc-field-receiver-container-leak.md`](docs/advisories/2026-08-09-ifc-field-receiver-container-leak.md):
  the field-chain-receiver extension of the container-mutation taint. A
  `@secret` inserted into a container through a **field-chain receiver** on
  a local struct (`bag.items.push(secret)`, `bag.tags.add(secret)`,
  `bag.m.set(k, secret)`, nested `o.inner.items.push(secret)`), then read
  back through that same path into a public sink, leaked unflagged: the
  container-mutation taint fired only for a plain-identifier receiver, so
  the field-chain mutation was dropped. No default warning, no `@strict_ifc`
  error, and the secret reached the sink at runtime on both backends
  (reproduced on the released `1.27.0` binary). The taint is now keyed on
  the `(root-binding, field-path)` the container lives at and joined back on
  a read of that path or a nested path, so the leak warns by default and is
  a hard error under `@strict_ifc` for `List.push` / `Set.add` / `Map.set`
  and nested depth, without re-introducing the sibling-field / branch-scope
  false positives `1.26.0` and `1.27.0` removed. It closes the
  intra-procedural field-chain read-back on the container's declared root
  only; three distinct residuals stay open and are documented (a
  call- / index-rooted receiver, a whole-struct read of the same root, and
  the different-root points-to aliases), each a tested false negative.
  Severity low-to-moderate. Affected `1.27.0` and earlier on the `1.x`
  line, shipped in `1.28.0` under the security exception.
- [`docs/advisories/2026-08-10-ifc-cross-function-whole-struct-read.md`](docs/advisories/2026-08-10-ifc-cross-function-whole-struct-read.md):
  the whole-struct-read closure of `1.28.0`'s disclosed residual. A
  `@secret` pushed **inline** into a container field of a local struct
  (`bag.items.push(secret)`, keyed on `(bag, ("items",))`), then read back
  by reading or passing the **whole** struct, leaked unflagged: whole-struct
  interpolation (`"${bag}"`), a getter or method whose receiver is the
  struct (`bag.reveal()`, `bag.dump(stdio)`), and passing the whole struct
  to a sink-reaching callee (`show(bag)`, including one that sinks the
  tainted field among clean siblings). A whole-value read consulted only the
  exact empty-path key and never the tainted field prefix, so no default
  warning and no `@strict_ifc` error fired and the secret reached the sink
  at run time on both backends (this was `1.28.0`'s disclosed residual #2,
  reproduced on the released `1.28.0` binary). A whole-aggregate read now
  prefix-scans the `(root, field-path)` container channel, so the leak warns
  by default and is a hard error under `@strict_ifc`, on both backends, for
  `List.push` / `Set.add` / `Map.set` and nested depth. The same release
  moves the cross-function container-mutation effect onto the field-keyed
  channel (a clean sibling of a callee-pushed struct is no longer
  over-reported, a false positive `1.28.0` still had) and adds a
  field-qualified sink summary (passing a whole struct to a callee that
  sinks only a clean sibling stays clean); the callee-push whole-read was
  already caught on `1.28.0` and stays caught. The closed claim is scoped to
  the enumerated read shapes: a lambda-flow residual (a `@secret` passed to
  a local lambda that sinks it, and a container captured by a closure
  defined before a push) stays open and is the more general, pre-existing
  gap tracked for a separate fix, alongside the different-root points-to
  aliases, a call- / index-rooted receiver, and two sound over-reports, each
  tested. Severity low-to-moderate. Affected `1.28.0` and earlier on the
  `1.x` line, shipped in `1.29.0` under the security exception.
- [`docs/advisories/2026-08-10-ifc-lambda-flow-sensitivity.md`](docs/advisories/2026-08-10-ifc-lambda-flow-sensitivity.md):
  the lambda-flow closure of the residual `1.29.0` disclosed as its most
  serious open item. A `@secret` reaching a public sink through a
  **locally-resolved** lambda (a `let`-bound lambda invoked in the same scope,
  or an IIFE `(fun...)(x)`) leaked unflagged: the parameter-sink face
  (`let g = fun(s) => sink_str(s, stdio); g(secret)`) and the
  container-capture-**result**-sink face
  (`let f = fun() => bag.reveal(); bag.items.push(secret); stdio.println(f())`).
  The named-call boundary was already caught, so the gap was the lambda
  indirection; on `1.29.0` these passed a clean `capa --check`, passed under
  `@strict_ifc` with ZERO errors, and reached the sink at run time on both
  backends. Each lambda literal now carries a sink-reaching summary applied at
  a locally-resolved invocation, and each captured binding's CURRENT LIVE label
  is re-read at the invocation, so both faces warn by default and are a hard
  error under `@strict_ifc` on both backends. A coupled correctness fix rejects
  a NAMED argument at a first-class / lambda call (a `Fun` value carries no
  parameter names), closing a silent Python / Wasm divergence that could
  reorder a `@secret` into an un-sunk slot. The closed claim is scoped to
  locally-resolved lambdas for the parameter-sink and capture-result-sink
  cases: a sink INTERNAL to a closure body, closures that ESCAPE local
  resolution, a sink via a NESTED LOCAL lambda, and struct-field-store flows
  through captures stay open documented residuals, alongside two sound
  over-reports, each tested. Severity low-to-moderate. Affected `1.29.0` and
  earlier on the `1.x` line, shipped in `1.30.0` under the security exception.

## Public disclosure

I will coordinate public disclosure with the reporter. A typical
flow:

1. Reporter submits via the channel above.
2. Maintainer acknowledges and triages.
3. Maintainer prepares a fix on a private branch.
4. A GitHub Security Advisory is drafted with the reporter as a
   collaborator.
5. The fix is merged and tagged; the advisory is published the same day.
6. Reporter is credited in the advisory (unless they request otherwise).
