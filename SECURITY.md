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

You can also email **nelson.duarte31@gmail.com** with the subject line
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

Capa is on the `1.x` line (latest `1.17.0`) and is a one-person
project. Only the latest tagged release is supported for security fixes.
I may publish patch releases for the latest minor when a fix is
significant.

| Version | Supported |
| ------- | --------- |
| 1.15.x (latest) | yes |
| < 1.15  | no, please upgrade |

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
