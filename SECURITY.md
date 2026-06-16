# Security policy

Capa is a programming language whose design centres on security
properties. If you find a way that the language fails to deliver on
those properties, a way to bypass the capability discipline, escape
attenuation, or compromise the analyzer, please report it.

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

Out of scope:

- A program that legitimately receives a capability and uses it
  maliciously. Capa narrows where authority *can* hide; it does not
  audit *what holders of authority choose to do*.
- Attacks that require uses of the `Unsafe` capability or `py_import`.
  The Python interop boundary deliberately exits the discipline.
- Issues with third-party Python packages used at build time.
- Theoretical issues in the type system that have no concrete attack.

## Supported versions

Capa is at version 1.0 and is a one-person project. Only the latest
tagged release is supported for security fixes. I may publish patch
releases for the latest minor when a fix is significant.

| Version | Supported |
| ------- | --------- |
| 1.0.x   | yes       |
| < 1.0   | no, please upgrade |

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
