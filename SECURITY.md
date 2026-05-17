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

The project is in alpha. Only the latest tagged release is supported
for security fixes. We may publish patch releases for the latest
minor when a fix is significant.

| Version | Supported |
| ------- | --------- |
| 0.2.x   | yes       |
| < 0.2   | no, please upgrade |

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
