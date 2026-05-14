# Capa and the EU Cyber Resilience Act

A focused mapping of Capa's machinery onto the specific
articles and annex items of Regulation (EU) 2024/2847, the
[Cyber Resilience Act][cra-text] (CRA). Included in the repo
so the technical claims are reviewable against the artefact.

> The CRA's core ask, in plain language: products with digital
> elements placed on the EU market must be *secure by design*,
> ship *transparent dependency information*, and have
> *vulnerability-handling processes* in place. The regulation
> entered into force on 10 December 2024 with most obligations
> applying from 11 December 2027.

[cra-text]: https://eur-lex.europa.eu/eli/reg/2024/2847/oj

---

## Scope of this document

The CRA has 71 articles and four annexes. Most of it is
**organisational** (vulnerability disclosure processes,
incident notification timelines, conformity assessment
modules, market surveillance). Capa, as a programming
language, addresses none of that.

What Capa does address is a narrow but load-bearing slice:
the *technical* requirements in Annex I Part I (essential
cybersecurity requirements) and Annex I Part II (vulnerability
handling), specifically the items that interact with how a
product is *built* and *described*. This document is honest
about the line.

The rest of the CRA stack (vulnerability disclosure policy,
CSIRT notification within 24 hours of awareness of an actively
exploited vulnerability, etc.) is the manufacturer's
responsibility regardless of language choice. Capa makes the
technical side cheaper; it does not displace the
organisational side.

---

## CRA requirements that Capa addresses

The table below maps Capa features to specific CRA
requirements. The "How Capa helps" column is intentionally
narrow: it describes the *technical lever* Capa provides, not
a claim of full compliance.

| CRA reference | What the regulation requires | How Capa helps |
|---|---|---|
| **Annex I Part I (2)(a)** | "be made available on the market without known exploitable vulnerabilities" | Indirect: Capa's structural capability discipline rules out a *class* of vulnerabilities (ambient-authority abuse), demonstrated by the six CVE case studies in [`docs/`](.). For known-CVE detection at dependency level, the CycloneDX SBOM Capa emits is consumable by Dependency-Track / OSV-Scanner. |
| **Annex I Part I (2)(b)** | "be made available on the market with a secure-by-default configuration" | Direct: Capa programs cannot exercise authority they did not declare. The default for any function is *zero capabilities*; widening is explicit. Secure-by-default is the only configuration available. |
| **Annex I Part I (2)(c)** | "ensure that vulnerabilities can be addressed through security updates" | Indirect: the CycloneDX SBOM includes versions and a stable component identity scheme (`pkg:` PURLs), so update tracking ties back to the same identity used at audit time. |
| **Annex I Part I (2)(d)** | "ensure protection from unauthorised access ... appropriate authentication, identity management or access management systems" | Direct, at the source level: capabilities are unforgeable handles; access management is the type system. Cross-process authentication is below Capa's layer. |
| **Annex I Part I (2)(e)** | "protect the confidentiality of stored, transmitted or otherwise processed data ... encrypting relevant data at rest or in transit" | Out of scope for the language layer. Capa does not provide crypto primitives; it provides capability discipline over whatever crypto the user calls. |
| **Annex I Part I (2)(f)** | "protect the integrity of stored, transmitted or otherwise processed data ... programs, configuration against any manipulation" | Direct: every function's declared capabilities are derivable from its signature alone (Manifest Completeness Theorem, see [`docs/semantics.md`](semantics.md)). Manipulation of a dependency that adds `Fs`/`Net`/`Env` access is statically visible in the SBOM diff. |
| **Annex I Part I (2)(g)** | "process only data ... that are necessary ... ('minimisation of data')" | Direct: the principle of least authority is built into the language. A function gets exactly the capabilities it declares; nothing more is reachable. |
| **Annex I Part I (2)(h)** | "protect the availability of essential and basic functions ... including the resilience against and mitigation of denial-of-service attacks" | Out of scope. Capa does not address DoS. |
| **Annex I Part I (2)(i)** | "minimise their own negative impact ... on the availability of services provided by other devices or networks" | Indirect: explicit `Net` declaration on functions makes side-channel network behaviour auditable. |
| **Annex I Part I (2)(j)** | "be designed, developed and produced to limit attack surfaces, including external interfaces" | Direct: capability declarations *are* the external-interface contract. Reducing the surface of a function is editing its signature. |
| **Annex I Part I (2)(k)** | "be designed, developed and produced to reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques" | Direct, structurally: capability attenuation ([`fs_env_attenuation.capa`](../examples/fs_env_attenuation.capa)) bounds the blast radius of any compromised dependency. |
| **Annex I Part I (2)(l)** | "provide security related information by recording and monitoring relevant internal activity" | Partial: Capa's opt-in runtime trace (`capa/runtime/_trace.py`) records capability invocations. Not a full audit log. |
| **Annex I Part I (2)(m)** | "provide the possibility for users to securely and easily remove on a permanent basis all data and settings" | Out of scope for the language layer. |
| **Annex I Part II (1)** | "identify and document vulnerabilities and components contained in the product ... including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies" | **Direct, primary fit**: `capa --cyclonedx` emits a CycloneDX 1.5 SBOM with the capability manifest embedded as standard `properties[]` entries. This is a strict superset of the CRA minimum: not just *what* is included but *what each component can do*. |
| **Annex I Part II (2)** | "address and remediate vulnerabilities without delay" | Out of scope (organisational). |
| **Annex I Part II (3)** | "apply effective and regular tests and reviews of the security of the product" | Partial: the property-based test suite (`tests/test_properties.py`) and the six CVE case studies demonstrate ongoing review of the discipline. Per-product test obligations remain the manufacturer's. |
| **Annex I Part II (5)** | "once a security update has been made available, share and publicly disclose information about fixed vulnerabilities" | Out of scope (organisational). |
| **Annex I Part II (7)** | "provide for mechanisms to securely distribute updates ... to ensure that vulnerabilities are fixed or mitigated in a timely manner" | Out of scope (deployment-pipeline concern). |

---

## The novel contribution: capability-aware SBOMs

The CRA's Annex I Part II (1) is satisfied by any
machine-readable SBOM. CycloneDX, SPDX, and SWID are the
common formats; all three list components and versions.
[NTIA's minimum elements][ntia] (which the European
Commission's CRA SBOM guidance largely mirrors) require:

- supplier name
- component name
- component version
- other unique identifiers
- dependency relationship
- author of SBOM data
- timestamp

[ntia]: https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf

These tell you *what is in the box*. They do not tell you
*what the box can do*. Two versions of a library with
identical PURLs can have wildly different behaviour at the
language level. SBOM diffs at the dependency layer don't
catch this; they would never have caught ua-parser-js 2021,
event-stream 2018, eslint-scope 2018, or torchtriton 2022
(see the case studies in [`docs/`](.)).

Capa's contribution is to extend the SBOM with one extra
column: **declared capabilities per function**, statically
derived from the source. The CycloneDX output includes
properties of the form:

```
"properties": [
  { "name": "capa:declared_capability", "value": "Fs" },
  { "name": "capa:declared_capability", "value": "Net" },
  { "name": "capa:has_unsafe",          "value": "false" }
]
```

These are not heuristic taint analysis; they are the typed
signatures verified by the compiler. An audit tool comparing
two SBOMs of the same component can flag any function whose
declared capability set has widened, even if the version
number and dependency tree are unchanged. The audit pipeline
in [`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa)
implements this comparison end-to-end.

A small, fully reproducible side-by-side of a real-world
pattern (microservice config loading) in Python vs Capa,
including the SBOM diff, is in
[`docs/empirical_micro.md`](empirical_micro.md). That is the
smallest demonstration of the *information-gain* claim made
in this section.

---

## What this looks like in practice

A CRA-aligned development workflow with Capa:

1. **Build time.** `capa --cyclonedx my-project.capa > sbom.json`
   produces the SBOM with capability metadata embedded. This
   becomes one of the conformity-assessment artefacts the
   manufacturer keeps under Article 31.

2. **Policy authoring.** The security manager writes a JSON
   policy file mapping function names to allowed capabilities
   (see [`examples/data/policy.json`](../examples/data/policy.json)).
   This policy is versioned alongside the source and is the
   declared *intent* of the product's authority surface.

3. **Audit on release.** The audit pipeline reads SBOM +
   policy, flags any function whose declared capability set
   exceeds its policy allowance. The pipeline itself is a
   Capa program that holds only `Stdio` + an attenuated `Fs`
   restricted to the directory containing the two JSON files;
   it cannot exfiltrate the SBOM, write outside `examples/`,
   or open the network. This addresses Annex I Part I (2)(g)
   (data minimisation) by example.

4. **Re-audit on update.** When a dependency updates, re-run
   the audit. Any widening of declared capabilities raises a
   policy violation that has to be reviewed before the new
   version reaches production. This addresses Annex I Part II
   (1) at a depth no PURL-only SBOM can match.

The four steps map onto CRA's conformity-assessment
requirements without requiring sandbox runtime enforcement.
The static check happens at build time; the audit happens at
release time; the trail lives in the SBOM the regulation
already requires.

---

## What Capa does *not* solve under CRA

Listed plainly, so the scope is honest:

- **Vulnerability disclosure (Article 13, Annex I Part II
  (4)-(7)).** Organisational: dedicated channels, CSIRT
  notification, coordinated disclosure policy. Capa does not
  intervene.

- **Security update distribution (Annex I Part II (7)).**
  Deployment pipeline; outside the language layer.

- **Incident notification (Article 14).** 24-hour CSIRT
  notification of actively exploited vulnerabilities is a
  process, not a language feature.

- **Cryptographic correctness.** Capa is capability-typed,
  not cryptographically typed. It can constrain *who* calls
  the crypto library but not whether the crypto is correct.
  TLS misconfigurations, weak primitives, key-management
  failures: out of scope.

- **DoS / availability (Annex I Part I (2)(h)).** Capa does
  not provide rate-limiting, resource quotas, or load
  shedding.

- **Hardware / firmware security.** CRA applies to "products
  with digital elements", a category that includes hardware.
  Capa is a source-level discipline; hardware-side attacks
  (Spectre, Rowhammer, side channels) are below its layer.

- **Below-language attacks.** Demonstrated explicitly by the
  [xz-utils 2024 case study](cve_xz_utils.md): build-script
  payload + dynamic-linker indirection + binary test
  fixtures. None of those is visible to Capa. The orthogonal
  defences (reproducible builds, code signing, transparency
  logs) live next to Capa, not inside it.

---

## Summary

Capa is a **technical contribution to one specific row** of
the CRA compliance stack: Annex I Part II (1), the SBOM
requirement, made richer by embedding statically-verified
capability metadata. Adjacent rows of Annex I Part I
(secure-by-default, integrity, attack-surface minimisation,
data minimisation, exploitation-mitigation) benefit
indirectly because the language enforces them by
construction.

Most of the CRA's bulk is organisational and remains the
manufacturer's responsibility. Capa makes the SBOM-aligned
technical row cheaper to satisfy and more informative when
satisfied. It does not displace conformity assessment,
vulnerability disclosure, security-update distribution, or
incident notification.

Anyone arguing that capability-typed source belongs in the
CRA-aligned toolbox can cite this mapping as the technical
artefact, and the [positioning document](positioning.md) as
the honest description of where the contribution sits in the
broader landscape of supply-chain defences.

---

## Primary sources

- [Regulation (EU) 2024/2847 (CRA) consolidated text][cra-text]
- [European Commission CRA factsheet (Nov 2024)](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act)
- [ENISA's CRA Q&A][enisa-faq]
- [NTIA SBOM minimum elements][ntia]
- [CycloneDX 1.5 specification](https://cyclonedx.org/docs/1.5/json/)

[enisa-faq]: https://www.enisa.europa.eu/topics/cyber-resilience-act
