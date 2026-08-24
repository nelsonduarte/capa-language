# Capa and the EU Cyber Resilience Act

A focused mapping of Capa's machinery onto the specific
articles and annex items of Regulation (EU) 2024/2847, the
[Cyber Resilience Act][cra-text] (CRA). Included in the repo
so the technical claims are reviewable against the artefact.

> For the multi-jurisdiction comparative view (CRA + NIS2 +
> DORA + NIST SSDF + OWASP SCVS), see
> [`docs/regulatory.md`](regulatory.md). This document is the
> CRA deep-dive that table references.

> The CRA's core ask, in plain language: products with digital
> elements placed on the EU market must be *secure by design*,
> ship *transparent dependency information*, and have
> *vulnerability-handling processes* in place. The regulation
> entered into force on 10 December 2024. Its obligations phase
> in: Chapter IV (notification of conformity-assessment bodies)
> applies from 11 June 2026, the Article 14 vulnerability and
> incident reporting obligations from 11 September 2026, and the
> remaining obligations from 11 December 2027.

[cra-text]: https://eur-lex.europa.eu/eli/reg/2024/2847/oj

---

## Scope of this document

The CRA has 71 articles and eight annexes. Most of it is
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

No CRA harmonised standard has yet been published in the
Official Journal: the 41 standards under standardisation
request M/606 (accepted by CEN, CENELEC, and ETSI in April
2025) are still in development, and no SBOM-format implementing
act exists. There is therefore no presumption of conformity to
invoke and nothing here can honestly be called "CRA-compliant".
This document uses "maps to" and "aligns with" deliberately.

---

## CRA requirements that Capa addresses

The table below maps Capa features to specific CRA
requirements. The "How Capa helps" column is intentionally
narrow: it describes the *technical lever* Capa provides, not
a claim of full compliance.

Several rows have a two-axis story. The compile-time axis is
the analyzer + manifest emission; the runtime axis is the
WebAssembly Component Model backend (`capa --wasm`), where
each declared capability lowers to a WIT import that the host
explicitly satisfies. Where both axes apply, the row reflects
both.

| CRA reference | What the regulation requires | How Capa helps |
|---|---|---|
| **Annex I Part I (2)(a)** | "be made available on the market without known exploitable vulnerabilities" | Direct (class-level): Capa's structural capability discipline rules out a *class* of vulnerabilities (ambient-authority abuse), demonstrated by the six CVE case studies in [`docs/`](.). The Wasm Component Model build adds a second layer at *interface granularity* for a compiler-produced component: the component imports only the WIT interfaces for the capabilities the program declares, so a capability whose interface is absent from the world is not reachable. This confinement is enforced by the trusted Capa emitter, not at the runtime boundary. Intra-artifact attenuation (a restricted capability passed across a function boundary) and the core-module path rely on the emitter too, and a third-party-supplied `.wasm` / `.cwasm` artifact is itself part of the trusted computing base (see [`trust-model.md`](trust-model.md)). For known-CVE detection at dependency level, the CycloneDX SBOM Capa emits is consumable by Dependency-Track / OSV-Scanner. |
| **Annex I Part I (2)(b)** | "be made available on the market with a secure-by-default configuration" | Direct: Capa programs cannot exercise authority they did not declare. The default for any function is *zero capabilities*; widening is explicit. Secure-by-default is the only configuration available. |
| **Annex I Part I (2)(c)** | "ensure that vulnerabilities can be addressed through security updates" | Indirect: the CycloneDX SBOM inventories the program's own functions and capabilities as components with deterministic `capa:` bom-refs, so a capability-level diff between two builds ties back to the same stable identity used at audit time. When the input belongs to a `capa.toml` project the SBOM additionally lists one `library` component per resolved dependency, each with its name, version, and (for a git dependency) a real `purl`, so a security update that moves a dependency to a new pinned commit surfaces as a changed purl in the same document. Residuals: a path dependency has no purl, a transitive dependency at a source the root `capa.lock` does not cover carries its declared pin rather than a resolved commit SHA, and the host Python interpreter is not itself a component. |
| **Annex I Part I (2)(d)** | "ensure protection from unauthorised access ... appropriate authentication, identity management or access management systems" | Direct, at the source level: capabilities are unforgeable handles; access management is the type system. Cross-process authentication is below Capa's layer. |
| **Annex I Part I (2)(e)** | "protect the confidentiality of stored, transmitted or otherwise processed data ... encrypting relevant data at rest or in transit" | Partial, at the data-flow level: Capa does not provide crypto primitives (the *encryption* half stays the user's), but information-flow control directly governs *where* confidential data may go. Mark data `@secret` and the analyzer tracks its flow to a public sink (a log, a network call, a file write). This is tiered: by default a secret reaching a sink without passing through an audited `declassify` is a *warning* (best-effort, the build still proceeds); under `@strict_ifc()` the same flow is a hard compile-time error (fail-closed). Either way, every audited `declassify` disclosure is recorded in the SBOM as `declassification_sites` and enumerated for the auditor. The analyzer itself is not machine-verified: the model-vs-implementation gap is argued informally and cross-checked by a differential harness against a machine-checked Agda noninterference proof of the core calculus, not closed by proof. See the IFC subsection below. |
| **Annex I Part I (2)(f)** | "protect the integrity of stored, transmitted or otherwise processed data ... programs, configuration against any manipulation" | Direct: every function's authority ceiling (`transitively_reachable_capabilities`) is derivable from its signature (Manifest Completeness Theorem, an upper bound, see [`docs/semantics.md`](semantics.md)). A capability reachable only through a container-typed parameter is charged to that ceiling and to its SBOM dependency edges, though it does not appear in the narrower per-function `declared_capabilities` (`capa:declared_capability`) view; diff the reachable view for a complete picture. Manipulation of a dependency that adds `Fs`/`Net`/`Env` access is statically visible in the SBOM diff. |
| **Annex I Part I (2)(g)** | "process only data ... that are necessary ... ('minimisation of data')" | Direct: the principle of least authority is built into the language. A function gets exactly the capabilities it declares; nothing more is reachable. |
| **Annex I Part I (2)(h)** | "protect the availability of essential and basic functions ... including the resilience against and mitigation of denial-of-service attacks" | Out of scope. Capa does not address DoS. |
| **Annex I Part I (2)(i)** | "minimise their own negative impact ... on the availability of services provided by other devices or networks" | Direct under the Wasm CM build: a function reaches the network only through the `Net` capability, which lowers to a WIT import (`capa:host/net`) the host must explicitly wire. A program that does not declare `Net` cannot emit it from the compiled component, period. Compile-time only: the same `Net` declaration makes side-channel network behaviour auditable in the manifest. |
| **Annex I Part I (2)(j)** | "be designed, developed and produced to limit attack surfaces, including external interfaces" | Direct: capability declarations *are* the external-interface contract. Reducing the surface of a function is editing its signature. Reinforced under the Wasm CM build: the WIT spec emitted alongside the `.wasm` component is *literally* the external interface, machine-readable, with one interface per capability the program touches. The auditor can read the WIT and know the entire surface. |
| **Annex I Part I (2)(k)** | "be designed, developed and produced to reduce the impact of an incident using appropriate exploitation mitigation mechanisms and techniques" | Direct, structurally: capability attenuation ([`fs_env_attenuation.capa`](../examples/fs_env_attenuation.capa)) bounds the blast radius of any compromised dependency at compile time. Under the Wasm Component Model build this holds at *interface granularity* for a compiler-produced component: the component runs in the Wasm sandbox and imports only the WIT interfaces for its declared capabilities, so a compromised dependency cannot reach an interface absent from the world. Intra-artifact attenuation (restriction state that must travel with a capability across a function boundary) and the core-module path are enforced by the trusted Capa emitter rather than the runtime boundary, and the executed `.wasm` / `.cwasm` is part of the trusted computing base (see [`trust-model.md`](trust-model.md)). |
| **Annex I Part I (2)(l)** | "provide security related information by recording and monitoring relevant internal activity" | Partial at compile time: Capa's opt-in runtime trace (`capa/runtime/_trace.py`) records capability invocations. Direct under the Wasm CM build: every capability call is a WIT import the host implements, so the host can transparently log every authority crossing without instrumenting the guest. |
| **Annex I Part I (2)(m)** | "provide the possibility for users to securely and easily remove on a permanent basis all data and settings" | Out of scope for the language layer. |
| **Annex I Part II (1)** | "identify and document vulnerabilities and components contained in the product ... including by drawing up a software bill of materials in a commonly used and machine-readable format covering at the very least the top-level dependencies" | **Primary fit**: `capa --cyclonedx` emits a CycloneDX 1.6 SBOM with the capability manifest embedded as standard `properties[]` entries. For a `capa.toml` project it enumerates the top-level dependencies the stated minimum asks for: one `library` component per resolved dependency, each with its name, version, and (for a git dependency) a real `purl`, plus a CycloneDX `dependencies` graph edge from the program to each one. That meets the "at the very least the top-level dependencies" floor for the resolved set, and a same-source transitive dependency locked by `capa.lock` is covered too (its diamond collapses to one component carrying the resolved commit SHA). The genuine contribution is the capability layer on top: not just *what* is in the box but *what each of the program's own functions can do*. The SPDX 2.3 output carries the same dependency set symmetrically: one `Package` per resolved dependency with its `purl` as an `externalRefs` entry (`referenceType` `purl`) plus a `DEPENDS_ON` relationship graph, from the same single dependency-identity source as the CycloneDX components. Residuals stay honest and apply to both formats: a transitive dependency at a source the root lock does not cover carries its declared pin rather than a SHA, and a path dependency gets no purl. |
| **Annex I Part II (2)** | "address and remediate vulnerabilities without delay" | Out of scope (organisational). |
| **Annex I Part II (3)** | "apply effective and regular tests and reviews of the security of the product" | Partial: the property-based test suite (`tests/test_properties.py`) and the six CVE case studies demonstrate ongoing review of the discipline. Per-product test obligations remain the manufacturer's. |
| **Annex I Part II (4)** | "once a security update has been made available, share and publicly disclose information about fixed vulnerabilities" | Out of scope (organisational). |
| **Annex I Part II (7)** | "provide for mechanisms to securely distribute updates ... to ensure that vulnerabilities are fixed or mitigated in a timely manner" | Out of scope (deployment-pipeline concern). |

---

## The novel contribution: capability-aware SBOMs

The CRA's Annex I Part II (1) asks for a commonly-used,
machine-readable SBOM covering at least the top-level
dependencies. CycloneDX, SPDX, and SWID are the common formats;
all three list components and versions. [NTIA's minimum
elements][ntia], a common baseline that later SBOM guidance
(ENISA and BSI TR-03183-2) builds on and extends, require:

- supplier name
- component name
- component version
- other unique identifiers
- dependency relationship
- author of SBOM data
- timestamp

[ntia]: https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf

Capa emits CycloneDX 1.6 and SPDX 2.3. BSI TR-03183-2 v2.1.0
(2025-08-20) asks for CycloneDX >= 1.6 or SPDX >= 3.0.1: the
CycloneDX output now meets that guideline's CycloneDX floor,
while the SPDX output stays a major version below the
SPDX >= 3.0.1 line. Both formats carry the dependency purls: the
SPDX 2.3 side emits each resolved dependency as a `Package` with
its `purl` as an `externalRefs` entry plus a `DEPENDS_ON`
relationship graph, symmetric with the CycloneDX dependency
components and keyed off the same dependency-identity source. BSI
TR-03183-2 is a German national technical guideline, not EU law
and not a CRA mandate; it is cited here only as a widely
referenced SBOM baseline.

For a `capa.toml` project both the CycloneDX and the SPDX
output resolve each declared dependency into a component and
name it as precisely as the lock allows, using one shared purl
producer, so the two formats carry identical purls:

- A **git dependency hosted on github.com** carries the native
  `pkg:github/<owner>/<repo>@<rev>` purl (owner and repo
  lower-cased, the form every SBOM consumer already
  understands). The revision `<rev>` is the `capa.lock` commit
  SHA when the dependency is resolved, including a same-source
  transitive dependency under the lock, whose diamond collapses
  to a single component carrying that SHA.
- A **git dependency on any other host** (GitLab, a self-hosted
  server, or a github URL the parser does not match) carries a
  `pkg:generic/<name>@<version>?vcs_url=git+<url>@<rev>` purl
  (percent-encoded), with the same `<rev>` rule.
- An **unresolved dependency**, or a transitive dependency at a
  source the root lock does not cover, carries its declared pin
  (tag or rev) instead of a SHA; an unresolved dependency also
  omits the version.
- A **path dependency** gets no purl: it is named by its name,
  version, a `capa:source_kind=path` property, and its
  root-relative path, because it has no registry or VCS identity
  to fabricate.

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

## The second contribution: machine-checked data-flow confidentiality

The capability layer answers "what can this component *do*?". The
information-flow layer answers a question the SBOM has never carried:
"where can this component's *secret data* go?". Capabilities bound
the effects; information-flow control bounds the disclosures.

A value typed `@secret` (an API key, a card number, a credential)
carries a security label the compiler propagates through every
derived value. A `@secret` value that reaches a public sink
(`Stdio.println`, `Net.post`, `Fs.write`, `Db.exec`, ...) is a
compile-time information-flow violation. The single sanctioned way
across is `declassify(value, reason: "...")`, and every use is
recorded in the manifest:

```
"declassifications": [
  { "reason": "PCI DSS 3.4: display only the last four PAN digits",
    "value": "mask_pan(pan)", "pos": "13:17" }
],
```

with a program-wide `declassification_sites` count in the summary. A
disclosure written outside any function body, in a top-level `const`
initializer, is recorded under `module_declassifications` and counted
in the same total, so the enumeration covers the whole module rather
than only its functions.
For Annex I Part I (2)(e) (confidentiality of processed data) and
(2)(g) (data minimisation), this turns an organisational assertion
("we are careful with cardholder data") into a machine-checkable one:
by default the analyzer warns when a secret reaches a sink without an
audited `declassify`, and under `@strict_ifc()` it refuses to build
that program; either way the conformity pack enumerates every
deliberate disclosure with its stated justification. An auditor does not have to trust a
data-handling policy document; they read the disclosure list the
compiler generated, by construction.

The worked example is
[`capa_paymentguard`](https://github.com/nelsonduarte/capa_paymentguard),
a payment-security core (PCI DSS / PSD2) that ships a complete CRA
conformity pack: the compiler proves a card number cannot reach a log
line or a network call unless masked, and the pack lists the four
disclosure points with their reasons.

---

## What this looks like in practice

A CRA-aligned development workflow with Capa:

1. **Build time.** `capa --cyclonedx my-project.capa > sbom.json`
   produces the SBOM with capability metadata embedded. This
   becomes one of the conformity-assessment artefacts the
   manufacturer keeps under Article 31. Set `SOURCE_DATE_EPOCH`
   (Unix UTC seconds) in the build environment to make this and
   the SPDX, VEX, and provenance artefacts byte-reproducible: an
   auditor can rebuild them from the pinned source and confirm
   they match the published copies, rather than trusting them.
   See [the reproducible-artefacts section of the regulatory
   note](regulatory.md#reproducible-sboms-rebuild-and-diff-byte-for-byte).

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

To start from a working skeleton rather than wiring this up by
hand, the [`capa_cra_template`](https://github.com/nelsonduarte/capa_cra_template)
repository is a CRA-ready starter project: a capability-bounded
program plus CI/release workflows that emit the SBOM, VEX, and
build provenance on every build. The language's own
`capa --provenance` emits an unsigned SLSA Build L1 attestation
([`capa/manifest/_provenance.py`](../capa/manifest/_provenance.py));
the template's release pipeline adds a signed SLSA
build-provenance attestation (Build L2) through its Sigstore
step, so the L2 property is a property of the signing CI, not of
the compiler. To turn those artefacts into a
regulator-readable Markdown audit pack plus a JSON attestation,
[`capa_governance_pack`](https://github.com/nelsonduarte/capa_governance_pack)
consumes the SBOM + policy + VEX and produces both.

---

## What Capa does *not* solve under CRA

Listed plainly, so the scope is honest:

- **Vulnerability disclosure (Article 13 "Obligations of
  manufacturers", Annex I Part II (4)-(7)).** Organisational:
  dedicated channels, coordinated disclosure policy. Capa does
  not intervene.

- **Security update distribution (Annex I Part II (7)).**
  Deployment pipeline; outside the language layer.

- **Reporting obligations of manufacturers (Article 14).**
  24-hour CSIRT notification of actively exploited
  vulnerabilities is a process, not a language feature.

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
- [CycloneDX 1.6 specification](https://cyclonedx.org/docs/1.6/json/)

[enisa-faq]: https://www.enisa.europa.eu/topics/cyber-resilience-act
