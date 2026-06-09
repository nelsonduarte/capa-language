# Capa across the supply-chain governance stack

Five frameworks set the rules for how software-bearing organisations report, audit, and remediate their codebases. This document maps which Capa artefacts answer which clauses across all five. It is descriptive rather than legal: the table below is one person's reading of each instrument, and any conformity decision belongs to an auditor or a supervisory authority, not to a compiler manual.

The five frameworks:

- The **Cyber Resilience Act** (Regulation (EU) 2024/2847), the EU's manufacturer-side rule for products with digital elements.
- The **NIS2 Directive** (Directive (EU) 2022/2555), the operator-side counterpart, scoped to essential and important entities across eighteen sectors.
- **DORA** (Regulation (EU) 2022/2554), the financial-sector operational resilience regulation. Only the cybersecurity articles are in scope here; business continuity sits outside what a programming language can affect.
- **NIST SSDF** (SP 800-218), the US federal baseline for secure software development cited by Executive Order 14028.
- **OWASP SCVS**, the vendor-neutral Software Component Verification Standard, with three levels.

For an article-by-article CRA deep dive, see [`docs/cra.md`](cra.md).

## Limits of the language's reach

Most of what these frameworks demand is organisational. Vulnerability disclosure processes, incident notification timelines, supplier due diligence, internal audit, conformity assessment. None of that is in Capa's reach. What Capa contributes is a narrow slice of the technical artefacts the organisational layer consumes. Where appropriate this document marks a fit as **direct** (the artefact satisfies the clause on its own), **indirect** (Capa enables it but the organisation still has work to do), **partial** (Capa contributes without closing the requirement), or **out of scope** (organisational, language cannot help).

A few frameworks are sometimes confused with this set but are not covered here. ISO 27001, SOC 2, PCI DSS, and HIPAA are management and audit standards; Capa contributes evidence to them but does not deliver compliance. US Executive Order 14028 is subsumed in practice by NIST SSDF, the technical baseline EO 14028 cites. The AI Act and GDPR are tangential to supply-chain governance. SWID (ISO/IEC 19770-2) is a dying SBOM format; CycloneDX and SPDX cover the live ecosystem. The wider DORA articles on business continuity, recovery objectives, and board oversight are not technical.

## Capa artefacts at a glance

The rows below list what Capa emits today.

| Capa artefact | Flag | What it carries |
|---|---|---|
| Capability manifest | `--manifest` | Per-function declared capabilities, attributes, signatures, user-defined cap declarations |
| CycloneDX 1.5 SBOM | `--cyclonedx` | The manifest wrapped in CycloneDX with per-function `properties[]` and an optional `vulnerabilities[]` array |
| SPDX 2.3 SBOM | `--spdx` | Same metadata, SPDX `annotations[]` shape, Linux Foundation alignment |
| CycloneDX VEX | `--vex` | Per-function exploitability claims from `@vex(cve, status, justification, detail)` attributes |
| SLSA L1 provenance | `--provenance` | in-toto Statement v1 plus SLSA Provenance v1.0 predicate, source SHA-256 |
| Audit pipeline | `examples/sbom_capability_audit.capa` | SBOM vs policy diff, structural |
| SBOM diff tool | `examples/sbom_diff.capa` | Two SBOMs in, per-function widening / narrowing / added / removed out |
| Machine-checked soundness | `docs/semantics.md`, `proofs/` | λ_cap calculus with four Agda-checked soundness theorems, plus a machine-checked λ_if noninterference proof (Theorems 3 and 4, delimited release, `--safe`) |

And how each maps across the five frameworks:

| Capa output | CRA Annex I | NIS2 Art. 21 | DORA Chapters II-V | NIST SSDF | OWASP SCVS |
|---|---|---|---|---|---|
| Manifest | I-II(1) direct | 21(2)(d) indirect | Art. 8 indirect | PS.1, PS.2 indirect | Domain 1 partial |
| CycloneDX SBOM | I-II(1) **direct** | 21(2)(d) **direct** | Art. 8 **direct** | PS.3 **direct** | Domain 2 **direct** |
| SPDX SBOM | I-II(1) **direct** | 21(2)(d) **direct** | Art. 8 **direct** | PS.3 **direct** | Domain 2 **direct** |
| CycloneDX VEX | I-II(2) partial | Art. 23 indirect | Arts. 17-19 partial | RV.1, RV.2 **direct** | Domain 5 **direct** |
| SLSA L1 provenance | I-I(2)(f) indirect | 21(2)(d) indirect | Art. 28-30 partial | PS.3, PS.4 **direct** | Domain 6 **direct** |
| Audit pipeline | I-II(1) indirect | 21(2)(d) **direct** | Arts. 28-30 **direct** | PO.5 indirect | Domain 1 partial |
| SBOM diff tool | I-II(2) indirect | 21(2)(d) partial | Arts. 17-19 partial | RV.1 partial | Domain 2 partial |
| Machine-checked soundness | I-I(2)(b) indirect | n/a | n/a | PW.4 indirect | n/a |

## CRA: Cyber Resilience Act

The CRA entered into force on 10 December 2024 and applies most of its obligations from 11 December 2027. It binds manufacturers placing products with digital elements on the EU market. The clauses that matter most for a compiler are Annex I Part I (the essential cybersecurity requirements: secure by default, attack-surface minimisation, data minimisation, exploitation mitigation, integrity protection), Annex I Part II (1) (machine-readable SBOM covering at least top-level dependencies), and Annex I Part II (2)-(7) (vulnerability handling processes).

The strongest fits land in Part II (1) on SBOM, where CycloneDX and SPDX cover the requirement twice over; in Part I (2)(b) on secure-by-default, which Capa's capability discipline enforces structurally; in Part I (2)(g) on data minimisation, where least authority is the language model; and in Part I (2)(j) on attack-surface minimisation, where the function's signature is the declared attack surface. The article-by-article view lives in [`docs/cra.md`](cra.md).

What Capa does not address: vulnerability disclosure processes, the 24-hour incident notification window, security-update distribution, and the conformity assessment paperwork itself.

## NIS2

NIS2 entered into force on 16 January 2023 and Member States had to transpose it by 17 October 2024. It binds essential and important entities across eighteen sectors (energy, transport, banking, health, digital infrastructure, public administration, and others). It is the operator-side counterpart to the CRA's manufacturer framing.

Three articles are relevant. Article 21 requires cybersecurity risk-management measures, with subsection (2)(d) explicit on supply-chain security, including the security-related aspects of the relationships between an entity and its direct suppliers or service providers. Article 21(2)(e) covers security in network and information systems acquisition, development, and maintenance, including vulnerability handling and disclosure. Article 23 covers incident reporting on a 24-hour early warning, 72-hour notification, and one-month final-report cadence.

Article 21(2)(d) is the heart of the NIS2 supply-chain ask, and it is the operator-side mirror of CRA Annex I Part II (1). An entity governed by NIS2 has to assess the security of its direct suppliers. The CycloneDX or SPDX SBOM a Capa-using supplier ships gives that operator a per-function authority surface; the SBOM diff tool gives the operator a way to detect supplier widening across releases; the audit pipeline gives them a structural verifier that the supplier's declarations match an internal policy.

Article 23 incident reporting, Article 24 on European cybersecurity certification schemes, Article 26 on cross-border cooperation, and the board-level accountability under Article 20 all sit outside what a compiler can affect.

## DORA

DORA entered into force on 16 January 2023 and has applied since 17 January 2025. It binds financial entities (banks, insurance, investment firms, crypto-asset service providers, and others) plus critical ICT third-party providers. Only the cybersecurity articles are in scope for a programming-language mapping; the business-continuity bulk of DORA is not.

The relevant articles are 5 and 6 on ICT risk management governance and framework, Article 8 on identification of ICT-supported business functions and information and ICT assets (the operator-side parallel to CRA's SBOM clause), Articles 9 through 15 on ICT risk management policies and detection and response, Articles 17 through 23 on ICT-related incident management, and Articles 28 through 30 on management of ICT third-party risk including the contractual content of supplier arrangements.

Article 8 is served directly by CycloneDX or SPDX SBOMs; per-function metadata gives finer-grained inventory than the financial sector is used to. Articles 28 through 30 (third-party risk) are served by the audit pipeline and the SBOM diff tool, allowing a financial entity to verify a supplier's declared authority surface and detect widenings across releases. The provenance attestation supports Article 28's due-diligence-on-provider requirement.

What stays out of reach: business continuity (which is the bulk of DORA), digital operational resilience testing under Articles 24 through 27 (TLPT in particular), the financial-sector-specific contractual content of Article 30, and the critical-ICT-third-party regime in Articles 31 through 44.

## NIST SSDF

NIST published SP 800-218 (SSDF) in February 2022 as the US federal baseline for secure software development. EO 14028 cites it. US federal agencies must follow it, and their suppliers are pulled in through procurement. Industry has widely adopted SSDF voluntarily.

The practices group into four families. PO (Prepare the Organization) covers policy, training, and toolchain. PS (Protect the Software) covers integrity, access control, and archival. PW (Produce Well-Secured Software) covers secure design, reuse of well-secured components, and vulnerability remediation. RV (Respond to Vulnerabilities) covers identify, assess, and remediate.

Where Capa lands, by practice:

| Practice | What Capa provides |
|---|---|
| PS.1 (Protect all forms of code) | Manifest declares the access boundary per function; widening is loud in diffs |
| PS.2 (Provide a mechanism for verifying software release integrity) | SLSA L1 provenance attestation, source SHA-256 |
| PS.3 (Archive and protect each release) | CycloneDX, SPDX, and provenance bundled as a release-artefact set |
| PS.4 (Build artefacts from source) | Provenance names the builder, the source, and the parameters |
| PW.4 (Reuse existing, well-secured software) | Capability discipline rules out ambient-authority abuse in third-party Capa code |
| RV.1 (Identify and confirm vulnerabilities) | VEX entries make per-function exploitability assertions; SBOM diff catches supplier widening |
| RV.2 (Assess, prioritise, and remediate) | VEX `state` and `justification` shape feeds standard tooling |

The PO family is organisational. PW.1 (threat modelling), PW.5 (configure tools for security defaults), and the bulk of the RV organisational follow-through sit outside what a language can offer.

## OWASP SCVS

OWASP maintains the Software Component Verification Standard continuously, with three verification levels (L1 baseline, L2 standard, L3 advanced). It is vendor-neutral and has no jurisdiction. Any organisation procuring or auditing software components can use it.

The six domains are inventory, SBOM, build environment, package management, component analysis, and pedigree and provenance.

| Domain | What Capa provides |
|---|---|
| 1. Inventory | Per-function inventory finer than SCVS asks for; the manifest is the canonical list |
| 2. SBOM | CycloneDX 1.5 and SPDX 2.3 satisfy L1 through L3 |
| 3. Build Environment | Out of reach; reproducible builds are a toolchain concern |
| 4. Package Management | `capa.toml` + `capa install` + `capa.lock` with a signed registry index; lockfile SHA pinning and GPG-verified tags |
| 5. Component Analysis | VEX entries feed component-analysis tooling at function granularity |
| 6. Pedigree and Provenance | SLSA L1 provenance attestation; signing for L3 is external |

SCVS is the cleanest fit of the five. Every Capa artefact maps directly to a domain, and the framework is explicit about which levels each capability satisfies. An organisation using Capa can probably claim SCVS L1 across Domains 1, 2, 5, and 6 without additional work, and L2 on Domains 2 and 6 with the existing artefacts.

## The triangle the frameworks all reference

Supply-chain governance literature converges on three artefacts. The SBOM describes what is in the box. VEX describes how the box is affected by known vulnerabilities. Provenance describes where the box came from. CRA names all three in Annex I Part II; NIS2 and DORA touch them through inventory and supplier-risk clauses; NIST SSDF allocates a practice to each; OWASP SCVS gives each its own domain.

Capa is the first compiler I know of that emits all three from one source, at per-function granularity for the first two. The alternative today is to combine `cargo-cyclonedx` plus a hand-written VEX plus `cosign sign` plus a separate provenance attestation, all at package level. Capa packages the three together at finer granularity, with each artefact's contents grounded in the type system rather than in a separate analyser's heuristics.

## Caveats

Compliance with any of the five frameworks is an organisational outcome that combines technical artefacts with processes. Capa contributes evidence, not compliance.

The mapping above is my reading of each instrument. Wording in regulations is open to interpretation, and an organisation's auditors or supervisory authority may classify the same artefact differently. Treat the table as a starting point for an internal gap analysis, not as a legal opinion.

These frameworks evolve. CRA implementing acts are still being drafted in 2026. NIS2 transposition varies by Member State. NIST SSDF is at v1.1 and will see further revisions. The mapping reflects the state of the five frameworks as of mid-2026.

Capa is a one-person project at 1.0. It is suitable for proofs of concept and personal projects, and it has not been through the independent assurance a production deployment in a regulated industry would expect. The artefact outputs are stable enough to integrate into compliance pipelines; the language runtime is CPython, with the WebAssembly Component Model backend an alternative for performance-sensitive deployments.

## Primary sources

- [Regulation (EU) 2024/2847 (CRA)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [Directive (EU) 2022/2555 (NIS2)](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)
- [Regulation (EU) 2022/2554 (DORA)](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)
- [NIST SP 800-218 (SSDF) v1.1](https://csrc.nist.gov/Projects/ssdf)
- [OWASP SCVS](https://owasp.org/www-project-software-component-verification-standard/)
- [CycloneDX 1.5 specification](https://cyclonedx.org/docs/1.5/json/)
- [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/)
- [SLSA v1.0 specification](https://slsa.dev/spec/v1.0/)
- [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
