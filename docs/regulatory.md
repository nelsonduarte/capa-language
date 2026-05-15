# Regulatory mapping: Capa across the supply-chain governance stack

A comparative table of which Capa artefacts map to which
requirements in the five frameworks Capa is built to serve:

- **CRA** (Cyber Resilience Act, Regulation (EU) 2024/2847):
  EU, manufacturer-side, products with digital elements.
- **NIS2** (Directive (EU) 2022/2555): EU, operator-side,
  essential and important entities in 18 sectors.
- **DORA** (Regulation (EU) 2022/2554): EU, financial-sector
  operational resilience. Cybersecurity articles only here; the
  business-continuity side is out of scope for a programming
  language.
- **NIST SSDF** (SP 800-218, Secure Software Development
  Framework): US, the federal baseline for "secure development"
  cited by EO 14028.
- **OWASP SCVS** (Software Component Verification Standard):
  industry, vendor-neutral, three verification levels.

This document is the **multi-jurisdiction comparative view**.
For the article-by-article CRA deep-dive, see
[`docs/cra.md`](cra.md).

---

## Scope and honesty notes

Most of what these frameworks demand is **organisational**:
vulnerability disclosure processes, incident notification
timelines, supplier due diligence, internal audit, conformity
assessment. None of that is in Capa's reach.

What Capa contributes is a narrow but load-bearing slice: the
**technical artefacts** the organisational layer consumes. The
table below maps each Capa output to the specific requirement
it satisfies, with the same four-level classification used in
the CRA deep-dive:

- **Direct**: Capa output satisfies the requirement on its own.
- **Indirect**: Capa enables the requirement; the organisation
  still has to do something with the output.
- **Partial**: Capa contributes to but does not close the
  requirement.
- **Out of scope**: the requirement is organisational and Capa
  cannot help with it.

Frameworks deliberately **excluded** from this document:

- **ISO 27001**, **SOC 2**, **PCI DSS**, **HIPAA**: management
  and audit standards. Capa contributes evidence; it does not
  deliver compliance.
- **US EO 14028**: subsumed in practice by NIST SSDF, which is
  the technical baseline EO 14028 cites.
- **AI Act**, **GDPR**: tangential to supply-chain governance.
- **SWID** (ISO/IEC 19770-2): a dying SBOM format. CycloneDX
  and SPDX cover the live ecosystem.
- **Wider DORA articles** (business continuity, recovery time
  objectives, board oversight): not technical.

---

## Headline table: Capa artefacts versus framework requirements

The rows below list the artefacts Capa emits today:

| Capa artefact | Flag | What it carries |
|---|---|---|
| Capability manifest | `--manifest` | Per-function declared capabilities, attributes, signatures, user-defined cap declarations |
| CycloneDX 1.5 SBOM | `--cyclonedx` | The manifest wrapped in CycloneDX with per-function `properties[]` and an optional `vulnerabilities[]` array (VEX) |
| SPDX 2.3 SBOM | `--spdx` | Same metadata, SPDX `annotations[]` shape; Linux Foundation alignment |
| CycloneDX VEX | `--vex` | Per-function exploitability claims from `@vex(cve, status, justification, detail)` attributes |
| SLSA L1 provenance | `--provenance` | in-toto Statement v1 + SLSA Provenance v1.0 predicate, source SHA-256 |
| Audit pipeline | `examples/sbom_capability_audit.capa` | SBOM vs policy diff, structural |
| SBOM diff tool | `examples/sbom_diff.capa` | Two SBOMs in, per-function widening/narrowing/added/removed out |
| Soundness sketch | `docs/semantics.md` | λ_cap calculus, two soundness theorems |

The mapping to each framework follows. Cells are direct
references to the specific clause Capa addresses; "+" notation
means the artefact contributes alongside others.

| Capa output | CRA Annex I | NIS2 Art. 21 | DORA Chapters II-V | NIST SSDF | OWASP SCVS |
|---|---|---|---|---|---|
| Manifest | I-II(1) direct | 21(2)(d) indirect | Art. 8 indirect | PS.1, PS.2 indirect | Domain 1 partial |
| CycloneDX SBOM | I-II(1) **direct** | 21(2)(d) **direct** | Art. 8 **direct** | PS.3 **direct** | Domain 2 **direct** |
| SPDX SBOM | I-II(1) **direct** | 21(2)(d) **direct** | Art. 8 **direct** | PS.3 **direct** | Domain 2 **direct** |
| CycloneDX VEX | I-II(2) partial | Art. 23 indirect | Arts. 17-19 partial | RV.1, RV.2 **direct** | Domain 5 **direct** |
| SLSA L1 provenance | I-I(2)(f) indirect | 21(2)(d) indirect | Art. 28-30 partial | PS.3, PS.4 **direct** | Domain 6 **direct** |
| Audit pipeline | I-II(1) indirect | 21(2)(d) **direct** | Arts. 28-30 **direct** | PO.5 indirect | Domain 1 partial |
| SBOM diff tool | I-II(2) indirect | 21(2)(d) partial | Arts. 17-19 partial | RV.1 partial | Domain 2 partial |
| Soundness sketch | I-I(2)(b) indirect | n/a | n/a | PW.4 indirect | n/a |

---

## 1. CRA (Regulation (EU) 2024/2847)

**In force**: 10 December 2024. **Most obligations apply from**:
11 December 2027.

**Who it applies to**: manufacturers of products with digital
elements placed on the EU market.

**Key technical clauses**:

- **Annex I Part I (2)(a)-(m)**: essential cybersecurity
  requirements covering secure-by-default, attack-surface
  minimisation, data minimisation, exploitation mitigation,
  and integrity protection.
- **Annex I Part II (1)**: machine-readable SBOM covering at
  least top-level dependencies.
- **Annex I Part II (2)-(7)**: vulnerability handling
  processes (disclosure, patching, distribution).

**What Capa contributes**: see the article-by-article table in
[`docs/cra.md`](cra.md). The strongest fits are Part II (1) on
SBOM (CycloneDX + SPDX cover this twice over), Part I (2)(b)
on secure-by-default (capability discipline enforces it
structurally), Part I (2)(g) on data minimisation (least
authority is the language model), and Part I (2)(j) on
attack-surface minimisation (the function's signature *is* the
declared attack surface).

**What Capa does not do**: vulnerability disclosure processes,
24-hour incident notification, security-update distribution,
conformity assessment paperwork.

---

## 2. NIS2 (Directive (EU) 2022/2555)

**In force**: 16 January 2023. **Transposition deadline**: 17
October 2024.

**Who it applies to**: "essential" and "important" entities in
18 sectors (energy, transport, banking, health, digital
infrastructure, public administration, and others). The
operator-side counterpart to the CRA's manufacturer-side.

**Key technical clauses for Capa**:

- **Article 21(1)-(2)**: cybersecurity risk-management
  measures. Subsection (2)(d) is explicit on **supply chain
  security**, including "security-related aspects concerning
  the relationships between each entity and its direct
  suppliers or service providers".
- **Article 21(2)(e)**: security in network and information
  systems acquisition, development, and maintenance, including
  vulnerability handling and disclosure.
- **Article 23**: incident reporting (24h early warning, 72h
  notification, 1-month final report).

**What Capa contributes**: Article 21(2)(d) is the heart of
the NIS2 supply-chain ask, and it is the operator-side mirror
of CRA Annex I Part II (1). An entity governed by NIS2 needs
to assess the security of its direct suppliers. The CycloneDX
or SPDX SBOM a Capa-using supplier ships gives that operator a
per-function authority surface; the SBOM diff tool gives the
operator a way to detect supplier widening across releases;
the audit pipeline gives the operator a structural verifier
that the supplier's declarations match an internal policy.

**What Capa does not do**: Article 23 incident reporting,
Article 24 use of European cybersecurity certification
schemes, Article 26 cross-border cooperation, board-level
accountability under Article 20.

---

## 3. DORA (Regulation (EU) 2022/2554)

**In force**: 16 January 2023. **Applies from**: 17 January
2025.

**Who it applies to**: financial entities (banks, insurance,
investment firms, crypto-asset service providers, and others)
plus critical ICT third-party providers.

**Cybersecurity articles only**:

- **Article 5**: ICT risk management governance.
- **Article 6**: ICT risk management framework.
- **Article 8**: identification of ICT-supported business
  functions, information assets, and ICT assets. **The
  inventory clause**: the operator-side parallel to CRA's
  SBOM clause.
- **Articles 9-15**: ICT risk management (policies,
  protection, detection, response, recovery, learning).
- **Articles 17-23**: ICT-related incident management,
  classification, reporting.
- **Articles 28-30**: management of ICT third-party risk
  (including the contractual content of supplier
  arrangements).

**What Capa contributes**: Article 8 (identification) is
directly served by the CycloneDX or SPDX SBOM; per-function
metadata gives finer-grained inventory than the financial
sector is used to. Articles 28-30 (third-party risk) are
served by the audit pipeline and the SBOM diff tool: a
financial entity can verify a supplier's declared authority
surface and detect widenings across releases. The provenance
attestation supports Article 28's "due-diligence on the
provider" requirement.

**What Capa does not do**: business-continuity (which is the
bulk of DORA), digital operational resilience testing
(Article 24-27, TLPT), the financial-sector-specific
contractual content of Article 30, the critical-ICT-third-
party regime in Articles 31-44.

---

## 4. NIST SSDF (SP 800-218)

**Published**: February 2022. **US federal baseline** for
secure software development, cited by Executive Order 14028.

**Who it applies to**: US federal agencies (mandatory) and
their suppliers (effectively mandatory through procurement).
Widely adopted as a voluntary baseline by industry.

**Practices grouped into four families**:

- **PO** (Prepare the Organization): policy, training,
  toolchain.
- **PS** (Protect the Software): integrity, access control,
  archival.
- **PW** (Produce Well-Secured Software): secure design,
  reuse of well-secured components, vulnerability
  remediation.
- **RV** (Respond to Vulnerabilities): identify, assess,
  remediate.

**What Capa contributes by practice**:

| Practice | What Capa provides |
|---|---|
| PS.1 (Protect all forms of code) | Manifest declares the access boundary per function; widening is loud in diffs |
| PS.2 (Provide a mechanism for verifying software release integrity) | SLSA L1 provenance attestation, source SHA-256 |
| PS.3 (Archive and protect each release) | CycloneDX + SPDX SBOM + provenance form a release-artefact bundle |
| PS.4 (Build artefacts from source) | Provenance attestation names the builder, the source, the parameters |
| PW.4 (Reuse existing, well-secured software) | Capability discipline rules out a class of misuse (ambient authority abuse) in any third-party Capa code |
| RV.1 (Identify and confirm vulnerabilities) | VEX entries make per-function exploitability assertions; SBOM diff catches supplier widening |
| RV.2 (Assess, prioritise, and remediate) | VEX `state` + `justification` shape feeds standard tooling |

**What Capa does not do**: PO family (organisational), PW.1
(threat modelling), PW.5 (configure tools for security
defaults), most of the RV organisational follow-through.

---

## 5. OWASP SCVS (Software Component Verification Standard)

**Published**: continuously maintained by OWASP. Vendor-
neutral, three verification levels (L1 baseline, L2 standard,
L3 advanced).

**Who it applies to**: any organisation procuring or
auditing software components. Vendor-neutral, no jurisdiction.

**Six domains**:

1. **Inventory**: components are identified.
2. **SBOM**: the inventory is machine-readable.
3. **Build Environment**: builds are reproducible, isolated,
   attested.
4. **Package Management**: dependencies are managed and
   pinned.
5. **Component Analysis**: components are scanned for
   vulnerabilities; results are tracked.
6. **Pedigree and Provenance**: components are traceable to
   source and builder.

**What Capa contributes by domain**:

| Domain | What Capa provides |
|---|---|
| 1. Inventory | Per-function inventory is finer-grained than SCVS asks for; the manifest is the canonical list |
| 2. SBOM | CycloneDX 1.5 and SPDX 2.3 satisfy L1 through L3 |
| 3. Build Environment | Out of Capa's reach; reproducible builds are a toolchain concern |
| 4. Package Management | Capa has no package manager yet; this is a v2 question |
| 5. Component Analysis | VEX entries feed component-analysis tooling at function granularity |
| 6. Pedigree and Provenance | SLSA L1 provenance attestation; signing for L3 is external |

SCVS is the cleanest fit of the five frameworks: every Capa
artefact maps directly to a domain, and the framework is
explicit about which levels each capability satisfies. An
organisation using Capa can probably claim **SCVS L1 across
Domains 1, 2, 5, and 6** without further work, and **L2** on
Domains 2 and 6 with the existing artefacts.

---

## The triangle Capa closes

A common shorthand in supply-chain governance literature is
the **SBOM and VEX and provenance triangle**:

- **SBOM** says *what is in the box*.
- **VEX** says *how the box is affected by known
  vulnerabilities*.
- **Provenance** says *where the box came from*.

CRA names all three (Annex I Part II), NIS2 and DORA touch
them via inventory + supplier-risk clauses, NIST SSDF
allocates a practice to each, and OWASP SCVS gives each its
own domain.

Capa is the first compiler to emit all three from one source,
at **per-function granularity** for the first two. The
alternative today is to combine `cargo-cyclonedx` plus a
hand-written VEX plus `cosign sign` plus a separate
provenance attestation, all at package level. Capa packages
the three together at finer granularity, with each artefact's
contents grounded in the type system rather than in a separate
analyser's heuristics.

---

## What this document does not claim

- **Capa does not deliver compliance.** Compliance with any
  of the five frameworks is an organisational outcome that
  combines technical artefacts (which Capa provides) with
  organisational processes (which Capa cannot provide).

- **The mapping is the author's reading of each framework.**
  Wording in regulations is open to interpretation; an
  organisation's auditors or supervisory authority may
  classify the same Capa artefact differently. Use the table
  as a starting point for an internal compliance gap
  analysis, not as a legal opinion.

- **Frameworks evolve.** CRA implementing acts are still being
  drafted in 2026; NIS2 transposition varies by Member State;
  NIST SSDF is at version 1.1 and will likely see further
  revisions. The mapping reflects the state of the five
  frameworks as of mid-2026.

- **Capa is alpha.** v0.6.0 is suitable for proofs of concept
  and personal projects, not for production deployments in
  any regulated industry. The artefact outputs are stable
  enough to integrate into compliance pipelines; the language
  runtime is not yet.

---

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
