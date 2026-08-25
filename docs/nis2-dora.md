# Capa, the NIS2 Directive, and DORA

A focused, honest mapping of Capa's machinery onto specific
articles of the [NIS2 Directive][nis2-text] (Directive (EU)
2022/2555) and [DORA][dora-text] (Regulation (EU) 2022/2554).
This is the companion to [`docs/cra.md`](cra.md), and the two
documents make deliberately different claims, because the
regulations are different *kinds* of instrument.

> For the multi-jurisdiction comparative table (CRA + NIS2 +
> DORA + NIST SSDF + OWASP SCVS), see
> [`docs/regulatory.md`](regulatory.md). This document is the
> NIS2/DORA deep-dive that table references, and it is stricter
> than that table's shorthand about what a compiler can and
> cannot be to these two regimes.

[nis2-text]: https://eur-lex.europa.eu/eli/dir/2022/2555/oj
[dora-text]: https://eur-lex.europa.eu/eli/reg/2022/2554/oj

---

## The one distinction this whole document rests on

The CRA is a **product** conformance regime: its obligations
attach to a *product with digital elements* placed on the EU
market, and a piece of software is exactly the kind of thing
that regime is about. That is why [`docs/cra.md`](cra.md) can
map Capa's SBOM to a real requirement (Annex I Part II (1)) and
say "primary fit", while still refusing the word "compliant"
because no harmonised standard has been published.

NIS2 and DORA are not product regimes. They are **entity /
organisational** regimes. Their obligations attach to an
*operator*:

- Under **NIS2 Article 21(1)**, the duty-holder is an
  **essential or important entity**, and **Article 20** places
  the responsibility on that entity's **management body**, which
  can be held personally accountable.
- Under **DORA**, the duty-holder is a **financial entity** (and,
  for the third-party regime, a critical ICT third-party
  service provider). **Article 28(1)(a)** states that the
  financial entity **remains fully responsible** for compliance
  with its ICT obligations even when it uses a third party.

A programming language is neither an essential/important entity
nor a financial entity. It has no management body, files no
incident report, signs no contract, and maintains no register.
Therefore:

> **"Capa is NIS2-compliant" and "Capa is DORA-compliant" are
> category errors, not merely premature claims.** There is no
> sense in which a compiler can be compliant with an
> obligation the regulation places on an operator.

What Capa *can* be is a **technical lever** that an in-scope
entity uses toward **specific, named measures**, producing
**supporting evidence** for an audit file. Evidence is not
discharge. For every row below, the honest verb is "supports"
or "is evidence toward Article X", never "satisfies NIS2" or
"meets DORA".

The ladder, stated once so it is unambiguous:

| Regime | Kind | Strongest honest claim for Capa |
|---|---|---|
| **CRA** (2024/2847) | Product conformance | Real requirement mapping to Annex I Part II (1); still not "CRA-compliant" absent a harmonised standard (see [`docs/cra.md`](cra.md)) |
| **NIS2** (2022/2555) | Entity risk-management | Technical lever / supporting evidence toward named Art 21 measures, for the components built with Capa. Never "compliant" |
| **DORA** (2022/2554) | Entity operational resilience | Technical input to the ICT-transparency side of named Art 28-30 duties. Never "compliant" |

---

## NIS2 (Directive (EU) 2022/2555)

### Regime type

NIS2 requires **essential and important entities** across
eighteen sectors to take appropriate technical, operational, and
organisational risk-management measures (**Article 21(1)**), and
places the accountability for those measures on the entity's
**management body** (**Article 20**). There is no
product-conformance mechanism in NIS2, no CE-style marking, and
no notion of a "compliant compiler". A supplier's tooling can
only feed the entity's own risk-management process.

Because it is a directive, NIS2 binds through national
transposition rather than directly. The transposition deadline
was **17 October 2024**, with obligations applying from **18
October 2024**.

> **Transposition status is secondary-sourced and in motion.**
> As of 2026, transposition into national law is materially
> incomplete across Member States, and the Commission has opened
> infringement steps against several. This document deliberately
> does not hard-code a count of transposing states as durable
> fact: check the current national implementation before relying
> on any specific figure. The regulatory *text* cited here is
> stable; the *implementation landscape* is not.

### Where Capa is a lever (evidence, not discharge)

The NIS2 measures that a Capa-built component can produce
evidence toward are the supply-chain and secure-development
ones:

| NIS2 reference | What the article requires | Capa as supporting evidence |
|---|---|---|
| **Art 21(2)(d)** | supply-chain security, including "the security-related aspects concerning the relationships between each entity and its direct suppliers or service providers" | For components the entity builds in Capa, the machine-readable SBOM (`--cyclonedx`, `--spdx`) carries one component per resolved `capa.toml` dependency with a real per-dependency purl and a dependency graph, and the capability manifest (`--manifest`) records what each of the program's own functions can do. An entity assessing a *direct supplier* who ships Capa artefacts has a per-function authority surface to inspect and diff across releases, not just a name-and-version list. This is input to the entity's supplier assessment, not the assessment itself. |
| **Art 21(3)** | Member States shall ensure entities take into account "the overall quality and resilience of products ... the cybersecurity practices of their suppliers ... including their secure development procedures" | Capa's capability discipline is a *secure development procedure* whose output is inspectable: a function cannot exercise authority its signature does not carry (the Manifest Completeness upper bound, [`docs/semantics.md`](semantics.md)), and SLSA L1 provenance (`--provenance`) names the source and builder. This is evidence about the *quality of the product and its development procedure*, one input the entity weighs. |
| **Art 21(2)(e)** | "security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure" | The SBOM (deps + purls + graph) is consumable by vulnerability tooling (Dependency-Track, OSV-Scanner) at the dependency layer, and the per-function capability metadata plus information-flow control add a language-level view a dependency-only SBOM cannot carry. Supports the acquisition/development/maintenance measure for Capa-built components; it does not constitute the entity's vulnerability-handling process. |

### Out of scope under NIS2 (stated plainly)

Capa has no runtime posture as an operator and touches none of
the following:

- **Art 23 incident reporting.** The 24-hour early-warning,
  72-hour notification, and one-month final-report cadence is an
  organisational duty of the entity. Capa emits no telemetry and
  files nothing.
- **Art 21(2)(a)-(c), (f)-(j).** Risk-analysis and information-
  system security policies; business continuity, backup, and
  crisis management; the assessment of the effectiveness of
  measures; cybersecurity training; policies on cryptography and
  encryption; human-resources security, access-control policies,
  and asset management; and multi-factor authentication and
  secured communications. All organisational or operational;
  none is a language feature.
- **Art 20 accountability, Art 24 certification schemes, Art 26
  cooperation.** Governance and cross-border machinery, outside
  a compiler's reach.

---

## DORA (Regulation (EU) 2022/2554)

### Regime type

DORA binds **financial entities** and their **ICT third-party
service providers**. It is *lex specialis* for the financial
sector: an in-scope financial entity follows DORA's ICT
risk-management and reporting regime rather than NIS2's. Crucially,
**Article 28(1)(a)** provides that the financial entity **remains
fully responsible** for compliance with its ICT obligations, so
no supplier, tool, or attestation can discharge the entity's
duty. DORA has applied since **17 January 2025** (a settled
date, the regulation being directly applicable).

### Where Capa is a lever (evidence toward transparency, not the register)

DORA's ICT-third-party chapter turns on *transparency and
description* of ICT services and their subcontracting chains.
That is the only surface a compiler's artefacts touch:

| DORA reference | What the article requires | Capa as supporting evidence |
|---|---|---|
| **Art 28(3)** | maintain and update a **Register of Information** on all contractual arrangements for the use of ICT services | The SBOM's per-dependency components (purls + `DEPENDS_ON` / `dependencies` graph) are a *technical input* an entity can reconcile against its register for the Capa-built parts of a service. It is **not** the register: DORA's register is of **contracts**, not an SBOM, and it is the entity's to keep. |
| **Art 30(2)(a)** | contracts shall include "a clear and complete description of all functions and ICT services ... indicating whether subcontracting an ICT service ... is permitted and, when that is the case, the conditions applying to such subcontracting" | The capability manifest and information-flow surface are evidence toward the *description of functions* for a Capa component, and the SBOM's dependency graph maps onto the *subcontracting-chain* concern at the software-dependency level. Supporting material for the contractual description, not the contract. |
| **Art 30(2)(c)** | provisions on "the availability, authenticity, integrity and confidentiality in relation to the protection of data" | Capa's information-flow control governs *where* data typed `@secret` may flow: by default a secret reaching a public sink without an audited `declassify` is a **warning** (best-effort; the build proceeds), and only under `@strict_ifc()` is it a **hard compile-time error**. Every audited disclosure is enumerated in the manifest. This is evidence toward the *confidentiality* and *integrity* description, scoped to the Capa component and carrying the warn-vs-strict caveat. |
| **Art 29** | preliminary assessment of ICT concentration risk, including "long or complex chains of subcontracting" | The resolved dependency graph (per-dependency purls + `DEPENDS_ON`) is a technical input to reasoning about the software-dependency chain for a Capa component. Input to the entity's assessment, never the assessment. |

### Out of scope under DORA (stated plainly)

- **Art 5-16, ICT risk-management framework and governance.** The
  management body's responsibilities, the framework itself,
  protection and prevention, detection, response and recovery,
  and backup policies are organisational.
- **Chapter III, ICT-related incident management and reporting.**
  Classification and reporting of major ICT-related incidents is
  an operational duty; a compiler has no runtime and reports
  nothing.
- **Chapter IV, digital operational resilience testing,
  including TLPT.** Threat-led penetration testing exercises
  *live production systems*, not a compiler. Out of reach.

---

## What Capa actually emits (the levers, verified)

Every artefact named above exists at HEAD and was run against a
real `capa.toml` project while writing this document. Each is
supporting evidence toward the named articles, nothing more.

- **CycloneDX 1.6 SBOM** (`--cyclonedx`,
  [`capa/manifest/_cyclonedx.py`](../capa/manifest/_cyclonedx.py),
  `CYCLONEDX_SPEC_VERSION = "1.6"`). For a `capa.toml` project it
  emits one `library` component per resolved dependency carrying
  its name, version, and a real purl, plus a `dependencies` graph
  edge from the program to each. A github-hosted git dependency
  carries a `pkg:github/<owner>/<repo>@<commit>` purl with the
  `capa.lock` commit SHA.
- **SPDX 2.3 SBOM** (`--spdx`,
  [`capa/manifest/_spdx.py`](../capa/manifest/_spdx.py),
  `SPDX_SPEC_VERSION = "SPDX-2.3"`). Symmetric with CycloneDX from
  the same dependency-identity source: one `Package` per resolved
  dependency, its purl as a `referenceType` `purl` `externalRefs`
  entry, and `DEPENDS_ON` relationships for the graph.
- **Capability manifest** (`--manifest`,
  [`capa/manifest/__init__.py`](../capa/manifest/__init__.py)).
  Per-function `declared_capabilities`,
  `transitively_reachable_capabilities` (the authority ceiling),
  `provably_excluded_capabilities`, `declassifications`, and
  `unaudited_secret_sinks`. The completeness property is an
  **upper bound**: a function cannot exercise authority absent
  from its reachable set (Manifest Completeness, Theorem 2,
  [`docs/semantics.md`](semantics.md)), machine-checked in Agda
  under `--safe`.
- **Information-flow control** (`@secret` / `@public`,
  [`capa/analyzer/_ifc.py`](../capa/analyzer/_ifc.py)). Warn-only
  by default; a hard error only under `@strict_ifc()`. Never
  write "cannot leak" for the default mode.
- **SLSA provenance** (`--provenance`,
  [`capa/manifest/_provenance.py`](../capa/manifest/_provenance.py)).
  An unsigned SLSA **Build L1** in-toto Statement v1 + Provenance
  v1.0 predicate. Signing (L2) is a property of a signing CI, not
  of the compiler.

---

## Overclaims to avoid

State these the wrong way and the honesty discipline breaks:

- **"Capa is NIS2-compliant" / "Capa is DORA-compliant."**
  Category error. These regimes bind operators, not compilers. A
  compiler cannot hold a duty placed on a management body or a
  financial entity.
- **"Capa satisfies Article 21(2)(d)" / "Capa satisfies Article
  28."** No. Capa produces *evidence* one entity feeds into *its*
  risk-management or third-party-risk process. Say "supporting
  evidence toward" and name the article.
- **"Capa's SBOM is the DORA Register of Information."** No. The
  register is of *contracts* under Art 28(3); the SBOM is a
  technical input the entity reconciles against it.
- **"Capa's IFC guarantees confidentiality of processed data
  (Art 30(2)(c))."** By default the secret-to-sink check is a
  **warning**, not a guarantee; the fail-closed behaviour exists
  only under `@strict_ifc()`. State the mode.
- **"Capa handles NIS2 incident reporting / DORA resilience
  testing."** It touches neither. Both are runtime, operational
  duties; Capa has no runtime as an operator.
- **"Provenance proves the build to L2."** `--provenance` is
  unsigned L1. L2 is the signing CI's property.
- **"Capa covers the whole dependency chain."** The SBOM covers
  the *resolved* set; a transitive dependency at a source the root
  lock does not cover carries its declared pin rather than a SHA,
  and a path dependency has no purl. Same residuals as
  [`docs/cra.md`](cra.md).

---

## Summary

Against the CRA, Capa maps to a real product requirement and
still stops short of "compliant". Against NIS2 and DORA the
honest claim is one rung lower and of a different kind: these are
**entity regimes**, so Capa is a **technical lever** producing
**supporting evidence** toward **named articles** (NIS2 Art
21(2)(d), 21(3), 21(2)(e); DORA Art 28(3), 29, 30(2)(a),
30(2)(c)), for the components an in-scope entity builds with it.
It never discharges an operator's obligation, and calling a
compiler "NIS2/DORA-compliant" is a category error.

Everything organisational (NIS2 incident reporting and
governance; DORA's ICT risk-management framework, incident
reporting, and resilience testing) stays with the entity,
regardless of language choice. Capa makes the transparency and
secure-development *evidence* cheaper to produce and more
informative when produced. That is the whole claim.

See [`docs/cra.md`](cra.md) for the product-regime deep-dive,
[`docs/regulatory.md`](regulatory.md) for the five-framework
comparison, and [`docs/positioning.md`](positioning.md) for where
the contribution sits among supply-chain defences.

---

## Primary sources

- [Directive (EU) 2022/2555 (NIS2) consolidated text][nis2-text]
- [Regulation (EU) 2022/2554 (DORA) consolidated text][dora-text]
- [Regulation (EU) 2024/2847 (CRA)](https://eur-lex.europa.eu/eli/reg/2024/2847/oj)
- [CycloneDX 1.6 specification](https://cyclonedx.org/docs/1.6/json/)
- [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/)
- [SLSA v1.0 specification](https://slsa.dev/spec/v1.0/)
