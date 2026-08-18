# SBOM parsers in Capa: representation and validation

Three Capa example programs parse the two ISO-blessed SBOM formats
across both serialisations they ship in. Each parser is paired with
a validator. The split between "produces a typed AST" and "checks
that AST against the spec's semantic rules" is deliberate: a
syntactically valid but semantically broken SBOM is the auditor's
most common encounter, and a parser that conflates the two leaves
the auditor without a structure to inspect when something goes
wrong.

This document explains what each parser covers, what each validator
catches, and how the three fit together with the rest of Capa's
supply-chain story.

## TL;DR

| Format | Serialisation | File | LOC | Status |
|---|---|---|---:|---|
| SPDX 2.3 | JSON | [`examples/spdx_parser.capa`](../examples/spdx_parser.capa) | ~430 | full optional-field coverage |
| SPDX 2.3 | tag-value (text) | [`examples/spdx_tag_parser.capa`](../examples/spdx_tag_parser.capa) | ~440 | core fields; multi-line text + snippets deferred |
| CycloneDX 1.5 | JSON | [`examples/cyclonedx_parser.capa`](../examples/cyclonedx_parser.capa) | ~720 | full optional-field coverage including VEX |

Tests: [`tests/test_transpiler.py`](../tests/test_transpiler.py) carries
`test_spdx_parser` (10 assertIns), `test_spdx_tag_parser` (9), and
`test_cyclonedx_parser` (~30) that exercise the demo programs each
parser ships with.

A separate "consumer" example,
[`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa),
demonstrates the downstream use case: take a parsed CycloneDX
document and cross-check it against a policy file. That is the
auditable-supply-chain pitch the whole stack exists to support.

## What each parser covers

### SPDX 2.3 JSON ([`examples/spdx_parser.capa`](../examples/spdx_parser.capa))

| Section | Fields |
|---|---|
| Document | `spdxVersion`, `dataLicense`, `SPDXID`, `name`, `documentNamespace` |
| `creationInfo` | `created`, `creators[]` |
| `packages[]` | `SPDXID`, `name`, `versionInfo`, `downloadLocation`, `licenseConcluded`, `licenseDeclared`, `filesAnalyzed`, `checksums[]`, `annotations[]` |
| `relationships[]` | `spdxElementId`, `relationshipType`, `relatedSpdxElement` |
| `annotations[]` (document-level) | `annotator`, `annotationDate`, `annotationType`, `comment` |
| `hasExtractedLicensingInfos[]` | `licenseId`, `extractedText`, `name`, `seeAlsos[]`, `comment` |
| `snippets[]` | `SPDXID`, `snippetFromFile`, byte-offset `ranges[]`, `licenseConcluded`, `licenseInfoInSnippets[]`, `name`, `comment`, `copyrightText` |
| `externalDocumentRefs[]` | `externalDocumentId`, `spdxDocument`, `checksum` |

Out-of-scope shapes (deferred by design): `files[]` parsing, SPDX
line-pointer ranges (only byte-offset pointers supported), the SPDX
3.0 graph-flavoured re-modelling.

### SPDX 2.3 tag-value ([`examples/spdx_tag_parser.capa`](../examples/spdx_tag_parser.capa))

The text serialisation: lines of `Tag: value`, with `##` heading
comments and blank lines for structure. A state machine tracks a
current package and a current annotation as tags arrive, flushing
them at boundaries (next `PackageName:`, first `Relationship:`, or
EOF). v1 covers:

| Section | Tags |
|---|---|
| Document | `SPDXVersion`, `DataLicense`, `SPDXID`, `DocumentName`, `DocumentNamespace` |
| Creation info | `Creator` (multi), `Created` |
| Per package | `PackageName` (opens), `SPDXID`, `PackageVersion`, `PackageDownloadLocation`, `PackageLicenseConcluded`, `PackageLicenseDeclared`, `FilesAnalyzed`, `PackageChecksum` (multi) |
| Annotation groups (document-level) | `Annotator` + `AnnotationDate` + `AnnotationType` + `AnnotationComment` |
| Relationships | `Relationship: <src> <kind> <tgt>` |

Out-of-scope shapes (reject at parse time with a message pointing
the user at the JSON parser): multi-line `<text>...</text>` value
blocks, `Snippet*` tags, `LicenseID` / `ExtractedText`,
`ExternalDocumentRef`, per-package annotations, `CreatorComment`.

The tag-value parser is the format old tooling (FOSSology, the
official spdx-tools CLI) emits and consumes. Capa supports it so
SBOMs produced by upstream toolchains can be audited without a
pre-processing step.

### CycloneDX 1.5 ([`examples/cyclonedx_parser.capa`](../examples/cyclonedx_parser.capa))

| Section | Fields |
|---|---|
| Document | `bomFormat`, `specVersion`, `serialNumber`, `version` |
| Metadata | `timestamp`, `tools.components[].name+version`, `component` (the main product entry) |
| `components[]` | `bom-ref`, `type`, `name`, `version`, `purl`, `hashes[]`, `licenses[]`, `evidence`, `externalReferences[]` |
| `evidence` (per component) | `identity` (`field`, `confidence`, `methods[]`), `occurrences[]`, `copyright[]` |
| `externalReferences[]` (per component) | `type`, `url`, `comment`, `hashes[]` |
| `dependencies[]` | `ref`, `dependsOn[]` |
| `vulnerabilities[]` | `bom-ref`, `id`, `source`, `ratings[]`, `cwes[]`, `description`, `recommendation`, `published`, `updated`, `affects[]`, VEX `analysis` |
| `services[]` | `bom-ref`, `provider`, `group`, `name`, `version`, `description`, `endpoints[]`, `authenticated`, `x-trust-boundary`, `data[]` classifications |
| `signature` | JSF: `algorithm`, `keyId`, `value` |
| `compositions[]` | `bom-ref`, `aggregate`, `assemblies[]`, `dependencies[]`, `vulnerabilities[]` |

Out-of-scope shapes: the XML alternative serialisation, the
1.6+ multi-`signers[]` / `chain[]` JSF shapes, nested `publicKey`
JWK content, actual cryptographic verification of signatures.

The CycloneDX parser is the most surface-rich of the three because
CycloneDX is the format the Capa compiler itself emits via
`capa --cyclonedx`, so the parser is implicitly a round-trip check
against the emitter.

## The representation-and-validation pattern

Each example exposes the same three-function surface:

```capa
fun parse_<format>(text: String) -> Result<<Format>Document, String>
fun validate_<format>(doc: <Format>Document) -> List<String>
fun main(stdio: Stdio) // prints both
```

The split between `parse_*` and `validate_*` is the load-bearing
design decision. Three reasons:

1. **Composability**. A syntactically valid but semantically
   broken SBOM (a `dependsOn` that points at a non-existent
   `bom-ref`, a `licenseId` that does not start with
   `LicenseRef-`, a CVE severity outside the spec's enum) still
   parses to a complete typed AST. The auditor gets both the
   structure *and* the list of violations, instead of one or the
   other, and can decide which violations to surface and which to
   tolerate.
2. **Re-use**. The same `<Format>Document` AST drives the demo
   pretty-printer, the validator, and any downstream consumer the
   user writes. If validation were embedded inside parsing, every
   consumer would re-parse to get the AST without the spec's
   semantic checks running, which is a recipe for parser drift.
3. **Pedagogy**. The example reads top-down without burying
   semantic policy inside syntactic dispatch. A reader following
   the parser code can keep "what is the grammar" and "what is
   the spec saying about this field" mentally separate, the same
   way ISO/IEC documents themselves do (grammar in one annex,
   semantics in another).

## Catalogue of validators

### SPDX (both serialisations)

`validate_spdx` runs these checks against a parsed `SpdxDocument`:

- **Referential integrity** of `relationships[]`. Every
  `spdxElementId` and `relatedSpdxElement` must point at an SPDXID
  the document defines (the `SPDXRef-DOCUMENT` itself, or one of
  the parsed packages). Dangling references are by far the most
  common failure mode in real-world SBOMs.
- **Annotation-type enum**. Each annotation's `annotationType` must
  be `"REVIEW"` or `"OTHER"` per the SPDX 2.3 spec.
- **Extracted licensing info** (JSON only). Each entry's
  `licenseId` must start with `LicenseRef-`; `extractedText` must
  be non-empty.
- **Snippets** (JSON only). Each snippet's `SPDXID` must start
  with `SPDXRef-`; the `ranges[]` array must have at least one
  range; each range's offsets must be non-negative and monotonic
  (start <= end). Snippets that reference a `snippetFromFile` are
  NOT cross-checked against a `files[]` set today, because Capa
  does not yet parse SPDX `files[]`; the validator records the
  reference but does not resolve it.
- **External document refs** (JSON only). The
  `externalDocumentId` must start with `DocumentRef-`; the
  `spdxDocument` URI must be non-empty; the `checksum` must have a
  non-empty algorithm and value.
- **Cycle detection on the relationship graph** (JSON only). The
  classic three-colour DFS reports an arbitrary witness when a
  cycle exists. The tag-value parser intentionally skips cycle
  detection in v1 to keep the example shorter; the same
  algorithm is one paste away.

### CycloneDX

`validate_cyclonedx` runs these checks:

- **Dependency referential integrity**. Every `dependencies[].ref`
  and `dependencies[].dependsOn[]` entry must be a known
  `bom-ref` (the metadata main component, any
  `components[].bom-ref`, or any `services[].bom-ref`).
- **Cycle detection on the dependency graph**. Same three-colour
  DFS as the SPDX side.
- **Vulnerability checks**. Every `affects[].ref` must resolve to
  a known `bom-ref`; every `ratings[].severity` must be in the
  CycloneDX enum (`critical` / `high` / `medium` / `low` / `info`
  / `none` / `unknown`); every `analysis.state` (when present)
  must be in the analysis enum
  (`resolved` / `resolved_with_pedigree` / `exploitable` /
  `in_triage` / `false_positive` / `not_affected`).
- **Service data-flow enum**. Each
  `services[].data[].flow` must be in
  `{ inbound, outbound, bi-directional, unknown }`.
- **Evidence integrity**. Every
  `components[].evidence.identity.field` must be in the spec's
  9-value enum (`group`, `name`, `version`, `purl`, `cpe`,
  `swid`, `hash`, `omniborId`, `swhid`); every
  `evidence.identity.methods[].technique` must be in the 10-value
  technique enum; every confidence value (per-identity and
  per-method) must be in `[0.0, 1.0]`.
- **External-reference enum**. Every
  `externalReferences[].type` must be in the 39-value spec enum
  (`vcs`, `issue-tracker`, `website`, `advisories`, ...,
  `other`); the `url` must be non-empty.
- **Signature checks**. When `signature` is present: the
  `algorithm` must be in the JSF enum (RS256/384/512,
  PS256/384/512, ES256/384/512, Ed25519, Ed448, HS256/384/512)
  and the `value` must be non-empty. Cryptographic verification
  is explicitly out of scope here; the validator captures the
  shape, an external verifier handles the bytes.
- **Composition checks**. Each `aggregate` must be in the
  10-value enum (`complete`, `incomplete`,
  `incomplete_first_party_only`, ..., `unknown`); every
  `assemblies[]` / `dependencies[]` entry must resolve to a known
  component bom-ref; every `vulnerabilities[]` entry must resolve
  to a known vulnerability bom-ref.

## Closing the loop: the audit consumer

The parsers exist to feed
[`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa).
That example takes the CycloneDX SBOM that the Capa compiler emits
for some user program and compares each function's declared
capabilities against a policy JSON file in two ways:

- **Per-function allow-list**. The policy's `rules` map names a
  set of capabilities each function is allowed; anything else is a
  violation.
- **Structural rules**. The policy's `structural` array pins a
  capability to a list of allowed containers ("Net is allowed
  only inside an impl of trait NetClient"). Every function
  declaring the capability is checked against every applicable
  structural rule independently of its per-function allow-list,
  so a single (function, capability) pair can raise both a
  per-function and a structural violation in the same run.

This is the demonstrable pitch of Capa's supply-chain story: the
SBOM is true *by construction* (the compiler rejects any program
whose capability footprint exceeds its declarations), the parser
gives you a typed view of it, the validator catches authoring
errors before they reach an auditor, and the audit consumer reduces
the auditor's question to a finite syntactic comparison.

The same story works downstream of an upstream SBOM too: the SPDX
tag-value parser accepts what FOSSology emits; the CycloneDX JSON
parser accepts what Dependency-Track, OSV-Scanner, and syft emit;
in either case the downstream consumer can compare the parsed
shape against a policy without trusting the upstream tool to be
honest about its claims.

## What is intentionally out of scope

Each parser's header comment documents its scope cuts. Aggregated
here for the reader who wants the whole picture:

- **SPDX**: SPDX 3.0 graph re-modelling (different format, will need
  a separate example); SPDX `files[]` (the SBOM most tools emit
  does not enumerate every file, and the snippet reference check
  works around the gap by capturing rather than resolving);
  line-pointer ranges (only byte-offset).
- **SPDX tag-value**: multi-line `<text>...</text>` values, snippets,
  extracted licensing info, external document refs, per-package
  annotations, `CreatorComment`. All raise a clear parse-time
  error pointing the user at the JSON parser.
- **CycloneDX**: the XML alternative serialisation; the
  1.6+ multi-`signers[]` / `chain[]` JSF shapes; nested
  `publicKey` JWK content; actual signature verification (the
  validator records the shape, an external verifier handles the
  bytes).

Closing any one of these is mechanical, not research; each is
tracked internally when there is a concrete user ask.

## How to run

```bash
# Each parser doubles as a demo.
python -m capa --run examples/spdx_parser.capa
python -m capa --run examples/spdx_tag_parser.capa
python -m capa --run examples/cyclonedx_parser.capa

# The downstream audit consumer (reads two files via Fs).
python -m capa --run examples/sbom_capability_audit.capa

# Tests:
python -m unittest tests.test_transpiler.TestTranspileExamples.test_spdx_parser
python -m unittest tests.test_transpiler.TestTranspileExamples.test_spdx_tag_parser
python -m unittest tests.test_transpiler.TestTranspileExamples.test_cyclonedx_parser
python -m unittest tests.test_transpiler.TestTranspileExamples.test_sbom_capability_audit
```

## See also

- [`docs/positioning.md`](positioning.md) -- why the SBOM Capa emits
  has a property no other ecosystem's SBOM has.
- [`docs/regulatory.md`](regulatory.md) -- which CRA / NIS2 / DORA
  / NIST SSDF / OWASP SCVS requirements each Capa artefact satisfies.
- [`docs/cra.md`](cra.md) -- article-by-article CRA mapping.
- [`examples/sbom_diff.capa`](../examples/sbom_diff.capa) -- diff
  two CycloneDX SBOMs by per-function capability widening /
  narrowing.
