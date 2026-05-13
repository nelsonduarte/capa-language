# Capa WhitePaper

The full design rationale for the Capa language ("WhitePaper") is
**not currently checked into this repository**. It is being held back
while the academic work it underpins (a PhD thesis on SBOM
Governance under the EU Cyber Resilience Act) goes through
publication.

## Why this stub exists

References throughout the codebase cite specific sections of the
WhitePaper, e.g. `// see WhitePaper §4.6` for the capability
discipline. Those references are still meaningful, they just point at
a document that lives elsewhere for now.

## What it covers

- The motivation and target audience for Capa.
- The capability-typing model, in three layers: structural, flow,
  linear.
- A survey of contemporary languages and where Capa sits in that
  landscape.
- The relationship to CRA-compliant SBOMs and supply-chain
  governance.
- The roadmap from transpiled prototype to native backend.

## How to obtain a copy

The WhitePaper will be made public as a pre-print with a citable
DOI as soon as the thesis is submitted. Until then, copies can be
requested by emailing the project author.

Once the pre-print is up, this stub will be replaced with the DOI
and a permanent link.

## See also

[`docs/positioning.md`](docs/positioning.md) is a short companion
document that states honestly what is and is not unique about Capa:
which parts of the design predate it, which adjacent languages
(Pony, Koka, Roc, WebAssembly Component Model) work in the same
intellectual space, and which one-sentence claim Capa stands behind
when challenged with "you could do this in Python". The page is
intended for reviewers and prospective contributors.
