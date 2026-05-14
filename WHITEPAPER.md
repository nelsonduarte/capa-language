# Capa WhitePaper

A full design-rationale document for Capa (working name:
"WhitePaper") **is not yet written**. References scattered
through the codebase like `// see WhitePaper §4.6` are
forward-pointers to a document that will exist eventually;
they are not pointers to a private draft.

## Where to look in the meantime

For the parts of the rationale that are written down:

- [`docs/semantics.md`](docs/semantics.md): a working sketch
  of the formal core. A minimal lambda calculus *λ_cap* with
  syntax, typing rules, and small-step operational semantics
  that anchor the capability discipline, plus two soundness
  theorems (Capability Soundness, Manifest Completeness) with
  proof sketches.

- [`docs/positioning.md`](docs/positioning.md): an honest
  short companion that states what is and is not unique about
  Capa, which adjacent languages (Pony, Koka, Roc,
  WebAssembly Component Model) work in the same intellectual
  space, and the one-sentence claim Capa stands behind when
  challenged with "you could do this in Python".

- [`docs/cra.md`](docs/cra.md): the article-by-article
  mapping of Capa's machinery onto Regulation (EU) 2024/2847
  (the Cyber Resilience Act), with explicit callouts for
  which obligations Capa addresses and which remain
  organisational.

- [`Capa-EBNF.md`](Capa-EBNF.md): the formal grammar.

- [`README.md`](README.md): the project layout, install
  instructions, and a tour of the example files.

## What the WhitePaper will contain

When written, it will gather the strands the documents above
sketch separately:

- Motivation and target audience.
- The capability-typing model in three layers: structural,
  flow, linear.
- A survey of contemporary capability languages and where
  Capa sits in that landscape.
- The relationship between capability-typed source and the
  SBOM / supply-chain governance stack.
- The roadmap from transpiled prototype to native backend.

No publication timeline is committed. This file will be
replaced with the WhitePaper itself when it is ready.
