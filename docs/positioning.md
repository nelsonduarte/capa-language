# Positioning of Capa

This document explains where Capa sits in the landscape of capability-typed languages and supply-chain tooling. It is meant for reviewers who want to understand whether the project is genuinely different from what already exists, and for contributors trying to decide if their time is better spent here or upstream of someone else's effort.

## What is actually new

Given a CycloneDX SBOM whose components carry per-function capability declarations and a policy file listing which functions may declare which capabilities, comparing the two sets is roughly thirty lines of Python. The audit example in `examples/sbom_capability_audit.capa` is short for the same reason. So the audit pipeline itself is not the contribution; if it were, the right move would be to write the comparator in Go and skip the language.

The contribution is upstream of the audit: making the SBOM's capability claims true in the first place. In every ecosystem I know about, the source of those claims is one of three things, and none of them gives an auditor what they need.

The first option is asking the author. npm has `permissions`, Deno has `--allow-*` flags, Android has `AndroidManifest.xml`. The author writes down the authorities the program uses, the runtime enforces them. The static picture relies on the author being honest and complete. They are usually neither. A previous release's manifest gets copy-pasted into the next one and the discrepancies pile up release by release.

The second option is heuristic static analysis: Slither, Joern, CodeQL, Semgrep, the long tail of security scanners. The output has false negatives when the analyser fails to model some indirect call pattern, and false positives when it conservatively flags safe code. Adversarial code can hide deliberately by routing through patterns the analyser does not understand. A reviewer who reads "no Net usage detected" cannot distinguish between "this code is safe" and "the analyser missed something".

The third option is runtime sandbox observation: seccomp, the Linux audit subsystem, Deno's permission prompts, eBPF tracing. The log records what the program did during one run; it cannot describe what the program could do on a path that was not exercised during that run. Absence of an entry is ambiguous between "never touches X" and "did not touch X during this test".

What an auditor wants is a different shape entirely: a declaration that lists every authority the program could possibly use, with a compiler that refuses to ship programs whose actual code reaches authorities the declaration omits. That is the property Capa is built around.

## Adjacent languages

The capability-typing idea is older than I am and has been explored in several language families. None of them targets the same use case.

Pony attaches reference capabilities (`iso`, `trn`, `ref`, `val`, `box`, `tag`) to types. The discipline is about aliasing and data-race freedom in a concurrent actor model. The intellectual family is the same; the problem is different.

Koka, Eff, and OCaml 5's effect handlers provide effect systems where rows can stand in for capabilities. A function whose row includes `<net>` is shape-equivalent to a function taking a `Net` parameter. The ecosystems are research-grade and there is no SBOM tooling story today.

Haskell can simulate capabilities with phantom types and the `ReaderT`-of-capability-record pattern. The soundness property is close to what Capa offers, but it is a library convention rather than a language guarantee. Any new contributor who imports `IO` directly bypasses it.

Roc, from Richard Feldman, ships capabilities through its platform: the platform provides effectful primitives and the program receives them as values. Of the production-aimed new languages, Roc is closest in spirit. It is still pre-1.0 and the SBOM angle has not been explored upstream.

The WebAssembly Component Model with WIT is the most credible production contender. Each component declares its imports in a WIT interface, and those imports are effectively its capability surface. Deriving an SBOM from a `.wit` file is mechanical. The crucial difference is granularity: Wasm-CM operates at the module boundary, while Capa operates at the function boundary. For CRA-style audit work, the function-level view matters because most CVEs are caused by a small set of functions inside an otherwise-trusted module. Capa compiles to Wasm-CM, so the two are complementary rather than competing.

Zero (Vercel Labs, May 2026) is the most recent entrant and the only other language with capability-based I/O as its headline. Zero is a systems language in the C and Rust space: small native binaries, explicit memory control, every function declaring its side effects. The distinctive choice is that the toolchain emits stable error codes and typed repair categories so AI agents can read and repair code without a human in the loop. Zero's audience is the AI-agent toolchain. Capa's audience is the supply-chain auditor. The languages share an intellectual root and split on application.

## What Capa can claim

The type checker enforces, by construction, that every external capability use is reachable only through a capability parameter in the function's signature. There is no back-door: no ambient state, no global IO, no hidden import. The Capability Soundness theorem over the λ_cap calculus in [`docs/semantics.md`](semantics.md) captures the property formally, and the four soundness theorems are mechanised in Agda under [`proofs/`](../proofs/).

Each function in `--cyclonedx` carries its own list of declared capabilities. That granularity is what makes a per-function audit possible.

The SBOM-to-source correspondence is mechanical: an auditor can verify an SBOM by running `capa --cyclonedx` against the source themselves. No second analyser, no calibration, no false positives.

The SBOM diff tool at [`examples/sbom_diff.capa`](../examples/sbom_diff.capa) reports per-function widenings and narrowings between releases. Because the granularity is per-function, the diff catches authority changes that a PURL-level diff cannot see, including a dependency widening internally without bumping its version.

## What Capa cannot claim

Capability typing predates Capa by decades. The mechanism is well-understood. The contribution is in the combination, not the primitive.

Capa is at 1.0, but it is a one-person project. The default runtime is CPython, with overhead between 1.00x and 1.45x against hand-Python on the benchmark suite. The WebAssembly Component Model backend has shipped and is functional, with full generics and trait parity: generic structs, sums, and methods, including nested and monomorphic forms, dynamic multi-impl trait dispatch over both struct and sum targets, trait-typed values in containers, and structural trait equality. There is no from-scratch native LLVM backend, and that is a deliberate deferral: Wasm AOT through Cranelift and wasmtime already covers native execution, and a dedicated LLVM backend waits for a concrete driver (see [`docs/design/llvm-backend-feasibility.md`](design/llvm-backend-feasibility.md)).

The ecosystem is shallow. There is a CLI, an LSP server, a formatter, an SBOM emitter, an SBOM diff tool, a package manager with a signed registry index (`capa install` and `capa add` over `capa.toml` and a SHA-pinned `capa.lock`), a runtime benchmark suite, an article-by-article CRA mapping, six CVE case studies, an empirical SBOM-diff micro-validation, and a small standard library. There is no debugger story beyond CPython's, no third-party libraries, no industrial adopters.

The WebAssembly Component Model competes for the same role at module granularity, and it has a much larger ecosystem behind it.

## The thesis in one sentence

Capa is a capability-typed language whose discipline holds by construction, and whose type system therefore backs machine-verifiable per-function audit artefacts with one specific property: the compiler rejects any program whose SBOM would be smaller than its actual capability footprint.

If a reviewer challenges that with "you could do the audit in Python", the reply is that the SBOM you would be auditing in Python would not have the property that makes the audit meaningful. The language is the contribution; the artefacts follow from it.
