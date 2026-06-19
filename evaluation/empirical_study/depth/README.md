# Depth: two real enterprise programs

The [breadth study](../README.md) is a head-to-head: 25 hand-built
Python / Capa pairs, four treatments (T1 dependency SBOM, T2 Semgrep,
T2b CodeQL, T3 Capa), scored by one per-function `(function, capability)`
fact. It establishes the *gap* against the best real tools (Q1: Capa
ties CodeQL at 38/48; Q2: Capa false-clears 0/48 against CodeQL's 10 and
the dependency SBOM's 48).

This depth component is **deliberately not a head-to-head.** The two
programs here exist only in Capa; there is no Python equivalent, so there
is nothing to run Semgrep or CodeQL against and nothing to port. Running
either would mean first reimplementing ~3,500 lines of Capa in Python,
which would be expensive and would bias the result toward whatever
shape we chose to write. The tool comparison is already settled on the
breadth corpus.

What depth adds is the other half of the argument, all read from the
**real SBOM the Capa build emits** (`capa --manifest main.capa`):

1. **Granularity at scale.** A dependency SBOM names packages. For
   `capa_claimdesk` that is six package rows. Capa's manifest is a map
   over **213 functions**, app and vendored alike. The per-function
   facts a dependency SBOM does not express number in the thousands.
2. **Richness.** Per-function capabilities, *sound* provably-excluded
   facts, IFC declassification sites, `@constant_time` functions, and a
   typestate protocol, none of which any dependency SBOM carries.
3. **Concentration.** What fraction of functions actually hold authority.
   This supplies data for the [`docs/positioning.md`](../../../docs/positioning.md)
   claim that "most CVEs are caused by a small set of functions inside an
   otherwise-trusted module", which until now was asserted without
   measurement. The numbers below confirm it, strongly, in both
   programs; if they had not, this file would report the spread.

The numbers are extracted by [`extract.py`](extract.py) from the two
committed manifests under [`manifests/`](manifests/). Regenerate them
with `python extract.py` (or `--json`); the harness reads only the
committed JSON, so it is deterministic and CI-safe and does not need the
downstream repos present. [`test_extract.py`](test_extract.py) pins every
headline number so a manifest refresh cannot silently drift the prose.

All manifests were generated with **Capa v1.5.2**. Both programs pass
`capa --check main.capa` (exit 0) and the PKG-1 supply-chain gate
(`verify_vendored_deps`, vendor HEAD == locked commit) runs on the build
path and passed for both. One regeneration finding is recorded at the
end of this file.

## capa_paymentguard (PCI / payment-transaction core)

A payment-security core: HMAC-SHA256 integrity over `capa_hash`, fraud
scoring, IBAN/PAN masking, `@secret` field handling, and an append-only
audit log. Entrypoint `main.capa`; one runtime dependency (`capa_hash`,
pure, zero-capability) plus a dev-dependency (`capa_test`).

| Metric | Value |
|---|---|
| Functions analysed (app + vendored) | 70 |
| Pure (zero reachable capabilities) | **66 / 70 (94.3 %)** |
| Provably-excluded `(function, capability)` facts | **625** |
| Reachable `(function, capability)` facts | 5 |
| Declassification sites (IFC) | 6 |
| `@constant_time` functions | 7 |
| Functions crossing `unsafe` | 0 |
| Typestates | none |
| User-defined capabilities | none |

Capability reach (functions that transitively reach each axis):

| Capability | Functions | % |
|---|---|---|
| Stdio | 2 | 2.9 % |
| Fs | 3 | 4.3 % |
| Net | 0 | 0.0 % |
| Db | 0 | 0.0 % |
| Clock | 0 | 0.0 % |
| Env | 0 | 0.0 % |
| Random | 0 | 0.0 % |
| Proc | 0 | 0.0 % |
| Unsafe | 0 | 0.0 % |

**Concentration: extreme.** 66 of 70 functions are provably pure. Only
**3 functions (4.3 %)** reach `Fs` (the audit-log write path), 2 reach
`Stdio`, and **no function reaches `Net`, `Db`, `Proc`, or `Unsafe`** at
all. The entire crypto core (`capa_hash`: 26 functions of SHA-256 and
HMAC) is pure. An auditor reviewing this program for filesystem authority
reads 3 functions out of 70 and is done; the build has *proved* the other
67 cannot touch the disk.

## capa_claimdesk (insurance / claims processing engine)

An expense-claim intake, rules engine, tamper-evident audit ledger,
multi-format reporter, and CLI. Entrypoint `main.capa`; six runtime
dependencies (`capa_hash`, `capa_csv`, `capa_cli`, `capa_log`,
`capa_datetime`, `capa_sbom`) plus a dev-dependency. 140 app functions
and 73 vendored functions are reachable.

| Metric | Value |
|---|---|
| Functions analysed (app + vendored) | 213 |
| Pure (zero reachable capabilities) | **187 / 213 (87.8 %)** |
| Provably-excluded `(function, capability)` facts | **2,295** |
| Reachable `(function, capability)` facts | 48 |
| Declassification sites (IFC) | 3 |
| `@constant_time` functions | 8 |
| Functions crossing `unsafe` | 0 |
| Typestates | `Claim` (6 states: Draft, Submitted, UnderReview, Approved, Rejected, Settled) |
| User-defined capabilities | `Notifier`, `Logger` |

Capability reach (functions that transitively reach each axis):

| Capability | Functions | % |
|---|---|---|
| Stdio | 14 | 6.6 % |
| Fs | 4 | 1.9 % |
| Net | 2 | 0.9 % |
| Db | 5 | 2.3 % |
| Clock | 1 | 0.5 % |
| Env | 3 | 1.4 % |
| Random | 2 | 0.9 % |
| Proc | 3 | 1.4 % |
| Unsafe | 0 | 0.0 % |
| Logger (user-defined) | 9 | 4.2 % |
| Notifier (user-defined) | 5 | 2.3 % |

**Concentration: strong, even at scale.** 87.8 % of functions are pure.
The most-reached sensitive axis is `Db` on **5 functions (2.3 %)**; `Net`
on 2 (0.9 %), `Fs` on 4 (1.9 %), `Proc` on 3 (1.4 %), `Unsafe` on none.
A program of 213 functions concentrates database authority in five of
them and network authority in two. The `Claim` typestate further records
that the claim lifecycle is a six-state protocol the build enforces, and
the two user-defined capabilities (`Logger`, `Notifier`) show the same
concentration discipline extends to program-specific authority, not just
the nine built-ins.

## The measured concentration claim

Across both programs, the worst-case sensitive-axis concentration is
paymentguard's `Fs` at **4.3 %** (3 of 70). No sensitive axis in either
program is held by more than ~4 % of functions, and the pure fraction is
**88-94 %**. This is direct, auditable evidence for the positioning
claim. It is reported as measured; `test_extract.py` pins the 5 % ceiling
to the data, not to a target chosen in advance.

## Delta versus a dependency SBOM (T1) for the same program

A Syft / cdxgen-style dependency SBOM enumerates packages and versions.
It carries **zero** per-function capability facts (the breadth study
measures T1 at 0/48 on Q1 and 48/48 false-clearances on Q2). The same
gap, at program scale:

| | T1 dependency SBOM | Capa per-function manifest |
|---|---|---|
| **paymentguard** rows / facts | 1 runtime package (`capa_hash`) + 1 dev | 70 functions, **630** determined `(function, capability)` facts (5 reachable + 625 provably-excluded) |
| **claimdesk** rows / facts | 6 runtime packages + 1 dev | 213 functions, **2,343** determined facts (48 reachable + 2,295 provably-excluded) |

The delta is the entire per-function map. A dependency SBOM for
`capa_claimdesk` tells a consumer that the program uses CSV, hashing,
CLI, logging, and datetime libraries. It cannot tell the consumer that
exactly two functions reach the network, that the SHA-256 core is pure,
or that 187 functions are provably side-effect-free. Capa's manifest
states all of that, and the provably-excluded facts are **sound** (used
&sube; declared, used &cap; provably-excluded = &empty;, mechanised in
Agda), which is the column no heuristic SBOM generator can fill.

## Indirection in the wild

The breadth study's separation (Q2) lives on indirection: dispatch
tables, callbacks in data, handlers chosen by name. Do these real
programs contain that pattern?

**Yes, one clear instance.** `capa_claimdesk`'s `report.capa` defines a
`Reporter` trait with three implementors (`TextReporter`, `CsvReporter`,
`JsonReporter`). `pick_reporter(format_name: String) -> Reporter` selects
one at runtime by a format string, and `render_report(r: Reporter, data)`
dispatches dynamically with `r.render(data)`. This is exactly the
via-dispatch shape of the synthetic `command_registry` / `event_bus`
pairs, occurring in a real enterprise reporter, and the manifest records
the dispatch as a `method` call on a trait-typed parameter rather than a
resolved target. A CodeQL-style points-to analysis would face the same
trait-object opacity here it faced on the synthetic dispatchers.

**The honest qualifier:** in this instance the laundering is benign,
because **all three reporter implementations are pure** (zero
capabilities). The dispatch carries no authority to launder, so Capa's
record (the trait carries no capability, the dispatcher reaches none) is
both sound and correct without resolving the runtime target. That is the
point worth reporting plainly: the indirection-as-laundering *risk* is
demonstrated on the synthetic pairs, where a handler does hold authority;
the case studies show the same dispatch *structure* arising naturally in
a real program, and Capa typing it soundly, but they do not happen to
contain a hostile authority-laundering path. The rest of both programs is
largely direct call structure. Depth is about richness and scale on a
real program, not about manufacturing more indirection than the programs
naturally have.

## Regeneration finding (v1.5.2)

`capa_paymentguard` compiled and passed PKG-1 unchanged.

`capa_claimdesk` did **not** compile as committed under v1.5.2:

```
intake.capa:46:1: error: module 'capa_csv.model' imported twice with
different selection: ... which symbols end up visible would depend on
import order.
```

The cause is real, not a bit-rot accident. Commit `2bd1072` changed the
app's `intake.capa` to a **selective** import `import capa_csv.model
(CsvError, error_message)` to dodge a `parse` name clash with `capa_cli`.
But the vendored `capa_csv` library imports its own `model` module
**whole-module** (`vendor/capa_csv/header.capa:12`, `parse.capa`,
`write.capa`), and `header.capa` is reachable from the app. v1.5.2
rejects mixing a whole-module and a selective import of the same module
across one compilation unit, because which symbols end up visible would
depend on import order.

The fix used to obtain the manifest is minimal and faithful: the app's
two `import capa_csv.model` sites were returned to whole-module imports,
matching the vendored library's own convention. This is safe and does not
reintroduce the `parse` clash, because `capa_csv`'s `parse` lives in
`capa_csv.parse` (never imported by the app), not in `capa_csv.model`.
The selective import was only ever needed for `capa_csv.parse` vs
`capa_cli.parser`, both of which remain selective.

This fix lives in the downstream `capa_claimdesk` repository, not in this
study; it is recorded here so the manifest is reproducible. It is a
genuine cross-module import-consistency tightening worth a follow-up:
either the diagnostic should exempt a vendored library's internal
whole-module import from an app's selective import of the same module, or
the showcase should standardise on one import style end to end.
