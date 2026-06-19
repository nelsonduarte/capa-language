# event_bus (via-dispatch, callbacks in data)

An event bus / observer registry: callbacks are carried in a data
structure, registered at runtime, and invoked in a dispatch loop.

## Pattern

```python
class EventBus:
    def __init__(self):
        self._subscribers = []
    def subscribe(self, callback):
        self._subscribers.append(callback)
    def emit(self, event):
        for cb in self._subscribers:
            cb(event)
```

The subscriber list is populated by RUNTIME `subscribe` calls, not
a literal. One subscriber (`audit_to_disk`) exercises `Fs`
(`open(..., "a")`); another (`forward_to_webhook`) exercises `Net`
(`urlopen` of a POST). `emit` reaches both only through `cb(event)`.

## Provenance (where this appears in production)

* `blinker`, Django signals, Flask signals: subscribers register a
  callable; `send()` iterates the receiver list and calls each.
* `pluggy` (pytest / tox plugin hooks): hook impls are collected
  into a list and the hook caller invokes each.
* webhook dispatchers, `pyee` / `asyncio` `EventEmitter.emit`, GUI
  signal/slot tables, the observer pattern generally.

## Authority surface (ground-truth facts)

| Function | Capability | How |
|---|---|---|
| `audit_to_disk` | `Fs` | `direct` (the `open(..., "a")` is in its body) |
| `forward_to_webhook` | `Net` | `direct` (the `urlopen` is in its body) |
| `emit` | `Fs` | `via-dispatch` (reached only via `cb(event)`) |
| `emit` | `Net` | `via-dispatch` (reached only via `cb(event)`) |

`emit` genuinely reaches both: with the two subscribers above
registered, calling `emit` writes the disk and opens the network.
Neither sink is lexically in `emit`.

## Faithful transliteration?

Yes. The `.capa` keeps the SAME shape: an `EventBus` struct holds
a `List<Fun(String) -> Unit>`, `subscribe` pushes a callback at
runtime, and `emit` loops and calls each. The capability is
reached through the registered callback, exactly as in the Python.

In Capa the authority is named:

* `audit_to_disk` carries `Fs`, `forward_to_webhook` carries `Net`.
* `run` (the wiring site) carries `Fs` AND `Net`, because it must
  hold both to capture them into the subscriber closures.
* `new_bus`, `subscribe`, and `emit` all carry a `Fun` in their
  signature (directly or via the `EventBus` struct that holds a
  `List<Fun>`), so their manifest reports
  `provably_excluded_capabilities = []`: Capa will not vouch the
  bus core is capability-free.

On the dispatcher itself Capa attributes nothing: `emit` reports
`transitively_reachable_capabilities = []`, so T3 does NOT credit
`emit` with the `Fs` or `Net` authority. Capa ties the tools on
Q1 here -- all three attribute the two `direct` subscriber facts
and none attributes the two `emit` facts. The two dispatch facts
the manifest carries are on `audit_to_disk` / `forward_to_webhook`
and on the `run` wiring site, not on `emit`. The separation from
the tools is Q2, not Q1: see below.

## Expected treatment behaviour

| Treatment | direct (`audit_to_disk:Fs`, `forward_to_webhook:Net`) | via-dispatch (`emit:Fs`, `emit:Net`) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss |
| T2 pattern heuristic | **hit** | **miss** (no sink in `emit`) |
| T2b dataflow (CodeQL) | hit | **miss** (confirmed in Phase 1c) -- the subscriber list is filled by runtime `append` calls; the list contents are not resolved in the dispatch loop |
| T3 Capa by construction | hit | **miss on attribution** (Q1: `emit` reach = `[]`, same as the tools) but **does NOT false-clear** (Q2: `provably_excluded = []`) |

On the two dispatcher facts Q1 T2 = Q1 T2b = Q1 T3 = 2/4 (per
`per_pair.csv`): all three attribute the two `direct` subscriber
facts, none attributes the two `emit` facts. The difference is Q2:
Semgrep and CodeQL each false-clear 2/4, Capa false-clears 0/4.

## CodeQL verdict (Phase 1c, measured)

**Loses.** Running the good-faith reachability query
(`scratch_codeql/capquery/CapabilityReachability.ql`, CodeQL
2.25.6, `python-all` 7.1.2) against `naive.py` attributes `Fs` to
`audit_to_disk` and `Net` to `forward_to_webhook` (the direct
sinks) and reports NOTHING for `emit` (confirmed in
`scratch_codeql/codeql_facts.csv`, where `emit` never appears). The
callbacks reach the dispatch loop through a list filled at runtime
by separate `subscribe` calls; CodeQL's points-to does not resolve
the list's contents, so the `cb(event)` edge is never followed and
the `Fs` / `Net` authority never propagates to `emit`. This is the
middle of the indirection spectrum: harder than a constant dict
(`command_registry` also loses), easier than a name computed from
external input (`reflect_dispatch`). Capa carries the authority in
the closure's type instead, with no points-to budget.
