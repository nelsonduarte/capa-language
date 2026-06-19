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

Pair axis coverage in the manifest is `{Fs, Net}`, so T3 recovers
both `emit` facts.

## Expected treatment behaviour

| Treatment | direct (`audit_to_disk:Fs`, `forward_to_webhook:Net`) | via-dispatch (`emit:Fs`, `emit:Net`) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss |
| T2 pattern heuristic | **hit** | **miss** (no sink in `emit`) |
| T2b dataflow (CodeQL) | hit | **likely miss** -- the subscriber list is built by runtime `append` calls, not a literal; resolving `cb` in the loop requires tracking every `subscribe` call site into the list and back out, across the bus boundary. Default points-to typically loses the list contents |
| T3 Capa by construction | hit | **hit** (axis coverage) |

## CodeQL expectation (recorded for Phase 1c, not yet run)

**Likely loses.** The callbacks reach the dispatch loop through a
mutable list filled by separate `subscribe` calls. To resolve
`cb(event)` to `audit_to_disk` / `forward_to_webhook`, the engine
must model the list's contents flowing in via `append` and out via
iteration, across the `EventBus` instance. This is the middle of
the indirection spectrum: harder than a constant dict
(`command_registry`), easier than a name computed from external
input (`reflect_dispatch`). The honest expectation is a miss with
default CodeQL settings; Phase 1c will confirm.
