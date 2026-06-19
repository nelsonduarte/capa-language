# reflect_dispatch (via-dispatch, reflection / dynamic name)

A handler method selected by a NAME built at runtime via
`getattr`. The opaque end of the dispatch spectrum: the call
target is a string the engine would have to predict.

## Pattern

```python
def dispatch(self, msg_type, payload):
    method = getattr(self, "handle_" + msg_type)
    return method(payload)
```

`handle_sync` exercises `Net` (`urlopen` of a POST);
`handle_persist` exercises `Fs` (`open(..., "a")`). The method
name is `"handle_" + msg_type`, computed from runtime input.

## Provenance (where this appears in production)

* `xmlrpc.server` / `SimpleXMLRPCServer`: dispatches a method name
  to `getattr(self, "export_" + name)`.
* `cmd.Cmd.onecmd`: `getattr(self, "do_" + command)`.
* JSON-RPC and homegrown RPC servers: `getattr(handler, "rpc_" +
  method)(params)`.
* `unittest`'s loader (`getattr(case, "test_" + name)`); visitor
  patterns that pick `visit_<nodetype>` by name.

## Authority surface (ground-truth facts)

| Function | Capability | How |
|---|---|---|
| `handle_sync` | `Net` | `direct` (the `urlopen` is in its body) |
| `handle_persist` | `Fs` | `direct` (the `open(..., "a")` is in its body) |
| `dispatch` | `Net` | `via-dispatch` (reached only via the getattr-resolved method) |
| `dispatch` | `Fs` | `via-dispatch` (reached only via the getattr-resolved method) |

`dispatch` genuinely reaches both: with `msg_type="sync"` it opens
the network, with `msg_type="persist"` it writes the disk.

## Faithful transliteration?

Faithful with one honest structural difference recorded here.
**Capa has no reflection** -- no `getattr`, no attribute lookup by
a computed string, no way to turn a runtime `String` into a call
target except by indexing a table the program built explicitly.
That absence is itself a security property (the whole class of
"call a method whose name I computed from input" does not exist),
so a 1:1 translation of `getattr` is impossible by design.

The faithful equivalent **keeps the defining property**: the
selector is a string BUILT from runtime input (`"handle_" +
msg_type`), constructed the same way and used to index a
`Map<String, Fun>`. An unknown computed name resolves to `None`
instead of raising `AttributeError`; the authority reached is
still exactly the handler the computed name selects. This is
recorded as a structural difference, not papered over: where the
Python is open-world over every attribute, the Capa is
closed-world over the registered table -- but in BOTH the call
target is selected by a runtime-computed name, which is the
property the study is testing.

In Capa the authority is named: `handle_sync` carries `Net`,
`handle_persist` carries `Fs`, `build_table` carries both, and
`dispatch` reports `provably_excluded_capabilities = []`. Pair
axis coverage is `{Fs, Net, Stdio}`, so T3 recovers both
`dispatch` facts.

## Expected treatment behaviour

| Treatment | direct (`handle_sync:Net`, `handle_persist:Fs`) | via-dispatch (`dispatch:Net`, `dispatch:Fs`) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss |
| T2 pattern heuristic | **hit** | **miss** (no sink in `dispatch`) |
| T2b dataflow (CodeQL) | hit | **miss** -- the call target is `getattr(self, "handle_" + msg_type)`, a name computed from runtime input; there is no value for points-to to enumerate |
| T3 Capa by construction | hit | **hit** (axis coverage) |

## CodeQL expectation (recorded for Phase 1c, not yet run)

**Loses.** This is the opaque end of the spectrum. The call target
is a method resolved by a name string assembled from runtime
input. CodeQL's points-to has no value to follow at the `method =
getattr(...)` line: it would have to predict the string
`"handle_" + msg_type` and match it against method names, which
default dataflow does not do. Reflection dispatch is the canonical
case where interprocedural dataflow cannot resolve the target and
a type-carried capability still can, because Capa never needs to
know WHICH handler runs -- only that the dispatcher can reach
whatever authority the registered handlers hold. Phase 1c confirms.
