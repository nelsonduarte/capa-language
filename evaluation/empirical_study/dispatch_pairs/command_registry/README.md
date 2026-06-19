# command_registry (via-dispatch)

A command/handler registry dispatched by a runtime string key:
the canonical CLI-subcommand router / HTTP URL router shape.

## Pattern

A module-level constant dict maps a string to a handler function,
and a dispatcher resolves the key at runtime and calls the
handler:

```python
HANDLERS = {"fetch": _fetch, "save": _save}

def dispatch(name, arg):
    return HANDLERS[name](arg)
```

One handler (`_fetch`) exercises `Net` (`urllib.request.urlopen`);
the other (`_save`) exercises `Fs` (`open(..., "w")`). The
authority is reached only through the runtime-keyed call.

## Provenance (where this appears in production)

* `argparse` / `click` subcommand tables: the parsed subcommand
  name indexes a `{name: handler}` dict.
* Django / Flask URL routing: the matched route name selects a
  view function from a route table.
* `cmd.Cmd`'s `do_<name>` lookup; `aws-cli` / `gcloud` command
  trees; every plugin host with a `{name: plugin_fn}` registry.

## Authority surface (ground-truth facts)

The unit is `(python_function, capability)`, transitively
reachable from that function in `naive.py`:

| Function | Capability | How |
|---|---|---|
| `_fetch` | `Net` | `direct` (the `urlopen` is in its body) |
| `_save` | `Fs` | `direct` (the `open(..., "w")` is in its body) |
| `dispatch` | `Net` | `via-dispatch` (reached only via `HANDLERS[name](arg)`) |
| `dispatch` | `Fs` | `via-dispatch` (reached only via `HANDLERS[name](arg)`) |

`dispatch` genuinely reaches both authorities: called with
`name="fetch"` it opens the network, with `name="save"` it writes
the disk. Neither sink is lexically in its body.

## Faithful transliteration?

Yes. The `.capa` keeps the SAME dispatch mechanism: a
`Map<String, Fun(String) -> Result<String, DispatchError>>` is
keyed by a runtime string and the resolved closure is invoked
(`reg.get(name)` then `h(arg)`). The capability is reached through
the registered handler, exactly as in the Python.

In Capa the authority is named, not hidden:

* `fetch_handler` carries `Net`, `save_handler` carries `Fs`.
* `build_registry` (the registration site) carries `Net` AND `Fs`
  in its signature, because it must hold both capabilities to
  build the two closures. This is the Capa analogue of the
  `HANDLERS = {...}` literal.
* `dispatch` is the pure runtime dispatcher. Its manifest reports
  `transitively_reachable_capabilities = []` AND
  `provably_excluded_capabilities = []`: Capa refuses to vouch
  that the dispatcher is capability-free, because at runtime it
  can reach whatever the table carries. That empty exclusion list
  is the honest record an auditor needs.

On the dispatcher itself Capa attributes nothing: `dispatch`
reports `transitively_reachable_capabilities = []`, so T3 does NOT
credit `dispatch` with the `Net` or `Fs` authority. Capa ties the
tools on Q1 here -- all three (Semgrep, CodeQL, Capa) attribute
the two `direct` handler facts (`_fetch:Net`, `_save:Fs`) and none
attributes the two dispatcher facts. The two dispatch facts the
manifest does carry are on the handlers and on `build_registry`,
not on `dispatch`. The separation from the tools is Q2, not Q1:
see below.

## Expected treatment behaviour

| Treatment | `_fetch:Net` / `_save:Fs` (direct) | `dispatch:Net` / `dispatch:Fs` (via-dispatch) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss (package granularity) |
| T2 pattern heuristic (Semgrep) | **hit** (sink is lexical) | **miss** (sink not in `dispatch` body) |
| T2b dataflow (CodeQL) | hit | **miss** (confirmed in Phase 1c) -- points-to does NOT traverse the dict-subscript `HANDLERS[name]`, so the handler edges are never followed, even though the dict is a module-level constant |
| T3 Capa by construction | hit | **miss on attribution** (Q1: `dispatch` reach = `[]`, same as the tools) but **does NOT false-clear** (Q2: `provably_excluded = []`, no false sense of safety) |

On the two dispatcher facts Q1 T2 = Q1 T2b = Q1 T3 = 2/4 (per
`per_pair.csv`): all three attribute the two `direct` handler
facts, none attributes the two `dispatch` facts. The difference is
Q2: Semgrep and CodeQL each false-clear 2/4, Capa false-clears
0/4.

## CodeQL verdict (Phase 1c, measured)

**Loses.** This is the empirical correction to the Phase-1b
expectation, which guessed CodeQL would resolve a constant table.
It does not. Running the good-faith reachability query
(`scratch_codeql/capquery/CapabilityReachability.ql`, CodeQL
2.25.6, `python-all` 7.1.2) against `naive.py` attributes `Net` to
`_fetch` and `Fs` to `_save` (the direct sinks) and reports
NOTHING for `dispatch`. The reason is precise and is NOT the
dynamicity of the key: CodeQL's points-to call graph does not
traverse a dict-subscript. Even with a module-level constant dict
and a constant key, `HANDLERS[name](arg)` is not resolved to the
enumerated values, so the handler edges are never followed and the
`Net` / `Fs` authority never propagates to `dispatch`. The
"constant table is the easy end of dataflow's reach" intuition is
wrong for this engine: subscript-through-a-container is already
outside its precise points-to. A *sound* analysis could only
recover this by over-approximating the subscript to every value
the container can hold, which is imprecise in general and degrades
to "any value" once the table is populated from outside the
module. Capa carries the authority through the closure's type
instead, with no points-to budget and no constant-table
precondition. So even at the supposedly-easy end of the spectrum,
the real tool loses and Capa keeps the record by construction.
