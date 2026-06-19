# tagged_factory (via-data, deserialization-driven dispatch)

A factory whose authority is selected by a TAG field read from
deserialized input. The selector is DATA, not code.

## Pattern

```python
def run_action(raw):
    doc = json.loads(raw)
    tag = doc["type"]
    handler = _ACTIONS[tag]
    return handler(doc)
```

`_action_export` exercises `Net` (`urlopen` POST);
`_action_archive` exercises `Fs` (`open(..., "a")`). The handler
chosen depends on `doc["type"]`, a value read from the bytes that
arrive.

## Provenance (where this appears in production)

* JSON-RPC: the request's `"method"` field selects the procedure.
* `yaml.load` / `pickle` payloads whose tag drives construction --
  the CVE class this repo already studies in
  `examples/cve_pickle.capa` and `examples/cve_pyyaml*.capa`: a tag
  in untrusted data chooses what runs.
* Celery / RQ task messages keyed on a `"task"` name; event-sourcing
  / CQRS command buses keyed on an `"action"` field.

## Authority surface (ground-truth facts)

| Function | Capability | How |
|---|---|---|
| `_action_export` | `Net` | `direct` (the `urlopen` is in its body) |
| `_action_archive` | `Fs` | `direct` (the `open(..., "a")` is in its body) |
| `run_action` | `Net` | `via-data` (handler chosen by `doc["type"]`) |
| `run_action` | `Fs` | `via-data` (handler chosen by `doc["type"]`) |

`run_action` genuinely reaches both: a document with
`{"type":"export"}` opens the network, `{"type":"archive"}` writes
the disk. The deserialization (`json.loads`) is pure of these
capabilities; the authority is in the handler the tag names.

## Faithful transliteration?

Yes. The `.capa` keeps the SAME shape: `parse_json` (a pure free
function) deserializes the input, the `type` field is read from the
parsed data at runtime, and that runtime value indexes the handler
table (`actions.get(tag)`). The capability reached depends on the
data, exactly as in the Python.

In Capa the authority is named, and the consequence of the
deserialization is bounded by construction: `action_export` carries
`Net`, `action_archive` carries `Fs`, `build_actions` carries both,
`doc_body` is provably pure. On the dispatcher itself Capa
attributes nothing: `run_action` reports
`transitively_reachable_capabilities = []`, so T3 does NOT credit
`run_action` with the `Net` or `Fs` authority -- it only reports
`provably_excluded_capabilities = []` (its authority is whatever
the table carries under the data-supplied tag, which it will not
vouch away). Capa ties the tools on Q1 here; the separation from
the tools is Q2, not Q1: see below.

This is the same deserialization-dispatch class as the pickle /
PyYAML CVEs, with the consequence scoped: `run_action` can reach
only the capabilities of the handlers actually registered, and the
manifest states that bound.

## Expected treatment behaviour

| Treatment | direct (`_action_export:Net`, `_action_archive:Fs`) | via-data (`run_action:Net`, `run_action:Fs`) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss |
| T2 pattern heuristic | **hit** | **miss** (no sink in `run_action`) |
| T2b dataflow (CodeQL) | hit | **miss** -- the tag is `json.loads(raw)["type"]`, a value from external input; points-to has no constant to follow into `_ACTIONS[tag]` |
| T3 Capa by construction | hit | **miss on attribution** (Q1: `run_action` reach = `[]`, same as the tools) but **does NOT false-clear** (Q2: `provably_excluded = []`) |

On the two dispatcher facts Q1 T2 = Q1 T2b = Q1 T3 = 2/4 (per
`per_pair.csv`): all three attribute the two `direct` handler
facts, none attributes the two `run_action` facts. The difference
is Q2: Semgrep and CodeQL each false-clear 2/4, Capa false-clears
0/4.

## CodeQL verdict (Phase 1c, measured)

**Loses.** Running the good-faith reachability query
(`scratch_codeql/capquery/CapabilityReachability.ql`, CodeQL
2.25.6, `python-all` 7.1.2) against `naive.py` attributes `Net` to
`_action_export` and `Fs` to `_action_archive` (the direct sinks)
and reports NOTHING for `run_action` (confirmed in
`scratch_codeql/codeql_facts.csv`, where `run_action` never
appears). The selector `tag` is `doc["type"]` where `doc =
json.loads(raw)`: the value is external data, so points-to cannot
fix it to a constant key and `_ACTIONS[tag]` is never resolved to a
single handler. Even though `_ACTIONS` itself is a constant dict
(as in `command_registry`, which also loses), the KEY is runtime
data, so the lookup is unresolved. This is near the opaque end of
the spectrum, alongside `reflect_dispatch`, and is the direct
analogue of why deserialization CVEs are dangerous: the data
chooses the code. Capa bounds it by construction.
