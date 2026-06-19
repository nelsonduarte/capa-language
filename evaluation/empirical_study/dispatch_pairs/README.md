# Phase-1b dispatch / data indirection corpus

Five hand-Python / Capa pairs where the capability authority is reached
through DYNAMIC DISPATCH or DATA, so the call target is not resolvable
by reading the dispatcher's body. These extend the empirical study
(../README.md, ../summary.md) past the direct / via-helper pairs in
../../sbom_diff/.

Each pair directory holds:
  naive.py   a real production-shaped Python dispatch pattern whose
             dispatcher GENUINELY reaches the authority (the handlers
             do real open / urlopen / os.environ.get -- no stubs).
  capa.capa  a FAITHFUL transliteration keeping the SAME dispatch
             mechanism: the capability is reached through a Fun value
             that carries it, selected at runtime exactly as in the
             Python. Compiles under `python -m capa --check`.
  README.md  pattern, provenance, ground-truth facts, faithfulness
             note, and the per-pair CodeQL (dataflow) expectation.

The pairs, ordered by opacity (least dynamic to most), with the
Phase-1c CodeQL verdict MEASURED (not guessed). CodeQL loses ALL five
dispatch facts; the order is the degree of opacity, not a recall split:

  command_registry   constant {name: handler} dict, runtime key
                     -> via-dispatch ; CodeQL: LOSES (points-to does
                        not traverse the dict-subscript, even constant)
  middleware_chain   pipeline of stages passed in as a list parameter
                     -> via-dispatch ; CodeQL: LOSES (locally-built list,
                        stages not resolved through the list)
  event_bus          callbacks registered at runtime, invoked in a loop
                     -> via-dispatch ; CodeQL: LOSES (callbacks appended
                        to a list at runtime, not resolved in the loop)
  reflect_dispatch   getattr(self, "handle_" + name)
                     -> via-dispatch ; CodeQL: LOSES (computed attribute
                        name from runtime input)
  tagged_factory     handler chosen by a tag in deserialized data
                     -> via-data ; CodeQL: LOSES (handler selected by a
                        field of externally-deserialized data)

Phase 1c (the CodeQL T2b treatment) confirmed this empirically: with a
good-faith reachability query (scratch_codeql/, CodeQL 2.25.6,
python-all 7.1.2) CodeQL attributes every DIRECT sink (36/36) and the
two via-helper facts, but ZERO of the ten dispatch / data facts. The
correction to record is command_registry: Phase 1b guessed CodeQL would
resolve the constant dict; it does not.

How the Capa side carries the authority, by construction (verified in
each manifest):
  - the handler / factory functions name the capability in their
    signature (Net / Fs / Env);
  - the registration / assembly site holds the capabilities it captures
    into the handler closures;
  - the runtime dispatcher (dispatch / emit / run_action / run_pipeline)
    reports transitively_reachable_capabilities = [] AND
    provably_excluded_capabilities = [] -- Capa declines to vouch the
    dispatcher is capability-free, the honest record that its authority
    depends on what was registered into the table it receives.

Ground truth for these pairs lives in ../ground_truth.csv with
how = via-dispatch / via-data. The harness (../run_study.py) scores both
corpus roots together. On Q1 (positive attribution) Capa does NOT credit
the dispatcher with the handler's authority: on each 1b pair T3 attributes
2/4 (the two direct handler facts only), exactly tying CodeQL and Semgrep,
which also miss the two dispatcher facts. Capa's advantage is in Q2: on
each dispatcher fact Capa reports provably_excluded_capabilities = []
(false-clears 0/4), while both tools clear it under closed-world semantics
(false-clear 2/4). The separation is the sound non-clearance in Q2, not
extra attribution in Q1.
