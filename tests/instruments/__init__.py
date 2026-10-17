"""The measuring instruments: tests that compare the compiler with a RULE,
not with another backend, so they survive the removal of any one backend.

Every rule lives in ONE place; the modules below are the map:

- ``_provenance``: build identity. The whole-package hash of ``capa`` is
  computed by every child process over the tree it imported from and
  recomputed by the parent; a child whose line differs voids its rows.
- ``_outcome``: the OUTCOME type, one of six per (member, leg):
  CORRECT, WRONG:<key>, REFUSED, TIMEOUT, BROKEN, VOID, and THE normaliser
  that turns an observation into a key. Every consumer reads this one
  enumeration.
- ``_runner``: how a program runs on a backend: one bounded child process
  per leg, a per-program watchdog, the command-line route as a sibling leg.
  The in-process leg bodies are the parity harness's own runners, imported.
- ``_register``: the known-outcome register: load, the member identity
  (file name plus the program's hash), the diff classes, the shrink-only
  ratchet. The stdlib characterization's known-divergent list is DERIVED
  from it.
- ``absolute``: instrument (a), the absolute rule oracle: the clause table,
  the generator whose builders ARE the clauses, the hand-written anchors,
  the grammar completeness pin, the evaluator self-test.
- ``analysis_execution``: instrument (b): a labelled program is analysed
  and never run; its marker-carrying twin is guarded with the compiler's
  own secret-source table, then run on every backend.
- ``release_differential``: instrument (d): what the previous build
  diagnosed or recorded in a manifest that the candidate no longer does.
  Invoked by the release procedure, not by test discovery.

Optional PRIVATE modules (``_private``) extend the grammar, the case set and
the register when present; the public tree is complete and green without
them.
"""
