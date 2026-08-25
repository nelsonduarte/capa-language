"""Per-invocation dispatch context for the Capa CLI.

Leaf module for :mod:`capa.cli`: a small dataclass carrying the state that
``_main_dispatch`` computes once, after the single ``analyze()`` call, and
hands to the artifact-emitter and execution branches. Bundling it in one
value is what lets those branches move into their own modules in later
steps (each takes a ``DispatchCtx``) without re-deriving the shared facts.

``_file_root`` is the project root resolved from the FILE
(``find_package_root(Path(filename))``), computed a single time here and
read by every SBOM/manifest emitter, replacing the per-branch
recomputations. It is distinct from the cwd root the floor gate resolves.

It imports only the standard library; it must not import from
:mod:`capa.cli`. The dependency runs one way, ``capa.cli`` -> ``capa.cli._ctx``.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class DispatchCtx:
    """Shared post-analysis state threaded through the dispatch branches.

    ``module`` / ``result`` / ``args`` are the analysed AST, the analysis
    result, and the parsed CLI namespace (annotated ``Any`` so this leaf
    imports no ``capa`` types). ``source`` is the root file's raw text and
    ``sources`` the multi-file source map (or None). ``gated_roots`` is the
    live set the floor gate mutates, so the branches share one enforcement
    record.
    """

    module: Any
    source: str
    sources: Any
    filename: str
    result: Any
    args: Any
    use_color: bool
    operator_grants: dict | None
    gated_roots: set[Path]
    _file_root: Path | None


@dataclass
class ExecCtx:
    """Core slice the Wasm/component execution path reads (``run_execute``).

    A smaller, different surface than :class:`DispatchCtx`: it adds
    ``program_args`` (the tail after ``--`` forwarded to the guest) and
    omits the post-analysis emitter fields the execute path never touches.
    Both are populated directly from the same ``_main_dispatch`` locals, so
    neither is derived from the other. ``result`` may be None for a bare
    ``--transpile`` / ``--output`` (no analysis ran); every read of it in the
    execute path is guarded by ``args.run`` / ``args.wasm``, which force the
    analysis, so it is never None where it is used.
    """

    module: Any
    source: str
    filename: str
    result: Any
    args: Any
    use_color: bool
    program_args: list[str]
