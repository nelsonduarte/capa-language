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
    imports no ``capa`` types). ``gated_roots`` is the live set the floor
    gate mutates, so the branches share one enforcement record.
    """

    module: Any
    source: str
    filename: str
    result: Any
    args: Any
    use_color: bool
    operator_grants: dict | None
    gated_roots: set[Path]
    _file_root: Path | None
