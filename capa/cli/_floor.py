"""Compiler-floor enforcement for a file's project root.

Leaf module for :mod:`capa.cli`: the second-layer floor gate, shared by
``_main_dispatch`` (which runs it for every file-based invocation before
analysis) and the project-wide SBOM emitters. It imports only the
standard library and ``capa.pkg``; never :mod:`capa.cli`.
"""

from pathlib import Path

from capa.pkg import enforce_root_floor


def _enforce_floor_for_file_root(
    root_dir: Path, gated_roots: set[Path],
) -> None:
    """Enforce the root floor for the project root a FILE resolves to.

    Two jobs, and they are the same check for different reasons.

    The first is correctness of scope. ``--compose-sbom``,
    ``--check-capabilities``, ``--check-policies`` and
    ``--conformance-report`` resolve their project root by walking up
    from the FILE they were given, not from the cwd. When the file lives
    outside the cwd's project tree those two roots differ, and the gate
    in ``_main_dispatch`` will have enforced the wrong one (or none).
    Since these are precisely the commands that emit composed SBOMs and
    ceiling verdicts for a whole project, the floor has to hold for the
    root they actually act on.

    The second is DEPTH. Every file-based invocation re-checks here, not
    just the four artefact-emitting ones, so the floor does not rest on
    a single predicate. It used to have a second layer inside
    ``_capa_search_paths`` (in :mod:`capa.loader_paths`); that one was
    scoped to ``Path.cwd()``, so it
    saw nothing from a subdirectory, and it never ran for a command that
    does not resolve modules (``--parse``). This seam is scoped to the
    root the command actually acts on and runs for every file, which is
    why it replaces that one rather than reinstating it. It is what kept
    the four artefact commands refusing while the ``--`` bypass was open.

    ``gated_roots`` is every root already enforced during this
    invocation, starting with the cwd gate's. Recording them keeps the
    ``CAPA_IGNORE_CAPA_FLOOR`` warning printing exactly ONCE per root in
    the ordinary case where all of them are the same directory. Every
    entry comes from ``find_package_root``, which resolves before
    walking, so plain set membership is the right comparison.
    """
    if root_dir in gated_roots:
        return
    gated_roots.add(root_dir)
    enforce_root_floor(root_dir)
