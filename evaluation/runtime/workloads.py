"""Workload definitions for the runtime harness.

Each workload pins:

- ``name``: stable identifier used in the CSV and plot labels.
- ``cwd``: working directory the subprocess runs from (each
  downstream demo's repo root, so its relative `data/` paths
  resolve correctly).
- ``entry``: the entry .capa file path relative to cwd.
- ``args``: CLI args forwarded to the Capa program (after `--`).
- ``timeout_s``: wall-clock cap; a trial that exceeds this is
  killed and counts as failed.

The downstream demos are separate checkouts, one directory per
demo, all under one parent directory. That parent is named by the
``CAPA_DEMO_REPOS`` environment variable; when it is not set, the
default is a ``repos`` directory next to this compiler checkout.
Harnesses that cannot find a demo (e.g. on CI) skip the workload
with a warning rather than aborting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from evaluation.shared.runner_utils import repo_root

BACKEND_CAPA_PYTHON = "capa_python"
BACKEND_CAPA_WASM = "capa_wasm"

#: Environment variable naming the directory that holds the demos.
REPOS_ENV = "CAPA_DEMO_REPOS"


def repos_dir(environ: Mapping[str, str] = os.environ) -> Path:
    """The directory that holds the downstream demo checkouts.

    ``CAPA_DEMO_REPOS`` when it is set and not empty, otherwise a
    ``repos`` directory beside the compiler checkout. No machine's
    home layout is assumed.
    """
    override = environ.get(REPOS_ENV)
    if override:
        return Path(override)
    return repo_root().parent / "repos"


REPOS = repos_dir()


@dataclass
class Workload:
    name: str
    cwd: Path
    entry: str
    args: list[str] = field(default_factory=list)
    timeout_s: float = 120.0


WORKLOADS: dict[str, Workload] = {
    "policy_eval": Workload(
        name="policy_eval",
        cwd=REPOS / "policy-eval",
        entry="policy_eval.capa",
        args=["data/subject.json"],
    ),
    "sbom_watch": Workload(
        name="sbom_watch",
        cwd=REPOS / "sbom-watch",
        entry="watch.capa",
        args=["data/sbom.json"],
    ),
    "audit_trail": Workload(
        name="audit_trail",
        cwd=REPOS / "audit-trail-reporter",
        entry="reporter.capa",
        args=["data/transactions.jsonl"],
    ),
}
