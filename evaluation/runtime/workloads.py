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

The downstream demos live under ``~/Desktop/repos/`` per the
``project_repo_layout`` memo. Harnesses that cannot find them
(e.g. on CI) skip the workload with a warning rather than
aborting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

BACKEND_CAPA_PYTHON = "capa_python"
BACKEND_CAPA_WASM = "capa_wasm"

REPOS = Path.home() / "Desktop" / "repos"


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
