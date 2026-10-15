"""Every shell script a workflow step invokes DIRECTLY (a ``run:`` line whose
command is the script path, no interpreter in front) must be committed with
the executable bit, or the Linux runner fails with "Permission denied".

The mode is read from the git index (``git ls-files -s``), which is what a
checkout on the runner reproduces; the working tree on Windows does not
carry the bit, so a file-system check would pass here and fail there.
"""

import re
import subprocess
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"
_DIRECT_SCRIPT = re.compile(r"^\s*(scripts/[\w./-]+\.sh)\b")


def directly_invoked_scripts() -> dict:
    """``{script path: [workflow:job:step, ...]}`` for every ``run:`` whose
    first command token is a script under ``scripts/``."""
    found: dict = {}
    for wf in sorted(WORKFLOWS.glob("*.yml")):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8"))
        for job_name, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                for line in run.splitlines():
                    m = _DIRECT_SCRIPT.match(line)
                    if m:
                        found.setdefault(m.group(1), []).append(
                            "%s:%s:%s" % (wf.name, job_name, step.get("name", "?")))
    return found


def index_mode(path: str) -> str:
    out = subprocess.run(["git", "ls-files", "-s", "--", path], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True).stdout.strip()
    return out.split(" ")[0] if out else ""


class DirectlyInvokedScriptsAreExecutable(unittest.TestCase):
    def test_the_set_is_not_empty(self):
        self.assertTrue(directly_invoked_scripts(), "no workflow step invokes a script directly; the guard is vacuous")

    def test_every_directly_invoked_script_has_the_executable_bit(self):
        for script, sites in directly_invoked_scripts().items():
            with self.subTest(script=script):
                self.assertEqual(
                    index_mode(script), "100755",
                    "%s is run directly by %s but is committed without the executable "
                    "bit; `git update-index --chmod=+x %s`" % (script, sites, script),
                )


if __name__ == "__main__":
    unittest.main()
