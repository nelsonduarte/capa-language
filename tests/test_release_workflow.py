"""Supply-chain guards for the release-binaries workflow.

The compiler's own binaries and install scripts are the artefacts every
downstream user actually executes, so the release workflow has to hold the
same properties the ecosystem libraries do:

  - every published artefact carries a SLSA build-provenance attestation
    (a ``.sha256`` sidecar proves integrity of a download, not origin);
  - the attested path is the path that gets uploaded, so the attested
    digest matches the released asset byte for byte;
  - signing rights are granted per job, not workflow-wide;
  - every third-party action is pinned to a full commit SHA.

These are cheap to break by editing YAML and expensive to notice, since
the failure mode is a release that verifies against nothing.
"""

import re
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - PyYAML is not a project dependency
    yaml = None

WORKFLOW = (
    Path(__file__).resolve().parent.parent
    / ".github"
    / "workflows"
    / "release-binaries.yml"
)

ATTEST_ACTION = "actions/attest-build-provenance"

# `uses: owner/repo@<40-hex>  # vX.Y.Z`
PINNED_USES = re.compile(r"^\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*\S+\s*$")


def subject_paths(step: dict) -> list:
    raw = step["with"]["subject-path"]
    return [line.strip() for line in raw.splitlines() if line.strip()]


def upload_paths(step: dict) -> list:
    raw = step["with"]["files"]
    return [line.strip() for line in raw.splitlines() if line.strip()]


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestReleaseWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.wf = yaml.safe_load(cls.text)

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------

    def test_workflow_level_permissions_deny_everything(self):
        # A job added later must start with nothing rather than inherit
        # release-upload and artefact-signing tokens.
        self.assertEqual(self.wf["permissions"], {})

    def test_attesting_jobs_hold_exactly_the_rights_they_need(self):
        for name, job in self.wf["jobs"].items():
            with self.subTest(job=name):
                self.assertEqual(
                    job["permissions"],
                    {
                        "contents": "write",
                        "id-token": "write",
                        "attestations": "write",
                    },
                )

    # ---------------------------------------------------------
    # Attestation coverage
    # ---------------------------------------------------------

    def test_every_uploaded_artefact_is_attested_or_a_sha256_sidecar(self):
        for name, job in self.wf["jobs"].items():
            attested, uploaded = set(), set()
            for step in job["steps"]:
                uses = step.get("uses", "")
                if uses.startswith(ATTEST_ACTION + "@"):
                    attested.update(subject_paths(step))
                elif uses.startswith("softprops/action-gh-release@"):
                    uploaded.update(upload_paths(step))

            with self.subTest(job=name):
                self.assertTrue(attested, "job publishes but attests nothing")
                # Nothing is attested that is not also released, otherwise
                # the provenance would describe an intermediate file.
                self.assertEqual(attested - uploaded, set())
                for path in uploaded - attested:
                    self.assertTrue(
                        path.endswith(".sha256")
                        and path[: -len(".sha256")] in attested,
                        f"{path} is released without an attestation",
                    )

    def test_binary_is_attested_after_the_rename(self):
        # The subject must be the renamed asset, not `dist/capa`, or the
        # attested digest will not match the released file.
        steps = self.wf["jobs"]["build"]["steps"]
        names = [s["name"] for s in steps]
        attest = next(
            i
            for i, s in enumerate(steps)
            if s.get("uses", "").startswith(ATTEST_ACTION + "@")
        )
        self.assertLess(names.index("Rename binary for upload"), attest)
        self.assertEqual(
            subject_paths(steps[attest]),
            ["dist/${{ matrix.asset }}"],
        )

    def test_install_scripts_are_attested(self):
        # These are piped straight into a shell by end users.
        steps = self.wf["jobs"]["installer"]["steps"]
        attest = next(
            s
            for s in steps
            if s.get("uses", "").startswith(ATTEST_ACTION + "@")
        )
        self.assertEqual(
            sorted(subject_paths(attest)),
            ["deploy/install.ps1", "deploy/install.sh"],
        )

    # ---------------------------------------------------------
    # Pinning
    # ---------------------------------------------------------

    def test_every_action_is_pinned_to_a_commit_sha(self):
        lines = [
            line
            for line in self.text.splitlines()
            if re.match(r"^\s*uses:", line)
        ]
        self.assertTrue(lines)
        for line in lines:
            self.assertRegex(line.strip(), PINNED_USES.pattern.strip())


if __name__ == "__main__":
    unittest.main()
