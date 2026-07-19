"""Supply-chain guards for the release workflows.

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

Two more properties joined them in 1.18.1, from two things that shipped:

  - the binary smoke test must exercise `capa test`, which was broken in
    every released binary because nothing had ever run it against a
    frozen build (the smoke test ran `--check` and `--run`, both of
    which compile in memory and prove nothing about freezing);
  - the copy-paste example in the reusable `release-guards.yml` must
    declare `permissions:` on the calling job, because a caller who
    copies it verbatim otherwise hands the guards the caller's own
    workflow-level grant, which in a release workflow includes
    `id-token: write`, the token that signs attestations. That
    contradicts the comment inside the same file saying a guard must
    never hold a credential that can sign.
"""

import re
import unittest
from pathlib import Path

# Imported unconditionally. This was `try: import yaml / except
# ImportError: yaml = None` with a `@unittest.skipIf` below, and its own
# comment gave the reason: "PyYAML is not a project dependency". That was
# accurate, and it meant these seven supply-chain checks skipped by
# DEFAULT rather than by exception. A run without PyYAML reported OK
# while verifying nothing about SHA-pinning, permissions, or attestation
# coverage, which is the precise failure mode this module exists to
# detect in the workflow it guards. PyYAML is now in the `[test]` extra,
# so a missing one is a loud ERROR instead.
import yaml

_WORKFLOW_DIR = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows"
)
WORKFLOW = _WORKFLOW_DIR / "release-binaries.yml"
GUARDS_WORKFLOW = _WORKFLOW_DIR / "release-guards.yml"

ATTEST_ACTION = "actions/attest-build-provenance"

# `uses: owner/repo@<40-hex>  # vX.Y.Z`
PINNED_USES = re.compile(r"^\s*uses:\s*\S+@[0-9a-f]{40}\s+#\s*\S+\s*$")


def subject_paths(step: dict) -> list:
    raw = step["with"]["subject-path"]
    return [line.strip() for line in raw.splitlines() if line.strip()]


def upload_paths(step: dict) -> list:
    raw = step["with"]["files"]
    return [line.strip() for line in raw.splitlines() if line.strip()]


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
        # Split by what a job DOES rather than assuming every job here
        # publishes. A guard job was added that only reads the checkout
        # to compare the tag against pyproject.toml, and holding it to
        # "must have three write tokens" would have forced exactly the
        # over-granting the workflow-level `permissions: {}` exists to
        # prevent. Publishers keep the strict equality; everything else
        # is held to a STRICTER rule, no write rights at all.
        for name, job in self.wf["jobs"].items():
            with self.subTest(job=name):
                if self.publishes(job):
                    self.assertEqual(
                        job["permissions"],
                        {
                            "contents": "write",
                            "id-token": "write",
                            "attestations": "write",
                        },
                    )
                else:
                    self.assertNotIn(
                        "write", set(job["permissions"].values()),
                        f"non-publishing job '{name}' holds a write token",
                    )

    def test_non_publishing_jobs_gate_the_publishing_ones(self):
        # A job in this file that neither publishes nor is waited on by
        # something that does is doing nothing at release time. That is
        # how a guard quietly stops guarding.
        jobs = self.wf["jobs"]
        for name, job in jobs.items():
            if self.publishes(job):
                continue
            with self.subTest(job=name):
                waiters = [
                    other for other, o in jobs.items()
                    if name in self.needs_of(o)
                ]
                self.assertTrue(
                    waiters,
                    f"job '{name}' publishes nothing and nothing waits for it",
                )

    @staticmethod
    def needs_of(job: dict) -> list:
        needs = job.get("needs")
        if isinstance(needs, str):
            return [needs]
        return list(needs or [])

    @staticmethod
    def publishes(job: dict) -> bool:
        return any(
            step.get("uses", "").startswith("softprops/action-gh-release@")
            for step in job["steps"]
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
                if not self.publishes(job):
                    # A job that uploads nothing must also attest
                    # nothing: an attestation over a file that is never
                    # released describes an intermediate nobody can
                    # verify against.
                    self.assertEqual(attested, set())
                    continue
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


class TestBinarySmokeTest(unittest.TestCase):
    """The smoke test has to cover what FREEZING can break.

    `capa test` shipped broken in every released binary and the smoke
    test did not notice, because it only ran `--check` and `--run`: two
    commands that parse and analyse text in memory and spawn nothing.
    These cases pin the commands whose frozen behaviour differs from
    their source-checkout behaviour, so that dropping one is a failing
    test rather than a discovery made by a user.
    """

    SCRIPT = (
        Path(__file__).resolve().parent.parent
        / "deploy" / "binary_smoke_test.py"
    )

    @classmethod
    def setUpClass(cls):
        cls.wf = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        cls.script = cls.SCRIPT.read_text(encoding="utf-8")

    def test_the_workflow_runs_the_smoke_script(self):
        runs = [
            step.get("run", "")
            for step in self.wf["jobs"]["build"]["steps"]
        ]
        self.assertTrue(
            any("deploy/binary_smoke_test.py" in r for r in runs),
            "the build job no longer runs the binary smoke test",
        )

    def test_smoke_test_is_one_step_for_every_platform(self):
        # It used to be two steps gated on `matrix.os`, running the same
        # bash commands and differing only in how they spelled the
        # executable. Two copies of a check drift; one does not.
        smoke = [
            step for step in self.wf["jobs"]["build"]["steps"]
            if "binary_smoke_test.py" in step.get("run", "")
        ]
        self.assertEqual(len(smoke), 1)
        self.assertNotIn("if", smoke[0])

    def test_smoke_test_covers_the_freezing_sensitive_commands(self):
        # Each of these depends on something beyond in-memory
        # compilation: spawning itself, bundled metadata, writing a
        # project, reading capa.toml back, a bundled optional dependency.
        for command in ('"test"', '"init"', '"install"', '"repl"',
                        '"--version"', '"--check-capabilities"'):
            with self.subTest(command=command):
                self.assertIn(
                    command, self.script,
                    f"the binary smoke test no longer exercises {command}",
                )

    def test_smoke_test_asserts_a_failing_test_still_fails(self):
        # A `capa test` that spawns nothing usable reports every test as
        # failed, so "the suite passed" alone would not have caught the
        # inverse bug. The script must check both directions.
        self.assertIn("1 test(s): 1 passed, 0 failed", self.script)
        self.assertIn("2 test(s): 1 passed, 1 failed", self.script)


class TestReusableGuardsExample(unittest.TestCase):
    """The `HOW TO CALL IT` block in the reusable release-guards
    workflow is documentation that gets COPIED, so its defects are
    copied with it. Three of them shipped: no `permissions:` on the
    calling job (which inherits the caller's `id-token: write` in a
    release workflow, the token that signs attestations), no capability
    ceiling check, and one entry point where a package with two
    front-ends needs both.
    """

    @classmethod
    def setUpClass(cls):
        cls.text = GUARDS_WORKFLOW.read_text(encoding="utf-8")
        # The example lives in the leading comment block, above `on:`.
        header, _, _ = cls.text.partition("\non:")
        cls.example = header

    def test_example_caps_the_guards_at_read(self):
        self.assertIn("permissions:", self.example)
        self.assertIn("contents: read", self.example)

    def test_example_explains_why_the_permissions_line_is_there(self):
        # An unexplained permissions block is a block a reader deletes
        # because it looks redundant. The reason it exists is the whole
        # point: without it the guards inherit a signing token.
        self.assertIn("id-token: write", self.example)

    def test_example_never_grants_the_guards_a_signing_token(self):
        # Compare whole comment LINES, so prose that merely names
        # `id-token: write` while explaining the hazard does not read as
        # a grant of it.
        granted = {
            line.lstrip("#").strip()
            for line in self.example.splitlines()
        }
        for grant in ("id-token: write", "attestations: write",
                      "contents: write"):
            with self.subTest(grant=grant):
                self.assertNotIn(
                    grant, granted,
                    "the example grants the guards a write token",
                )

    def test_example_checks_the_capability_ceiling(self):
        # A package whose central claim is a ceiling gets a clean room
        # verifying the less interesting half without this.
        self.assertIn("capa --check-capabilities", self.example)

    def test_example_covers_more_than_one_entry_point(self):
        checks = [
            line for line in self.example.splitlines()
            if "capa --check " in line
        ]
        self.assertGreaterEqual(
            len(checks), 2,
            "the example checks a single entry point; a package with "
            "two front-ends needs both compiled",
        )
        ceilings = [
            line for line in self.example.splitlines()
            if "capa --check-capabilities " in line
        ]
        self.assertEqual(
            len(checks), len(ceilings),
            "every entry point that is compiled must also be "
            "ceiling-checked",
        )

    def test_example_still_runs_the_full_consumer_flow(self):
        for command in ("gpg --import publisher.asc", "capa install",
                        "python tools/nest_vendor.py", "capa test"):
            with self.subTest(command=command):
                self.assertIn(command, self.example)

    def test_version_marker_is_current(self):
        # The trailing comment on the `uses:` line tells a reader which
        # release the pinned SHA belongs to. It must not name a version
        # whose binaries the guard itself cannot verify: the guard
        # downloads a released compiler and runs `gh attestation
        # verify`, and v1.17.0 and earlier carry no attestation.
        import capa
        marker = f"# v{capa.__version__.rsplit('.', 1)[0]}."
        self.assertIn(
            marker, self.example,
            "the example's version marker no longer matches the "
            "release series it ships in",
        )


if __name__ == "__main__":
    unittest.main()
