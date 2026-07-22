"""The wiring test's verdicts must not depend on how much text follows.

WHY THIS FILE EXISTS. ``fleet/templates/tests/test_release_wiring.sh``
runs under ``set -o pipefail`` and used to answer most of its questions
with ``printf ... | grep -q``. ``grep -q`` exits at its FIRST match while
``printf`` is still writing, so ``printf`` takes SIGPIPE and the
PIPELINE reports 141 over a search that succeeded. Whether it does
depends on how much text follows the match, and on the machine: only a
write issued AFTER the reader has gone takes the signal, so a block that
fits in one buffer was always answered correctly and a longer one was a
race. The buffer is about 4 KiB where stdio sizes it from a pipe's
``st_blksize``, which is the Linux runners, and the pipe's own 64 KiB
capacity where the shell buffers more, which is MSYS.

Measured on a manifest that parses perfectly, the ``[capabilities]``
check failed 7 runs in 15; on the same manifest with 200 comment lines
added after ``max`` it failed 10 out of 10. The failure message accused
the manifest.

AND THE NEGATED FORM WAS WORSE THAN FLAKY. ``! printf ... | grep -q X``
turns that same 141 into SUCCESS, so ``continue-on-error`` sitting early
in a long ``guards:`` job was reported ABSENT. A release gate that had
been switched off read as green, which is the class of defect the whole
file exists to catch. ``DisabledGateBehindALongBlockTests`` is that case,
and it is the one that would have been a soundness hole rather than
noise.

HOW THE FIXTURES ARE BUILT. Each test constructs a complete synthetic
adopter (manifest, both workflows, the pin record, one module) and runs
the REAL template against it, because a re-implementation of the checks
would prove nothing about the file adopters run. The padding is sized
past the 64 KiB pipe capacity rather than past the 4 KiB stdio buffer,
so an unfixed body cannot pass by luck on ANY of these platforms: a
producer with that much left to write cannot finish after the reader has
gone, wherever the buffer boundary falls. The unpadded control in
``MinimalAdoptionTests`` is what rules out the fixture being green for
some unrelated reason.

Run them the way CI does::

    python -m unittest discover tests
"""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_fleet_templates import BASH, TEMPLATES, bash_path

WIRING_TEMPLATE = TEMPLATES / "tests" / "test_release_wiring.sh"

#: The guard pin and the digest the two workflows and the pin record all
#: have to agree on. Their values are irrelevant; that they match is not.
PIN = "a" * 40
CHECKOUT_PIN = "c" * 40
GUARD_DIGEST = "b" * 64
GUARD_WORKFLOW = ".github/workflows/release-guards.yml"

#: One padding line, sized so the arithmetic below is obvious.
PAD_LINE = "padding " * 8

#: Enough padding to exceed a pipe's 64 KiB capacity by a clear margin.
#: The 4 KiB stdio buffer is where the flakiness started, but a producer
#: can still win that race; it cannot win this one, so every assertion
#: here is deterministic on the unfixed body rather than probabilistic.
PAD_LINES = (96 * 1024) // len(PAD_LINE) + 1


def padding(prefix: str) -> str:
    """``PAD_LINES`` lines of inert text, each opened by ``prefix``."""
    return "\n".join(f"{prefix}{PAD_LINE}{i}" for i in range(PAD_LINES))


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def write_unauthenticated_gh(directory: Path) -> Path:
    """A ``gh`` that is present but refuses to authenticate.

    The wiring test SKIPS its two network assertions in that state, which
    is what makes these runs identical on a laptop with credentials and
    on a runner without them. It is not a way of suppressing anything
    under test: nothing here is about the network half.
    """
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / "gh"
    stub.write_text(
        "#!/usr/bin/env bash\nexit 1\n", encoding="utf-8", newline="\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


@unittest.skipIf(BASH is None, "bash is required")
class WiringFixtureTestCase(unittest.TestCase):
    """A synthetic adopter the shipped wiring test passes clean."""

    #: The consumer flow, in the order the body requires it.
    FLOW = [
        "gpg --import publisher.asc",
        "capa install",
        "capa --check main.capa",
        "capa --check-capabilities main.capa",
        "capa test",
    ]

    def flow_block(self, extra=()) -> str:
        lines = [*self.FLOW, *extra]
        return "\n".join(f"        {line}" for line in lines)

    def release_yml(self, flow: str, guards_head: str = "") -> str:
        return f"""name: release

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: write
  id-token: write

env:
  PINNED_FPR: 0123456789ABCDEF0123456789ABCDEF01234567

jobs:
  guards:
{guards_head}    permissions:
      contents: read
    uses: nelsonduarte/capa-language/{GUARD_WORKFLOW}@{PIN}
    with:
      consumer-commands: |
{flow}
      guard-digests: |
        {GUARD_DIGEST}  {GUARD_WORKFLOW}

  release:
    needs: guards
    runs-on: ubuntu-latest
    steps:
      - name: Check out the tag
        uses: actions/checkout@{CHECKOUT_PIN}
      - name: The tag is signed by the pinned key
        run: git verify-tag "$GITHUB_REF_NAME"
      - name: The tarball is the one the guards verified
        run: echo "${{{{ needs.guards.outputs.tarball-sha256 }}}}"
"""

    def selftest_yml(self, flow: str) -> str:
        return f"""name: guard-selftest

on:
  workflow_dispatch:
    inputs:
      tag:
        description: The tag to rehearse against
        required: true

permissions:
  contents: read

jobs:
  guards:
    permissions:
      contents: read
    uses: nelsonduarte/capa-language/{GUARD_WORKFLOW}@{PIN}
    with:
      consumer-commands: |
{flow}
      guard-digests: |
        {GUARD_DIGEST}  {GUARD_WORKFLOW}
"""

    def manifest(self, tail: str = "") -> str:
        return (
            "[package]\n"
            'name = "capa_fixture"\n'
            'version = "0.1.0"\n'
            'capa = ">=1.18.1"\n'
            "\n"
            "[capabilities]\n"
            'max = ["Stdio"]\n' + (tail + "\n" if tail else "")
        )

    def build(self, root: Path, *, manifest_tail="", flow_extra=(), guards_head=""):
        """A repository the wiring test has everything it needs to judge."""
        flow = self.flow_block(flow_extra)
        write(root / "main.capa", "pub fun main()\n    let _ = 0\n")
        write(root / "capa.toml", self.manifest(manifest_tail))
        write(root / ".github" / "workflows" / "release.yml",
              self.release_yml(flow, guards_head))
        write(root / ".github" / "workflows" / "guard-selftest.yml",
              self.selftest_yml(flow))
        write(root / ".github" / "guard-pins.sha256",
              f"revision {PIN}\n\n{GUARD_DIGEST}  {GUARD_WORKFLOW}\n")

        # The template, with only its CONFIG block adapted, which is the
        # one part of it an adopter may touch.
        body = WIRING_TEMPLATE.read_text(encoding="utf-8")
        for name in ("ENTRY_POINTS", "CEILING_ENTRIES"):
            before = f"{name}=(main.capa example.capa)"
            self.assertIn(before, body, f"the template no longer declares {name}")
            body = body.replace(before, f"{name}=(main.capa)")
        write(root / "tests" / "test_release_wiring.sh", body)
        return root

    def run_wiring(self, root: Path):
        binx = root.parent / "stubbin"
        write_unauthenticated_gh(binx)
        env = dict(os.environ)
        env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(
            [BASH, bash_path(root / "tests" / "test_release_wiring.sh")],
            capture_output=True,
            text=True,
            env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def failures(self, out: str):
        return [l for l in out.splitlines() if l.startswith("FAIL ")]

    def assert_clean(self, code: int, out: str):
        self.assertEqual(self.failures(out), [], out)
        self.assertEqual(code, 0, out)
        # A run that asserted nothing also reports no failures.
        self.assertNotIn("0 passed", out)


class MinimalAdoptionTests(WiringFixtureTestCase):
    """The control. Without it a green padded run proves nothing."""

    def test_the_synthetic_adopter_passes_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.build(Path(tmp) / "repo")
            self.assert_clean(*self.run_wiring(root))


class LongCapabilitiesRegionTests(WiringFixtureTestCase):
    """The reported defect, as a fixture that cannot pass by luck.

    The manifest is valid and the ceiling is tight. Only the volume of
    comment lines after ``max`` differs from the control, and nothing
    about the question being asked turns on that.
    """

    def test_a_long_capabilities_region_still_parses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.build(
                Path(tmp) / "repo", manifest_tail=padding("# ")
            )
            code, out = self.run_wiring(root)
            self.assertNotIn("single-line array", "\n".join(self.failures(out)))
            self.assert_clean(code, out)

    def test_a_malformed_max_is_still_refused_behind_the_same_tail(self):
        """The fix must not have bought its greenness by asking less.

        A multi-line ``max`` is the shape the assertion exists for, and
        it must still redden with the identical padding in place.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = self.build(
                Path(tmp) / "repo", manifest_tail=padding("# ")
            )
            manifest = root / "capa.toml"
            write(
                manifest,
                manifest.read_text(encoding="utf-8").replace(
                    'max = ["Stdio"]', 'max = [\n  "Stdio",\n]'
                ),
            )
            code, out = self.run_wiring(root)
            self.assertNotEqual(code, 0, out)
            self.assertTrue(
                any("single-line array" in line for line in self.failures(out)),
                out,
            )


class LongConsumerFlowTests(WiringFixtureTestCase):
    """``flow_has`` asked the same question the same way.

    Every ``capa --check`` assertion goes through it, so a package whose
    consumer flow carries anything after the line being looked for was
    told the line is missing.
    """

    def test_a_long_consumer_flow_does_not_hide_the_lines_it_carries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.build(
                Path(tmp) / "repo",
                flow_extra=[f"echo {PAD_LINE}{i}" for i in range(PAD_LINES)],
            )
            self.assert_clean(*self.run_wiring(root))

    def test_a_missing_flow_line_is_still_caught_behind_the_same_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            extra = [f"echo {PAD_LINE}{i}" for i in range(PAD_LINES)]
            root = self.build(Path(tmp) / "repo", flow_extra=extra)
            for wf in ("release.yml", "guard-selftest.yml"):
                path = root / ".github" / "workflows" / wf
                write(
                    path,
                    path.read_text(encoding="utf-8").replace(
                        "        capa test\n", ""
                    ),
                )
            code, out = self.run_wiring(root)
            self.assertNotEqual(code, 0, out)
            self.assertTrue(
                any("runs the tests" in line for line in self.failures(out)), out
            )


class DisabledGateBehindALongBlockTests(WiringFixtureTestCase):
    """The soundness half, and the reason this was not merely flaky.

    ``continue-on-error`` on the guards job turns a failing gate into a
    passing one. The check for it is negated, so the SIGPIPE status was
    read as "no match" and the disabled gate was reported absent. Here
    the marker sits at the top of a job with 96 KiB of comment after it,
    which is the state in which an unfixed body goes green.
    """

    def long_guards_head(self) -> str:
        return (
            "    continue-on-error: true\n"
            + padding("    # ")
            + "\n"
        )

    def test_a_disabled_gate_is_reported_however_long_the_job_is(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.build(
                Path(tmp) / "repo", guards_head=self.long_guards_head()
            )
            code, out = self.run_wiring(root)
            self.assertNotEqual(code, 0, out)
            self.assertTrue(
                any("continue-on-error" in line for line in self.failures(out)),
                "a switched-off release gate was reported as absent:\n" + out,
            )

    def test_the_same_job_without_the_marker_stays_green(self):
        """The negation still says yes when the answer is yes."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self.build(
                Path(tmp) / "repo", guards_head=padding("    # ") + "\n"
            )
            self.assert_clean(*self.run_wiring(root))


class NoEarlyClosingPipelineTests(unittest.TestCase):
    """A reading of the shared bodies, so this cannot return unnoticed.

    The dynamic cases above cover the three shapes that were reachable
    and dangerous. This covers the SITES: any new pipeline into a reader
    that closes its input early is refused wherever it is written, in
    every file the fleet copies, including the ones whose defect would
    only appear in a repository nobody has adopted yet.
    """

    #: Readers that stop before their input does.
    EARLY = re.compile(r"\|\s*(head\b|grep\s+(-[a-zA-Z]*q|-m)\b)")

    #: The one legitimate reading. These lines assert that the CONSUMER
    #: FLOW contains a `... | grep -q ...` command, which runs in the
    #: clean room and not here, so the text is data rather than a
    #: pipeline this file executes.
    QUOTED_FLOW = re.compile(r"flow_has\s+\"")

    def test_no_shared_body_pipes_into_a_reader_that_stops_early(self):
        for path in sorted((TEMPLATES / "tests").glob("*.sh")):
            with self.subTest(template=path.name):
                offenders = []
                for number, line in enumerate(
                    path.read_text(encoding="utf-8").splitlines(), start=1
                ):
                    if line.lstrip().startswith("#"):
                        continue
                    if not self.EARLY.search(line):
                        continue
                    if self.QUOTED_FLOW.search(line):
                        continue
                    offenders.append(f"{path.name}:{number}: {line.strip()}")
                self.assertEqual(
                    offenders,
                    [],
                    "under `pipefail` these report 141 over a search that "
                    "SUCCEEDED, and a negated one reads that as no match:\n"
                    + "\n".join(offenders),
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
