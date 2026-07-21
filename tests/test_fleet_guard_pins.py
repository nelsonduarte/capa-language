"""``fleet/guard_pins.sh``, and the audit note that must not be copyable.

WHAT THIS CLOSES. ``.github/guard-pins.sha256`` records the SHA-256 of
every file the shared release guards execute, at the revision
``release.yml`` pins. Until this generator existed, nothing produced it:
there was no template, no tool, and ``fleet/adopt.sh`` did not write it,
while the adoption checklist said to copy it "from the template
repository". No such thing existed, so the only place a first-timer
could obtain one was another adopter.

THE HOLE IS NOT IN THE DIGESTS, and that is what made it survive. A
copied record's digests genuinely ARE the pinned revision's bytes, so
every check passes correctly: 14 passed, 0 failed, exit 0, having
audited nothing. The hole is entirely in what the file CLAIMS about how
it came to exist. capa_hex's record asserts, in prose a copy carries
verbatim, "each digest below was recomputed here by re-fetching the file
at the pin" and "ALL FIVE FILES WERE READ AT THIS REVISION, not accepted
on their digests". Both false in the receiving repository, and no layer
can falsify them.

That is the same class as the incident this fleet deleted two branches
over: a record asserting the opposite of how it was produced. The
general form, which these tests exist to enforce rather than to state:

    A RECORD SHOULD NEVER CARRY A PRE-WRITTEN SENTENCE DESCRIBING WORK
    A HUMAN DID, BECAUSE COPIES CARRY THE SENTENCE AND NOT THE WORK.

So the generator writes the digests, which are mechanical, and leaves
the audit note as a marked blank. ``AuditNoteTests`` is the assertion
that the blank fails closed, which turns a sentence nobody can check
into a red test.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import stat

from tests.test_fleet_adopt import GIT, write_gh_stub
from tests.test_fleet_templates import BASH, REPO_ROOT, TEMPLATES, bash_path


def write_resolving_stub(directory: Path, upstream: Path) -> Path:
    """A ``gh`` that resolves a 40-hex ref to ITSELF, others to REVISION.

    The shared stub in ``test_fleet_adopt`` answers every ``commits/``
    query with one SHA, which makes "did it read release.yml's pin, or
    just default to something" unobservable. Mutation testing found
    exactly that: replacing the parsed pin with a constant passed every
    assertion in this file.
    """
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / "gh"
    script = "\n".join([
        "#!/usr/bin/env bash",
        "set -u",
        'case "${1:-}" in',
        "  auth) exit 0 ;;",
        "  api)",
        '    ep="${2:-}"',
        '    case "${ep}" in',
        "      */commits/*)",
        '        ref="${ep##*/commits/}"',
        '        if printf "%s" "${ref}" | grep -qE "^[0-9a-f]{40}$"; then',
        '          printf "%s" "${ref}"',
        "        else",
        '          printf "%s" "' + REVISION + '"',
        "        fi",
        "        exit 0 ;;",
        "    esac",
        '    path="${ep#*/contents/}"',
        '    path="${path%%\\?*}"',
        '    src="' + bash_path(upstream) + '/${path}"',
        '    [ -f "${src}" ] || exit 1',
        '    base64 < "${src}"',
        "    ;;",
        "  *) exit 1 ;;",
        "esac",
        "",
    ])
    stub.write_text(script, encoding="utf-8", newline="\n")
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


GUARD_PINS = REPO_ROOT / "fleet" / "guard_pins.sh"
GUARD_WORKFLOW = ".github/workflows/release-guards.yml"
GUARD_REPO = "nelsonduarte/capa-language"
REVISION = "d" * 40
AUDIT_BLANK = "REPLACE-THIS-AUDIT-NOTE"

#: Every file the record must end up covering: what the pinned workflow
#: invokes, unioned with what the installed check requires. Neither list
#: is hardcoded in the generator; this one is hardcoded HERE on purpose,
#: as the independent statement the derivation is checked against.
EXPECTED = {
    GUARD_WORKFLOW,
    "tools/check_tag_version.sh",
    "tools/clean_room_build.sh",
    "tools/capa_floor.sh",
    "tools/verify_guard_digests.sh",
}


@unittest.skipIf(BASH is None or GIT is None, "bash and git are required")
class GuardPinsTestCase(unittest.TestCase):
    def build_upstream(self, root: Path) -> Path:
        """Serve this working tree as the compiler repository."""
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / "tools").mkdir(parents=True)
        shutil.copyfile(REPO_ROOT / GUARD_WORKFLOW, root / GUARD_WORKFLOW)
        for name in (
            "check_tag_version.sh",
            "clean_room_build.sh",
            "capa_floor.sh",
            "verify_guard_digests.sh",
        ):
            shutil.copyfile(REPO_ROOT / "tools" / name, root / "tools" / name)
        return root

    def build_target(self, root: Path, pin: str = REVISION, with_check: bool = True):
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / "tests").mkdir(parents=True)
        (root / ".github" / "workflows" / "release.yml").write_text(
            "jobs:\n  guards:\n"
            f"    uses: {GUARD_REPO}/{GUARD_WORKFLOW}@{pin}\n"
            "    with:\n      guard-digests: |\n        placeholder\n",
            encoding="utf-8",
            newline="\n",
        )
        if with_check:
            shutil.copyfile(
                TEMPLATES / "tests" / "test_guard_pins.sh",
                root / "tests" / "test_guard_pins.sh",
            )
        (root / "README.md").write_text("# x\n", encoding="utf-8", newline="\n")
        for args in (
            ["init", "-q"],
            ["config", "user.email", "t@example.com"],
            ["config", "user.name", "t"],
            ["add", "-A"],
            ["commit", "-qm", "initial"],
        ):
            subprocess.run([GIT, "-C", str(root), *args], check=True,
                           capture_output=True)
        return root

    def generate(self, target: Path, upstream: Path, *extra):
        binx = target.parent / "stubbin"
        write_resolving_stub(binx, upstream)
        env = dict(os.environ)
        env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(
            [BASH, bash_path(GUARD_PINS), bash_path(target), *extra],
            capture_output=True, text=True, env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def scenario(self, tmp: str, **kw):
        root = Path(tmp)
        return (
            self.build_target(root / "target", **kw),
            self.build_upstream(root / "upstream"),
        )

    def record_paths(self, target: Path):
        out = set()
        for line in (target / ".github" / "guard-pins.sha256").read_text(
            encoding="utf-8"
        ).splitlines():
            parts = line.split()
            if len(parts) == 2 and len(parts[0]) == 64:
                out.add(parts[1])
        return out


class GenerationTests(GuardPinsTestCase):
    def test_it_writes_a_record_covering_every_executed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            code, out = self.generate(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertEqual(self.record_paths(target), EXPECTED)

    def test_the_digests_are_the_fetched_bytes(self):
        """The whole point: computed here, not copied from anywhere."""
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            self.assertEqual(self.generate(target, upstream)[0], 0)
            recorded = {}
            for line in (target / ".github" / "guard-pins.sha256").read_text(
                encoding="utf-8"
            ).splitlines():
                parts = line.split()
                if len(parts) == 2 and len(parts[0]) == 64:
                    recorded[parts[1]] = parts[0]
            for path, digest in recorded.items():
                with self.subTest(path=path):
                    self.assertEqual(
                        hashlib.sha256((upstream / path).read_bytes()).hexdigest(),
                        digest,
                    )

    def test_it_defaults_to_the_revision_release_yml_pins(self):
        """The only revision the record can correctly describe.

        The pin here is deliberately NOT the stub's default, so a
        generator that ignored release.yml and used some other revision
        would be caught. It was not, until a mutation showed that every
        ref resolved to the same SHA in these fixtures.
        """
        pin = "1" * 40
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp, pin=pin)
            code, out = self.generate(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn(f"release.yml pins {pin}", out)
            record = (target / ".github" / "guard-pins.sha256").read_text(
                encoding="utf-8"
            )
            self.assertRegex(record, rf"(?m)^revision {pin}$")
            self.assertNotIn(REVISION, record)

    def test_an_explicit_ref_overrides_release_yml(self):
        pin = "1" * 40
        explicit = "2" * 40
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp, pin=pin)
            code, out = self.generate(target, upstream, explicit)
            self.assertEqual(code, 0, out)
            record = (target / ".github" / "guard-pins.sha256").read_text(
                encoding="utf-8"
            )
            self.assertRegex(record, rf"(?m)^revision {explicit}$")
            self.assertNotIn(pin, record)

    def test_the_derivation_is_not_hardcoded_in_the_generator(self):
        """A third copy of the list would be the drift problem one level up."""
        text = GUARD_PINS.read_text(encoding="utf-8")
        for path in EXPECTED - {GUARD_WORKFLOW}:
            self.assertNotIn(
                f'"{path}"', text, f"{path} is hardcoded in guard_pins.sh"
            )

    def test_it_unions_the_checks_required_list(self):
        """The union must be a real union, not two lists that agree today.

        The check keeps a hardcoded floor precisely because a regex over
        YAML could miss an invocation. Today the two sources name the
        same five files, so a generator using only the derivation passes
        every other assertion here; a mutation proved that. This makes
        them DIFFER: the served workflow no longer invokes capa_floor.sh,
        so only the check's floor still requires it.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            wf = upstream / GUARD_WORKFLOW
            text = wf.read_text(encoding="utf-8")
            # Remove the INVOCATION, not the file: the derivation then
            # misses capa_floor.sh entirely and only the check's floor
            # still names it. Renaming it to a file that does not exist
            # upstream would instead exercise the fetch refusal, which is
            # a different assertion.
            hidden = text.replace(
                "bash _release_guards/tools/capa_floor.sh",
                "cat /dev/null",
            )
            self.assertNotEqual(hidden, text, "the invocation was not found")
            wf.write_text(hidden, encoding="utf-8", newline="\n")

            code, out = self.generate(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn(
                "tools/capa_floor.sh",
                self.record_paths(target),
                "the check's hardcoded floor was not unioned in",
            )

    def test_without_the_installed_check_only_the_workflow_is_derived(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp, with_check=False)
            code, out = self.generate(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("is not installed here yet", out)

    def test_a_missing_release_yml_is_refused_with_a_route(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream = self.build_upstream(root / "upstream")
            target = root / "target"
            target.mkdir()
            subprocess.run([GIT, "-C", str(target), "init", "-q"], check=True,
                           capture_output=True)
            code, out = self.generate(target, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("has no .github/workflows/release.yml", out)
            self.assertIn("Copy release.yml", out)

    def test_it_says_the_audit_is_not_done(self):
        """It must not report success for work it did not do."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            code, out = self.generate(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("WRITTEN, NOT YET AUDITED", out)
            self.assertIn("it cannot read them for you", out)


class AuditNoteTests(GuardPinsTestCase):
    """The blank must fail closed, and it must be the only prose about work.

    This is the enforcement of the generalisation. A pre-written sentence
    describing what a human did is carried by ``cp``; the work is not. So
    the generator writes no such sentence, and the check refuses the
    record while the blank survives.
    """

    def check(self, target: Path, upstream: Path):
        binx = target.parent / "stubbin"
        write_gh_stub(binx, upstream)
        env = dict(os.environ)
        env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(
            [BASH, bash_path(target / "tests" / "test_guard_pins.sh")],
            capture_output=True, text=True, env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def fill_note(self, target: Path, text: str = "# read it all, honestly\n"):
        record = target / ".github" / "guard-pins.sha256"
        lines = record.read_text(encoding="utf-8").split("\n")
        start = next(i for i, l in enumerate(lines) if AUDIT_BLANK in l) - 1
        end = next(i for i, l in enumerate(lines) if l.startswith("revision "))
        record.write_text(
            "\n".join(lines[:start] + text.split("\n") + lines[end:]),
            encoding="utf-8",
            newline="\n",
        )

    def test_the_generated_record_carries_a_blank_not_a_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            self.assertEqual(self.generate(target, upstream)[0], 0)
            text = (target / ".github" / "guard-pins.sha256").read_text(
                encoding="utf-8"
            )
            self.assertIn(AUDIT_BLANK, text)
            # And none of the sentences a copy used to carry.
            for claim in (
                "was deliberately NOT copied",
                "each digest below was recomputed here",
                "WERE READ AT THIS REVISION",
            ):
                self.assertNotIn(claim, text)

    def test_the_check_refuses_an_unwritten_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            self.assertEqual(self.generate(target, upstream)[0], 0)
            code, out = self.check(target, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("the audit note in guard-pins.sha256 has not been written", out)

    def test_the_check_passes_once_the_note_is_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.scenario(tmp)
            self.assertEqual(self.generate(target, upstream)[0], 0)
            self.fill_note(target)
            code, out = self.check(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("the audit note has been written", out)
            self.assertIn("0 failed", out)

    def test_a_record_copied_from_a_sibling_still_carries_the_blank(self):
        """The copy path, which is what actually happens under time pressure.

        Copying a record that has been properly audited elsewhere is not
        detectable by any digest, and this does not claim to detect it.
        What it does is ensure the thing available to copy is either a
        blank, which reddens, or someone else's note, which names the
        wrong repository and revision to any reader.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream = self.build_upstream(root / "upstream")
            source = self.build_target(root / "source")
            self.assertEqual(self.generate(source, upstream)[0], 0)

            sibling = self.build_target(root / "sibling")
            shutil.copyfile(
                source / ".github" / "guard-pins.sha256",
                sibling / ".github" / "guard-pins.sha256",
            )
            code, out = self.check(sibling, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("has not been written", out)


class NoPrewrittenClaimsTests(unittest.TestCase):
    """No shipped record may assert work a copy would carry without doing.

    Applied to every template that becomes a record in an adopter. This
    is the generalisation as a test rather than as a paragraph, which is
    the difference between a rule and a wish.
    """

    CLAIMS = [
        "was deliberately NOT copied",
        "each digest below was recomputed here",
        "WERE READ AT THIS REVISION",
        "recomputed here by re-fetching",
    ]

    def test_no_shipped_record_pre_writes_an_audit_claim(self):
        """Scoped to RECORDS, which is where the rule bites.

        The checks quote the old false sentences in their headers to
        explain the defect they now refuse, and that is documentation
        rather than a claim a record carries into a repository where it
        is untrue. The distinction is not a loophole: a record is a file
        whose content asserts something about THIS repository, so a
        sentence in it travels as an assertion. A comment in a check
        explaining why the rule exists travels as an explanation.
        """
        records = [p for p in TEMPLATES.rglob("*.sha256") if p.is_file()]
        self.assertTrue(records, "no record templates found")
        for path in records:
            text = path.read_text(encoding="utf-8", errors="replace")
            for claim in self.CLAIMS:
                with self.subTest(path=path.name, claim=claim):
                    self.assertNotIn(claim, text)

    def test_the_generator_pre_writes_no_audit_claim_either(self):
        text = GUARD_PINS.read_text(encoding="utf-8")
        # It quotes the old claims in its header to explain the defect,
        # which is documentation rather than something a record carries.
        record_block = text[text.index("cat > "):]
        for claim in self.CLAIMS:
            with self.subTest(claim=claim):
                self.assertNotIn(claim, record_block)


if __name__ == "__main__":
    unittest.main()
