"""``fleet/adopt.sh``, the one supported way to adopt the apparatus.

WHY THE SCRIPT EXISTS, since that determines what these tests must
prove. Adoption used to be an eight-step prose checklist. Two of those
steps could go wrong QUIETLY, and one of them was uniquely dangerous:
transcribing the five digests. The natural shortcut is to copy
``.github/shared-regions.sha256`` from a sibling repository rather than
from the compiler revision being adopted. If the sibling is one revision
stale, layer 1 goes GREEN, because the test files came from the same
stale place and genuinely match, while layer 2 goes red. The obvious
response is to bump the revision line until it passes, which creates
exactly the "update the digests without re-copying" fork the record's own
header warns against. It is the one place in the design where the obvious
way to make it green is the wrong action.

So the property under test is not "the script works". It is that the
stale-sibling path DOES NOT EXIST: every byte, including all five
digests, comes from the named revision, and re-running over a
hand-edited or stale record overwrites it with the canonical numbers.
``StaleRecordTests`` is that case.

The rest is mutation testing, to the same standard as everything else
here: an adoption that skips ``.gitattributes``, one whose record does
not come from the named revision, and one whose CONFIG block cannot be
preserved. Each case states whether the SCRIPT catches it or the CHECKS
IT INSTALLS do, because those are different guarantees.

Every case runs against a stubbed ``gh`` serving this working tree, so
the suite needs no network and no credentials.
"""

import base64
import os
import re
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.test_fleet_templates import (
    ADOPTER_RECORD_TEMPLATE,
    BASH,
    BEGIN_MARK,
    CANON_PREFIX,
    END_MARK,
    REPO_ROOT,
    SHARED_FILES,
    TEMPLATES,
    bash_path,
    read_lines,
    recorded_digests,
)

ADOPT = REPO_ROOT / "fleet" / "adopt.sh"
FLEET_RECORD = REPO_ROOT / "fleet" / "shared-regions.sha256"

#: The stub resolves any ref to this and serves the working tree at it.
REVISION = "d" * 40

GIT = shutil.which("git")


def write_gh_stub(directory: Path, upstream: Path, revision: str = REVISION) -> Path:
    """A ``gh`` speaking the two calls ``adopt.sh`` makes.

    ``gh api repos/<r>/commits/<ref>  --jq .sha`` and
    ``gh api repos/<r>/contents/<p>?ref=<rev> --jq .content``. Serving a
    local tree means these tests exercise the real fetch path with no
    network, which matters because the fetch path is the whole point of
    the script.
    """
    directory.mkdir(parents=True, exist_ok=True)
    stub = directory / "gh"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        "set -u\n"
        'case "${1:-}" in\n'
        "  auth) exit 0 ;;\n"
        "  api)\n"
        '    ep="${2:-}"\n'
        '    case "${ep}" in\n'
        f'      */commits/*) printf "%s" "{revision}"; exit 0 ;;\n'
        "    esac\n"
        '    path="${ep#*/contents/}"\n'
        '    path="${path%%\\?*}"\n'
        f'    src="{bash_path(upstream)}/${{path}}"\n'
        '    [ -f "${src}" ] || exit 1\n'
        '    base64 < "${src}"\n'
        "    ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
        newline="\n",
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return stub


@unittest.skipIf(BASH is None or GIT is None, "bash and git are required")
class AdoptScriptTestCase(unittest.TestCase):
    """Shared scaffolding: a stubbed upstream and a throwaway target repo."""

    def build_upstream(self, root: Path) -> Path:
        """Serve THIS working tree as the compiler repository."""
        dest = root / CANON_PREFIX
        for rel in SHARED_FILES:
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(TEMPLATES / rel, dest / rel)
        (dest / ".github").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(
            ADOPTER_RECORD_TEMPLATE, dest / ".github" / "shared-regions.sha256"
        )
        return root

    def build_target(self, root: Path, gitattributes: str = "* text eol=lf\n"):
        """An empty but committed git repository, as a new adopter is."""
        root.mkdir(parents=True, exist_ok=True)
        if gitattributes is not None:
            (root / ".gitattributes").write_text(
                gitattributes, encoding="utf-8", newline="\n"
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

    def adopt(self, target: Path, upstream: Path, ref: str = "main", *extra):
        binx = target.parent / "stubbin"
        write_gh_stub(binx, upstream)
        env = dict(os.environ)
        env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(
            [BASH, bash_path(ADOPT), bash_path(target), ref, *extra],
            capture_output=True,
            text=True,
            env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def full_adoption(self, tmp: str, **target_kwargs):
        root = Path(tmp)
        upstream = self.build_upstream(root / "upstream")
        target = self.build_target(root / "target", **target_kwargs)
        return target, upstream


class FreshAdoptionTests(AdoptScriptTestCase):
    def test_a_fresh_adoption_installs_everything_and_goes_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("ADOPTED", out)
            self.assertIn("33 passed, 0 failed, 0 skipped", out)
            for rel in SHARED_FILES:
                self.assertTrue((target / rel).is_file(), f"{rel} not installed")
            self.assertTrue(
                (target / ".github" / "shared-regions.sha256").is_file()
            )

    def test_the_installed_files_are_byte_identical_to_the_templates(self):
        """A copy that is not a copy is the entire problem being solved."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            for rel in SHARED_FILES:
                with self.subTest(rel=rel):
                    self.assertEqual(
                        (target / rel).read_bytes(),
                        (TEMPLATES / rel).read_bytes(),
                    )

    def test_the_record_pins_the_resolved_sha_and_the_canonical_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            code, out = self.adopt(target, upstream, "main")
            self.assertEqual(code, 0, out)
            record = target / ".github" / "shared-regions.sha256"
            text = record.read_text(encoding="utf-8")
            self.assertRegex(text, rf"(?m)^revision {REVISION}$")
            # A branch name was given; a SHA must be what is pinned.
            self.assertNotIn("revision main", text)
            self.assertEqual(
                recorded_digests(record), recorded_digests(FLEET_RECORD)
            )

    def test_a_fresh_adoption_says_the_config_is_still_placeholders(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("Fill in the CONFIG block of", out)
            for rel, (kind, _) in SHARED_FILES.items():
                if kind == "region":
                    self.assertIn(rel, out)

    def test_it_always_names_what_it_cannot_reach(self):
        """The residual is printed on every run, not buried in a header."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("SETTINGS", out)
            self.assertIn("Actions is enabled", out)


class StaleRecordTests(AdoptScriptTestCase):
    """THE CASE THE SCRIPT EXISTS FOR: the stale sibling.

    A human copying the record from a sibling repository one revision
    behind produces a green layer 1 and a red layer 2, and the obvious
    fix is the wrong one. The script closes this by never reading a
    sibling and never reading the target's record for anything but a
    report, so the state is not reachable through the supported path and
    is repaired if it is reached any other way.
    """

    def stale_record(self) -> str:
        text = ADOPTER_RECORD_TEMPLATE.read_text(encoding="utf-8")
        text = re.sub(r"(?m)^revision .*$", "revision " + "a" * 40, text)
        # Every digest one character different: a plausible stale copy.
        return re.sub(
            r"(?m)^([0-9a-f])([0-9a-f]{63})(\s+\S+)$",
            lambda m: ("0" if m.group(1) != "0" else "1") + m.group(2) + m.group(3),
            text,
        )

    def test_a_stale_record_is_overwritten_not_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            record = target / ".github" / "shared-regions.sha256"
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text(self.stale_record(), encoding="utf-8", newline="\n")
            stale = recorded_digests(record)
            self.assertNotEqual(stale, recorded_digests(FLEET_RECORD))

            code, out = self.adopt(target, upstream, "main", "--allow-dirty")
            self.assertEqual(code, 0, out)
            self.assertEqual(
                recorded_digests(record),
                recorded_digests(FLEET_RECORD),
                "the stale digests survived, which is the whole failure mode",
            )
            self.assertRegex(
                record.read_text(encoding="utf-8"), rf"(?m)^revision {REVISION}$"
            )

    def test_the_previous_revision_is_reported_not_silently_replaced(self):
        """Overwriting quietly would hide a re-pin the reader should see."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            record = target / ".github" / "shared-regions.sha256"
            record.parent.mkdir(parents=True, exist_ok=True)
            record.write_text(self.stale_record(), encoding="utf-8", newline="\n")
            code, out = self.adopt(target, upstream, "main", "--allow-dirty")
            self.assertEqual(code, 0, out)
            self.assertIn("was pinned to " + "a" * 40, out)

    def test_a_hand_written_digest_never_survives(self):
        """MUTATION: a record digest that is not from the named revision.

        Caught by the SCRIPT, before the checks run, because the script
        does not merge with the existing record at all: it writes the
        canonical one. The installed check would also catch it at layer
        2, but only after someone pushed.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            record = target / ".github" / "shared-regions.sha256"
            forged = re.sub(
                r"(?m)^[0-9a-f]{64}(\s+tests/test_guard_pins\.sh)$",
                "f" * 64 + r"\1",
                record.read_text(encoding="utf-8"),
            )
            record.write_text(forged, encoding="utf-8", newline="\n")
            self.assertIn("f" * 64, record.read_text(encoding="utf-8"))

            code, out = self.adopt(target, upstream, "main", "--allow-dirty")
            self.assertEqual(code, 0, out)
            self.assertNotIn("f" * 64, record.read_text(encoding="utf-8"))


class ConfigPreservationTests(AdoptScriptTestCase):
    """Re-adoption must carry the CONFIG forward, or refuse legibly."""

    def customise(self, target: Path):
        """Give the target a real CONFIG, as an adopted repository has."""
        f = target / "tests" / "test_release_wiring.sh"
        text = f.read_text(encoding="utf-8")
        text = text.replace(
            "ENTRY_POINTS=(main.capa example.capa)",
            "ENTRY_POINTS=(alpha.capa beta.capa gamma.capa)",
        )
        text = text.replace("NEEDS_NEST_VENDOR=no", "NEEDS_NEST_VENDOR=yes")
        f.write_text(text, encoding="utf-8", newline="\n")
        return f

    def test_a_re_adoption_preserves_the_config_and_refreshes_the_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            self.assertEqual(self.adopt(target, upstream)[0], 0)
            f = self.customise(target)

            # Now damage the BODY, which a re-adoption must repair.
            text = f.read_text(encoding="utf-8").replace(
                "set -uo pipefail", "set -uo pipefail  # local edit", 1
            )
            f.write_text(text, encoding="utf-8", newline="\n")

            code, out = self.adopt(target, upstream, "main", "--allow-dirty")
            self.assertEqual(code, 0, out)
            self.assertIn("local CONFIG preserved (6 names)", out)

            after = f.read_text(encoding="utf-8")
            self.assertIn("ENTRY_POINTS=(alpha.capa beta.capa gamma.capa)", after)
            self.assertIn("NEEDS_NEST_VENDOR=yes", after)
            self.assertNotIn("# local edit", after)
            self.assertIn("33 passed, 0 failed, 0 skipped", out)

    def test_malformed_markers_are_refused_before_anything_is_written(self):
        """MUTATION: a mangled CONFIG block.

        Caught by the SCRIPT, and refused rather than repaired: with no
        well-formed region there is nothing to lift out, and guessing
        where it starts is guessing which lines are exempt from the
        digest. Nothing must be written, or a half-adopted tree is left
        behind for someone to interpret.
        """
        for description, mutate in (
            ("no begin marker", lambda t: t.replace(BEGIN_MARK + "\n", "", 1)),
            ("no end marker", lambda t: t.replace(END_MARK + "\n", "", 1)),
            (
                "a duplicated begin marker",
                lambda t: t.replace(BEGIN_MARK, BEGIN_MARK + "\n" + BEGIN_MARK, 1),
            ),
        ):
            with self.subTest(case=description), tempfile.TemporaryDirectory() as tmp:
                target, upstream = self.full_adoption(tmp)
                self.assertEqual(self.adopt(target, upstream)[0], 0)
                f = target / "tests" / "test_release_wiring.sh"
                f.write_text(
                    mutate(f.read_text(encoding="utf-8")),
                    encoding="utf-8",
                    newline="\n",
                )
                before = (target / "tests" / "test_guard_pins.sh").read_bytes()
                # Make a zero-config file stale, so that "nothing was
                # written" is observable rather than assumed.
                (target / "tests" / "test_guard_pins.sh").write_bytes(
                    before + b"# stale\n"
                )

                code, out = self.adopt(target, upstream, "main", "--allow-dirty")
                self.assertNotEqual(code, 0, out)
                self.assertIn("cannot preserve the CONFIG block", out)
                self.assertIn("markers are malformed", out)
                self.assertEqual(
                    (target / "tests" / "test_guard_pins.sh").read_bytes(),
                    before + b"# stale\n",
                    "the script wrote files after refusing",
                )

    def test_a_changed_set_of_config_names_is_refused_with_both_lists(self):
        """The real re-adoption hazard, in both directions.

        Upstream gaining a config dimension, or dropping one this
        repository still uses, is a question about what the repository
        MEANS. A script that answered it would invent a value nobody
        chose, so it refuses and names the exact difference.
        """
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            self.assertEqual(self.adopt(target, upstream)[0], 0)
            f = target / "tests" / "test_release_wiring.sh"
            lines = f.read_text(encoding="utf-8").split("\n")
            lines.insert(lines.index(END_MARK), "SOMETHING_ELSE=yes")
            f.write_text("\n".join(lines), encoding="utf-8", newline="\n")

            code, out = self.adopt(target, upstream, "main", "--allow-dirty")
            self.assertNotEqual(code, 0, out)
            self.assertIn("cannot preserve the CONFIG block", out)
            self.assertIn("SOMETHING_ELSE", out)
            self.assertIn("no longer declared upstream", out)


class GitattributesTests(AdoptScriptTestCase):
    """MUTATION: an adoption that skips ``.gitattributes``.

    Caught by the SCRIPT. Nothing else in the apparatus asserts it: every
    CRLF handler exists because this has bitten repeatedly, and it was
    step 3 of a prose checklist that no test read.
    """

    def test_a_missing_gitattributes_is_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp, gitattributes=None)
            self.assertFalse((target / ".gitattributes").exists())
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("created .gitattributes", out)
            self.assertIn(
                "* text eol=lf",
                (target / ".gitattributes").read_text(encoding="utf-8"),
            )

    def test_an_existing_gitattributes_without_an_lf_rule_is_refused(self):
        """Appending to a file somebody wrote is their decision, not ours."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(
                tmp, gitattributes="*.png binary\n"
            )
            code, out = self.adopt(target, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("does not pin LF", out)
            self.assertIn("* text eol=lf", out)
            self.assertEqual(
                (target / ".gitattributes").read_text(encoding="utf-8"),
                "*.png binary\n",
                "the script edited a file it said it would not edit",
            )

    def test_the_text_auto_spelling_is_accepted(self):
        """capa_authgate uses `* text=auto eol=lf`, which is equivalent."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(
                tmp, gitattributes="* text=auto eol=lf\n"
            )
            code, out = self.adopt(target, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("already pins LF", out)


class PreconditionTests(AdoptScriptTestCase):
    def test_a_non_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            upstream = self.build_upstream(root / "upstream")
            plain = root / "target"
            plain.mkdir()
            code, out = self.adopt(plain, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("not a git repository", out)

    def test_a_dirty_tree_is_refused_by_default(self):
        """So that `git checkout -- .` undoes exactly what this wrote."""
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            (target / "README.md").write_text("dirty\n", encoding="utf-8", newline="\n")
            code, out = self.adopt(target, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("uncommitted changes", out)
            self.assertFalse((target / "tests").exists(), "it wrote anyway")

    def test_an_unresolvable_ref_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            target, upstream = self.full_adoption(tmp)
            binx = target.parent / "stubbin"
            write_gh_stub(binx, upstream, revision="not-a-sha")
            env = dict(os.environ)
            env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
            proc = subprocess.run(
                [BASH, bash_path(ADOPT), bash_path(target), "nonsense"],
                capture_output=True, text=True, env=env,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("could not resolve", proc.stdout + proc.stderr)

    def test_a_revision_without_the_templates_is_refused(self):
        """Adopting a revision that predates the apparatus must fail closed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "upstream"
            (empty / CANON_PREFIX).mkdir(parents=True)
            target = self.build_target(root / "target")
            code, out = self.adopt(target, empty)
            self.assertNotEqual(code, 0, out)
            self.assertIn("does not carry", out)


class ScriptShapeTests(unittest.TestCase):
    """The script is a fleet file too, so it is held to the fleet's rules."""

    def test_it_is_not_in_the_shared_region_record(self):
        """Stated as a test so the decision is recorded, not just argued.

        The record exists because files are COPIED and copies drift.
        ``adopt.sh`` is not copied anywhere: it lives here, is run from
        here against a target directory, and has exactly one instance.
        Putting it in the record would mean shipping it into seventeen
        repositories in order to check that seventeen copies agree,
        manufacturing the problem the record exists to solve.
        """
        self.assertNotIn("fleet/adopt.sh", recorded_digests(FLEET_RECORD))
        self.assertNotIn("adopt.sh", "".join(SHARED_FILES))
        self.assertFalse(
            (TEMPLATES / "adopt.sh").exists(),
            "adopt.sh must not be a template; adopters do not copy it",
        )

    def test_it_has_no_carriage_returns_and_ends_with_one_newline(self):
        data = ADOPT.read_bytes()
        self.assertNotIn(b"\r", data)
        self.assertTrue(data.endswith(b"\n"))
        self.assertFalse(data.endswith(b"\n\n"))

    def test_it_derives_the_file_table_rather_than_hardcoding_it(self):
        """A hardcoded copy would be the drift problem one level up.

        The set of files to install and the config names each may declare
        are read out of the canonical check AT THE ADOPTED REVISION, so a
        change to the apparatus does not need this script edited in
        lockstep.
        """
        text = ADOPT.read_text(encoding="utf-8")
        self.assertIn("SHARED_FILES=", text)
        for rel in SHARED_FILES:
            self.assertNotIn(
                f'"{rel}"', text, f"{rel} is hardcoded in adopt.sh"
            )


if __name__ == "__main__":
    unittest.main()
