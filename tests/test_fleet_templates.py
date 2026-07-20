"""Regression tests for the shared wiring templates in ``fleet/``.

WHAT THESE COVER. ``fleet/templates/tests/test_release_wiring.sh`` and
``fleet/templates/tests/test_wiring_mutations.sh`` are ~1000 lines of
security-checking logic that is COPIED, in full, into every repository
that adopts the shared release guards. Fifteen more copies are planned.
Nothing noticed when a copy diverged, and this fleet has been bitten by
exactly that twice: a capability tuple hand-copied at 21 sites in this
repository that had already drifted before anyone looked, and
capa_authgate's ``check_tag_version.sh`` becoming a second copy whose
two versions immediately printed different messages.

The adopter-side check is ``fleet/templates/tests/test_shared_regions.sh``.
It digests everything OUTSIDE the two CONFIG markers and compares that
to a number recorded in the adopting repository. What THIS file proves,
on the canonical side, is that the shipped templates extract cleanly and
that the numbers recorded in ``fleet/shared-regions.sha256`` are the
templates' own. Without it, the fleet's recorded digests could describe
bytes that were never here.

TWO INDEPENDENT EXTRACTIONS, on purpose. ``SharedRegionDigestTests``
re-implements the boundary rule in Python and compares against the
record; ``AdopterCheckTests`` runs the REAL shell script against a
synthetic adopter tree built from the templates. Agreement between an
awk implementation and a Python one is a much stronger statement about
the boundary than either alone, and disagreement is the thing that would
otherwise be discovered fifteen repositories later.

Run them the way CI does::

    python -m unittest discover tests
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FLEET = REPO_ROOT / "fleet"
TEMPLATES = FLEET / "templates"
RECORD = FLEET / "shared-regions.sha256"
DIGEST_TOOL = FLEET / "shared_region_digest.sh"
ADOPTER_RECORD_TEMPLATE = TEMPLATES / ".github" / "shared-regions.sha256"
SHARED_CHECK = TEMPLATES / "tests" / "test_shared_regions.sh"

BASH = shutil.which("bash")

BEGIN_MARK = "# ================== CONFIG: the only repo-specific part =================="
END_MARK = "# ======================= END CONFIG; shared body ========================="

# The files under check, and the config names each one's config region
# may declare. This table is the same one the adopter-side check
# carries, and ``TemplateTableTests`` below asserts the two agree rather
# than leaving a fourth copy of a constant to drift on its own.
SHARED_FILES = {
    "tests/test_release_wiring.sh": [
        "ENTRY_POINTS",
        "CEILING_ENTRIES",
        "NEGATIVE_CEILING_ENTRIES",
        "COMPILER_REJECTS",
        "UNCHECKED_MODULES",
        "NEEDS_NEST_VENDOR",
    ],
    "tests/test_wiring_mutations.sh": [
        "PRIMARY_MODULE",
        "SECOND_MODULE",
        "CEILING_LINE_WIDE",
        "CEILING_NAME",
    ],
}


def bash_path(path) -> str:
    """Render a filesystem path the way the ``bash`` on this host wants it."""
    text = str(path)
    if os.name == "nt" and len(text) > 1 and text[1] == ":":
        return "/" + text[0].lower() + text[2:].replace("\\", "/")
    return text


def read_lines(path: Path):
    """Read a file as lines with any trailing ``\\r`` stripped.

    Stripped EXPLICITLY, and not left to the platform. A CRLF copy of one
    of these files digests identically under MSYS gawk, which strips
    ``\\r`` on its own, and would not on a Linux runner, where the marker
    lines would not match at all. Relying on the local behaviour is how
    a Windows-authored copy passes here and reddens in CI.
    """
    text = path.read_bytes().decode("utf-8")
    return [line.rstrip("\r") for line in text.split("\n")]


def extract_shared_region(lines):
    """The digestible surface: everything except strictly between the markers.

    Raises ``ValueError`` rather than returning anything when the markers
    are absent, duplicated or out of order. There is deliberately no
    fall-through to digesting the whole file: that would give a
    markerless file a stable digest describing no boundary at all.

    Both markers stay IN the result, so the marker text cannot be edited
    to move the boundary without the digest noticing.
    """
    begins = [i for i, line in enumerate(lines) if line == BEGIN_MARK]
    ends = [i for i, line in enumerate(lines) if line == END_MARK]
    if len(begins) != 1:
        raise ValueError(f"begin marker occurs {len(begins)} time(s), expected 1")
    if len(ends) != 1:
        raise ValueError(f"end marker occurs {len(ends)} time(s), expected 1")
    if begins[0] > ends[0]:
        raise ValueError("the end marker precedes the begin marker")
    return [
        line
        for i, line in enumerate(lines)
        if i <= begins[0] or i >= ends[0]
    ]


def shared_digest(path: Path) -> str:
    region = extract_shared_region(read_lines(path))
    return hashlib.sha256("\n".join(region).encode("utf-8")).hexdigest()


def config_region(lines):
    """The lines strictly between the markers, exclusive of both."""
    begin = lines.index(BEGIN_MARK)
    end = lines.index(END_MARK)
    return lines[begin + 1 : end]


def recorded_digests(path: Path):
    """Parse ``<sha256>  <path>`` lines out of a record file."""
    out = {}
    for line in read_lines(path):
        match = re.match(r"^([0-9a-f]{64})\s+(\S+)$", line)
        if match:
            out[match.group(2)] = match.group(1)
    return out


class SharedRegionDigestTests(unittest.TestCase):
    """The recorded numbers are the templates' own."""

    def test_every_shared_file_has_a_template(self):
        for rel in SHARED_FILES:
            self.assertTrue(
                (TEMPLATES / rel).is_file(),
                f"fleet/templates/{rel} is missing; adopters copy it from here",
            )

    def test_templates_extract_cleanly(self):
        for rel in SHARED_FILES:
            with self.subTest(rel=rel):
                # Raises on a malformed boundary, which is the assertion.
                region = extract_shared_region(read_lines(TEMPLATES / rel))
                self.assertIn(BEGIN_MARK, region)
                self.assertIn(END_MARK, region)

    def test_recorded_digests_match_the_templates(self):
        recorded = recorded_digests(RECORD)
        for rel in SHARED_FILES:
            with self.subTest(rel=rel):
                self.assertIn(
                    rel, recorded, f"fleet/shared-regions.sha256 records no digest for {rel}"
                )
                self.assertEqual(
                    shared_digest(TEMPLATES / rel),
                    recorded[rel],
                    f"{rel} has changed and fleet/shared-regions.sha256 was not "
                    f"regenerated; run `bash fleet/shared_region_digest.sh`",
                )

    def test_the_adopter_record_template_carries_the_same_digests(self):
        """An adopter copies the numbers from the template, so it must agree.

        A stale template is worse than an absent one here: it would seed
        every new adopter with a number describing a revision of the
        body that no longer exists, and the adoption would go red for a
        reason that looks like drift and is not.
        """
        self.assertEqual(
            recorded_digests(ADOPTER_RECORD_TEMPLATE),
            recorded_digests(RECORD),
            "fleet/templates/.github/shared-regions.sha256 has drifted from "
            "fleet/shared-regions.sha256",
        )

    def test_the_adopter_record_template_pins_no_usable_revision(self):
        """The shipped placeholder must fail closed, offline, unedited.

        If the placeholder were a well-formed 40-hex SHA, an adopter who
        copied the file and forgot to edit it would get a check that
        passed layer 1 and only complained once it reached the network,
        which on a machine without ``gh`` is a SKIP. It has to redden
        immediately instead.
        """
        text = ADOPTER_RECORD_TEMPLATE.read_text(encoding="utf-8")
        revisions = [
            line.split()[1]
            for line in text.splitlines()
            if line.startswith("revision ")
        ]
        self.assertEqual(len(revisions), 1)
        self.assertNotRegex(revisions[0], r"^[0-9a-f]{40}$")

    def test_templates_have_no_carriage_returns(self):
        """CRLF has bitten this fleet repeatedly.

        A CRLF template is not a cosmetic problem. The adopter check
        matches its markers by whole-line equality, and on a Linux runner
        a trailing ``\\r`` makes those matches fail, so the check would
        report a malformed boundary on a file that is byte-for-byte the
        canonical one.
        """
        paths = list(TEMPLATES.rglob("*"))
        self.assertTrue(paths, "fleet/templates/ is empty")
        for path in paths:
            if path.is_file():
                with self.subTest(path=path.name):
                    self.assertNotIn(b"\r", path.read_bytes())

    def test_a_crlf_copy_digests_identically(self):
        """A CRLF checkout must produce the SAME digest, not a different one.

        This assertion is made in Python on purpose. The equivalent shell
        experiment is worthless on this host: MSYS gawk strips ``\\r`` on
        its own and MSYS grep is CR-tolerant, so a CRLF fixture digests
        identically here whether or not anything strips it deliberately.
        Python has neither leniency, so if the stripping in
        ``read_lines`` were removed this case would redden, which is
        what a Linux runner would do.
        """
        for rel in SHARED_FILES:
            with self.subTest(rel=rel):
                path = TEMPLATES / rel
                with tempfile.TemporaryDirectory() as tmp:
                    crlf = Path(tmp) / "copy.sh"
                    crlf.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
                    self.assertIn(b"\r\n", crlf.read_bytes())
                    self.assertEqual(shared_digest(crlf), shared_digest(path))

    def test_the_digest_tool_agrees_with_the_record(self):
        """The awk implementation and the Python one must produce one answer."""
        proc = subprocess.run(
            [BASH, bash_path(DIGEST_TOOL)],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        emitted = {}
        for line in proc.stdout.splitlines():
            match = re.match(r"^([0-9a-f]{64})\s+(\S+)$", line.strip())
            if match:
                emitted[match.group(2)] = match.group(1)
        self.assertEqual(emitted, recorded_digests(RECORD))


class TemplateConfigGrammarTests(unittest.TestCase):
    """The templates' own config blocks obey the rule adopters are held to."""

    def test_config_declares_exactly_the_allowlisted_names(self):
        for rel, names in SHARED_FILES.items():
            with self.subTest(rel=rel):
                region = config_region(read_lines(TEMPLATES / rel))
                assigned = [
                    line.split("=", 1)[0]
                    for line in region
                    if re.match(r"^[A-Z_]+=", line)
                ]
                self.assertEqual(sorted(assigned), sorted(names))
                self.assertEqual(
                    len(assigned), len(set(assigned)), "a name is assigned twice"
                )

    def test_config_holds_nothing_but_comments_and_assignments(self):
        allowed = re.compile(r"^\s*(#|$)")
        for rel, names in SHARED_FILES.items():
            with self.subTest(rel=rel):
                for line in config_region(read_lines(TEMPLATES / rel)):
                    if allowed.match(line):
                        continue
                    self.assertRegex(line, r"^(" + "|".join(names) + r")=")


class AdopterCheckTests(unittest.TestCase):
    """The real adopter-side script, run against the shipped templates.

    This is the end-to-end statement: a repository that copies the
    templates and the record verbatim gets a green check. Everything
    above is a re-implementation, and a re-implementation that agrees
    with itself proves nothing about the file adopters will actually run.
    """

    def build_tree(self, root: Path, revision: str = "a" * 40):
        (root / "tests").mkdir(parents=True)
        (root / ".github").mkdir(parents=True)
        for rel in SHARED_FILES:
            shutil.copyfile(TEMPLATES / rel, root / rel)
        shutil.copyfile(SHARED_CHECK, root / "tests" / "test_shared_regions.sh")
        record = ADOPTER_RECORD_TEMPLATE.read_text(encoding="utf-8")
        record = re.sub(
            r"^revision .*$", f"revision {revision}", record, flags=re.MULTILINE
        )
        (root / ".github" / "shared-regions.sha256").write_text(
            record, encoding="utf-8", newline="\n"
        )

    def run_check(self, root: Path):
        env = dict(os.environ)
        # Layer 2 needs the network and is allowed to skip; this test is
        # about layer 1 and about the templates parsing. Layer 1 has no
        # skip branch, so nothing under test is being suppressed.
        env["SHARED_REGIONS_SKIP_FETCH"] = "1"
        proc = subprocess.run(
            [BASH, bash_path(root / "tests" / "test_shared_regions.sh")],
            capture_output=True,
            text=True,
            env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def test_a_verbatim_adoption_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            code, out = self.run_check(root)
            self.assertEqual(code, 0, out)
            self.assertIn("0 failed", out)
            # A check that ran nothing also reports zero failures.
            self.assertNotIn("0 passed", out)

    def test_a_body_edit_is_caught(self):
        """The mutation the whole design exists for, at the canonical end."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            target = root / "tests" / "test_release_wiring.sh"
            text = target.read_text(encoding="utf-8")
            target.write_text(
                text.replace("FLEET_FLOOR_MIN=", "FLEET_FLOOR_MIN =", 1),
                encoding="utf-8",
                newline="\n",
            )
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("DRIFTED", out)

    def test_a_statement_in_the_config_region_is_caught(self):
        """The bypass a digest alone does not see.

        The config region is un-digested by construction, so a digest
        over everything else is silent about it. One line of shell here
        makes the wiring test exit 0 while still printing every failure
        it found, which is a green CI run over a release gate that is no
        longer there, with the shared-region digest UNCHANGED.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            target = root / "tests" / "test_release_wiring.sh"
            lines = target.read_text(encoding="utf-8").split("\n")
            lines.insert(lines.index(END_MARK), "trap 'exit 0' EXIT")
            target.write_text("\n".join(lines), encoding="utf-8", newline="\n")

            # The premise: the digest genuinely does not move.
            self.assertEqual(
                shared_digest(target), recorded_digests(RECORD)["tests/test_release_wiring.sh"]
            )

            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("not a comment", out)

    def test_a_missing_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            target = root / "tests" / "test_release_wiring.sh"
            lines = [
                line
                for line in target.read_text(encoding="utf-8").split("\n")
                if line != BEGIN_MARK
            ]
            target.write_text("\n".join(lines), encoding="utf-8", newline="\n")
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("begin marker occurs 0 time(s)", out)

    def test_a_duplicated_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            target = root / "tests" / "test_release_wiring.sh"
            lines = target.read_text(encoding="utf-8").split("\n")
            lines.insert(lines.index(BEGIN_MARK) + 3, BEGIN_MARK)
            target.write_text("\n".join(lines), encoding="utf-8", newline="\n")
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("begin marker occurs 2 time(s)", out)

    def test_an_unedited_revision_placeholder_fails_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            shutil.copyfile(
                ADOPTER_RECORD_TEMPLATE, root / ".github" / "shared-regions.sha256"
            )
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("no usable canonical revision", out)

    def test_a_config_only_edit_does_not_trigger(self):
        """The false-positive case, which is as much a defect as a miss.

        The config region is what every adopter edits, on purpose, on
        adoption. A drift check that reddens there is one that gets
        switched off, and then none of the rest of it runs either.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.build_tree(root)
            target = root / "tests" / "test_release_wiring.sh"
            text = target.read_text(encoding="utf-8")
            text = text.replace(
                "ENTRY_POINTS=(main.capa example.capa)",
                "ENTRY_POINTS=(a.capa b.capa c.capa)",
            )
            text = text.replace("NEEDS_NEST_VENDOR=no", "NEEDS_NEST_VENDOR=yes")
            target.write_text(text, encoding="utf-8", newline="\n")
            code, out = self.run_check(root)
            self.assertEqual(code, 0, out)


class TemplateTableTests(unittest.TestCase):
    """This file's table and the shell script's must not become two facts."""

    def test_the_shell_check_lists_the_same_files_and_names(self):
        text = SHARED_CHECK.read_text(encoding="utf-8")
        block = re.search(r"SHARED_FILES=\((.*?)\n\)", text, re.DOTALL)
        self.assertIsNotNone(block, "SHARED_FILES not found in the adopter check")
        found = {}
        for line in block.group(1).splitlines():
            entry = line.strip().strip('"')
            if not entry:
                continue
            rel, _, names = entry.partition(":")
            found[rel] = names.split()
        self.assertEqual(found, SHARED_FILES)


if __name__ == "__main__":
    unittest.main()
