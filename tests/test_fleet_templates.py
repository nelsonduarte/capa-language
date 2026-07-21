"""Regression tests for the shared test files in ``fleet/``.

WHAT THESE COVER. Everything under ``fleet/templates/tests/`` is ~1600
lines of security-checking logic that is COPIED, in full, into every
repository that adopts the shared release guards. Fifteen more copies
are planned. Nothing noticed when a copy diverged, and this fleet has
been bitten by exactly that twice: a capability tuple hand-copied at 21
sites in this repository that had already drifted before anyone looked,
and capa_authgate's ``check_tag_version.sh`` becoming a second copy
whose two versions immediately printed different messages.

The adopter-side check is ``fleet/templates/tests/test_shared_regions.sh``.
It digests each shared file and compares that to a number recorded in
the adopting repository. What THIS file proves, on the canonical side,
is that the shipped files digest cleanly and that the numbers recorded
in ``fleet/shared-regions.sha256`` are those files' own. Without it, the
fleet's recorded digests could describe bytes that were never here.

TWO KINDS OF ENTRY, and the second one is what makes the check cover
itself. ``tests/test_release_wiring.sh`` and
``tests/test_wiring_mutations.sh`` carry a CONFIG block, so only what
lies outside it is digested and the block itself is held to a grammar.
``tests/test_shared_regions.sh`` and ``tests/test_guard_pins.sh`` carry
no repo-specific configuration at all, so the whole file is digested.
Before that was true, deleting one row from the drift check's own table
removed a file from the check while every remaining assertion still
passed; ``TableShrinkAttackTests`` below is that attack, run end to end.

TWO INDEPENDENT EXTRACTIONS, on purpose. ``SharedRegionDigestTests``
re-implements the boundary rule in Python and compares against the
record; ``AdopterCheckTests`` runs the REAL shell script against a
synthetic adopter tree built from the templates. Agreement between an
awk implementation and a Python one is a much stronger statement about
the boundary than either alone, and disagreement is the thing that would
otherwise be discovered fifteen repositories later. ``RecordParserTests``
holds the two record parsers to that same standard, which they failed
until now.

Run them the way CI does::

    python -m unittest discover tests
"""

import hashlib
import os
import re
import shutil
import stat
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
GUARD_PINS_CHECK = TEMPLATES / "tests" / "test_guard_pins.sh"
GUARD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release-guards.yml"

BASH = shutil.which("bash")

BEGIN_MARK = "# ================== CONFIG: the only repo-specific part =================="
END_MARK = "# ======================= END CONFIG; shared body ========================="

CANON_PREFIX = "fleet/templates/"

# The files under check: the entry KIND, and the config names a region
# entry's config block may declare. This table is the same one the
# adopter-side check and ``fleet/shared_region_digest.sh`` carry, and
# ``TemplateTableTests`` below asserts all three agree rather than
# leaving copies of a constant to drift on their own.
SHARED_FILES = {
    "tests/test_release_wiring.sh": (
        "region",
        [
            "ENTRY_POINTS",
            "CEILING_ENTRIES",
            "NEGATIVE_CEILING_ENTRIES",
            "COMPILER_REJECTS",
            "UNCHECKED_MODULES",
            "NEEDS_NEST_VENDOR",
        ],
    ),
    "tests/test_wiring_mutations.sh": (
        "region",
        ["PRIMARY_MODULE", "SECOND_MODULE", "CEILING_LINE_WIDE", "CEILING_NAME"],
    ),
    "tests/test_shared_regions.sh": ("whole", []),
    "tests/test_guard_pins.sh": ("whole", []),
}

REGION_FILES = {
    rel: names for rel, (kind, names) in SHARED_FILES.items() if kind == "region"
}

# The record-line shape, written to be character-for-character the rule
# the shell parsers apply: a 64-character lowercase hex digest, one or
# more spaces or tabs, a path, and nothing else on the line. The two
# used to disagree about leading indentation, trailing whitespace and
# trailing junk. See ``RecordParserTests``.
RECORD_LINE = re.compile(r"^([0-9a-f]{64})[ \t]+([^ \t]+)$")


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


def shared_digest(path: Path, kind: str = "region") -> str:
    """The digest the adopter check computes for a file of this kind.

    A whole-file entry digests every line; a region entry digests
    everything outside the markers. Both go through :func:`read_lines`,
    so both are CRLF-insensitive, exactly as the awk side is.
    """
    lines = read_lines(path)
    if kind == "region":
        lines = extract_shared_region(lines)
    elif kind != "whole":
        raise ValueError(f"unknown entry kind {kind!r}")
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def config_region(lines):
    """The lines strictly between the markers, exclusive of both."""
    begin = lines.index(BEGIN_MARK)
    end = lines.index(END_MARK)
    return lines[begin + 1 : end]


def recorded_digests(path: Path):
    """Parse ``<sha256>  <path>`` lines out of a record file."""
    out = {}
    for line in read_lines(path):
        match = RECORD_LINE.match(line)
        if match:
            out[match.group(2)] = match.group(1)
    return out


def derived_guard_files(workflow_text: str):
    """The files a release-guards workflow INVOKES, read out of its text.

    The same derivation ``tests/test_guard_pins.sh`` performs online
    against the pinned workflow. Comment lines are dropped first, which
    is what keeps ``python tools/nest_vendor.py`` (documentation inside
    the workflow's own header, not an invocation) out of the result.

    It is a heuristic over YAML and is used ONLY to add requirements to
    a hardcoded floor, never to replace one. See the note in
    ``test_guard_pins.sh`` for why an under-approximation would be the
    one unacceptable outcome.
    """
    found = set()
    for line in workflow_text.split("\n"):
        if re.match(r"^\s*#", line):
            continue
        for match in re.finditer(r"bash [^ ]*/tools/([A-Za-z0-9_.-]+\.(?:sh|py))", line):
            found.add("tools/" + match.group(1))
    return found


def write_gh_stub(directory: Path, upstream: Path) -> Path:
    """A ``gh`` that answers from a local tree, so layer 2 can be tested.

    Layer 2 and the derived-completeness layer are the parts that make
    the recorded numbers honest, and both SKIP without ``gh``. A test
    suite that lets them skip is testing layer 1 twice. This stub speaks
    the two calls those layers make, ``gh auth status`` and
    ``gh api repos/<owner>/<repo>/contents/<path>?ref=<rev> --jq
    .content``, and serves the content out of ``upstream``.
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


class SharedRegionDigestTests(unittest.TestCase):
    """The recorded numbers are the shipped files' own."""

    def test_every_shared_file_has_a_template(self):
        for rel in SHARED_FILES:
            self.assertTrue(
                (TEMPLATES / rel).is_file(),
                f"fleet/templates/{rel} is missing; adopters copy it from here",
            )

    def test_region_templates_extract_cleanly(self):
        for rel in REGION_FILES:
            with self.subTest(rel=rel):
                # Raises on a malformed boundary, which is the assertion.
                region = extract_shared_region(read_lines(TEMPLATES / rel))
                self.assertIn(BEGIN_MARK, region)
                self.assertIn(END_MARK, region)

    def test_whole_file_templates_carry_no_config_markers(self):
        """A whole-file entry with markers would be a contradiction.

        The markers announce an un-digested region. A whole-file entry
        has none, so a marker in one would tell a reader that part of it
        is exempt when nothing is, and would leave the next person to
        wonder which statement is true.
        """
        for rel, (kind, _) in SHARED_FILES.items():
            if kind != "whole":
                continue
            with self.subTest(rel=rel):
                lines = read_lines(TEMPLATES / rel)
                self.assertNotIn(BEGIN_MARK, lines)
                self.assertNotIn(END_MARK, lines)

    def test_recorded_digests_match_the_templates(self):
        recorded = recorded_digests(RECORD)
        self.assertEqual(
            set(recorded),
            set(SHARED_FILES),
            "fleet/shared-regions.sha256 and the file table describe different sets",
        )
        for rel, (kind, _) in SHARED_FILES.items():
            with self.subTest(rel=rel):
                self.assertEqual(
                    shared_digest(TEMPLATES / rel, kind),
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

    def test_templates_end_with_exactly_one_newline(self):
        """Both digest implementations assume it, so it is asserted.

        awk emits a trailing newline after the last record whether or not
        the input had one; the Python side reproduces that by joining the
        list ``read_lines`` produces, whose final element is the empty
        string for a newline-terminated file. For a file NOT ending in a
        newline the two would differ by one byte, which would surface as
        drift in a file nobody had touched.
        """
        for path in TEMPLATES.rglob("*"):
            if path.is_file():
                with self.subTest(path=path.name):
                    data = path.read_bytes()
                    self.assertTrue(data.endswith(b"\n"), "no trailing newline")
                    self.assertFalse(data.endswith(b"\n\n"), "blank line at EOF")

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
        for rel, (kind, _) in SHARED_FILES.items():
            with self.subTest(rel=rel):
                path = TEMPLATES / rel
                with tempfile.TemporaryDirectory() as tmp:
                    crlf = Path(tmp) / "copy.sh"
                    crlf.write_bytes(path.read_bytes().replace(b"\n", b"\r\n"))
                    self.assertIn(b"\r\n", crlf.read_bytes())
                    self.assertEqual(
                        shared_digest(crlf, kind), shared_digest(path, kind)
                    )

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
            match = RECORD_LINE.match(line.strip())
            if match:
                emitted[match.group(2)] = match.group(1)
        self.assertEqual(emitted, recorded_digests(RECORD))


class RecordParserTests(unittest.TestCase):
    """The shell record parser and the Python one must agree, including on junk.

    The stated value of maintaining two implementations is that they
    agree; two that disagree about what a record line IS are two answers
    to the question the record exists to settle. They diverged on three
    shapes at once: trailing junk after the path, leading indentation and
    trailing whitespace were accepted by awk and refused by Python. No
    test fed either of them a malformed record, which is why it survived.
    """

    #: ``(description, line, is_well_formed)``. A well-formed line must
    #: be found by BOTH parsers; a malformed one by NEITHER.
    CASES = [
        ("the canonical two-space form", "{d}  tests/x.sh", True),
        ("a single space", "{d} tests/x.sh", True),
        ("a tab", "{d}\ttests/x.sh", True),
        ("trailing junk after the path", "{d}  tests/x.sh extra", False),
        ("leading indentation", "  {d}  tests/x.sh", False),
        ("trailing whitespace", "{d}  tests/x.sh ", False),
        ("a 63-character digest", "{d63}  tests/x.sh", False),
        ("a 65-character digest", "{d65}  tests/x.sh", False),
        ("an uppercase digest", "{dU}  tests/x.sh", False),
        ("a comment naming the path", "# {d}  tests/x.sh", False),
        ("the path with no digest", "tests/x.sh", False),
        ("a digest with no path", "{d}", False),
    ]

    def render(self, template: str) -> str:
        digest = "a" * 64
        return template.format(
            d=digest,
            d63="a" * 63,
            d65="a" * 65,
            dU="A" * 64,
        )

    def shell_lookup(self, line: str) -> str:
        """Run the shell record parser, lifted verbatim out of the check."""
        source = SHARED_CHECK.read_text(encoding="utf-8")
        body = re.search(
            r"recorded_digest\(\) \{\n(.*?)\n\}\n", source, re.DOTALL
        )
        self.assertIsNotNone(body, "recorded_digest not found in the adopter check")
        with tempfile.TemporaryDirectory() as tmp:
            record = Path(tmp) / "record"
            record.write_text(line + "\n", encoding="utf-8", newline="\n")
            script = Path(tmp) / "run.sh"
            script.write_text(
                "set -uo pipefail\n"
                f'RECORD="{bash_path(record)}"\n'
                "recorded_digest() {\n"
                + body.group(1)
                + "\n}\n"
                'recorded_digest "tests/x.sh"\n',
                encoding="utf-8",
                newline="\n",
            )
            proc = subprocess.run(
                [BASH, bash_path(script)], capture_output=True, text=True
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            return proc.stdout.strip()

    def python_lookup(self, line: str) -> str:
        match = RECORD_LINE.match(line)
        if match and match.group(2) == "tests/x.sh":
            return match.group(1)
        return ""

    def test_both_parsers_agree_on_every_shape(self):
        for desc, template, well_formed in self.CASES:
            line = self.render(template)
            with self.subTest(case=desc):
                shell = self.shell_lookup(line)
                python = self.python_lookup(line)
                self.assertEqual(
                    shell,
                    python,
                    f"awk and Python disagree about {desc!r}: "
                    f"awk gave {shell!r}, Python gave {python!r}",
                )
                if well_formed:
                    self.assertEqual(shell, "a" * 64)
                else:
                    self.assertEqual(shell, "")

    def test_a_crlf_record_line_is_read_normally(self):
        """W1: a CRLF record must not be reported as a missing entry.

        Both parsers strip a trailing ``\\r``. Without that the check
        fails closed, which is correct, but blames "the audit record has
        no digest for it" for what is a line-ending problem, and sends
        the reader hunting for an entry that is present.
        """
        line = "a" * 64 + "  tests/x.sh\r"
        self.assertEqual(self.shell_lookup(line), "a" * 64)
        self.assertEqual(self.python_lookup(line.rstrip("\r")), "a" * 64)


class TemplateConfigGrammarTests(unittest.TestCase):
    """The templates' own config blocks obey the rule adopters are held to."""

    def test_config_declares_exactly_the_allowlisted_names(self):
        for rel, names in REGION_FILES.items():
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
        for rel, names in REGION_FILES.items():
            with self.subTest(rel=rel):
                for line in config_region(read_lines(TEMPLATES / rel)):
                    if allowed.match(line):
                        continue
                    self.assertRegex(line, r"^(" + "|".join(names) + r")=")


class AdopterTreeMixin:
    """Build a synthetic adopter, and optionally a canonical upstream.

    Shared by the ordinary adopter cases and by the table-shrink attack,
    which needs the same tree in the same states. A mixin rather than a
    base class with tests on it, so that inheriting the helpers does not
    silently re-run every case in the parent.
    """

    REVISION = "a" * 40

    def build_tree(self, root: Path, revision: str = REVISION, unwired=()):
        (root / "tests").mkdir(parents=True)
        (root / ".github" / "workflows").mkdir(parents=True)
        for rel in SHARED_FILES:
            shutil.copyfile(TEMPLATES / rel, root / rel)
        # A workflow that actually names each file. Without one the check
        # correctly reddens: a control nothing executes reports nothing.
        steps = "".join(
            f"      - run: bash {rel}\n" for rel in SHARED_FILES if rel not in unwired
        )
        (root / ".github" / "workflows" / "checks.yml").write_text(
            "on: [push]\njobs:\n  wiring:\n    runs-on: ubuntu-latest\n    steps:\n"
            + (steps or "      - run: true\n"),
            encoding="utf-8",
            newline="\n",
        )
        record = ADOPTER_RECORD_TEMPLATE.read_text(encoding="utf-8")
        record = re.sub(
            r"^revision .*$", f"revision {revision}", record, flags=re.MULTILINE
        )
        (root / ".github" / "shared-regions.sha256").write_text(
            record, encoding="utf-8", newline="\n"
        )

    def build_upstream(self, root: Path):
        """A tree the ``gh`` stub serves as the canonical repository."""
        dest = root / CANON_PREFIX
        (dest / "tests").mkdir(parents=True, exist_ok=True)
        for rel in SHARED_FILES:
            shutil.copyfile(TEMPLATES / rel, dest / rel)
        return root

    def regenerate_record(self, root: Path, revision: str = REVISION, omit=()):
        """Recompute the adopter's record from its OWN files.

        This is what an attacker who edits a body does, and what layer 2
        exists to defeat. It is a helper rather than a mutation because
        several of the tests below need to reach the state it produces.
        """
        lines = [f"revision {revision}", ""]
        for rel, (kind, _) in SHARED_FILES.items():
            if rel in omit:
                continue
            lines.append(f"{shared_digest(root / rel, kind)}  {rel}")
        (root / ".github" / "shared-regions.sha256").write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
        )

    def run_check(self, root: Path, online: bool = False):
        env = dict(os.environ)
        if online:
            binx = root.parent / "stubbin"
            write_gh_stub(binx, self.build_upstream(root.parent / "upstream"))
            env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
            env.pop("SHARED_REGIONS_SKIP_FETCH", None)
        else:
            # Layer 2 needs the network and is allowed to skip; these
            # cases are about layer 1 and about the templates parsing.
            # Layer 1 has no skip branch, so nothing under test is being
            # suppressed.
            env["SHARED_REGIONS_SKIP_FETCH"] = "1"
        proc = subprocess.run(
            [BASH, bash_path(root / "tests" / "test_shared_regions.sh")],
            capture_output=True,
            text=True,
            env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr


class AdopterCheckTests(AdopterTreeMixin, unittest.TestCase):
    """The real adopter-side script, run against the shipped templates.

    This is the end-to-end statement: a repository that copies the
    templates and the record verbatim gets a green check. Everything
    above is a re-implementation, and a re-implementation that agrees
    with itself proves nothing about the file adopters will actually run.
    """

    def test_a_verbatim_adoption_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            code, out = self.run_check(root)
            self.assertEqual(code, 0, out)
            self.assertIn("0 failed", out)
            # A check that ran nothing also reports zero failures.
            self.assertNotIn("0 passed", out)
            self.assertIn(f"all {len(SHARED_FILES)} shared files were reached", out)

    def test_layer_two_confirms_a_verbatim_adoption(self):
        """With ``gh`` available, layer 2 must CONFIRM rather than skip.

        Every other case here runs with layer 2 forced to skip. If layer
        2 could not pass even against an upstream that is byte-identical
        to the adopter's files, the mutation cases below would be
        reddening for the wrong reason.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            code, out = self.run_check(root, online=True)
            self.assertEqual(code, 0, out)
            self.assertIn("0 skipped", out)
            for rel in SHARED_FILES:
                self.assertIn(f"{rel}: the audited digest is the canonical", out)

    def test_a_body_edit_is_caught(self):
        """The mutation the whole design exists for, at the canonical end."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
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

    def test_a_whole_file_entry_notices_any_byte(self):
        """A whole-file entry has no exempt region, so one comment is drift.

        The point of the kind is that there is nothing to argue about:
        no markers to place, no config block to widen, no line that is
        outside the digest. One added comment must be enough.
        """
        for rel, (kind, _) in SHARED_FILES.items():
            if kind != "whole":
                continue
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "repo"
                self.build_tree(root)
                target = root / rel
                target.write_text(
                    target.read_text(encoding="utf-8") + "# local note\n",
                    encoding="utf-8",
                    newline="\n",
                )
                code, out = self.run_check(root)
                self.assertNotEqual(code, 0, out)
                self.assertIn(f"{rel}: the file has DRIFTED", out)

    def test_a_statement_in_the_config_region_is_caught(self):
        """The bypass a digest alone does not see.

        The config region is un-digested by construction, so a digest
        over everything else is silent about it. One line of shell here
        makes the wiring test exit 0 while still printing every failure
        it found, which is a green CI run over a release gate that is no
        longer there, with the shared-region digest UNCHANGED.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            target = root / "tests" / "test_release_wiring.sh"
            lines = target.read_text(encoding="utf-8").split("\n")
            lines.insert(lines.index(END_MARK), "trap 'exit 0' EXIT")
            target.write_text("\n".join(lines), encoding="utf-8", newline="\n")

            # The premise: the digest genuinely does not move.
            self.assertEqual(
                shared_digest(target),
                recorded_digests(RECORD)["tests/test_release_wiring.sh"],
            )

            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("not a comment", out)

    def test_a_missing_marker_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
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
            root = Path(tmp) / "repo"
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
            root = Path(tmp) / "repo"
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
            root = Path(tmp) / "repo"
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

    def test_a_file_no_workflow_runs_is_caught(self):
        """BLOCKER C2, made structural rather than remembered.

        Both original adopters named all four of these files in YAML only
        inside comments, so all four executed zero times per push. Wiring
        them by hand fixes two repositories; this assertion fixes the
        fifteen that have not been visited yet, because an adoption that
        forgets the workflow cannot go green.
        """
        for victim in SHARED_FILES:
            with self.subTest(victim=victim), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "repo"
                self.build_tree(root, unwired=(victim,))
                code, out = self.run_check(root)
                self.assertNotEqual(code, 0, out)
                self.assertIn(f"{victim}: no workflow names it", out)

    def test_a_mention_in_a_yaml_comment_does_not_count(self):
        """The exact state both adopters were in, which looked like coverage."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root, unwired=("tests/test_guard_pins.sh",))
            workflow = root / ".github" / "workflows" / "checks.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8")
                + "      # see also: bash tests/test_guard_pins.sh\n",
                encoding="utf-8",
                newline="\n",
            )
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("tests/test_guard_pins.sh: no workflow names it", out)

    def test_a_missing_workflow_directory_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            shutil.rmtree(root / ".github" / "workflows")
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn(".github/workflows/ does not exist", out)

    def test_a_double_quoted_scalar_is_accepted(self):
        """S3: the most natural thing a new adopter writes must parse.

        ``NAME="a b"`` was refused until now, not by decision but because
        the double-quoted alternative was reachable only as an array
        item. The class inside it admits no expansion, no second
        statement and no redirection, so accepting it widens nothing.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            target = root / "tests" / "test_wiring_mutations.sh"
            text = target.read_text(encoding="utf-8")
            self.assertIn("CEILING_NAME=", text)
            text = re.sub(
                r"^CEILING_NAME=.*$",
                'CEILING_NAME="Net Fs"',
                text,
                flags=re.MULTILINE,
            )
            target.write_text(text, encoding="utf-8", newline="\n")
            code, out = self.run_check(root)
            self.assertEqual(code, 0, out)

    def test_a_second_statement_after_a_quoted_scalar_is_still_refused(self):
        """Accepting the quoted form must not have opened the door.

        The bracket class inside a quoted value has no ``$``, backtick,
        ``;``, ``&``, ``|``, ``<``, ``>`` or backslash, and the pattern
        is anchored at both ends, so a value followed by anything else
        cannot match a single alternative.
        """
        for payload in (
            'CEILING_NAME="Net"; trap \'exit 0\' EXIT',
            'CEILING_NAME="Net" "Fs"',
            'CEILING_NAME="$(echo Net)"',
            'CEILING_NAME="Net" # a comment',
        ):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "repo"
                self.build_tree(root)
                target = root / "tests" / "test_wiring_mutations.sh"
                text = re.sub(
                    r"^CEILING_NAME=.*$",
                    payload.replace("\\", "\\\\"),
                    target.read_text(encoding="utf-8"),
                    flags=re.MULTILINE,
                )
                target.write_text(text, encoding="utf-8", newline="\n")
                code, out = self.run_check(root)
                self.assertNotEqual(code, 0, out)
                self.assertIn("not a comment", out)


class TableShrinkAttackTests(AdopterTreeMixin, unittest.TestCase):
    """BLOCKER C1, end to end: delete a row from the table, then attack.

    Before ``tests/test_shared_regions.sh`` was itself a whole-file entry
    it was in no record, had no markers and counted nothing. Deleting one
    row from its ``SHARED_FILES`` table removed a file from the check
    entirely, and the wiring test could then be neutralised in the
    un-digested config region with both checks reporting success:

        drift check : exit=0   FAILs=0
        wiring test : exit=0

    Three things now stand in the way, and each is asserted separately
    below, because the first two are defeatable by an attacker who keeps
    editing and only the third is not.
    """

    def shrink_table(self, root: Path, victim: str = "tests/test_release_wiring.sh"):
        target = root / "tests" / "test_shared_regions.sh"
        lines = [
            line
            for line in target.read_text(encoding="utf-8").split("\n")
            if not (line.strip().startswith('"') and f":{victim}:" in line)
        ]
        target.write_text("\n".join(lines), encoding="utf-8", newline="\n")
        return target

    def neutralise_wiring_test(self, root: Path):
        target = root / "tests" / "test_release_wiring.sh"
        lines = target.read_text(encoding="utf-8").split("\n")
        lines.insert(lines.index(END_MARK), "trap 'exit 0' EXIT")
        target.write_text("\n".join(lines), encoding="utf-8", newline="\n")

    def test_the_row_is_actually_removed(self):
        """The premise, measured rather than assumed."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            before = (root / "tests" / "test_shared_regions.sh").read_text(
                encoding="utf-8"
            )
            self.shrink_table(root)
            after = (root / "tests" / "test_shared_regions.sh").read_text(
                encoding="utf-8"
            )
            self.assertNotEqual(before, after)
            self.assertNotIn(":tests/test_release_wiring.sh:", after)

    def test_shrinking_the_table_reddens_offline_on_the_counts(self):
        """Defence one: the counts, which work with no network at all."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            self.shrink_table(root)
            self.neutralise_wiring_test(root)
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("shared file(s) were reached, expected", out)
            self.assertIn("the audit record has", out)

    def test_shrinking_the_table_reddens_offline_on_its_own_digest(self):
        """Defence two: the check is in the record, so editing it is drift.

        Defeated by regenerating the record, which the next case does.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            self.shrink_table(root)
            code, out = self.run_check(root)
            self.assertNotEqual(code, 0, out)
            self.assertIn("tests/test_shared_regions.sh: the file has DRIFTED", out)

    def test_the_full_attack_reddens_against_upstream(self):
        """Defence three, the one that holds: layer 2.

        The attacker deletes the row, fixes the expected count so the
        counts agree, neutralises the wiring test in its un-digested
        config region, and regenerates the whole record from the edited
        files. Every offline assertion is now satisfied. Layer 2 compares
        the recorded number for the check itself against UPSTREAM's
        bytes, which the attacker does not control.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            self.build_tree(root)
            target = self.shrink_table(root)
            text = target.read_text(encoding="utf-8").replace(
                f"EXPECTED_SHARED_FILES={len(SHARED_FILES)}",
                f"EXPECTED_SHARED_FILES={len(SHARED_FILES) - 1}",
            )
            target.write_text(text, encoding="utf-8", newline="\n")
            self.neutralise_wiring_test(root)
            self.regenerate_record(root, omit=("tests/test_release_wiring.sh",))

            # The attack has genuinely satisfied layer 1 and the counts.
            code, out = self.run_check(root)
            self.assertEqual(code, 0, "the offline attack was supposed to succeed\n" + out)
            self.assertNotIn("test_release_wiring", out)

            # And is refused the moment the numbers are checked upstream.
            code, out = self.run_check(root, online=True)
            self.assertNotEqual(code, 0, out)
            self.assertIn(
                "tests/test_shared_regions.sh: the audited digest is NOT the canonical",
                out,
            )


class GuardPinsCheckTests(unittest.TestCase):
    """``tests/test_guard_pins.sh``, including the derived completeness set.

    The hardcoded ``for required in ...`` list is a fleet fact replicated
    into every copy: a sixth guard file upstream means twenty-two files
    changing in lockstep, which is the drift problem one level down
    inside the file that polices drift. The derived layer reads the
    executed set out of the pinned workflow instead. It is ADDITIVE: a
    regex over YAML could miss an invocation written some other way, and
    an under-approximation of what runs is the one outcome this must not
    ship.
    """

    REVISION = "b" * 40
    GUARD_REPO = "nelsonduarte/capa-language"
    GUARD_WORKFLOW_PATH = ".github/workflows/release-guards.yml"

    def build_upstream(self, root: Path, extra_invocation: str = ""):
        (root / ".github" / "workflows").mkdir(parents=True)
        (root / "tools").mkdir(parents=True)
        text = GUARD_WORKFLOW.read_text(encoding="utf-8")
        if extra_invocation:
            text += (
                "\n# a later revision grows a guard\n"
                "          run: |\n"
                f"            bash _release_guards/{extra_invocation}\n"
            )
        (root / self.GUARD_WORKFLOW_PATH).write_text(
            text, encoding="utf-8", newline="\n"
        )
        for name in (
            "check_tag_version.sh",
            "clean_room_build.sh",
            "capa_floor.sh",
            "verify_guard_digests.sh",
        ):
            shutil.copyfile(REPO_ROOT / "tools" / name, root / "tools" / name)
        if extra_invocation:
            (root / extra_invocation).write_text(
                "#!/usr/bin/env bash\nexit 0\n", encoding="utf-8", newline="\n"
            )
        return root

    def build_adopter(self, root: Path, upstream: Path, omit=()):
        (root / "tests").mkdir(parents=True)
        (root / ".github" / "workflows").mkdir(parents=True)
        shutil.copyfile(GUARD_PINS_CHECK, root / "tests" / "test_guard_pins.sh")
        (root / ".github" / "workflows" / "release.yml").write_text(
            "jobs:\n"
            "  guards:\n"
            f"    uses: {self.GUARD_REPO}/.github/workflows/release-guards.yml@{self.REVISION}\n"
            "    with:\n"
            "      guard-digests: |\n"
            "        placeholder\n",
            encoding="utf-8",
            newline="\n",
        )
        lines = [f"revision {self.REVISION}", ""]
        for path in sorted(
            p.relative_to(upstream).as_posix()
            for p in upstream.rglob("*")
            if p.is_file()
        ):
            if path in omit:
                continue
            digest = hashlib.sha256((upstream / path).read_bytes()).hexdigest()
            lines.append(f"{digest}  {path}")
        (root / ".github" / "guard-pins.sha256").write_text(
            "\n".join(lines) + "\n", encoding="utf-8", newline="\n"
        )

    def run_check(self, root: Path, upstream: Path):
        binx = root.parent / "stubbin"
        write_gh_stub(binx, upstream)
        env = dict(os.environ)
        env["PATH"] = str(binx) + os.pathsep + env.get("PATH", "")
        proc = subprocess.run(
            [BASH, bash_path(root / "tests" / "test_guard_pins.sh")],
            capture_output=True,
            text=True,
            env=env,
        )
        return proc.returncode, proc.stdout + proc.stderr

    def test_a_correct_audit_passes_and_derives(self):
        with tempfile.TemporaryDirectory() as tmp:
            upstream = self.build_upstream(Path(tmp) / "upstream")
            root = Path(tmp) / "repo"
            self.build_adopter(root, upstream)
            code, out = self.run_check(root, upstream)
            self.assertEqual(code, 0, out)
            self.assertIn("the audit record covers every file", out)
            self.assertIn("0 skipped", out)

    def test_the_derivation_reproduces_the_hardcoded_list(self):
        """The two completeness statements must describe the same set today.

        The reviewer's check, kept as a test: if the derivation ever
        stops reproducing the hand list, one of them is wrong and the
        divergence itself is the signal.
        """
        derived = derived_guard_files(GUARD_WORKFLOW.read_text(encoding="utf-8"))
        hardcoded = set(
            re.findall(
                r"^  (tools/[A-Za-z0-9_.-]+\.sh) ?\\?$",
                GUARD_PINS_CHECK.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
        )
        hardcoded.add("tools/verify_guard_digests.sh")
        self.assertEqual(derived, hardcoded)
        # And nest_vendor.py, which appears only inside a comment block,
        # is correctly not in it.
        self.assertNotIn("tools/nest_vendor.py", derived)

    def test_the_derived_layer_reddens_when_the_record_omits_a_file(self):
        """The hazard the derived layer exists for.

        Upstream grows a sixth guard file. Every adopter's hardcoded list
        still names five and passes. The derived set reads the sixth out
        of the pinned workflow and refuses the record that omits it.
        """
        with tempfile.TemporaryDirectory() as tmp:
            upstream = self.build_upstream(
                Path(tmp) / "upstream", extra_invocation="tools/new_guard.sh"
            )
            root = Path(tmp) / "repo"
            self.build_adopter(root, upstream, omit=("tools/new_guard.sh",))
            code, out = self.run_check(root, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("omits file(s) the pinned workflow invokes", out)
            self.assertIn("tools/new_guard.sh", out)

            # The hardcoded floor, on its own, saw nothing.
            self.assertNotIn("the audit record omits tools/new_guard.sh, which", out)

    def test_the_hardcoded_floor_still_bites(self):
        with tempfile.TemporaryDirectory() as tmp:
            upstream = self.build_upstream(Path(tmp) / "upstream")
            root = Path(tmp) / "repo"
            self.build_adopter(root, upstream, omit=("tools/capa_floor.sh",))
            code, out = self.run_check(root, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn(
                "the audit record omits tools/capa_floor.sh, which the guards execute",
                out,
            )

    def test_a_pin_that_is_not_the_audited_revision_stops_the_run(self):
        """Fail fast on preconditions: nothing after this could mean anything."""
        with tempfile.TemporaryDirectory() as tmp:
            upstream = self.build_upstream(Path(tmp) / "upstream")
            root = Path(tmp) / "repo"
            self.build_adopter(root, upstream)
            record = root / ".github" / "guard-pins.sha256"
            record.write_text(
                record.read_text(encoding="utf-8").replace(
                    f"revision {self.REVISION}", "revision " + "c" * 40
                ),
                encoding="utf-8",
                newline="\n",
            )
            code, out = self.run_check(root, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("the audited revision is not the pinned one", out)
            self.assertNotIn("matches its audited digest", out)

    def test_a_drifted_guard_file_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            upstream = self.build_upstream(Path(tmp) / "upstream")
            root = Path(tmp) / "repo"
            self.build_adopter(root, upstream)
            target = upstream / "tools" / "capa_floor.sh"
            target.write_text(
                target.read_text(encoding="utf-8") + "# tampered\n",
                encoding="utf-8",
                newline="\n",
            )
            code, out = self.run_check(root, upstream)
            self.assertNotEqual(code, 0, out)
            self.assertIn("tools/capa_floor.sh at", out)
            self.assertIn("is NOT the audited file", out)

    def test_a_crlf_pin_record_is_read_normally(self):
        """W1 again, on the other record. Same trap, same fix."""
        with tempfile.TemporaryDirectory() as tmp:
            upstream = self.build_upstream(Path(tmp) / "upstream")
            root = Path(tmp) / "repo"
            self.build_adopter(root, upstream)
            record = root / ".github" / "guard-pins.sha256"
            record.write_bytes(record.read_bytes().replace(b"\n", b"\r\n"))
            code, out = self.run_check(root, upstream)
            self.assertEqual(code, 0, out)


class TemplateTableTests(unittest.TestCase):
    """One fleet fact, stated in three files, held to one value."""

    def test_the_shell_check_lists_the_same_files_and_names(self):
        text = SHARED_CHECK.read_text(encoding="utf-8")
        block = re.search(r"SHARED_FILES=\((.*?)\n\)", text, re.DOTALL)
        self.assertIsNotNone(block, "SHARED_FILES not found in the adopter check")
        found = {}
        for line in block.group(1).splitlines():
            entry = line.strip().strip('"')
            if not entry:
                continue
            parts = entry.split(":")
            self.assertEqual(
                len(parts), 3, f"a table row must be kind:path:names, got {entry!r}"
            )
            kind, rel, names = parts
            found[rel] = (kind, names.split())
        self.assertEqual(found, SHARED_FILES)

    def test_the_shell_check_expects_the_right_number_of_files(self):
        text = SHARED_CHECK.read_text(encoding="utf-8")
        match = re.search(r"^EXPECTED_SHARED_FILES=(\d+)$", text, re.MULTILINE)
        self.assertIsNotNone(match, "EXPECTED_SHARED_FILES not found")
        self.assertEqual(int(match.group(1)), len(SHARED_FILES))

    def test_the_digest_tool_lists_the_same_files_and_kinds(self):
        text = DIGEST_TOOL.read_text(encoding="utf-8")
        block = re.search(r"TEMPLATES=\((.*?)\n\)", text, re.DOTALL)
        self.assertIsNotNone(block, "TEMPLATES not found in the digest tool")
        found = {}
        for line in block.group(1).splitlines():
            entry = line.strip().strip('"')
            if not entry:
                continue
            kind, _, rel = entry.partition(":")
            found[rel] = kind
        self.assertEqual(
            found, {rel: kind for rel, (kind, _) in SHARED_FILES.items()}
        )


if __name__ == "__main__":
    unittest.main()
