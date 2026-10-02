"""Fail-closed guard: no tracked file may carry a personal path.

What is checked, where, and over which files is stated in the docstring
of ``tests/_personal_paths.py``, which holds the matcher and the scan.
This module holds the tests: planted controls for every encoding and
entry kind, the rules that select which account is looked for (with
made-up names only), and the scan of this repository's tracked files.
"""

from __future__ import annotations

import getpass
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Iterable
from unittest import mock

from tests._personal_paths import (
    ACCOUNT,
    GENERIC_ACCOUNTS,
    LAYOUT,
    MIN_ACCOUNT_LENGTH,
    NON_PERSONAL_LAYOUT_LINES,
    NON_PERSONAL_NAMES,
    USER_DIR,
    checked_accounts,
    excuse_for,
    find_personal_paths,
    machine_account_names,
    published_author_words,
    render,
    running_accounts,
    scan_tracked,
    stale_entries,
    tracked_files,
)

#: A made-up account for the matcher tests. No test uses a real one.
SAMPLE_ACCOUNT = "quillon"


def _kinds(text: str, accounts: "Iterable[str]" = ()) -> "set[str]":
    return {f.kind for f in find_personal_paths(text.encode("utf-8"), accounts)}


class MatcherTests(unittest.TestCase):
    """Planted controls: a zero from the tracked-file scan means
    nothing unless the matcher is shown to see every encoding."""

    U = "Us" + "ers"
    D = "Desk" + "top"
    A = "App" + "Data"
    BS = "\\"

    def test_every_encoding_of_a_user_directory_is_found(self):
        u, bs, who = self.U, self.BS, "alice"
        for label, text in {
            "single backslash": f"C:{bs}{u}{bs}{who}{bs}f.txt",
            "JSON-doubled": f"C:{bs * 2}{u}{bs * 2}{who}{bs * 2}f.py",
            "quadrupled": f"C:{bs * 4}{u}{bs * 4}{who}{bs * 4}f",
            "forward slash": f"C:/{u}/{who}/f",
            "lower case": f"c:/{u.lower()}/{who}/f",
            "lower case, JSON-doubled": (
                f"c:{bs * 2}{u.lower()}{bs * 2}{who}{bs * 2}f"
            ),
            "JSON escaped slash": f"C:{bs}/{u}{bs}/{who}{bs}/f",
            "MSYS": f"/c/{u}/{who}/f",
            "macOS": f"/{u}/{who}/f",
            "percent-encoded backslash": f"file:///C:%5C{u}%5C{who}%5Cf",
            "percent-encoded backslash, lower case": f"C:%5c{u}%5c{who}%5cf",
            "percent-encoded slash": f"C:%2F{u}%2F{who}%2Ff",
            "percent-encoded slash, lower case": f"C:%2f{u}%2f{who}%2ff",
            "no trailing separator": f"'C:{bs * 2}{u}{bs * 2}{who}'",
            "linux home": f"see /home/{who}/work",
            "linux home at end of text": f"a\nb\n/home/{who}",
        }.items():
            with self.subTest(label):
                found = find_personal_paths(text.encode("utf-8"))
                self.assertEqual(
                    [(f.kind, f.name) for f in found], [(USER_DIR, who)]
                )

    def test_a_user_directory_in_utf16_text_is_found(self):
        text = f"C:{self.BS}{self.U}{self.BS}alice{self.BS}f"
        for codec in ("utf-16-le", "utf-16-be"):
            with self.subTest(codec):
                found = find_personal_paths(text.encode(codec))
                self.assertEqual(
                    [(f.kind, f.name) for f in found], [(USER_DIR, "alice")]
                )

    def test_the_line_number_is_reported(self):
        who = "alice"
        found = find_personal_paths(f"one\ntwo\n/home/{who}/x\nfour\n".encode())
        self.assertEqual([f.line for f in found], [3])

    def test_the_home_layout_is_found_as_a_path_component(self):
        d, a, bs = self.D, self.A, self.BS
        for label, text in {
            "tilde, forward": f"in `~/{d}/repos/`",
            "tilde, backslash": f"in ~{bs}{d}{bs}repos",
            "trailing backslash": f"cd {d}{bs}repos",
            "trailing slash": f"cd {d}/repos",
            "application data, backslash": f"{a}{bs}Local{bs}Temp",
            "application data, slash": f"x/{a}/Local",
            "composed from the home directory": f'Path.home() / "{d}" / "repos"',
            "joined": f"os.path.join(home, '{d}')",
        }.items():
            with self.subTest(label):
                self.assertEqual(_kinds(text), {LAYOUT})

    def test_a_running_account_is_found_as_a_token(self):
        who = SAMPLE_ACCOUNT
        for label, text in {
            "bare": f"built by {who}@host",
            "end of sentence": f"the user {who}.",
            "upper case": f"USER={who.upper()}",
            "end of text": f"owner: {who}",
            "after a word character": f"file:///c%3a%5cusers%5c{who}%5cf",
            "host name": f"{who}-laptop.local",
            # Separators flattened to dashes, the way some tools name a
            # per-project directory: no path rule sees it.
            "dash-flattened path": f"c--{self.U}-{who}-{self.D}-project",
        }.items():
            with self.subTest(label):
                self.assertEqual(_kinds(text, [who]), {ACCOUNT})

    def test_an_account_followed_by_a_letter_is_not_a_token(self):
        self.assertEqual(_kinds(f"{SAMPLE_ACCOUNT}duarte", [SAMPLE_ACCOUNT]), set())

    def test_with_no_account_only_the_path_kinds_are_checked(self):
        self.assertEqual(_kinds(f"built by {SAMPLE_ACCOUNT}@host"), set())

    def test_an_account_in_a_path_is_two_findings(self):
        text = f"C:{self.BS}{self.U}{self.BS}{SAMPLE_ACCOUNT}{self.BS}f.txt"
        self.assertEqual(_kinds(text, [SAMPLE_ACCOUNT]), {USER_DIR, ACCOUNT})

    def test_legitimate_forms_are_accepted(self):
        d = self.D
        for label, text in {
            "the folder as a word in prose": f"projects on your {d}, in ~/code/",
            "the folder closing a sentence": f"written to the user's {d}.",
            "lower-case word": "ua-parsed: Chrome on Linux (desktop)",
            "an identifier that ends with it": f"    return Device{d}\n",
            "an identifier that starts with it": f"class {self.A}Store: pass",
            "the directories with no name": f"the /home/ tree and C:{self.BS}{self.U}",
            "a home path with a template": "/home/<name>/work",
            "relative project paths": "src/capa/loader.py and docs/users.md",
            "a users segment in a URL": "https://api.example.org/users/octocat/repos",
            "a users directory in a relative path": "docs/users/guide.md",
            "a home segment in a URL": "https://example.org/home/index.html",
            "a home directory in a relative path": "site/home/page.md",
            "empty": "",
        }.items():
            with self.subTest(label):
                found = find_personal_paths(text.encode("utf-8"), [SAMPLE_ACCOUNT])
                self.assertEqual(found, [])

    def test_a_justified_name_is_excused_and_an_unknown_one_is_not(self):
        bs, u = self.BS, self.U
        runner = find_personal_paths(f"C:{bs}{u}{bs}runneradmin{bs}x".encode())
        other = find_personal_paths(f"C:{bs}{u}{bs}alice{bs}x".encode())
        self.assertEqual(excuse_for("any/file.py", runner[0]), "runneradmin")
        self.assertIsNone(excuse_for("any/file.py", other[0]))

    def test_a_layout_excuse_is_bound_to_its_file_and_its_line(self):
        [(path, marker)] = [
            k for k in NON_PERSONAL_LAYOUT_LINES if k[0].startswith("docs/")
        ]
        [hit] = find_personal_paths(f"to `~/{self.D}/{marker}.txt`".encode())
        [plain] = find_personal_paths(f"to `~/{self.D}/repos`".encode())
        self.assertEqual(excuse_for(path, hit), (path, marker))
        self.assertIsNone(excuse_for("docs/other.md", hit))
        self.assertIsNone(excuse_for(path, plain))

    def test_a_failure_message_does_not_repeat_the_text(self):
        who = SAMPLE_ACCOUNT
        findings = find_personal_paths(
            f"x\nC:{self.BS}{self.U}{self.BS}{who}{self.BS}f".encode(), [who]
        )
        message = render({"some/file.txt": findings})
        self.assertIn("some/file.txt", message)
        self.assertIn("line 2", message)
        # A fixed message: on failure, assertNotIn would print the text.
        self.assertFalse(who in message, "the rendered message repeats the text")
        self.assertFalse(self.U in message, "the rendered message repeats the text")

    def test_the_staleness_check_reports_an_unused_entry(self):
        everything = set(NON_PERSONAL_NAMES) | set(NON_PERSONAL_LAYOUT_LINES)
        self.assertEqual(stale_entries(everything), set())
        self.assertEqual(stale_entries(everything - {"victim"}), {"victim"})


class AccountTests(unittest.TestCase):
    """Which accounts the running-account kind checks, with made-up
    names only."""

    def test_a_personal_account_is_checked(self):
        self.assertEqual(
            checked_accounts({SAMPLE_ACCOUNT}, set()),
            {SAMPLE_ACCOUNT.encode()},
        )

    def test_ci_and_container_accounts_are_not_checked(self):
        # The accounts GitHub's runners and common images run as, in the
        # letter case they use, and the whole declared list.
        for name in ("runner", "runneradmin", "root", "vscode", "node",
                     "Administrator", "codespace", "ec2-user",
                     *GENERIC_ACCOUNTS):
            with self.subTest(name):
                self.assertEqual(checked_accounts({name}, set()), frozenset())

    def test_a_short_name_is_not_checked_and_the_bound_is_exact(self):
        short = "q" * (MIN_ACCOUNT_LENGTH - 1)
        enough = "q" * MIN_ACCOUNT_LENGTH
        self.assertEqual(MIN_ACCOUNT_LENGTH, 4)
        self.assertEqual(checked_accounts({short}, set()), frozenset())
        self.assertEqual(checked_accounts({enough}, set()), {enough.encode()})

    def test_a_published_author_word_is_not_checked(self):
        self.assertEqual(
            checked_accounts({"Quillon"}, {"quillon", "smith"}), frozenset()
        )

    def test_the_author_words_are_read_from_the_authors_table(self):
        with tempfile.TemporaryDirectory() as td:
            pyproject = Path(td) / "pyproject.toml"
            pyproject.write_text(
                '[project]\nname = "pkg"\nauthors = [\n'
                '    { name = "Ada Quillon", email = "a@example.invalid" },\n'
                ']\ndescription = "x"\n',
                encoding="utf-8",
            )
            self.assertEqual(published_author_words(pyproject), {"ada", "quillon"})
            self.assertEqual(published_author_words(Path(td) / "none.toml"), set())

    def test_the_project_publishes_author_words(self):
        self.assertTrue(published_author_words())

    def test_both_names_are_read_from_the_machine(self):
        with mock.patch.object(getpass, "getuser", return_value="quillona"), \
                mock.patch.object(Path, "home", return_value=Path("/x/quillonb")):
            self.assertEqual(machine_account_names(), {"quillona", "quillonb"})

    def test_an_unknown_login_name_leaves_the_home_name(self):
        with mock.patch.object(getpass, "getuser", side_effect=OSError("none")), \
                mock.patch.object(Path, "home", return_value=Path("/x/quillonb")):
            self.assertEqual(machine_account_names(), {"quillonb"})

    def test_on_a_ci_runner_nothing_is_looked_for(self):
        # The homes are built from parts so this file carries no path.
        u, h = "Us" + "ers", "ho" + "me"
        for login, home in (("runneradmin", f"C:/{u}/runneradmin"),
                            ("runner", f"/{h}/runner"), ("root", "/root")):
            with self.subTest(login), \
                    mock.patch.object(getpass, "getuser", return_value=login), \
                    mock.patch.object(Path, "home", return_value=Path(home)):
                self.assertEqual(running_accounts(), frozenset())


class PlantedTreeTests(unittest.TestCase):
    """The scan over a planted repository: every entry kind, encoding,
    size and offset the docstring promises."""

    U, BS = "Us" + "ers", "\\"

    def test_every_planted_entry_is_scanned(self):
        path = f"C:{self.BS}{self.U}{self.BS}alice{self.BS}f".encode()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            g = ["git", "-C", str(root), "-c", "core.autocrlf=false"]
            subprocess.run(["git", "init", "-q", str(root)], check=True,
                           stdin=subprocess.DEVNULL, capture_output=True)
            planted = {
                "a.csv": b"x," + path + b"\n",
                "b.txt": ("x " + path.decode()).encode("utf-16"),
                "c.bin": b"\x00" * 10 + b"y" * 1_100_000 + path,
                "d.md": b"pad\n" * 20_000 + path + b"\n",
                "no_extension": b"\xff\xfe latin-1 bytes " + path,
                "sub dir/e.json": b'{"p": "' + path.replace(b"\\", b"\\\\") + b'"}',
                "h.txt": f"built by {SAMPLE_ACCOUNT}@host\n".encode(),
            }
            for name, data in planted.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
            (root / "excused.md").write_bytes(b"/ho" + b"me/user/x\n")
            (root / "clean.md").write_bytes(b"nothing here\n")
            subprocess.run([*g, "add", "-A"], check=True,
                           stdin=subprocess.DEVNULL, capture_output=True)
            # A symbolic link and a gitlink, entered in the index the same
            # way on every platform; neither exists in the working tree.
            target = subprocess.run(
                [*g, "hash-object", "-w", "--stdin"], check=True,
                input=b"/ho" + b"me/alice/secret.txt", capture_output=True,
            ).stdout.decode().strip()
            for spec in (f"120000,{target},link",
                         "160000," + "1" * 40 + ",module"):
                subprocess.run([*g, "update-index", "--add", "--cacheinfo", spec],
                               check=True, stdin=subprocess.DEVNULL,
                               capture_output=True)
            result = scan_tracked(root, accounts={SAMPLE_ACCOUNT.encode()})
        self.assertEqual(sorted(result.violations), sorted([*planted, "link"]))
        self.assertEqual(
            {f.kind for f in result.violations["h.txt"]}, {ACCOUNT}
        )
        self.assertEqual(result.used, {"user": {"excused.md"}})
        self.assertEqual(result.gitlinks, ["module"])

    def test_outside_a_checkout_there_is_nothing_to_scan(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertIsNone(tracked_files(Path(td)))

    def test_a_checkout_that_cannot_be_listed_fails_instead_of_skipping(self):
        with tempfile.TemporaryDirectory() as td:
            # A ``.git`` that git itself rejects: a checkout by the
            # test's own criterion, with no tracked-file list.
            (Path(td) / ".git").write_text("gitdir: nowhere\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                tracked_files(Path(td))


class TrackedFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if tracked_files() is None:
            raise unittest.SkipTest(
                "not a git checkout (an unpacked source distribution "
                "has no tracked-file list to scan)"
            )
        cls.result = scan_tracked()

    def test_the_checkout_lists_tracked_files(self):
        files = tracked_files()
        self.assertIn("pyproject.toml", files)
        self.assertIn("tests/test_no_personal_paths.py", files)

    def test_no_tracked_file_carries_a_personal_path(self):
        # ``fail`` rather than ``assertEqual``: a dict diff would print
        # the offending text, which is the thing not to repeat.
        if self.result.violations:
            self.fail(
                "personal paths in tracked files (file: kind: lines; the "
                "text is deliberately not repeated here). Replace them "
                "with a neutral form, or justify a non-personal match in "
                "the allow-lists of this module:\n"
                + render(self.result.violations)
            )

    def test_no_tracked_gitlink(self):
        self.assertEqual(
            self.result.gitlinks, [],
            "a tracked gitlink's content is in another repository this "
            "guard cannot scan",
        )

    def test_the_allow_list_has_no_stale_entry(self):
        self.assertEqual(
            stale_entries(self.result.used), set(),
            "allow-list entries that excuse nothing any more; remove them",
        )

    def test_every_excuse_names_every_file_it_excuses(self):
        missing = {
            str(key): sorted(
                f for f in files
                if f not in (NON_PERSONAL_NAMES.get(key) or "")
                and not (isinstance(key, tuple) and key[0] == f)
            )
            for key, files in self.result.used.items()
        }
        missing = {k: v for k, v in missing.items() if v}
        self.assertEqual(
            missing, {},
            "allow-list justifications that do not name a file they excuse",
        )


if __name__ == "__main__":
    unittest.main()
