"""Every repository file a workflow step runs DIRECTLY (as a command, with
no interpreter in front) must be committed with the executable bit, or the
Linux runner fails with "Permission denied".

The set is derived from the workflow files themselves: every ``run:`` block
of every job in ``.github/workflows`` is read as shell, and every word in
COMMAND position that is a relative path (``scripts/x.sh``, ``./x.sh``,
``tools/y``, under any directory, resolved against the step's
``working-directory``) is a candidate. A candidate the git index holds is a
repository file run directly, and its index mode must be ``100755``; a
candidate the index does not hold (a build product, a virtual environment's
interpreter) is not a repository file and is not judged.

Command position, as read here: the first word of the block and the first
word after a newline, ``;``, ``&``, ``&&``, ``|``, ``||``, ``(`` or ``$(``,
skipping variable assignments, option words and the prefixes ``if``,
``then``, ``else``, ``elif``, ``do``, ``while``, ``until``, ``!``, ``{``,
``time``, ``exec``, ``env``, ``nohup``, ``sudo`` and ``command``. A
backslash-newline continues the line, comments are dropped, the body of a
here-document is not read and the target of a redirection is not a command.
Not read: backquoted commands, a command whose path is built from a
variable or an expression, a block under an explicit ``shell:`` other than
bash or sh, and the argument of a prefix that takes one (``sudo -u <user>``).

The mode is read from the git index (``git ls-files -s``), which is what a
checkout on the runner reproduces; the working tree on Windows does not
carry the bit, so a file-system check would pass here and fail there. A
tree that is not a git checkout (an archive extraction) has no index to
read, so the mode check skips there and says so; CI runs on a checkout.
"""

import posixpath
import re
import shlex
import subprocess
import unittest
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

_OPERATOR_CHARS = "();<>|&\n"
_PREFIX_WORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{",
                           "time", "exec", "env", "nohup", "sudo", "command"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_HEREDOC = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_SHELLS = ("bash", "sh")


def _strip_comments(text: str) -> str:
    """Drop every ``#`` comment: a ``#`` outside quotes at the start of a word."""
    out = []
    for line in text.split("\n"):
        quote, prev, cut = None, " ", len(line)
        for i, ch in enumerate(line):
            if quote:
                if ch == quote and not (quote == '"' and prev == "\\"):
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "#" and (prev.isspace() or prev in _OPERATOR_CHARS):
                cut = i
                break
            prev = ch
        out.append(line[:cut])
    return "\n".join(out)


def _strip_heredoc_bodies(text: str) -> str:
    """Keep each here-document's opening line, drop its body and delimiter.
    A here-document whose delimiter never comes is refused."""
    lines, out, i = text.split("\n"), [], 0
    while i < len(lines):
        out.append(lines[i])
        m = _HEREDOC.search(lines[i])
        i += 1
        if m:
            end = next((j for j in range(i, len(lines)) if lines[j].strip() == m.group(2)), None)
            if end is None:
                raise ValueError("here-document %r is never closed" % m.group(2))
            i = end + 1
    return "\n".join(out)


def command_words(script: str) -> list:
    """The words in command position of a shell block, in order."""
    text = _strip_heredoc_bodies(_strip_comments(re.sub(r"\\\r?\n", " ", script)))
    lex = shlex.shlex(text, posix=True, punctuation_chars=_OPERATOR_CHARS)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    words, at_start, redirect_target = [], True, False
    for tok in lex:
        if tok and all(c in _OPERATOR_CHARS for c in tok):
            if tok[0] in "<>":
                redirect_target = True
            else:
                at_start = True
            continue
        if redirect_target:
            redirect_target = False
            continue
        if not at_start:
            continue
        if tok in _PREFIX_WORDS or _ASSIGNMENT.match(tok) or tok.startswith("-"):
            continue
        words.append(tok)
        at_start = False
    return words


def repository_path(word: str, workdir: str = "") -> str:
    """The repository-relative path a command word names, or ``""`` when it
    is not a relative path (a bare name looked up on PATH, an absolute
    path, a home path, a variable)."""
    if "/" not in word or word.startswith(("/", "~", "-")) or "$" in word or "{" in word:
        return ""
    path = posixpath.normpath(posixpath.join(workdir, word))
    return "" if path.startswith("..") else path


def _run_setting(doc: dict, job: dict, step: dict, key: str):
    for scope in (step, (job.get("defaults") or {}).get("run") or {}, (doc.get("defaults") or {}).get("run") or {}):
        if scope.get(key):
            return str(scope[key])
    return ""


def run_blocks():
    """``(site, working directory, shell block)`` for every ``run:`` step
    of every workflow whose shell is the default, bash or sh."""
    for wf in sorted(list(WORKFLOWS.glob("*.yml")) + list(WORKFLOWS.glob("*.yaml"))):
        doc = yaml.safe_load(wf.read_text(encoding="utf-8")) or {}
        for job_name, job in (doc.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                run = step.get("run")
                if not isinstance(run, str):
                    continue
                shell = _run_setting(doc, job, step, "shell").split(" ")[0]
                if shell and shell not in _SHELLS:
                    continue
                site = "%s:%s:%s" % (wf.name, job_name, step.get("name", "?"))
                yield site, _run_setting(doc, job, step, "working-directory"), run


def directly_invoked_paths() -> dict:
    """``{repository path: [workflow:job:step, ...]}`` for every relative
    path a workflow step runs as a command."""
    found: dict = {}
    for site, workdir, run in run_blocks():
        try:
            words = command_words(run)
        except ValueError as e:
            raise ValueError("%s: %s" % (site, e)) from e
        for word in words:
            path = repository_path(word, workdir)
            if path:
                found.setdefault(path, []).append(site)
    return found


def index_mode(path: str) -> str:
    """The git index mode of exactly ``path``, or ``""`` when the index does
    not hold it."""
    out = subprocess.run(["git", "ls-files", "-s", "--", path], cwd=REPO_ROOT,
                         capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        meta, _tab, name = line.partition("\t")
        if name == path:
            return meta.split(" ")[0]
    return ""


class CommandPositionReader(unittest.TestCase):
    """The reader on its own, no checkout needed."""

    def test_paths_in_command_position_under_any_directory(self):
        self.assertEqual(command_words("./scripts/relock.sh\ntools/x.sh --flag\nscripts/a.sh \"$B\""),
                         ["./scripts/relock.sh", "tools/x.sh", "scripts/a.sh"])

    def test_after_operators_assignments_and_prefixes(self):
        script = ("set -e && ./a/one.sh; FOO=1 ./a/two.sh | ./a/three.sh\n"
                  "if ./a/four.sh; then\n  exec ./a/five.sh\nfi\nx=$(./a/six.sh)\nenv -i ./a/seven.sh\n")
        self.assertEqual([w for w in command_words(script) if "/" in w],
                         ["./a/one.sh", "./a/two.sh", "./a/three.sh", "./a/four.sh", "./a/five.sh",
                          "./a/six.sh", "./a/seven.sh"])

    def test_arguments_continuations_comments_heredocs_and_redirections_are_not_commands(self):
        script = ("bash scripts/a.sh\npython tools/b.py \\\n  deploy/c.spec\n"
                  "echo hi # ./scripts/d.sh\n# ./scripts/e.sh\n"
                  "cat <<'EOF'\n./scripts/f.sh\nEOF\nsort < data/g.txt > out/h.txt\n"
                  "echo 'a; ./scripts/i.sh'\n")
        self.assertEqual([w for w in command_words(script) if "/" in w], [])

    def test_an_unclosed_heredoc_is_refused(self):
        with self.assertRaises(ValueError):
            command_words("cat <<EOF\nnever closed\n")

    def test_repository_paths(self):
        self.assertEqual(repository_path("./scripts/relock.sh"), "scripts/relock.sh")
        self.assertEqual(repository_path("./x.sh", "proofs"), "proofs/x.sh")
        self.assertEqual(repository_path(".audit-venv/bin/python"), ".audit-venv/bin/python")
        for word in ("relock.sh", "/usr/bin/env", "~/x.sh", "$HOME/x.sh", "dist/capa${{ matrix.ext }}", "../x.sh"):
            with self.subTest(word=word):
                self.assertEqual(repository_path(word), "")


class DirectlyInvokedScriptsAreExecutable(unittest.TestCase):
    def test_the_set_is_not_empty(self):
        self.assertTrue(directly_invoked_paths(), "no workflow step runs a path directly; the guard is vacuous")

    def test_every_directly_invoked_repository_file_has_the_executable_bit(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("not a git checkout: the executable bit lives in the git index")
        checked = 0
        for path, sites in sorted(directly_invoked_paths().items()):
            mode = index_mode(path)
            if not mode:
                continue
            checked += 1
            with self.subTest(path=path):
                self.assertEqual(
                    mode, "100755",
                    "%s is run directly by %s but is committed without the executable "
                    "bit; `git update-index --chmod=+x %s`" % (path, sites, path),
                )
        self.assertGreater(checked, 0, "no directly invoked path is a committed file; the guard is vacuous")


if __name__ == "__main__":
    unittest.main()
