"""Every path a workflow step runs as a COMMAND (no interpreter in front)
must be a repository file committed with the executable bit, or the Linux
runner fails with "Permission denied".

The guard fails closed: a command path it cannot resolve to a committed
file is a failure, unless it is one of the known non-repository paths
listed, each with its reason, in ``NOT_REPOSITORY_FILES``. "The index does
not hold it" never means "not ours": a path the reader resolved wrongly
looks exactly like a build product.

The paths are derived from the workflow files themselves: every ``run:``
block of every job in ``.github/workflows`` is read as shell, and every
word in COMMAND position that names a path (it holds a ``/``) is judged:

- a relative path is resolved against the step's ``working-directory``;
  the git index must hold it with mode ``100755``, or it must be listed;
- after a directory change in the block (``cd``, ``pushd``, ``popd``,
  wherever it stands, a subshell or a branch included) the reader does not
  know the directory, so a relative command path from there on cannot be
  resolved and fails; the forms the reader resolves are the step's
  ``working-directory`` and a path from the repository root;
- an absolute path, a home path (``~``), a path that leaves the checkout,
  and a path built from a variable, an expression, a substitution or a
  glob are not resolved to a committed file, so each fails unless listed.

Command position, as read here: the first word of the block and the first
word after a newline, ``;``, ``&``, ``&&``, ``|``, ``||``, ``(`` or ``$(``,
skipping variable assignments, option words and the prefixes ``if``,
``then``, ``else``, ``elif``, ``do``, ``while``, ``until``, ``!``, ``{``,
``time``, ``exec``, ``env``, ``nohup``, ``sudo``, ``command`` and
``builtin``. A backslash-newline continues the line, comments are dropped,
the body of a here-document is not read and the target of a redirection
is not a command.

Not followed, so a path there is not judged:

- a program that runs another program named among its arguments. Tried
  and not followed: ``timeout``, ``nice``, ``ionice``, ``stdbuf``,
  ``taskset``, ``setsid``, ``chrt``, ``xargs``, ``find -exec``,
  ``parallel``, ``watch``, ``flock``, ``chroot``, ``xvfb-run``,
  ``script -c``, ``su -c``, ``runuser``, ``doas``, ``pkexec``,
  ``fakeroot``, ``firejail``, ``unbuffer``, ``faketime``, ``strace``,
  ``valgrind``, ``gdb``, ``catchsegv``, ``unshare``, ``nsenter``,
  ``systemd-run``, ``caffeinate``, ``busybox``, ``docker run``, ``ssh``,
  ``coproc``, ``trap``, ``eval``, ``bash -c`` and ``sh -c``. A program not
  named here is not followed either;
- the argument of a prefix that takes one (``sudo -u <user>``,
  ``env -u <name>``, ``env -C <dir>``, ``exec -a <name>``);
- a backquoted command, a command named entirely by a variable
  (``$CMD``), a block under an explicit ``shell:`` other than bash or sh,
  a command after a leading redirection that names a file descriptor
  (``2> err.txt ./x.sh``), and a directory change made inside a sourced
  file or an ``eval``.

Read as commands although they are not (a false failure, the safe
direction): the elements of an array assignment (``A=( ./x.sh )``) and a
``case`` pattern after ``;;``.

The mode is read from the git index (``git ls-files -s``), which is what a
checkout on the runner reproduces; the working tree on Windows does not
carry the bit, so a file-system check would pass here and fail there. A
tree that is not a git checkout (an archive extraction) has no index to
read, so the mode check skips there and says so; CI runs on a checkout.
The judgement itself (``judge``) takes the index as a function, so it is
tested below without a checkout.
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

#: THE list of paths a workflow runs as a command that are not repository
#: files, each with its reason. A command path the index does not hold is
#: a failure unless it is here; an entry no workflow runs is stale.
NOT_REPOSITORY_FILES = {
    ".audit-venv/bin/python": "the audit job's virtual environment, created by "
                              "`python -m venv .audit-venv` earlier in the same step",
}

_OPERATOR_CHARS = "();<>|&\n"
_PREFIX_WORDS = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{",
                           "time", "exec", "env", "nohup", "sudo", "command", "builtin"})
_DIRECTORY_CHANGES = frozenset({"cd", "pushd", "popd"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_REDIRECTION = re.compile(r"(?:&>+|[<>]+[&|]?)$")
_HEREDOC = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
#: A word holding one of these is built from a variable, an expression, a
#: substitution or a glob: the guard cannot name the file it runs.
_UNRESOLVED = re.compile(r"[$`{}*?\[]")
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
    """The words in command position of a shell block, in order. A GitHub
    expression (``${{ ... }}``) is substituted before the shell runs, so it
    is read as one word, its spaces dropped."""
    text = re.sub(r"\$\{\{(.*?)\}\}", lambda m: "${{" + re.sub(r"\s+", "", m.group(1)) + "}}", script)
    text = _strip_heredoc_bodies(_strip_comments(re.sub(r"\\\r?\n", " ", text)))
    lex = shlex.shlex(text, posix=True, punctuation_chars=_OPERATOR_CHARS)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    words, at_start, redirect_target = [], True, False
    for tok in lex:
        if tok and all(c in _OPERATOR_CHARS for c in tok):
            # One run of operator characters may end a command and open a
            # redirection at once (a newline then `>`): split off the
            # trailing redirection operator, if any, and read both parts.
            m = _REDIRECTION.search(tok)
            if m:
                redirect_target = True
                tok = tok[:m.start()]
            if tok:
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


def _resolve(word: str, workdir: str, moved: bool):
    """The path a command word names. A word whose meaning does not depend
    on the directory (absolute, home, starting with a variable) is itself;
    a relative word is joined to the working directory, or ``None`` once a
    directory change has made that directory unknown."""
    if word.startswith(("/", "~", "$")):
        return word
    if moved:
        return None
    return posixpath.normpath(posixpath.join(workdir, word))


def command_paths(script: str, workdir: str = "") -> list:
    """``(word, path)`` for every word in command position that names a
    path (it holds a ``/``), in order; ``path`` as ``_resolve`` gives it."""
    out, moved = [], False
    for word in command_words(script):
        if word in _DIRECTORY_CHANGES:
            moved = True
        elif "/" in word:
            out.append((word, _resolve(word, workdir, moved)))
    return out


def _in_checkout(path: str) -> bool:
    """Whether ``path`` names one file of the checkout the index could hold."""
    return not (path.startswith(("/", "~", "..")) or _UNRESOLVED.search(path))


def judge(blocks, mode_of) -> tuple:
    """THE rule over ``(site, working directory, block)`` triples: every
    command path is a committed ``100755`` file or a listed non-repository
    path. ``mode_of(path)`` is the index mode of a checkout path, ``""``
    when the index does not hold it. Returns ``(failures, checked, listed)``:
    the failure messages, the committed paths found executable, and the
    entries of ``NOT_REPOSITORY_FILES`` that were used."""
    failures, checked, listed = [], set(), set()
    for site, workdir, run in blocks:
        try:
            pairs = command_paths(run, workdir)
        except ValueError as e:
            failures.append("%s: %s" % (site, e))
            continue
        for word, path in pairs:
            mode = mode_of(path) if path is not None and _in_checkout(path) else ""
            if mode == "100755":
                checked.add(path)
            elif mode:
                failures.append("%s: %s is run directly but is committed with mode %s, not 100755; "
                                "`git update-index --chmod=+x %s`" % (site, path, mode, path))
            elif path in NOT_REPOSITORY_FILES:
                listed.add(path)
            elif path is None:
                failures.append("%s: %s is run after a directory change, so the guard cannot tell which "
                                "file it is; use the step's working-directory or a path from the "
                                "repository root" % (site, word))
            else:
                failures.append("%s: %s is run as a command but is not a committed file; if it is not a "
                                "repository file, list it with its reason in NOT_REPOSITORY_FILES"
                                % (site, word))
    return failures, checked, listed


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
                  "if ./a/four.sh; then\n  exec ./a/five.sh\nfi\nx=$(./a/six.sh)\nenv -i ./a/seven.sh\n"
                  "> out/log.txt ./a/eight.sh\n")
        self.assertEqual([w for w in command_words(script) if "/" in w],
                         ["./a/one.sh", "./a/two.sh", "./a/three.sh", "./a/four.sh", "./a/five.sh",
                          "./a/six.sh", "./a/seven.sh", "./a/eight.sh"])

    def test_arguments_continuations_comments_heredocs_and_redirections_are_not_commands(self):
        script = ("bash scripts/a.sh\npython tools/b.py \\\n  deploy/c.spec\n"
                  "echo hi # done; ./scripts/d.sh\n# note && ./scripts/e.sh\n"
                  "cat <<'EOF'\n./scripts/f.sh\nEOF\nsort < data/g.txt > out/h.txt\n"
                  "echo 'a; ./scripts/i.sh'\n")
        self.assertEqual([w for w in command_words(script) if "/" in w], [])

    def test_an_unclosed_heredoc_is_refused(self):
        with self.assertRaises(ValueError):
            command_words("cat <<EOF\nnever closed\n")

    def test_resolution(self):
        self.assertEqual(command_paths("./scripts/relock.sh"), [("./scripts/relock.sh", "scripts/relock.sh")])
        self.assertEqual(command_paths("./x.sh", "proofs"), [("./x.sh", "proofs/x.sh")])
        self.assertEqual(command_paths("../scripts/x.sh", "proofs"), [("../scripts/x.sh", "scripts/x.sh")])
        for word in ("/usr/bin/tool", "~/x.sh", "$HOME/x.sh", "${{github.workspace}}/x.sh"):
            with self.subTest(word=word):
                self.assertEqual(command_paths(word), [(word, word)])
        self.assertEqual(command_paths("${{ github.workspace }}/x.sh a"),
                         [("${{github.workspace}}/x.sh", "${{github.workspace}}/x.sh")])
        self.assertEqual(command_paths("relock.sh\n$CMD"), [], "a bare name names no path")

    def test_a_directory_change_leaves_the_directory_unknown(self):
        for script in ("cd scripts && ./relock.sh", "cd scripts\n./relock.sh\n", "pushd scripts\n./relock.sh\n",
                       "popd\n./relock.sh", "(cd scripts && ./relock.sh)", "builtin cd scripts; ./relock.sh",
                       "if true; then cd scripts; fi; ./relock.sh"):
            with self.subTest(script=script):
                self.assertEqual(command_paths(script, "proofs"), [("./relock.sh", None)])
        self.assertEqual(command_paths("./a.sh; cd x; ./b.sh"), [("./a.sh", "a.sh"), ("./b.sh", None)],
                         "a path before the change is still resolved")

    def test_every_wrapper_the_docstring_names_is_not_followed(self):
        # The docstring's list must stay true: if the reader learns one of
        # these, the list must lose it in the same change.
        for name, shape in (
                ("timeout", "timeout 600 {}"), ("nice", "nice -n 5 {}"), ("ionice", "ionice -c 3 {}"),
                ("stdbuf", "stdbuf -oL {}"), ("taskset", "taskset -c 0 {}"), ("setsid", "setsid {}"),
                ("chrt", "chrt -f 1 {}"), ("xargs", "echo a | xargs -n 1 {}"), ("find -exec", "find . -exec {} ;"),
                ("parallel", "parallel {} ::: 1"), ("watch", "watch {}"), ("flock", "flock /tmp/l {}"),
                ("chroot", "chroot / {}"), ("xvfb-run", "xvfb-run {}"), ("script -c", "script -c {}"),
                ("su -c", "su -c {}"), ("runuser", "runuser -u bob {}"), ("doas", "doas {}"),
                ("pkexec", "pkexec {}"), ("fakeroot", "fakeroot {}"), ("firejail", "firejail {}"),
                ("unbuffer", "unbuffer {}"), ("faketime", "faketime 2020 {}"), ("strace", "strace {}"),
                ("valgrind", "valgrind {}"), ("gdb", "gdb -batch {}"), ("catchsegv", "catchsegv {}"),
                ("unshare", "unshare {}"), ("nsenter", "nsenter -t 1 {}"), ("systemd-run", "systemd-run {}"),
                ("caffeinate", "caffeinate {}"), ("busybox", "busybox {}"), ("docker run", "docker run img {}"),
                ("ssh", "ssh host {}"), ("coproc", "coproc {}"), ("trap", "trap '{}' EXIT"), ("eval", "eval {}"),
                ("bash -c", "bash -c '{}'"), ("sh -c", "sh -c '{}'"), ("sudo -u <user>", "sudo -u bob {}"),
                ("env -u <name>", "env -u NAME {}"), ("env -C <dir>", "env -C dir {}"),
                ("exec -a <name>", "exec -a name {}")):
            with self.subTest(wrapper=name):
                self.assertNotIn("./a/x.sh", command_words(shape.format("./a/x.sh")),
                                 "the reader follows %s now" % name)
                self.assertIn("``%s``" % name, __doc__, "%s is not followed but the docstring does not say so" % name)


class TheJudgement(unittest.TestCase):
    """``judge`` on planted blocks and an index given as a mapping, no
    checkout needed. ``relock.sh`` at the root is committed 100755 as a
    decoy: a reader that resolved a path after a directory change against
    the step's directory would find it and pass."""

    INDEX = {"scripts/relock.sh": "100644", "scripts/ok.sh": "100755", "relock.sh": "100755",
             "deploy/install.sh": "100644", "tools/b.py": "100644"}

    def _failures(self, block, workdir="", index=None):
        index = self.INDEX if index is None else index

        def mode_of(path):
            # As `git ls-files` does, refuse a path outside the checkout.
            if path.startswith(("/", "..")):
                raise ValueError("%s is outside the repository" % path)
            return index.get(path, "")
        return judge([("wf.yml:job:step", workdir, block)], mode_of)[0]

    def test_every_unresolvable_or_unexecutable_command_path_fails(self):
        no_decoy = {k: v for k, v in self.INDEX.items() if k != "relock.sh"}
        for block, workdir in (("./scripts/relock.sh", ""), ("./relock.sh", "scripts"),
                               ("cd scripts && ./relock.sh", ""), ("cd scripts\n./relock.sh\n", ""),
                               ("pushd scripts\n./relock.sh\npopd\n", ""),
                               ('cd "$GITHUB_WORKSPACE/scripts" && ./relock.sh', ""),
                               ("(cd scripts && ./relock.sh)", ""), ("cd scripts && ./ok.sh", ""),
                               ("$GITHUB_WORKSPACE/scripts/ok.sh", ""), ("${{ github.workspace }}/scripts/ok.sh", ""),
                               ("/usr/local/bin/tool", ""), ("~/bin/tool", ""), ("./scripts/*.sh", ""),
                               ("tools/missing.sh", ""), ("../outside.sh", ""), (".other-venv/bin/python", ""),
                               ("cat <<EOF\nnever closed\n", "")):
            for name, index in (("decoy", None), ("no decoy", no_decoy)):
                with self.subTest(block=block, workdir=workdir, index=name):
                    self.assertEqual(len(self._failures(block, workdir, index)), 1)

    def test_a_listed_path_the_index_holds_is_judged_by_its_mode(self):
        index = dict(self.INDEX, **{".audit-venv/bin/python": "100644"})
        self.assertEqual(len(self._failures(".audit-venv/bin/python -V", "", index)), 1)

    def test_legitimate_forms_pass(self):
        for block, workdir in (("./scripts/ok.sh", ""), ("scripts/ok.sh --flag", ""), ("./ok.sh", "scripts"),
                               ("sudo ./scripts/ok.sh", ""), (".audit-venv/bin/python -m pip install x", ""),
                               ("bash ./scripts/relock.sh", ""), ("python tools/b.py", ""),
                               ("./relock.sh", ""), ("./scripts/ok.sh\ncd deploy\nsha256sum install.sh", ""),
                               ("cd deploy\nsha256sum install.sh > install.sh.sha256\n"
                                "sha256sum install.ps1 > install.ps1.sha256\n", "")):
            with self.subTest(block=block, workdir=workdir):
                self.assertEqual(self._failures(block, workdir), [])

    def test_it_reports_what_it_checked_and_which_entries_it_used(self):
        _f, checked, listed = judge([("s", "", "./scripts/ok.sh\n.audit-venv/bin/python -V")],
                                    lambda p: self.INDEX.get(p, ""))
        self.assertEqual((checked, listed), ({"scripts/ok.sh"}, {".audit-venv/bin/python"}))


class DirectlyInvokedScriptsAreExecutable(unittest.TestCase):
    def test_the_workflows_run_some_path_as_a_command(self):
        self.assertTrue([p for _s, wd, run in run_blocks() for p in command_paths(run, wd)],
                        "no workflow step runs a path as a command; the guard is vacuous")

    def test_every_command_path_is_an_executable_committed_file_or_listed(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("not a git checkout: the executable bit lives in the git index")
        failures, checked, listed = judge(run_blocks(), index_mode)
        self.assertEqual(failures, [])
        self.assertTrue(checked, "no command path is a committed file; the guard is vacuous")
        self.assertEqual(sorted(set(NOT_REPOSITORY_FILES) - listed), [],
                         "listed as a non-repository path but no workflow runs it: a stale entry")


if __name__ == "__main__":
    unittest.main()
