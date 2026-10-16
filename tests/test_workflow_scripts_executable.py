"""Every path a workflow step runs as a COMMAND (no interpreter in front)
must be a repository file committed with the executable bit, or the Linux
runner fails with "Permission denied".

The guard fails closed: a command path it cannot resolve to a committed
file is a failure, unless it is one of the known non-repository paths
listed, each with its reason, in ``NOT_REPOSITORY_FILES``; an entry that
no workflow runs is a failure too (a stale entry). "The index does not
hold it" never means "not ours": a path the reader resolved wrongly looks
exactly like a build product.

The paths are derived from the workflow files themselves: the reader
described below finds the words in COMMAND position of the ``run:``
blocks, and every such word that names a path (it holds a ``/``) is
judged:

- a relative path is resolved against the step's ``working-directory``;
  the git index must hold it with mode ``100755``, or it must be listed;
- after a directory change in the block (``cd``, ``pushd`` or ``popd`` in
  command position, wherever it stands, a subshell or a branch included)
  the reader does not know the directory to the end of the block (the end
  of a subshell or a substitution, as in ``(true)`` or ``$(date)``, does
  not restore it), so a relative command path from there on cannot be
  resolved and fails; the forms the reader resolves are the step's
  ``working-directory`` and a path from the repository root;
- an absolute path, a home path (``~``), a path that leaves the checkout,
  and a path built from a variable, an expression, a substitution or a
  glob are not resolved to a committed file, so each fails unless listed.

What the reader reads is the closed list below, and nothing else. A word
it does not reach is not judged and passes silently, whatever it runs.

- Blocks: every ``run:`` step of every job in ``.github/workflows`` whose
  shell is the default (read as bash, whatever the runner), or whose
  ``shell:`` (the step's, else the job's, else the workflow's
  ``defaults.run``) starts with the bare word ``bash`` or ``sh``. A block
  under any other ``shell:`` is not read at all, a path to bash included
  (``shell: /bin/bash -e {0}``).
- Text: quotes and backslashes keep what they cover inside one word, and
  are then removed. So an opener inside a quoted word that holds anything
  else opens nothing: a command substitution inside double quotes
  (``"$(...)"``) is not read, while the same substitution unquoted is,
  and so is a quoted command word (``"./x.sh"``). A word that is only
  operator characters once its quotes and backslashes are removed acts as
  that operator (``"&&"``, ``\\;``, ``">"``).
- Command position: the first word of the block and of each line, and the
  first word after an opener, skipping variable assignments, words that
  start with ``-`` and the prefixes.
- Openers: ``;``, ``&``, ``|``, ``(``, ``)``, ``&&``, ``||``, ``|&``,
  ``;;``, ``$(``, ``<(`` and ``>(``, and any other run of ``;``, ``&``,
  ``|``, ``(`` and ``)``.
- Prefixes: ``if``, ``then``, ``else``, ``elif``, ``do``, ``while``,
  ``until``, ``!``, ``{``, ``time``, ``exec``, ``env``, ``nohup``,
  ``sudo``, ``command`` and ``builtin``.
- A ``{`` is skipped only in command position: the body of ``{ ...; }``
  and of ``f() { ...; }`` is read, but the first command of a one-line
  ``function NAME { ...; }`` is not (``function`` is the command word
  there); the lines after the ``{`` are read.
- Not commands: a comment (from a ``#`` that starts an unquoted word to
  the end of the line), and the target of a redirection: the next word
  after a redirection operator (``<``, ``>``, ``>>``, ``<<``, ``>&``,
  ``&>`` and the like), taken even past an opener or a line end between
  them. So the first word inside ``< <(...)`` or ``> >(...)`` is not read,
  nor is the first command of the line after a word that is only a
  redirection operator (``echo ">"``). A backslash-newline joins two
  lines, and a GitHub expression (``${{ ... }}``) is one word.
- Here-documents: the first ``<<WORD`` on a line starts a here-document
  wherever it stands, even inside quotes (``echo "<<END"``). WORD is the
  name (a letter or ``_``, then letters, digits and ``_``) after the
  ``<<``, an optional ``-`` and blanks: bare, it ends at the first other
  character (``<<END-X`` is read as ``<<END``); quoted, the quotes hold
  the name alone (``<<'END'``, ``<<"END"``). ``<<<`` starts none. The
  lines after it are skipped up to the first line that is WORD (spaces
  and tabs around it ignored), and a WORD that never comes fails the
  block.

Outside that list, so not judged (examples, not a complete list):

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
- a command inside backquotes (except where the backquote starts the
  command word: that word is judged as an unresolved path and fails), a
  command named entirely by a variable (``$CMD``), a command after a
  leading redirection that names a file descriptor (``2> err.txt
  ./x.sh``), and a directory change made inside a sourced file or an
  ``eval``.

Read as commands although they are not (a false failure, the safe
direction): the elements of an array assignment (``A=( ./x.sh )``), a
``case`` pattern after ``;;``, an argument after a ``)`` (``echo $(date)
./x.sh``) or after a quoted or escaped opener (``echo "&&" ./x.sh``,
``find . -exec rm {} \\; ./x.sh``), and the body of a here-document the
rule above does not see (``<<$X``, ``<<'END X'``, the second one opened on
a line).

The mode is read from the git index (``git ls-files -s``), which is what a
checkout on the runner reproduces; the working tree on Windows does not
carry the bit, so a file-system check would pass here and fail there. A
tree that is not a git checkout (an archive extraction) has no index to
read, so the mode check skips there and says so; CI runs on a checkout.
The judgement itself (``judge``, and ``judge_workflows`` with the stale
check) takes the index as a function, so it is tested below without a
checkout.
"""

import posixpath
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


def judge_workflows(blocks, mode_of) -> tuple:
    """``judge`` over every workflow at once, plus the list's own check: an
    entry of ``NOT_REPOSITORY_FILES`` that no block runs is stale, and a
    stale entry is a failure. Returns ``(failures, checked)``."""
    failures, checked, listed = judge(blocks, mode_of)
    failures += ["%s is listed in NOT_REPOSITORY_FILES but no workflow runs it: a stale entry" % path
                 for path in sorted(set(NOT_REPOSITORY_FILES) - listed)]
    return failures, checked


def _run_setting(doc: dict, job: dict, step: dict, key: str):
    for scope in (step, (job.get("defaults") or {}).get("run") or {}, (doc.get("defaults") or {}).get("run") or {}):
        if scope.get(key):
            return str(scope[key])
    return ""


def run_blocks(workflows: Path = WORKFLOWS):
    """``(site, working directory, shell block)`` for every ``run:`` step
    of every workflow whose shell is the default, or whose ``shell:``
    starts with the bare word bash or sh."""
    for wf in sorted(list(workflows.glob("*.yml")) + list(workflows.glob("*.yaml"))):
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
                       "if true; then cd scripts; fi; ./relock.sh", "cd scripts; (true); ./relock.sh",
                       "cd scripts; echo $(date); ./relock.sh"):
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

    # The docstring's closed list of what the reader reads is read back from
    # the docstring itself and checked against the code both ways, so the
    # two cannot drift apart.
    @staticmethod
    def _listed(label: str) -> list:
        """The double-backquoted items of the docstring bullet that starts
        ``- <label>:``."""
        m = re.search(r"^- %s:(.*?)(?=^- |^\s*$)" % re.escape(label), __doc__, re.M | re.S)
        return re.findall(r"``(.+?)``", m.group(1)) if m else []

    def test_every_opener_the_docstring_lists_is_read_and_no_other(self):
        openers = self._listed("Openers")
        self.assertTrue(openers, "the docstring lists no opener")
        for opener in openers + ["\n"]:
            with self.subTest(opener=opener):
                self.assertIn("./a/x.sh", command_words("true %s ./a/x.sh" % opener),
                              "the docstring lists %r as an opener but the reader does not open on it" % opener)
        self.assertEqual(set(_OPERATOR_CHARS) - {"\n"}, set("".join(openers)) - {"$"},
                         "the reader opens a command on a character the docstring does not list, or the reverse")

    def test_every_prefix_the_docstring_lists_is_skipped_and_no_other(self):
        prefixes = self._listed("Prefixes")
        self.assertEqual(set(prefixes), _PREFIX_WORDS, "the docstring's prefixes are not the reader's")
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                self.assertEqual(command_words("%s ./a/x.sh" % prefix), ["./a/x.sh"])

    def test_the_shapes_the_docstring_says_are_not_read_are_not_read(self):
        # The docstring states that each of these is not read. If the reader
        # learns one, the docstring must change in the same commit.
        for named, script in (('``"$(...)"``', 'V="$(./a/x.sh)"'),
                              ('``"$(...)"``', 'if [ -n "$(./a/x.sh)" ]; then true; fi'),
                              ('``"$(...)"``', 'echo "v=$(./a/x.sh)" >> "$GITHUB_OUTPUT"'),
                              ("``function NAME { ...; }``", "function f { ./a/x.sh; }"),
                              ('``echo "<<END"``', 'echo "<<END"\n./a/x.sh\nEND\n'),
                              ("``<<END-X``", "cat <<END-X\nEND-X\n./a/x.sh\nEND\n"),
                              ("``< <(...)``", "while read -r l; do true; done < <(./a/x.sh)"),
                              ("``> >(...)``", "make > >(./a/x.sh)"),
                              ('``echo ">"``', 'echo ">"\n./a/x.sh'),
                              ('``echo ">"``', "echo \\>\n./a/x.sh")):
            with self.subTest(script=script):
                self.assertNotIn("./a/x.sh", command_words(script), "the reader reads this shape now")
                self.assertIn(named, __doc__, "not read, but the docstring does not say so")

    def test_the_forms_the_docstring_says_are_read_are_read(self):
        # Beside each unread shape, the form the docstring says is read; then
        # the false failures it declares (read although not a command).
        for script in ("V=$(./a/x.sh)", "function f {\n./a/x.sh\n}", "f() { ./a/x.sh; }", "{ ./a/x.sh; }",
                       'echo "<<END"\nEND\n./a/x.sh', "cat <<END\n./a/y.sh\n \tEND \n./a/x.sh",
                       "A=( ./a/x.sh )", 'case "$X" in a) true;; ./a/x.sh) true;; esac',
                       '"./a/x.sh"', "diff <(./a/x.sh) f",
                       "echo $(date) ./a/x.sh", 'echo "&&" ./a/x.sh', "find . -exec rm {} \\; ./a/x.sh",
                       "cat <<$X\n./a/x.sh\n$X", "cat <<'END X'\n./a/x.sh\nEND X", "cat <<A <<B\nA\n./a/x.sh\nB"):
            with self.subTest(script=script):
                self.assertEqual([w for w in command_words(script) if "/" in w], ["./a/x.sh"])

    def test_only_a_default_bash_or_sh_shell_is_read(self):
        workflow = ("jobs:\n"
                    "  steps_shell:\n    runs-on: x\n    steps:\n"
                    "      - run: ./a/default.sh\n"
                    "      - shell: bash -e {0}\n        run: ./a/bash.sh\n"
                    "      - shell: sh\n        run: ./a/sh.sh\n"
                    "      - shell: /bin/bash -e {0}\n        run: ./a/bin_bash.sh\n"
                    "      - shell: pwsh\n        run: ./a/pwsh.sh\n"
                    "  job_default_bash:\n    runs-on: x\n    defaults:\n      run:\n        shell: bash\n"
                    "    steps:\n      - run: ./a/job_bash.sh\n"
                    "  job_default_bin_bash:\n    runs-on: x\n    defaults:\n      run:\n"
                    "        shell: /bin/bash -e {0}\n    steps:\n      - run: ./a/job_bin_bash.sh\n")
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "wf.yml").write_text(workflow, encoding="utf-8")
            read = [run for _site, _wd, run in run_blocks(Path(d))]
        self.assertEqual(read, ["./a/default.sh", "./a/bash.sh", "./a/sh.sh", "./a/job_bash.sh"])
        self.assertIn("``shell: /bin/bash -e {0}``", __doc__, "not read, but the docstring does not say so")


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
                               ("`./scripts/ok.sh`", ""),
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

    def test_an_entry_no_block_runs_is_a_stale_failure(self):
        def mode_of(path):
            return self.INDEX.get(path, "")
        runs_the_entry = ("s", "", ".audit-venv/bin/python -V")
        self.assertEqual(judge_workflows([runs_the_entry], mode_of)[0], [])
        for blocks, planted, stale in (([("s", "", "./scripts/ok.sh")], {}, ".audit-venv/bin/python"),
                                       ([runs_the_entry], {"extra/tool": "planted"}, "extra/tool")):
            with self.subTest(stale=stale), mock.patch.dict(NOT_REPOSITORY_FILES, planted):
                failures = judge_workflows(blocks, mode_of)[0]
                self.assertEqual(len(failures), 1, failures)
                self.assertIn(stale, failures[0])
                self.assertIn("stale", failures[0])


class DirectlyInvokedScriptsAreExecutable(unittest.TestCase):
    def test_the_workflows_run_some_path_as_a_command(self):
        self.assertTrue([p for _s, wd, run in run_blocks() for p in command_paths(run, wd)],
                        "no workflow step runs a path as a command; the guard is vacuous")

    def test_every_command_path_is_an_executable_committed_file_or_listed(self):
        if not (REPO_ROOT / ".git").exists():
            self.skipTest("not a git checkout: the executable bit lives in the git index")
        failures, checked = judge_workflows(run_blocks(), index_mode)
        self.assertEqual(failures, [])
        self.assertTrue(checked, "no command path is a committed file; the guard is vacuous")


if __name__ == "__main__":
    unittest.main()
