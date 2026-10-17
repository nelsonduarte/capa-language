"""Every path a workflow step runs as a COMMAND (no interpreter in front)
must be a repository file committed with the executable bit, or the Linux
runner fails with "Permission denied". This module guards that.

The guard is a heuristic. It finds the command paths of a step with a
small reader of its own, which is not a shell. What the guard reads is
stated in one place, the probe table ``READER_PROBES`` in this file, and
that table is the complete statement. Each row is a step that plants the
script ``a/x.sh``, and what the guard does with that script: reads it
(it is judged as below), does not read it (it is not judged), or refuses
the whole step (a failure). A test checks every row. A step that no row
states is unspecified: the guard may read the script in it or not, and
nothing in this file says which.

To cover a new shape, add a row with the outcome the guard gives today.
If the guard should read a shape it does not, harden the reader and
change the rows that move with it in the same commit.

What the guard does with a command path it reads (tested apart from the
table, in ``TheJudgement`` and the directory test):

- a relative path is resolved against the step's ``working-directory``;
  the git index must hold it with mode ``100755``, or it must be listed,
  with its reason, in ``NOT_REPOSITORY_FILES``;
- once the guard has read a ``cd``, ``pushd`` or ``popd`` command in a
  step, it does not know the directory to the end of that step, so a
  relative command path from there on fails; the forms it resolves are
  the step's ``working-directory`` and a path from the repository root;
- an absolute path, a home path (``~``), a path that leaves the checkout,
  and a path built from a variable, an expression, a substitution or a
  glob are not resolved to a committed file, so each fails unless listed;
- an entry of ``NOT_REPOSITORY_FILES`` that no step runs is a failure (a
  stale entry).

The guard fails closed because "the index does not hold it" never means
"not ours": a path resolved wrongly looks exactly like a build product.

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
    """The text with the reader's comments cut; what that cuts is stated
    only by ``READER_PROBES``."""
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
    """The text with the reader's here-document cut; what that cuts, and
    when it refuses the step, is stated only by ``READER_PROBES``."""
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
    """The words the reader takes as commands in a shell block, in order;
    which words those are is stated only by ``READER_PROBES``."""
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


READ, NOT_READ, REFUSED = "read", "not read", "refused"
_PLANTED = "a/x.sh"

#: THE probe table: the one statement of what the guard reads (see the
#: module docstring). A row is ``(step, outcome)``: the step is its ``run:``
#: text under the default shell, or a mapping of the step's keys, where a
#: ``defaults`` key is its job's; the outcome is what the guard does with
#: the planted script ``a/x.sh``. The comments only group the rows.
READER_PROBES = (
    # The script alone, or on a later line.
    ("./a/x.sh", READ), ("a/x.sh --flag", READ), ('true\na/x.sh "$B"', READ), ("true\n./a/x.sh", READ),
    ("true\r\n./a/x.sh", READ), ("\t./a/x.sh", READ), ("true;\t./a/x.sh", READ), ("./a/../a/x.sh", READ),
    (".//a//x.sh", READ), ('"./a/x.sh"', READ), ("'./a/x.sh'", READ), ("./a/x.sh &", READ),
    ("./a/x.sh <<< x", READ), ("# x\n./a/x.sh", READ),
    ("'./a/x.sh' arg", READ),
    # After another command and an operator.
    ("true ; ./a/x.sh", READ), ("true & ./a/x.sh", READ), ("true | ./a/x.sh", READ),
    ("true ( ./a/x.sh", READ), ("true ) ./a/x.sh", READ), ("true && ./a/x.sh", READ),
    ("true || ./a/x.sh", READ), ("true |& ./a/x.sh", READ), ("true ;; ./a/x.sh", READ),
    ("true $( ./a/x.sh", READ), ("true <( ./a/x.sh", READ), ("true >( ./a/x.sh", READ),
    ("true;./a/x.sh", READ), ("true&&./a/x.sh", READ), ("echo|./a/x.sh", READ), ("true&./a/x.sh", READ),
    ("false||./a/x.sh", READ), ("true;(./a/x.sh)", READ), ("echo a |& ./a/x.sh", READ),
    ("true &&\n./a/x.sh", READ), ("echo a |\n  ./a/x.sh", READ), ("true &&\\\n./a/x.sh", READ),
    ("true && \\\n  ./a/x.sh", READ), ("set -e && ./a/x.sh", READ), ("set -euo pipefail; ./a/x.sh", READ),
    ("set -e || ./a/x.sh", READ), ("sleep 1 & ./a/x.sh", READ), ("true &\n./a/x.sh", READ),
    ("true;)\n./a/x.sh", READ),
    ("true; ./a/x.sh", READ), ("echo a |\n./a/x.sh", READ), ("true &&\n  ./a/x.sh", READ),
    ("false || ./a/x.sh", READ),
    # After a word in front of the command.
    ("if ./a/x.sh", READ), ("then ./a/x.sh", READ), ("else ./a/x.sh", READ), ("elif ./a/x.sh", READ),
    ("do ./a/x.sh", READ), ("while ./a/x.sh", READ), ("until ./a/x.sh", READ), ("! ./a/x.sh", READ),
    ("{ ./a/x.sh", READ), ("time ./a/x.sh", READ), ("exec ./a/x.sh", READ), ("env ./a/x.sh", READ),
    ("nohup ./a/x.sh", READ), ("sudo ./a/x.sh", READ), ("command ./a/x.sh", READ), ("builtin ./a/x.sh", READ),
    ("time -p ./a/x.sh", READ), ("sudo -E ./a/x.sh", READ), ("env -i ./a/x.sh", READ),
    ("env A=1 ./a/x.sh", READ), ("env A=1 B=2 ./a/x.sh", READ), ("nohup ./a/x.sh > /dev/null", READ),
    ("nohup ./a/x.sh &", READ), ("exec ./a/x.sh 2>&1", READ), ("if true; then\n  exec ./a/x.sh\nfi", READ),
    ("FOO=1 ./a/x.sh", READ), ("FOO_BAR=1 ./a/x.sh", READ), ("_X=1 ./a/x.sh", READ), ("A1=1 ./a/x.sh", READ),
    ("a= ./a/x.sh", READ), ('X="a b" ./a/x.sh', READ), ("X=$(true) ./a/x.sh", READ),
    ('X="$(true)" ./a/x.sh', READ), ("x=1 y=2 ./a/x.sh", READ), (">/dev/null V=1 ./a/x.sh", READ),
    ('x="a b" ./a/x.sh', READ), ("x=$(true) ./a/x.sh", READ), ('x="$(true)" ./a/x.sh', READ),
    # Inside a substitution or a process substitution.
    ("V=$(./a/x.sh)", READ), ("x=$( ./a/x.sh )", READ), ("A=x$(./a/x.sh)", READ), ("echo $(./a/x.sh)", READ),
    ("echo $(echo $(./a/x.sh))", READ), ("export V=$(./a/x.sh)", READ), ("readonly v=$(./a/x.sh)", READ),
    ("f() { local v=$(./a/x.sh); }; f", READ), ("cat <<< $(./a/x.sh)", READ), ("diff <(./a/x.sh) f", READ),
    ("cat <(./a/x.sh)", READ), ("exec > >(tee log)\n./a/x.sh", READ),
    ("f() { local V=$(./a/x.sh); }", READ), ("diff <(./a/x.sh) a", READ),
    # In a compound command.
    ("if ./a/x.sh; then true; fi", READ), ("if ! ./a/x.sh; then exit 1; fi", READ),
    ("while ./a/x.sh && false; do true; done", READ), ("until ./a/x.sh || true; do true; done", READ),
    ("until ./a/x.sh; do sleep 1; done", READ), ("if true\nthen\n./a/x.sh\nfi", READ),
    ("if false; then true; else ./a/x.sh; fi", READ), ("if false; then true; elif ./a/x.sh; then true; fi", READ),
    ("for i in 1; do ./a/x.sh; done", READ), ("for i in 1\ndo\n./a/x.sh\ndone", READ),
    ("select x in a; do ./a/x.sh; done", READ), ('while read -r l; do ./a/x.sh "$l"; done < f', READ),
    ("case x in x) ./a/x.sh;; esac", READ), ("case x in (x) ./a/x.sh;; esac", READ),
    ("case x in\n  x)\n    ./a/x.sh\n    ;;\nesac", READ), ("(( 1 )) && ./a/x.sh", READ),
    ("(( x = 1 )) && ./a/x.sh", READ), ("(( 1 )); ./a/x.sh", READ), ("[[ -n x ]] && ./a/x.sh", READ),
    ("[[ -z a ]] || ./a/x.sh", READ), ("[ -d a ] && ./a/x.sh", READ), ("declare -x A=1; ./a/x.sh", READ),
    ("case a in (a) ./a/x.sh;; esac", READ), ("case $x in (a) ./a/x.sh;; esac", READ),
    ("[[ -f x ]] && ./a/x.sh", READ), ("if true\nthen\n  ./a/x.sh\nfi", READ),
    ("[ -x ./a/x.sh ] && ./a/x.sh", READ),
    # In a group or a function body.
    ("{ ./a/x.sh; }", READ), ("{ ./a/x.sh;}", READ), ("{ true;./a/x.sh;}", READ), ("{\n./a/x.sh\n}", READ),
    ("( ./a/x.sh )", READ), ("(\n./a/x.sh\n)", READ), ("{ ./a/x.sh; } 2>/dev/null", READ),
    ("{ ./a/x.sh; } 2>&1", READ), ("f() { ./a/x.sh; }", READ), ("f(){ ./a/x.sh; }; f", READ),
    ("f() ( ./a/x.sh ); f", READ), ("f()\n{\n./a/x.sh\n}\nf", READ), ("function f() { ./a/x.sh; }; f", READ),
    ("function f {\n./a/x.sh\n}", READ), ("function f\n{\n./a/x.sh\n}\nf", READ),
    ("function f {\n  ./a/x.sh\n}\nf", READ), ("function f {\n  ./a/x.sh\n}", READ),
    ("f() { ./a/x.sh; }\nf", READ), ("function f() { ./a/x.sh; }", READ),
    # Beside a redirection.
    ("> out/log.txt ./a/x.sh", READ), (">/dev/null ./a/x.sh", READ), ("</dev/null ./a/x.sh", READ),
    ("&>/dev/null ./a/x.sh", READ), (">&2 ./a/x.sh", READ), ("true 2>&1 | ./a/x.sh", READ),
    ("true >/dev/null & ./a/x.sh", READ), ("true >| /dev/null; ./a/x.sh", READ),
    ("true;>/dev/null ./a/x.sh", READ),
    ("true ;> f ./a/x.sh", READ), ("cmd 2>&1; ./a/x.sh", READ), ("cmd >&2\n./a/x.sh", READ),
    ("cmd &>/dev/null; ./a/x.sh", READ), ("cmd > out.txt; ./a/x.sh", READ), ("cmd <<< hi; ./a/x.sh", READ),
    # After a here-document.
    ("cat <<EOF\nx\nEOF\n./a/x.sh", READ), ("cat <<EOF && ./a/x.sh\nx\nEOF", READ),
    ("cat <<EOF | ./a/x.sh\nhi\nEOF", READ), (": <<'EOF'\nbody\nEOF\n./a/x.sh", READ),
    ("cat <<EOF | cat\nbody\nEOF\n./a/x.sh", READ), ("cat <<-EOF\n\tbody\n\tEOF\n./a/x.sh", READ),
    ("cat <<END\nbody\n \tEND \n./a/x.sh", READ), ('echo "<<END"\nEND\n./a/x.sh', READ),
    ('cat <<< "x"\n./a/x.sh', READ),
    ("cat <<\tEND\n./a/y.sh\nEND\n./a/x.sh", READ), ("cat <<EOF\r\nx\r\nEOF\r\n./a/x.sh", READ),
    # On the line after a line holding quotes, a hash or a backslash.
    ("echo 'a b'\n./a/x.sh", READ), ('echo "a # b"\n./a/x.sh', READ), ("echo a#b\n./a/x.sh", READ),
    ("echo $#\n./a/x.sh", READ), ("x=ab; echo ${#x}\n./a/x.sh", READ), ('echo "$(date)"\n./a/x.sh', READ),
    ("x=( a b )\n./a/x.sh", READ), ('echo "a\\\\"\n./a/x.sh', READ), ('echo "foo\\\\"\n./a/x.sh', READ),
    ("echo it\\'s\n./a/x.sh", READ), ('echo "it\'s"\n./a/x.sh', READ), ("echo '\"'\n./a/x.sh", READ),
    ('echo \\"\n./a/x.sh', READ), ('echo "|"\n./a/x.sh', READ), ('echo ";"\n./a/x.sh', READ),
    ("echo '('\n./a/x.sh", READ), ('echo ")"\n./a/x.sh', READ), ('echo "2>"\n./a/x.sh', READ),
    ('echo "\n"\n./a/x.sh', READ), ("echo 'a \\\nb'\n./a/x.sh", READ), ("case x in x) true;; esac\n./a/x.sh", READ),
    ("f() { true; }\n./a/x.sh", READ), ("if true; then true; fi\n./a/x.sh", READ),
    ("# ./old.sh --flag \\\n#   --more\n./a/x.sh", READ), ("echo ${{ a || 'b' }}\n./a/x.sh", READ),
    ('echo "=>"\n./a/x.sh', READ),
    # After a change of directory.
    ("cd scripts && ./a/x.sh", READ), ("f() { cd scripts; }\nf\n./a/x.sh", READ),
    ("function f { cd scripts; }\nf\n./a/x.sh", READ), ("cd scripts\ncd -\n./a/x.sh", READ),
    ("timeout 5 true && cd scripts && ./a/x.sh", READ), ("sudo true && cd scripts && ./a/x.sh", READ),
    ('"cd" scripts && ./a/x.sh', READ), ("\\cd scripts && ./a/x.sh", READ),
    ("command cd scripts && ./a/x.sh", READ), ("case x in x) cd scripts;; esac\n./a/x.sh", READ),
    ("for d in scripts; do cd $d; done\n./a/x.sh", READ), ("{ cd scripts; }\n./a/x.sh", READ),
    ("cd scripts || exit 1\n./a/x.sh", READ), ("cd \\\n scripts && ./a/x.sh", READ),
    ("cd scripts\r\n./a/x.sh\r\n", READ), ("\tcd scripts\n\t./a/x.sh", READ),
    ("# x\ncd scripts # y\n./a/x.sh", READ),
    ('"cd" a; ./a/x.sh', READ),
    # An array, a case pattern, an argument after a substitution or a quoted
    # operator, unusual here-documents, GitHub expressions.
    ("A=( ./a/x.sh )", READ), ('case "$X" in a) true;; ./a/x.sh) true;; esac', READ),
    ("echo $(date) ./a/x.sh", READ), ('echo "&&" ./a/x.sh', READ), ("find . -exec rm {} \\; ./a/x.sh", READ),
    ("cat <<$X\n./a/x.sh\n$X", READ), ("cat <<'END X'\n./a/x.sh\nEND X", READ),
    ("cat <<A <<B\nA\n./a/x.sh\nB", READ), ("echo ${{ fromJSON('1') }}; ./a/x.sh", READ),
    ("echo ${{ 2 > 1 }}; ./a/x.sh", READ), ('echo "${{ x }}"; ./a/x.sh', READ),
    ("cat <<'EOF'\nEOF # x\n./a/x.sh\nEOF", READ), ("true # cat <<EOF\n./a/x.sh\nEOF", READ),
    ("echo \\; ./a/x.sh", READ), ("echo '(' ./a/x.sh", READ), ("cat <<1E\n./a/x.sh\n1E", READ),
    # An argument, quoted text, or after a hash.
    ("bash ./a/x.sh", NOT_READ), ("python ./a/x.sh", NOT_READ), ("python tools/b.py \\\n  ./a/x.sh", NOT_READ),
    (". ./a/x.sh", NOT_READ), ("echo 'a; ./a/x.sh'", NOT_READ), ("true ! ./a/x.sh", NOT_READ),
    ("true { ./a/x.sh", NOT_READ), ("true } ./a/x.sh", NOT_READ), ("CMD=./a/x.sh\n$CMD", NOT_READ),
    ("echo hi # done; ./a/x.sh", NOT_READ), ("# note && ./a/x.sh", NOT_READ), ("true;# x; ./a/x.sh", NOT_READ),
    ("case ./a/x.sh in *) true;; esac", NOT_READ),
    ('echo a"b; ./a/x.sh"', NOT_READ), ('echo "a\n./a/x.sh"', NOT_READ),
    # Written into a longer word.
    ("./a/x.sh#x", NOT_READ), ("./a/x.sh\\ arg", NOT_READ), ("`./a/x.sh`", NOT_READ),
    # On the line after a line that ends with a backslash.
    ("# old \\\n./a/x.sh", NOT_READ), ("# old-tool --flag \\\n./a/x.sh", NOT_READ),
    ("# ./scripts/old.sh --flag \\\n./a/x.sh", NOT_READ), ("true # note \\\n./a/x.sh", NOT_READ),
    ("echo hi # note \\\n./a/x.sh", NOT_READ), ('echo "a" # x \\\n./a/x.sh', NOT_READ),
    ("# note \\\\\n./a/x.sh", NOT_READ), ("echo a \\\\\n./a/x.sh", NOT_READ), ("echo foo\\\\\n./a/x.sh", NOT_READ),
    ("# note \\\n./a/x.sh", NOT_READ),
    # Between two lines whose quotes pair up.
    ("echo \\\"x\\\" # it's\n./a/x.sh\necho it\\'s", NOT_READ),
    ("echo \"a\\\\\" # don't\n./a/x.sh\necho it\\'s", NOT_READ),
    ("echo $'it\\'s'\n./a/x.sh\necho it\\'s", NOT_READ),
    # Inside or after a here-document, or a word holding <<.
    ("cat <<'EOF'\n./a/x.sh\nEOF", NOT_READ), ("cat <<END\n./a/x.sh\n \tEND \n", NOT_READ),
    ("cat <<'EOF' > /dev/null\nline \\\nEOF\n./a/x.sh\ncat <<'EOF' > /dev/null\nz\nEOF", NOT_READ),
    ('echo "<<END"\n./a/x.sh\nEND\n', NOT_READ), ('echo "see <<END"\n./a/x.sh\nEND', NOT_READ),
    ("echo '<<EOF'\n./a/x.sh\nEOF", NOT_READ), ("a=1; b=1; echo $((a<<b))\n./a/x.sh\nb", NOT_READ),
    ("cat <<END-X\nEND-X\n./a/x.sh\nEND\n", NOT_READ),
    ('echo "<<END"\n./a/x.sh\nEND\ntrue', NOT_READ),
    # After a redirection, or a word that is one.
    ("sort < ./a/x.sh > out/h.txt", NOT_READ), ("sort < data/g.txt > ./a/x.sh", NOT_READ),
    ("while read -r l; do true; done < <(./a/x.sh)", NOT_READ), ("make > >(./a/x.sh)", NOT_READ),
    ("echo hi > >(./a/x.sh)", NOT_READ), ("true 2> >(./a/x.sh)", NOT_READ), ('echo ">"\n./a/x.sh', NOT_READ),
    ("echo \\>\n./a/x.sh", NOT_READ), ('echo ">"; ./a/x.sh', NOT_READ), ('echo "<"\n./a/x.sh', NOT_READ),
    ('echo "&>"\n./a/x.sh', NOT_READ), ("2> err.txt ./a/x.sh", NOT_READ), ("2>/dev/null ./a/x.sh", NOT_READ),
    (">/dev/null 2>&1 ./a/x.sh", NOT_READ),
    ("while read l; do echo $l; done < <(./a/x.sh)", NOT_READ), ("cmd > >(./a/x.sh arg)", NOT_READ),
    ("echo '<' && ./a/x.sh", NOT_READ), ('echo "<<"\n./a/x.sh', NOT_READ), ("true &> f ./a/x.sh", NOT_READ),
    # A substitution inside double quotes, or in backquotes.
    ('V="$(./a/x.sh)"', NOT_READ), ('echo "$(./a/x.sh)"', NOT_READ),
    ('if [ -n "$(./a/x.sh)" ]; then true; fi', NOT_READ), ('[[ "$(./a/x.sh)" == ok ]]', NOT_READ),
    ('echo "v=$(./a/x.sh)" >> "$GITHUB_OUTPUT"', NOT_READ), ('VERSION="$(./a/x.sh --version)"', NOT_READ),
    ('echo $(echo "$(./a/x.sh)")', NOT_READ), ('f() { local v="$(./a/x.sh)"; }; f', NOT_READ),
    ("echo `./a/x.sh`", NOT_READ),
    ("x=`./a/x.sh`", NOT_READ), ('if [ -n "$(./a/x.sh)" ]; then echo y; fi', NOT_READ),
    # A one-line body of the function keyword.
    ("function f { ./a/x.sh; }", NOT_READ), ("function f { ./a/x.sh; }; f", NOT_READ),
    ("function f { ./a/x.sh; }\nf", NOT_READ),
    # After a word of these forms in front of it.
    ("A+=1 ./a/x.sh", NOT_READ), ("A[0]=1 ./a/x.sh", NOT_READ), ("FLAGS+=-v ./a/x.sh", NOT_READ),
    ("PATH+=:/opt/x ./a/x.sh", NOT_READ), ("sudo -u bob ./a/x.sh", NOT_READ), ("env -u NAME ./a/x.sh", NOT_READ),
    ("env -C dir ./a/x.sh", NOT_READ), ("exec -a name ./a/x.sh", NOT_READ),
    ("PATH+=:/x ./a/x.sh", NOT_READ),
    # Run by another program.
    ("timeout 600 ./a/x.sh", NOT_READ), ("nice -n 5 ./a/x.sh", NOT_READ), ("ionice -c 3 ./a/x.sh", NOT_READ),
    ("stdbuf -oL ./a/x.sh", NOT_READ), ("taskset -c 0 ./a/x.sh", NOT_READ), ("setsid ./a/x.sh", NOT_READ),
    ("chrt -f 1 ./a/x.sh", NOT_READ), ("echo a | xargs -n 1 ./a/x.sh", NOT_READ),
    ("find . -exec ./a/x.sh ;", NOT_READ), ("parallel ./a/x.sh ::: 1", NOT_READ), ("watch ./a/x.sh", NOT_READ),
    ("flock /tmp/l ./a/x.sh", NOT_READ), ("chroot / ./a/x.sh", NOT_READ), ("xvfb-run ./a/x.sh", NOT_READ),
    ("script -c ./a/x.sh", NOT_READ), ("su -c ./a/x.sh", NOT_READ), ("runuser -u bob ./a/x.sh", NOT_READ),
    ("doas ./a/x.sh", NOT_READ), ("pkexec ./a/x.sh", NOT_READ), ("fakeroot ./a/x.sh", NOT_READ),
    ("firejail ./a/x.sh", NOT_READ), ("unbuffer ./a/x.sh", NOT_READ), ("faketime 2020 ./a/x.sh", NOT_READ),
    ("strace ./a/x.sh", NOT_READ), ("valgrind ./a/x.sh", NOT_READ), ("gdb -batch ./a/x.sh", NOT_READ),
    ("catchsegv ./a/x.sh", NOT_READ), ("unshare ./a/x.sh", NOT_READ), ("nsenter -t 1 ./a/x.sh", NOT_READ),
    ("systemd-run ./a/x.sh", NOT_READ), ("caffeinate ./a/x.sh", NOT_READ), ("busybox ./a/x.sh", NOT_READ),
    ("docker run img ./a/x.sh", NOT_READ), ("ssh host ./a/x.sh", NOT_READ), ("coproc ./a/x.sh", NOT_READ),
    ("true; coproc ./a/x.sh; wait", NOT_READ), ("coproc X { ./a/x.sh; }", NOT_READ),
    ("trap './a/x.sh' EXIT", NOT_READ), ("eval ./a/x.sh", NOT_READ), ("bash -c './a/x.sh'", NOT_READ),
    ("sh -c './a/x.sh'", NOT_READ), ("bash -lc './a/x.sh'", NOT_READ),
    # The step's shell, or its job's.
    ({"run": "./a/x.sh", "shell": "bash"}, READ), ({"run": "./a/x.sh", "shell": "bash -e {0}"}, READ),
    ({"run": "./a/x.sh", "shell": "sh"}, READ), ({"run": "./a/x.sh", "defaults": {"run": {"shell": "bash"}}}, READ),
    ({"run": "./a/x.sh", "shell": "/bin/bash -e {0}"}, NOT_READ), ({"run": "./a/x.sh", "shell": "pwsh"}, NOT_READ),
    ({"run": "./a/x.sh", "defaults": {"run": {"shell": "/bin/bash -e {0}"}}}, NOT_READ),
    # Refused.
    ("cat <<EOF\n./a/x.sh\n", REFUSED), ('echo "a\nb # c"\n./a/x.sh', REFUSED),
    ('echo "a\\\\" "b # c" ; ./a/x.sh', REFUSED), ("echo $'a\\'b'; ./a/x.sh", REFUSED),
    ("echo $'it\\'s' # c\n./a/x.sh", REFUSED), ("cat <<'EOF' > /dev/null\nfoo \\\nEOF\n./a/x.sh", REFUSED),
)


def probe_outcomes(rows) -> list:
    """What the guard does with the planted script of each row: every row
    becomes the one step of its own job in a planted workflow, read through
    ``run_blocks`` and ``command_paths`` as the checkout test reads the
    real ones."""
    jobs = {}
    for i, (step, _outcome) in enumerate(rows):
        step = dict(step) if isinstance(step, dict) else {"run": step}
        jobs["row%d" % i] = {"runs-on": "x", "defaults": step.pop("defaults", {}), "steps": [step]}
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "probes.yml").write_text(yaml.safe_dump({"jobs": jobs}), encoding="utf-8")
        blocks = {site.split(":")[1]: run for site, _wd, run in run_blocks(Path(d))}
    outcomes = []
    for job_name, job in jobs.items():
        run = blocks.get(job_name)
        if run is None:
            outcomes.append(NOT_READ)
            continue
        if run != job["steps"][0]["run"]:
            raise ValueError("%s did not reach the reader unchanged" % job_name)
        try:
            words = [posixpath.normpath(word) for word, _path in command_paths(run)]
        except ValueError:
            outcomes.append(REFUSED)
            continue
        outcomes.append(READ if _PLANTED in words else NOT_READ)
    return outcomes


class TheProbeTable(unittest.TestCase):
    """``READER_PROBES``, the specification of what the guard reads."""

    def test_the_guard_does_what_every_row_says(self):
        outcomes = probe_outcomes(READER_PROBES)
        self.assertEqual(len(outcomes), len(READER_PROBES))
        for (step, outcome), got in zip(READER_PROBES, outcomes):
            with self.subTest(step=step):
                self.assertEqual(got, outcome)

    def test_every_row_plants_the_script_and_is_stated_once(self):
        # A row with no planted script would hold "not read" vacuously, and
        # a row stated twice could state two outcomes.
        seen = set()
        for step, outcome in READER_PROBES:
            run = step["run"] if isinstance(step, dict) else step
            with self.subTest(step=step):
                self.assertIn(outcome, (READ, NOT_READ, REFUSED))
                self.assertIn("x.sh", run)
                self.assertNotIn(repr(step), seen, "a row stated twice")
            seen.add(repr(step))


class CommandPositionReader(unittest.TestCase):
    """Where a command path resolves, no checkout needed."""

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
