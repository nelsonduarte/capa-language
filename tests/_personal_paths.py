"""The personal-path guard's matcher and scan; its tests are in
``tests/test_no_personal_paths.py``.

Fail-closed guard: no tracked file may carry a personal path.

The project bans, in anything shareable, absolute paths that name a
person's account and paths that describe one machine's home layout.
The ban was a reading rule, and a reading rule had let a builder's
temporary directory into a committed CSV (138 rows written by a
harness), an account name into a lexer fixture, and one home layout
into script comments, a workflow, a design note and a harness default.
This module turns the rule into a check over every tracked file.

What is a finding, three kinds, and where each is checked:

* ``user directory``, checked everywhere: a path through a users or
  home directory followed by a name that is not on
  ``NON_PERSONAL_NAMES``. The rule refuses every unjustified name, not
  one account. The forms it matches are a drive letter followed by
  ``Users`` in any letter case, ``/Users`` or ``\\Users`` with a
  capital U, and ``/home`` not preceded by a word, each followed by any
  run of backslashes, slashes or their percent-encoded forms (either
  letter case) and then the name. That covers a plain Windows path,
  the JSON-doubled and forward-slash forms, and the MSYS, macOS and
  Linux forms. It does NOT cover, measured: drive-less lower-case
  ``users`` paths (a WSL mount, a UNC share), the WSL UNC form of a
  home directory, ``/var/home``, ``/export/home``, ``../home``,
  ``~name``, a path wrapped across lines or assembled by concatenation
  or a path join, separators written as escapes (``\\u005c``,
  ``\\x5c``, an HTML entity) or percent-encoded twice, localised or
  legacy profile folder names, and compressed or base64 content.
* ``home layout``, checked everywhere: the desktop or application-data
  folder of a user profile used as a path component, meaning next to a
  separator or a quote (so a path composed from the home directory in
  code is caught as well as a written one). The bare word in prose is
  left alone.
* ``running account``, checked only where the person running the test
  has a personal account: the account name of whoever runs the test,
  read from the machine at run time (the login name and the last
  component of the home directory), as a token in any letter case that
  is not followed by a letter. It catches what the two path rules miss:
  the name in a host name, after ``@``, in a path flattened with
  dashes, or in a path the rules above do not parse. It is NOT checked
  for a name on ``GENERIC_ACCOUNTS`` (CI runners and container
  defaults), a name shorter than ``MIN_ACCOUNT_LENGTH``, or a name equal,
  in any letter case, to a whole word of the author names published in
  ``pyproject.toml`` (a published name guards nothing, and it occurs in
  the licences and the examples). That last exemption is exact: a name
  that is only part of an author word, or an author word with more
  letters, is still checked, so it cannot switch the check off for an
  account named after a shortened or extended form of a published name.
  So on a CI runner or in a container running as root this kind checks
  nothing, and on a developer's own machine it checks that developer's
  account. This file names no particular account and holds nothing an
  account could be recovered from.

A failure reports file, kind and line numbers, never the offending
text, so a public CI log does not repeat what it found.

Scope of the scan, stated so a green run is not over-read: every entry
``git ls-files -s`` lists, the same way on every platform.

* A regular file is read in full from the working tree, whatever its
  extension, size or encoding, as raw bytes plus a projection with the
  NUL bytes removed (for UTF-16 text). A file deleted from the working
  tree is skipped.
* A symbolic link is scanned as the link target recorded in the index,
  never as the file it points to, so a Linux checkout (a real link)
  and a Windows checkout (a text file) are scanned identically.
* A gitlink (a submodule) is a failure: its content is in another
  repository this module cannot read.

It does not inflate compressed containers, does not read commit
messages, and does not read untracked or ignored files. An unpacked
source distribution has no ``.git`` and the tracked-file tests skip
there; in a checkout, failing to enumerate is a failure, not a skip.
"""

from __future__ import annotations

import functools
import getpass
import re
import subprocess
from pathlib import Path
from typing import Iterable, NamedTuple

REPO_ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = REPO_ROOT / "pyproject.toml"

#: Names that may follow a users or home directory because they are not
#: a person's account. Each justification names every file it excuses
#: (``test_every_excuse_names_every_file_it_excuses`` in the test module
#: fails otherwise), and an entry that excuses nothing fails
#: ``test_the_allow_list_has_no_stale_entry``.
NON_PERSONAL_NAMES = {
    "RUNNER~1": "GitHub Actions Windows runner, 8.3 short form, quoted in "
                "the tests/test_cli.py docstring that explains short names",
    "runneradmin": "GitHub Actions Windows runner account, in the same "
                   "tests/test_cli.py docstring",
    "...": "an elided path in prose: CHANGELOG.md (raw strings) and the "
           "tests/test_release_guards.py docstring",
    "n": "one-letter placeholder in the basename fixture of "
         "evaluation/sbom_diff/glob_walker/capa.capa",
    "noone": "placeholder account in the raw-string fixture of "
             "tests/test_lexer.py; its leading n keeps a backslash-n "
             "sequence in the path under test",
    "user": "placeholder account in a CVE walkthrough "
            "(docs/cve_eslint_scope.md), in file URL fixtures "
            "(tests/test_pkg.py) and in a comment giving an example file "
            "URL (capa/pkg/_manifest.py)",
    "victim": "placeholder account in a CVE walkthrough "
              "(docs/cve_eslint_scope.md)",
    "data": "placeholder directory in the attenuation example "
            "examples/wasm/allows_dynamic.capa and its parity test "
            "tests/test_ir_wasm_parity.py",
    "database": "the sibling-prefix twin of data in the same boundary "
                "example: examples/wasm/allows_dynamic.capa and "
                "tests/test_ir_wasm_parity.py",
}

#: Home-layout fragments that are not the project's own layout. Keyed by
#: (tracked path, text the offending line must contain). Same staleness
#: rule as above.
NON_PERSONAL_LAYOUT_LINES = {
    ("docs/cve_node_ipc.md", "WITH-LOVE-FROM-AMERICA"):
        "third-party text: the path the node-ipc malware wrote to",
    ("tests/test_cli.py", "RUNNER~1"):
        "the CI runner's temporary directory, quoted in a docstring",
}

#: Account names the running-account check skips: CI runner accounts and
#: container or image defaults, which are nobody's personal account.
GENERIC_ACCOUNTS = frozenset({
    "runner", "runneradmin", "root", "admin", "administrator", "user",
    "guest", "nobody", "default", "public", "shared", "vscode", "node",
    "codespace", "codespaces", "gitpod", "jenkins", "buildkite", "travis",
    "circleci", "appveyor", "vagrant", "ubuntu", "debian", "fedora",
    "ec2-user", "docker", "builder", "build", "app", "test", "dev",
})

#: Shorter account names occur inside too many ordinary words to check.
MIN_ACCOUNT_LENGTH = 4

_SEP = rb"(?:[\\/]|%5[Cc]|%2[Ff])"
_NAME = rb"([^\\/\s\"'`<>|:*?%,;()\[\]{}]+)"
_USER_DIR = re.compile(
    rb"(?:[A-Za-z]:" + _SEP + rb"+(?i:users)"  # drive form, any letter case
    rb"|" + _SEP + rb"Users"                   # macOS, MSYS, UNC
    rb"|(?<![A-Za-z0-9_.-])/home)"             # Linux; not a URL segment
    + _SEP + rb"+" + _NAME
)
_FOLDERS = b"|".join([b"Desk" + b"top", b"App" + b"Data"])
_EDGE = rb"[\\/\"']"
_LAYOUT = re.compile(
    rb"(?<=" + _EDGE + rb")(?:" + _FOLDERS + rb")(?![A-Za-z0-9_])"
    rb"|(?<![A-Za-z0-9_])(?:" + _FOLDERS + rb")(?=" + _EDGE + rb")"
)

USER_DIR = "user directory"
LAYOUT = "home layout"
ACCOUNT = "running account"

_MODE_LINK = "120000"
_MODE_GITLINK = "160000"


class Finding(NamedTuple):
    kind: str
    line: int
    #: The directory name for a ``user directory`` finding, else "".
    name: str
    #: The whole offending line, for the allow-list only. Never printed.
    text: str


class ScanResult(NamedTuple):
    #: Findings no allow-list entry excuses, per tracked path.
    violations: "dict[str, list[Finding]]"
    #: Allow-list key -> the tracked paths it excused.
    used: "dict[object, set[str]]"
    #: Tracked gitlinks, whose content this module cannot read.
    gitlinks: "list[str]"


# ------------------------------------------------------------- accounts


def machine_account_names() -> "set[str]":
    """The running account's names, read from this machine: the login
    name and the last component of the home directory."""
    names: "set[str]" = set()
    try:
        names.add(getpass.getuser())
    except (OSError, KeyError, ImportError):  # no name known to the OS
        pass
    try:
        names.add(Path.home().name)
    except RuntimeError:  # no home directory known to the OS
        pass
    return {n for n in names if n}


def published_author_words(pyproject: "Path | None" = None) -> "set[str]":
    """Lower-case words of the author names in ``pyproject.toml``.

    Only an exemption: a parse that finds nothing makes the account
    check stricter, never weaker.
    """
    path = PYPROJECT if pyproject is None else pyproject
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    block = re.search(r"(?ms)^authors\s*=\s*\[(.*?)^\]", text)
    if block is None:
        return set()
    names = re.findall(r'\bname\s*=\s*"([^"]*)"', block.group(1))
    return {w.lower() for n in names for w in n.split()}


def checked_accounts(
    names: "Iterable[str]", author_words: "Iterable[str]",
) -> "frozenset[bytes]":
    """The account names the running-account check looks for: every
    name that is personal by the rules in the module docstring."""
    authors = {w.lower() for w in author_words}
    return frozenset(
        n.encode("utf-8") for n in names
        if len(n) >= MIN_ACCOUNT_LENGTH
        and n.lower() not in GENERIC_ACCOUNTS
        and n.lower() not in authors
    )


def running_accounts() -> "frozenset[bytes]":
    return checked_accounts(machine_account_names(), published_author_words())


@functools.lru_cache(maxsize=None)
def _account_pattern(accounts: "frozenset[bytes]") -> "re.Pattern[bytes] | None":
    if not accounts:
        return None
    alternatives = b"|".join(re.escape(a) for a in sorted(accounts))
    return re.compile(rb"(?:" + alternatives + rb")(?![A-Za-z])", re.I)


# -------------------------------------------------------------- matcher


def find_personal_paths(
    data: bytes, accounts: "Iterable[bytes | str]" = (),
) -> "list[Finding]":
    """Every finding in one file's bytes, allow-list NOT applied.

    ``accounts`` are the names the running-account kind looks for;
    with none, only the two path kinds are checked.
    """
    account = _account_pattern(frozenset(
        a.encode("utf-8") if isinstance(a, str) else a for a in accounts
    ))
    layers = [data]
    if b"\x00" in data:
        layers.append(data.replace(b"\x00", b""))
    seen: "set[tuple[str, int, str]]" = set()
    found: "list[Finding]" = []
    for buf in layers:
        hits = [(USER_DIR, m, m.group(1).decode("utf-8", "replace"))
                for m in _USER_DIR.finditer(buf)]
        hits += [(LAYOUT, m, "") for m in _LAYOUT.finditer(buf)]
        if account is not None:
            hits += [(ACCOUNT, m, "") for m in account.finditer(buf)]
        for kind, m, name in hits:
            line = buf.count(b"\n", 0, m.start()) + 1
            if (kind, line, name) in seen:
                continue
            seen.add((kind, line, name))
            start = buf.rfind(b"\n", 0, m.start()) + 1
            end = buf.find(b"\n", m.end())
            text = buf[start:end if end >= 0 else len(buf)]
            found.append(
                Finding(kind, line, name, text.decode("utf-8", "replace"))
            )
    return found


def excuse_for(path: str, finding: Finding) -> "object | None":
    """The allow-list key that excuses ``finding``, or ``None``.

    The single place the allow-lists are consulted, so the scan and the
    staleness check cannot disagree about what an entry covers.
    """
    if finding.kind == USER_DIR and finding.name in NON_PERSONAL_NAMES:
        return finding.name
    if finding.kind == LAYOUT:
        for key in NON_PERSONAL_LAYOUT_LINES:
            if key[0] == path and key[1] in finding.text:
                return key
    return None


def stale_entries(used: "Iterable[object]") -> "set[object]":
    """Allow-list keys that excused nothing in a scan."""
    entries = set(NON_PERSONAL_NAMES) | set(NON_PERSONAL_LAYOUT_LINES)
    return entries - set(used)


# ----------------------------------------------------------------- scan


def _git(root: Path, *args: str, stdin: bytes = b"") -> bytes:
    proc = subprocess.run(
        ["git", "-C", str(root), *args], input=stdin, capture_output=True,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"git {args[0]} failed in a checkout whose tracked files must "
            f"be scanned: {proc.stderr.decode('utf-8', 'replace').strip()}"
        )
    return proc.stdout


def tracked_entries(root: Path = REPO_ROOT) -> "list[tuple[str, str, str]] | None":
    """(mode, object id, path) per tracked entry, or ``None`` outside a
    git checkout."""
    if not (root / ".git").exists():
        return None
    out = _git(root, "ls-files", "-s", "-z")
    entries = []
    for record in out.decode("utf-8").split("\x00"):
        if not record:
            continue
        meta, path = record.split("\t", 1)
        mode, oid, _stage = meta.split()
        entries.append((mode, oid, path))
    return entries


def tracked_files(root: Path = REPO_ROOT) -> "list[str] | None":
    entries = tracked_entries(root)
    return None if entries is None else [p for _m, _o, p in entries]


def _indexed_blobs(root: Path, oids: "list[str]") -> "list[bytes]":
    """The bytes of the given objects, from one ``git cat-file`` call."""
    if not oids:
        return []
    out = _git(root, "cat-file", "--batch",
               stdin="".join(o + "\n" for o in oids).encode())
    blobs, pos = [], 0
    for oid in oids:
        nl = out.index(b"\n", pos)
        header = out[pos:nl].split()
        if len(header) != 3 or header[0].decode() != oid:
            raise AssertionError(f"git cat-file could not read {oid}")
        size = int(header[2])
        blobs.append(out[nl + 1:nl + 1 + size])
        pos = nl + 1 + size + 1
    return blobs


def scan_tracked(
    root: Path = REPO_ROOT, accounts: "Iterable[bytes] | None" = None,
) -> ScanResult:
    """Scan every tracked entry of ``root`` as the docstring states."""
    if accounts is None:
        accounts = running_accounts()
    accounts = frozenset(accounts)
    violations: "dict[str, list[Finding]]" = {}
    used: "dict[object, set[str]]" = {}
    gitlinks: "list[str]" = []
    contents: "list[tuple[str, bytes]]" = []
    links: "list[tuple[str, str]]" = []
    for mode, oid, rel in tracked_entries(root) or []:
        if mode == _MODE_GITLINK:
            gitlinks.append(rel)
        elif mode == _MODE_LINK:
            links.append((rel, oid))
        else:
            full = root / rel
            if full.is_file():  # skipped only when deleted in the tree
                contents.append((rel, full.read_bytes()))
    contents += zip([r for r, _o in links],
                    _indexed_blobs(root, [o for _r, o in links]))
    for rel, data in contents:
        for finding in find_personal_paths(data, accounts):
            key = excuse_for(rel, finding)
            if key is None:
                violations.setdefault(rel, []).append(finding)
            else:
                used.setdefault(key, set()).add(rel)
    return ScanResult(violations, used, sorted(gitlinks))


def render(violations: "dict[str, list[Finding]]") -> str:
    """File, kind and line numbers only: the text is never repeated."""
    out = []
    for rel in sorted(violations):
        by_kind: "dict[str, list[int]]" = {}
        for f in violations[rel]:
            by_kind.setdefault(f.kind, []).append(f.line)
        for kind in sorted(by_kind):
            lines = sorted(set(by_kind[kind]))
            shown = ", ".join(str(n) for n in lines[:6])
            more = f" (+{len(lines) - 6} more lines)" if len(lines) > 6 else ""
            out.append(f"  {rel}: {kind}: line {shown}{more}")
    return "\n".join(out)
