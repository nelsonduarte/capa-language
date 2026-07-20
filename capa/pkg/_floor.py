"""Enforcement of the ``capa = ">=X.Y.Z"`` manifest floor.

``[package].capa`` is a package's declaration of the OLDEST compiler it
can be built with. Until 1.19.0 the field was parsed into
``Manifest.capa_requirement`` and never read back, so a package
declaring ``capa = ">=1.18.1"`` built without a word of complaint on
1.2.0. That made every floor in the ecosystem unfalsifiable at the point
of use: ``capa_hex`` shipped ``>=1.1.0`` and 1.1.0 could not compile its
own example, and nothing noticed for the life of the package.

The failure mode is not "the build breaks". The build SUCCEEDS, and
produces an SBOM, a provenance record and a set of capability claims
derived by a compiler missing the very fix the floor existed to require.
See ``docs/advisories/2026-07-20-capa-floor.md``.

The policy, split by ROOT versus TRANSITIVE rather than by time:

  * The ROOT manifest's floor is a HARD ERROR. It is the project's own
    declaration about the machine doing the build, it is maximally
    evidenced, and the user can act on it (upgrade the compiler, or edit
    the floor they own).
  * A DEPENDENCY's floor is a WARNING, once per offending package and
    naming it. It is someone else's declaration that the consumer cannot
    fix by editing their own manifest, so a hard stop there is the case
    most likely to be a false stop.

  * A MISSING ``capa`` key is UNCONSTRAINED. Absence is not a violation.
    NOTE: this is the OPPOSITE of ``tools/capa_floor.sh``, which fails
    CLOSED on a missing key. The divergence is intentional and the two
    are answering different questions. The script asks "which released
    compiler must release guard 2 build this artefact with?", and there
    is no honest answer when nothing is declared, so it refuses rather
    than guessing. This module asks "does the running compiler violate a
    stated requirement?", and an unstated requirement is violated by
    nothing.

  * ``CAPA_IGNORE_CAPA_FLOOR=1`` (read as exactly ``"1"``) turns the
    hard error into a warning that always names what it let through. An
    escape that is silent is indistinguishable from no gate at all; see
    ``capa/pkg/_install.py`` for the same convention.

The grammar is deliberately identical to ``tools/capa_floor.sh``: the
compiler must not be STRICTER than the release guard, or a manifest that
PASSES the guard would FAIL the compiler, inverting the intended
relationship between the two. A bare ``"1.17.0"`` therefore means a
FLOOR and not a pin, because that is what the script already treats it
as. Both sides were tightened together to reject ``1.17``, ``1.2.3.4``
and ``1..2``, which the script's old ``[0-9][0-9.]*[0-9]`` accepted.
``tests/test_capa_floor.py`` feeds one corpus to both and asserts they
agree case for case.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Optional

# Exactly three numeric components. Tighter than the shell guard's
# historical ``[0-9][0-9.]*[0-9]``, which also accepted ``1.17``,
# ``1.2.3.4`` and ``1..2``; the guard was tightened to match.
_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")

# The accepted requirement forms, matching ``tools/capa_floor.sh``'s sed
# expression character for character, INCLUDING the optional whitespace:
# ``>=1.17.0``, ``1.17.0``, ``>= 1.17.0`` and a leading / trailing space
# are all accepted. Only space and tab are allowed, because the shell
# side works line-wise and can never see a vertical whitespace character
# inside the value.
_REQUIREMENT_RE = re.compile(
    r"^[ \t]*(?:>=[ \t]*)?([0-9]+\.[0-9]+\.[0-9]+)[ \t]*$"
)

# The sentinel ``capa.__version__`` falls back to when neither the
# adjacent pyproject.toml nor the installed distribution metadata can be
# read (see ``capa/__init__.py``). Deliberately not a plausible release.
UNKNOWN_VERSION = "0+unknown"

IGNORE_ENV = "CAPA_IGNORE_CAPA_FLOOR"


class CapaFloorError(Exception):
    """The running compiler is older than the root manifest's declared floor.

    DELIBERATELY NOT A SUBCLASS OF ``ManifestError``. The reason is
    FORWARD-LOOKING and not a live path today, which is worth stating
    plainly so the next reader does not go hunting for the repro:
    ``capa/manifest/_compose.py`` catches ``(ManifestError, OSError,
    ValueError)`` around each DEPENDENCY's ``read_manifest``, and no
    ``CapaFloorError`` can reach that catch today, because dependency
    floors WARN (``warn_dependency_floor``) and never raise.

    The hazard it guards is what happens if that ever changes. A
    subclass caught there would be reported as "capa.toml is unreadable
    or invalid", turning a POLICY decision into a claim about file
    integrity: the composed SBOM would mark the dependency
    authority-UNKNOWN for a reason that has nothing to do with its
    authority. The same reasoning keeps
    :class:`capa.pkg.BrokenRootManifestError` out of the hierarchy, and
    there the hazard is live: it IS raised while reading a manifest.
    ``tests/test_capa_floor.py`` asserts both non-subclassings
    structurally, since the invariant is otherwise invisible.
    """


def parse_version(text: str) -> Optional[tuple[int, int, int]]:
    """Parse an exact ``X.Y.Z`` version. ``None`` when it is not one.

    Used for both sides of the comparison: the declared floor and the
    running ``capa.__version__``. The sentinel ``0+unknown`` fails here
    by construction, which is what makes the unknown-version branch
    reachable and explicit rather than an accidental comparison against
    zero.
    """
    if not isinstance(text, str) or not _VERSION_RE.match(text):
        return None
    major, minor, patch = text.split(".")
    return (int(major), int(minor), int(patch))


def parse_requirement(text: str) -> Optional[tuple[int, int, int]]:
    """Parse a ``[package].capa`` requirement into the floor it names.

    Accepts ``>=X.Y.Z`` and the bare ``X.Y.Z``, each with the optional
    whitespace ``tools/capa_floor.sh`` accepts. Returns ``None`` for
    anything else (ranges, carets, wildcards, two-component versions),
    which callers treat as unreadable rather than as satisfied.
    """
    if not isinstance(text, str):
        return None
    match = _REQUIREMENT_RE.match(text)
    if match is None:
        return None
    return parse_version(match.group(1))


def satisfies(running: tuple[int, int, int], floor: tuple[int, int, int]) -> bool:
    """Is ``running`` at or above ``floor``?

    Component-wise numeric comparison, which is the whole point: a
    lexical string comparison gets ``1.2.0`` versus ``1.11.0`` backwards
    (and ``1.9.0`` vs ``1.10.0``, and ``9.0.0`` vs ``10.0.0``). Tuple
    comparison over ints is exactly the ordering ``packaging.version``
    gives on three-component releases, verified over a 14400-pair grid
    while the golden table in ``tests/test_capa_floor.py`` was built.
    """
    return running >= floor


def ignore_requested() -> bool:
    """Is the ``CAPA_IGNORE_CAPA_FLOOR`` escape hatch engaged?

    Read as exactly ``"1"``, the same convention as ``CAPA_NO_VERIFY``
    and ``CAPA_ALLOW_MISSING_GH``: ``0``, ``false``, ``no`` and an empty
    value all mean "not engaged", so a half-remembered spelling fails
    safe instead of silently disabling the gate.
    """
    return os.environ.get(IGNORE_ENV) == "1"


def _running_version() -> str:
    """The version of the compiler doing the build.

    Single-sourced from ``capa.__version__`` (``capa/__init__.py``'s
    ``_resolve_version``), which reads the ADJACENT ``pyproject.toml``
    first and only then falls back to ``importlib.metadata``. That order
    is what makes the floor correct in a source checkout, an editable
    install with stale dist-info, a wheel and the frozen binary alike.
    Never call ``importlib.metadata.version`` here: a second version
    source is a second version, and the floor would then be enforced
    against a number nothing else in the toolchain reports.
    """
    from .. import __version__

    return __version__


def _remediation(floor_text: str, running: str, where: str) -> str:
    """The full remediation menu, in the shape ``_install.py`` uses.

    Three options, ordered from the durable to the disposable, and
    explicitly distinguishing a reviewable manifest-level decision from a
    for-this-run override.
    """
    return (
        f"How to proceed, most durable first:\n"
        f"  1. Upgrade the compiler to {floor_text} or newer "
        f"(`pip install --upgrade capa-lang`). This is the option the "
        f"floor is asking for.\n"
        f"  2. Lower or remove `capa` in {where} if the floor is wrong. "
        f"That is an explicit, reviewable decision that lives with the "
        f"project, and it is the right fix when the floor was copied "
        f"from a template or never re-checked against a real build.\n"
        f"  3. Set {IGNORE_ENV}=1 for this run, which builds anyway and "
        f"prints a warning naming the floor it ignored. Use it to get "
        f"unblocked, not to stay unblocked: the build it produces was "
        f"analysed by a compiler the package says is too old, so its "
        f"SBOM and capability claims carry that compiler's gaps."
    )


def check_root_floor(
    requirement: Optional[str],
    manifest_path: Path,
    *,
    running: Optional[str] = None,
    stream=None,
) -> None:
    """Enforce a ROOT manifest's floor. Raises :class:`CapaFloorError`.

    Returns silently when the manifest declares no floor (absence is
    unconstrained), when the running compiler satisfies it, or when the
    escape hatch is engaged (which always prints what it let through).
    """
    if stream is None:
        stream = sys.stderr
    if requirement is None:
        return

    running_text = _running_version() if running is None else running
    floor = parse_requirement(requirement)

    if floor is None:
        _refuse(
            f"capa: {manifest_path}: [package].capa = {requirement!r} is not "
            f"a requirement this compiler can read, so the floor it states "
            f"cannot be honoured.\n\n"
            f"Supported forms are \">=X.Y.Z\" and \"X.Y.Z\" (both mean a "
            f"FLOOR; the bare form is not a pin). Ranges, carets and "
            f"wildcards name no single release and are refused here for the "
            f"same reason tools/capa_floor.sh refuses them.\n\n"
            + _remediation("a readable floor", running_text, str(manifest_path)),
            stream,
        )
        return

    running_parsed = parse_version(running_text)
    if running_parsed is None:
        # The running compiler could not report its own version (the
        # ``0+unknown`` sentinel, reachable when a frozen build's
        # ``copy_metadata`` failed; see deploy/capa.spec). WARN, do not
        # refuse. A hard stop here would punish a packaging defect in the
        # compiler itself rather than anything about the manifest, and
        # the remediation menu would be empty: the user cannot upgrade to
        # satisfy a comparison that was never made, and editing their own
        # floor would not help either. The sentinel is already fail-closed
        # where it CAN be fixed, in deploy/binary_smoke_test.py, which
        # asserts official builds never reach it. So this branch only ever
        # fires on a build that is already known-broken, and it says so.
        print(
            f"capa: warning: cannot check the compiler floor in "
            f"{manifest_path}: this build reports its version as "
            f"{running_text!r}, not an X.Y.Z release, so it cannot be "
            f"compared against the declared {requirement!r}. The floor is "
            f"NOT being enforced for this build. An official Capa build "
            f"never reports this; a build that does was assembled without "
            f"its distribution metadata.",
            file=stream,
        )
        return

    if satisfies(running_parsed, floor):
        return

    floor_text = ".".join(str(p) for p in floor)
    _refuse(
        f"capa: {manifest_path}: this project declares "
        f"capa = {requirement!r}, but the compiler running the build is "
        f"{running_text}.\n\n"
        f"The floor is the oldest compiler the package says it can be "
        f"built with. Building below it does not fail loudly: it "
        f"SUCCEEDS, and emits an SBOM, a provenance record and capability "
        f"claims produced by a compiler missing whatever fix the floor "
        f"was raised for. That is why this is an error and not a "
        f"warning.\n\n"
        + _remediation(floor_text, running_text, str(manifest_path)),
        stream,
    )


def enforce_root_floor(
    project_dir: Path,
    *,
    running: Optional[str] = None,
    stream=None,
) -> None:
    """Read ``<project_dir>/capa.toml`` and enforce its floor.

    A MISSING manifest is unconstrained: there is no project to state a
    floor, so there is nothing to enforce.

    An UNREADABLE or INVALID manifest is refused, with
    :class:`BrokenRootManifestError`. This function used to swallow that
    case and return, on the reasoning that the CLI reported a broken
    ``capa.toml`` once already. It did report it, as a WARNING, and then
    built anyway. The consequence was that a one-letter typo anywhere in
    the manifest turned this gate off: a project declaring
    ``capa = ">=99.0.0"`` was refused, and the same project with
    ``max = ["stdio"]`` added to ``[capabilities]`` built and ran. A
    floor that a typo elsewhere in the file can disable is not a floor.

    So the two refusals travel together, and the ordering is the honest
    one: a manifest that cannot be PARSED cannot be shown to satisfy its
    floor, so it is refused before the floor is consulted rather than
    treated as declaring nothing.
    """
    from ._manifest import MANIFEST_FILENAME, read_root_manifest

    manifest_path = project_dir / MANIFEST_FILENAME
    if not manifest_path.is_file():
        return
    manifest = read_root_manifest(manifest_path)
    check_root_floor(
        manifest.capa_requirement, manifest_path,
        running=running, stream=stream,
    )


def _refuse(message: str, stream) -> None:
    """Raise, or warn and continue under the escape hatch.

    The escape never returns quietly. Every message it lets through is
    printed in full, prefixed so a log search for the variable name finds
    every build that used it.
    """
    if ignore_requested():
        print(
            f"capa: warning: {IGNORE_ENV}=1: building anyway, with the "
            f"compiler floor NOT enforced. The refusal that was "
            f"overridden follows.\n{message}",
            file=stream,
        )
        return
    raise CapaFloorError(message)


def warn_dependency_floor(
    requirement: Optional[str],
    package_name: str,
    manifest_path: Path,
    *,
    running: Optional[str] = None,
    stream=None,
) -> bool:
    """Warn about a DEPENDENCY whose floor the running compiler misses.

    Returns True when a warning was emitted. Never raises: a dependency's
    floor is someone else's declaration, and the consumer cannot fix it
    by editing their own manifest, so a hard stop there is the case most
    likely to be a false stop. Callers are responsible for calling this
    at most once per package (``build_package_dag`` memoises on the
    resolved manifest directory, so it already does).

    An unreadable requirement warns too, for the same reason it errors at
    the root: a floor that cannot be read cannot be honoured, and
    silently treating it as satisfied is the exact defect this whole
    change exists to close.
    """
    if stream is None:
        stream = sys.stderr
    if requirement is None:
        return False

    running_text = _running_version() if running is None else running
    running_parsed = parse_version(running_text)
    if running_parsed is None:
        # Same unknown-version branch as the root check. The root check
        # already warned once for this build; do not repeat it per
        # dependency.
        return False

    floor = parse_requirement(requirement)
    if floor is None:
        print(
            f"capa: warning: dependency {package_name!r} declares "
            f"capa = {requirement!r} in {manifest_path}, which is not a "
            f"requirement this compiler can read (supported: \">=X.Y.Z\" "
            f"and \"X.Y.Z\"). Its floor is not being checked.",
            file=stream,
        )
        return True

    if satisfies(running_parsed, floor):
        return False

    floor_text = ".".join(str(p) for p in floor)
    print(
        f"capa: warning: dependency {package_name!r} declares "
        f"capa = {requirement!r} ({manifest_path}), but this compiler is "
        f"{running_text}. The dependency states it needs {floor_text} or "
        f"newer, so anything it was analysed for above that version is "
        f"not being applied here. This is a warning and not an error "
        f"because the floor is the dependency's declaration, not yours: "
        f"upgrade the compiler to {floor_text} or newer, or report the "
        f"floor to {package_name!r} if you believe it is wrong.",
        file=stream,
    )
    return True
