"""The OUTCOME type and THE normaliser: one place.

Per (member, leg) a run ends in exactly one of six ways, and every
consumer (the oracles, the register, the ratchet, the controls) reads this
one enumeration:

  CORRECT        ran, and the exit class and stdout equal the rule's expectation
  WRONG:<key>    ran (or aborted) and differs; the key names WHICH wrong answer
  REFUSED        the checker refused a program the rule expects to compile
  TIMEOUT        the watchdog fired
  BROKEN         the compiler or the harness raised before the program ran
  VOID           provenance or ordering failure in the child

A transition INTO one of the last four is a REGRESSION: the instrument
stopped looking, which is never a fix.

The key is ``sha256(json(vector))[:16]``. For a run leg the vector is
``[exit_class, stdout]`` with stdout CRLF-normalised and nothing else:
no stderr, no traceback, no message text, no interpreter path, no code
offset, so a neutral emitter change, a Python version change or a
wasmtime upgrade cannot move it, while a changed exit class or a changed
byte of stdout does. The exit class is ``OK``, ``ABORT:<Python exception
class>`` on a Python leg, ``ABORT:wasm trap: <kind, hex offsets
replaced>`` on the Wasm leg, or ``ABORT:rc<N>`` on a command-line leg.
"""

from __future__ import annotations

import hashlib
import json
import re

CORRECT = "CORRECT"
WRONG = "WRONG"
REFUSED = "REFUSED"
TIMEOUT = "TIMEOUT"
BROKEN = "BROKEN"
VOID = "VOID"

OUTCOME_TYPES = (CORRECT, WRONG, REFUSED, TIMEOUT, BROKEN, VOID)

#: The outcomes a member can only enter by the instrument stopping to look.
NOT_RUN = frozenset({REFUSED, TIMEOUT, BROKEN, VOID})

#: Exit classes of a leg that RAN the program.
OK = "OK"
ABORT = "ABORT"

#: Expectations of the check leg.
ACCEPT = "ACCEPT"
REFUSE_IFC = "REFUSE-IFC"

_TRAP_LINE = re.compile(r"wasm trap: ([^\n]*)")
_HEX = re.compile(r"0x[0-9a-fA-F]+")


def outcome_type(outcome: str) -> str:
    return outcome.split(":", 1)[0]


def is_valid(outcome: str) -> bool:
    t = outcome_type(outcome)
    if t == WRONG:
        return len(outcome) == len(WRONG) + 1 + 16
    return t in OUTCOME_TYPES and outcome == t


def norm_text(s) -> str:
    return (s or "").replace("\r\n", "\n")


def exit_class_from_exception(exc) -> str:
    if exc is None:
        return OK
    name = type(exc).__name__
    if name == "Trap":
        m = _TRAP_LINE.search(str(exc))
        kind = m.group(1).strip() if m else "trap"
        return ABORT + ":wasm trap: " + _HEX.sub("0x?", kind)
    return ABORT + ":" + name


def exit_class_from_rc(rc: int) -> str:
    return OK if rc == 0 else ABORT + ":rc%s" % rc


def key(vector) -> str:
    return hashlib.sha256(json.dumps(list(vector)).encode("utf-8")).hexdigest()[:16]


def wrong(vector) -> str:
    return WRONG + ":" + key(vector)


def run_vector(exit_class: str, stdout: str) -> list:
    return [exit_class, norm_text(stdout)]


def expectation_text(exit: str, stdout: str) -> str:
    """The ONE format of an ``.expected`` file."""
    return json.dumps({"exit": exit, "stdout": stdout})


def expected_of(text: str) -> tuple:
    d = json.loads(text)
    return d["exit"], norm_text(d["stdout"])


def matches(exp_exit: str, exp_out: str, exit_class: str, stdout: str) -> bool:
    """THE rule comparison. An expected ABORT matches any ABORT kind (the
    abort text differs between backends; the effect is the same); stdout
    must be byte-equal after line-ending normalisation."""
    if norm_text(stdout) != exp_out:
        return False
    if exp_exit == OK:
        return exit_class == OK
    return exit_class.startswith(ABORT + ":")


def run_outcome(expected: tuple, row: dict) -> str:
    """The outcome of a run-leg row against the rule's ``(exit, stdout)``."""
    o = row["outcome"]
    if outcome_type(o) in NOT_RUN:
        return outcome_type(o)
    exp_exit, exp_out = expected
    if matches(exp_exit, exp_out, o, row.get("stdout", "")):
        return CORRECT
    return wrong(run_vector(o, row.get("stdout", "")))


def check_outcome(expected: str, row: dict) -> str:
    """The outcome of a check-leg row. ``expected`` is ACCEPT (the program
    must compile) or REFUSE-IFC (it must be refused with an information-flow
    error). A refusal of a program expected to compile is REFUSED, the
    regression class; the wrong verdict on a program expected to be refused
    is WRONG, keyed by what the checker said instead."""
    o = row["outcome"]
    if outcome_type(o) in (TIMEOUT, BROKEN, VOID):
        return outcome_type(o)
    refused = o == REFUSED
    if expected == ACCEPT:
        return REFUSED if refused else CORRECT
    if expected == REFUSE_IFC:
        if refused and row.get("ifc_errors", 0) > 0:
            return CORRECT
        return wrong(["refused-without-ifc-error" if refused else "accepted"])
    raise ValueError("unknown check expectation %r" % (expected,))
