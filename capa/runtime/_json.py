"""JSON sum type and parse / serialize helpers.

``JsonValue`` is a static union of six dataclass variants
(``JNull``, ``JBool``, ``JNum``, ``JStr``, ``JArr``, ``JObj``). The
shared base ``_JsonBase`` defines default ``as_*`` extractors that
return ``None_``; each concrete variant overrides exactly the one
that matches its own shape.

- ``parse_json``: returns ``Ok(JsonValue)`` or ``Err(message)``.
- ``to_json``: serialises a ``JsonValue`` back to a JSON string.
"""

from __future__ import annotations

import json as _stdlib_json
import math as _math
from dataclasses import dataclass

from ._list import CapaList
from ._result import Err, None_, Ok, Some, _NoneType


class _JsonBase:
    """Base class for JsonValue. Defines default extraction methods that
    return ``None_`` (Option), overridden by each variant that matches
    the extracted type.

    The methods here are called via the normal method dispatch, the
    user writes ``j.as_string()`` in Capa, and the transpiler emits
    ``j.as_string()`` in Python, which resolves via MRO to the right
    class.
    """

    def is_null(self) -> bool:
        return False

    def as_bool(self):
        return None_

    def as_num(self):
        return None_

    def as_number(self):
        # Alias for as_num. Capa's JsonValue API now exposes both
        # the terse and the verbose form; both call through to the
        # same Some(value) when this is a JNum.
        return self.as_num()

    def as_int(self):
        # Best-effort integer projection. JSON has only one numeric
        # type, mapped to float on the Capa side; as_int returns
        # Some(int(value)) only when the float is integer-valued
        # (1.0, -7.0) and None_ otherwise (3.14).
        n_opt = self.as_num()
        if isinstance(n_opt, _NoneType):
            return None_
        v = n_opt.value
        if isinstance(v, float) and v.is_integer():
            return Some(int(v))
        if isinstance(v, int):
            return Some(v)
        return None_

    def as_string(self):
        return None_

    def as_array(self):
        return None_

    def as_object(self):
        return None_


@dataclass(frozen=True)
class JNull(_JsonBase):
    """JSON null."""
    def __str__(self) -> str:
        return "JNull"

    def is_null(self) -> bool:
        return True


@dataclass(frozen=True)
class JBool(_JsonBase):
    """JSON boolean."""
    value: bool
    def __str__(self) -> str:
        return f"JBool({self.value})"

    def as_bool(self):
        return Some(self.value)


@dataclass(frozen=True)
class JNum(_JsonBase):
    """JSON number (unifies int and float into float).

    Capa unifies the two JSON numeric types into a single variant,
    represented as Float. For integer values, the user can use
    ``int(n.value)`` at runtime or match against a specific value.
    """
    value: float
    def __str__(self) -> str:
        return f"JNum({self.value})"

    def as_num(self):
        return Some(self.value)


@dataclass(frozen=True)
class JStr(_JsonBase):
    """JSON string."""
    value: str
    def __str__(self) -> str:
        return f"JStr({self.value!r})"

    def as_string(self):
        return Some(self.value)


@dataclass(frozen=True)
class JArr(_JsonBase):
    """JSON array (list of JsonValues)."""
    value: list  # CapaList[JsonValue]
    def __str__(self) -> str:
        return f"JArr({len(self.value)} items)"

    def as_array(self):
        return Some(self.value)


@dataclass(frozen=True)
class JObj(_JsonBase):
    """JSON object (map from String to JsonValue)."""
    value: dict  # dict[str, JsonValue]
    def __str__(self) -> str:
        return f"JObj({len(self.value)} keys)"

    def as_object(self):
        return Some(self.value)


# Static union for type hints; at runtime, any of these classes.
JsonValue = JNull | JBool | JNum | JStr | JArr | JObj


def _python_to_json_value(v):
    """Converts a Python value (result of json.loads) to JsonValue."""
    if v is None:
        return JNull()
    if isinstance(v, bool):
        return JBool(v)
    if isinstance(v, (int, float)):
        return JNum(float(v))
    if isinstance(v, str):
        return JStr(v)
    if isinstance(v, list):
        return JArr(CapaList(_python_to_json_value(x) for x in v))
    if isinstance(v, dict):
        return JObj({k: _python_to_json_value(x) for k, x in v.items()})
    return JNull()  # fallback for unexpected types


def _json_value_to_python(j):
    """Converts a JsonValue to Python (to feed json.dumps)."""
    if isinstance(j, JNull):
        return None
    if isinstance(j, JBool):
        return j.value
    if isinstance(j, JNum):
        # Keep integers whenever possible for cleaner output
        # (json.dumps(3.0) prints "3.0"; Capa's to_json prints "3"
        # on both backends). Two guards on the collapse:
        #
        # - non-finite floats: int(inf) raises OverflowError and
        #   int(nan) raises ValueError; a JNum can hold them even
        #   though parse_json rejects the NaN/Infinity constants,
        #   and to_json must never crash on data.
        # - negative zero: int(-0.0) is 0, which silently drops the
        #   sign. json.dumps with the real value emits "-0.0", and
        #   the bundled Wasm serialiser agrees, so -0.0 stays float.
        v = j.value
        if (
            isinstance(v, float)
            and _math.isfinite(v)
            and v == int(v)
            and not (v == 0.0 and _math.copysign(1.0, v) < 0.0)
        ):
            return int(v)
        return v
    if isinstance(j, JStr):
        return j.value
    if isinstance(j, JArr):
        return [_json_value_to_python(x) for x in j.value]
    if isinstance(j, JObj):
        return {k: _json_value_to_python(v) for k, v in j.value.items()}
    raise TypeError(f"not a JsonValue: {j!r}")


# Mirror of ``__CJ_MAX_DEPTH`` in ``capa/ir/_builtin_json.capa``:
# the bundled Wasm-side parser caps recursive nesting at 100 (its
# recursion runs on the real Wasm stack, where an adversarial
# ``[[[[...]]]]`` would otherwise trap or DoS). Python's json
# module has no such cap below the interpreter recursion limit,
# so the wrapper enforces the same one for cross-backend parity.
_MAX_DEPTH = 100


def _reject_constant(name):
    """``parse_constant`` hook: RFC 8259 has no NaN / Infinity /
    -Infinity. Python's ``json.loads`` accepts them by default
    (``allow_nan``); the bundled Wasm-side parser never did, and the
    strict reading wins, so both backends return ``Err``."""
    raise ValueError(
        f"{name} is not valid JSON (RFC 8259 has no NaN or Infinity)"
    )


def _depth_error(s):
    """Pre-scan for the nesting cap, mirroring the Wasm parser's
    rule: a value parsed inside more than ``_MAX_DEPTH`` enclosing
    containers is an error (a container may still OPEN at depth
    ``_MAX_DEPTH``; its elements are what overflow). The scan walks
    code points, skipping string literals (a bracket inside a quoted
    string nests nothing), and reports the same message at the same
    code-point position as the Wasm side's ``__cj_parse_value``.

    For inputs that are malformed BEFORE the depth overflow the two
    backends can word the error differently (this scan fires first
    where the Wasm parser errors at the earlier position); both
    sides still return ``Err``, which is the parity surface.
    """
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch in " \t\n\r,:":
            continue
        if ch in "]}":
            if depth > 0:
                depth -= 1
            continue
        # Everything else starts a value (container, string, or
        # scalar token; garbage is json.loads's problem).
        if depth > _MAX_DEPTH:
            return f"max nesting depth {_MAX_DEPTH} exceeded at {i}"
        if ch in "[{":
            depth += 1
        elif ch == '"':
            in_str = True
    return None


def parse_json(s):
    """Parses a JSON string. Returns ``Ok(JsonValue)`` on success or
    ``Err(message)`` on syntax error."""
    try:
        if isinstance(s, str):
            depth_err = _depth_error(s)
            if depth_err is not None:
                return Err(depth_err)
        return Ok(_python_to_json_value(
            _stdlib_json.loads(s, parse_constant=_reject_constant)
        ))
    except (ValueError, AttributeError) as e:
        return Err(str(e))


def to_json(j):
    """Serializes a JsonValue as a JSON string. Always returns String."""
    return _stdlib_json.dumps(_json_value_to_python(j), ensure_ascii=False)
