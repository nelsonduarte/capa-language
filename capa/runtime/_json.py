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
        # Keep integers whenever possible for cleaner output.
        if j.value == int(j.value):
            return int(j.value)
        return j.value
    if isinstance(j, JStr):
        return j.value
    if isinstance(j, JArr):
        return [_json_value_to_python(x) for x in j.value]
    if isinstance(j, JObj):
        return {k: _json_value_to_python(v) for k, v in j.value.items()}
    raise TypeError(f"not a JsonValue: {j!r}")


def parse_json(s):
    """Parses a JSON string. Returns ``Ok(JsonValue)`` on success or
    ``Err(message)`` on syntax error."""
    try:
        return Ok(_python_to_json_value(_stdlib_json.loads(s)))
    except (ValueError, AttributeError) as e:
        return Err(str(e))


def to_json(j):
    """Serializes a JsonValue as a JSON string. Always returns String."""
    return _stdlib_json.dumps(_json_value_to_python(j), ensure_ascii=False)
