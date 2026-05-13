"""Minimal runtime for Capa programs transpiled to Python.

This package provides the primitives that Capa programs need at runtime
but which are not part of the Python language:

- ``Result[T, E]`` and ``Option[T]`` (see :mod:`._result`): the sum
  types used for fallible and optional values.
- Concrete capabilities (see :mod:`._capabilities`): ``Stdio``,
  ``Fs``, ``Env``, ``Clock``, ``Random``, ``Net``, ``Proc``, ``Db``,
  ``Unsafe``. Each is instantiated in ``main`` and threaded through
  function arguments. There are no "ambient capabilities": importing
  this runtime does not grant any authority.
- The Python-interop boundary (see :mod:`._pyinterop`): ``py_import``
  and ``py_invoke``, both gated by ``Unsafe``.
- ``CapaList`` (see :mod:`._list`): the runtime list type.
- Builtin conversions (see :mod:`._convert`): ``parse_int``,
  ``parse_float``, ``to_int``, ``to_float``, plus the legacy ``?``
  helper ``_propagate_err``.
- JSON value type and codec (see :mod:`._json`): ``JsonValue``,
  ``parse_json``, ``to_json``.

Design conventions:

- Sum variants are simple *dataclasses*, without a complex hierarchy.
  Python 3.10+ match natively matches against these classes.
- Capability methods return ``Result`` when they can fail (real IO), and
  direct values when they cannot.
- There are no "ambient capabilities", a Python program that imports this
  runtime does not gain capacities by a simple import. It must instantiate
  ``Stdio()``, ``Fs()``, etc. and pass them explicitly. That discipline is
  what gives meaning to Capa's signatures.

The submodule split is purely internal organisation; the public API
is the names re-exported here and named in ``__all__``.
"""

from __future__ import annotations

from ._capabilities import (
    Clock,
    Db,
    Env,
    Fs,
    IoError,
    Net,
    Proc,
    Random,
    Stdio,
    Unsafe,
    _StubCapability,
)
from ._convert import (
    _propagate_err,
    parse_float,
    parse_int,
    to_float,
    to_int,
)
from ._json import (
    JArr,
    JBool,
    JNull,
    JNum,
    JObj,
    JStr,
    JsonValue,
    _JsonBase,
    _json_value_to_python,
    _python_to_json_value,
    parse_json,
    to_json,
)
from ._list import CapaList
from ._pyinterop import _require_unsafe, py_import, py_invoke
from ._result import (
    Err,
    None_,
    Ok,
    Option,
    Result,
    Some,
    _NoneType,
)


__all__ = [
    "Ok",
    "Err",
    "Result",
    "Some",
    "None_",
    "Option",
    "IoError",
    "Stdio",
    "Fs",
    "Env",
    "Clock",
    "Random",
    "Net",
    "Proc",
    "Db",
    "Unsafe",
    "py_import",
    "py_invoke",
    "to_float",
    "to_int",
    "_propagate_err",
]
