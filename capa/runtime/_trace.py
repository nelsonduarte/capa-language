"""Capability invocation trace, used by the property-based test
suite to assert soundness at runtime.

The instrumentation wraps the public methods of each built-in
capability class so every method call appends a record
``(class_name, method_name, first_arg)`` to a module-level list.
Tests read the list and compare it against the manifest the
analyser emits for the same program, asserting that the runtime
capability surface is a subset of the statically-declared one,
and (since the attenuation/exclusion slice) that every privileged
operation honoured the restriction in force on its capability.

``first_arg`` is the first positional argument of the call when
it is a string (the path read, the host contacted, the env key,
the prefix restricted to, ...) and ``None`` otherwise. It is the
single datum the "attenuation honoured" invariant needs: the
class+method alone cannot tell a read of ``/tmp/x`` from a read
of ``/etc/passwd``.

The instrumentation is **opt-in**: it is dormant unless a test
calls :func:`enable`. Production runs and the existing
end-to-end tests are unaffected -- nothing outside the property
suite ever calls :func:`enable`, so the wrapper (and the cost of
recording the argument) never runs in production. This matters
because patching the runtime classes has a measurable cost in
tight loops, and nobody outside the property suite cares about
the trace.
"""

from __future__ import annotations

from functools import wraps
from typing import Any, Optional


# Module-level accumulator. Tests should always call :func:`clear`
# at the top of each test to avoid bleed-over between cases. Each
# record is ``(class_name, method_name, first_arg)`` where
# ``first_arg`` is the first positional string argument or None.
_records: list[tuple[str, str, Optional[str]]] = []
_enabled = False


def clear() -> None:
    """Reset the trace. Tests should call this before each run."""
    _records.clear()


def get() -> list[tuple[str, str]]:
    """Return a copy of the trace as ``(class, method)`` pairs,
    oldest first. Kept argument-free for backward compatibility
    with the subset-invariant tests; callers that need the
    operation argument use :func:`records`."""
    return [(cls, op) for cls, op, _arg in _records]


def records() -> list[tuple[str, str, Optional[str]]]:
    """Return a copy of the full trace as
    ``(class, method, first_arg)`` triples, oldest first.
    ``first_arg`` is the first positional argument of the call
    when it is a string and ``None`` otherwise. This is the form
    the attenuation-honoured invariant consumes."""
    return list(_records)


def classes_used() -> set[str]:
    """Return the set of capability class names that appear in the
    trace. This is the runtime side of the soundness comparison."""
    return {cls for cls, _op, _arg in _records}


def enable() -> None:
    """Wrap every capability class's public methods so each call
    appends to the trace. Idempotent: calling twice does not
    double-wrap. Called once at the start of the property
    suite's setUp; the wrapped methods stay live for the rest
    of the process (a clean test isolates by calling
    :func:`clear` between cases, not by un-instrumenting).
    """
    global _enabled
    if _enabled:
        return
    _enabled = True

    from . import _capabilities as caps

    for cls in (
        caps.Stdio, caps.Fs, caps.Env, caps.Clock, caps.Random, caps.Net,
        caps.Db, caps.Proc,
    ):
        _wrap_class(cls)


def _wrap_class(cls: type) -> None:
    """Decorate every public method on ``cls`` with the trace
    appender. Skips dunder methods and the attenuator-style
    ``_deny`` helper. The decoration mutates the class in
    place; capability instances created before or after this
    call observe the wrapped version."""
    name = cls.__name__
    for attr_name in list(vars(cls)):
        if attr_name.startswith("_"):
            continue
        attr = vars(cls)[attr_name]
        if not callable(attr):
            continue
        setattr(cls, attr_name, _wrap_method(name, attr_name, attr))


def _wrap_method(cls_name: str, op_name: str, method) -> Any:
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        # Record the first positional argument when it is a string:
        # for the privileged operations that is the path / host /
        # key / prefix the call acted on, which is exactly what the
        # attenuation-honoured invariant checks. Non-string first
        # args (e.g. Clock.sleep's float, Random.with_seed's int)
        # record None -- those caps have no path-shaped restriction.
        first_arg = args[0] if args and isinstance(args[0], str) else None
        _records.append((cls_name, op_name, first_arg))
        return method(self, *args, **kwargs)
    return wrapper
