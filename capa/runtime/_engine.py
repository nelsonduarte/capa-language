"""The one place a wasmtime engine is configured.

Every engine Capa builds comes from :func:`new_engine`: the core-Wasm host,
the Component host (default and ``--wasi``), the fuel-metered engine for
untrusted foreign components, and AOT build and load. Before this module
each of those took whatever the installed ``wasmtime`` binding enabled by
default, and the binding's defaults move between releases, so which Wasm
features a guest could use was decided by the binding, not by Capa.

Two decisions live here, each in one place:

* :data:`ENGINE_FEATURES`, the Wasm feature allow-list. Every feature setter
  the binding exposes is applied: the rows marked ``True`` are on, every
  other feature is off, including one the table does not name yet (a new
  binding's new feature starts off, never on). A row whose setter the
  installed binding lacks refuses to build the engine, because a feature
  that cannot be switched off cannot be kept off.
* The binding floor, read back from the ``[wasm]`` extra declared in
  ``pyproject.toml`` (or from the installed distribution's metadata), so an
  older binding is refused with an upgrade message instead of failing later
  inside a binding call.

Both refusals raise :class:`WasmBindingError`, which the CLI prints as a
one-line diagnostic. ``wasmtime`` is imported lazily so the error type can be
imported without the ``[wasm]`` extra.
"""

from __future__ import annotations

import functools
import re
from typing import Optional

# Row name = the ``<name>`` in the binding's C-API setter
# ``wasmtime_config_wasm_<name>_set``. ``True`` = on. Allow-list: only what
# Capa's own output and the foreign components it runs need is on.
ENGINE_FEATURES: dict[str, bool] = {
    # Needed by Capa-emitted modules and components.
    "bulk_memory": True,
    "multi_value": True,
    "tail_call": True,
    "component_model": True,
    # Needed by common third-party foreign components (Rust wasm32 output
    # uses reference types for indirect calls).
    "reference_types": True,
    # Everything else is off.
    "branch_hinting": False,
    "component_model_async": False,
    "component_model_async_stackful": False,
    "component_model_map": False,
    "component_model_more_async_builtins": False,
    "custom_page_sizes": False,
    "exceptions": False,
    "function_references": False,
    "gc": False,
    "memory64": False,
    "multi_memory": False,
    "relaxed_simd": False,
    "relaxed_simd_deterministic": False,
    "simd": False,
    "stack_switching": False,
    "threads": False,
    "wide_arithmetic": False,
}

_SETTER = re.compile(r"^wasmtime_config_wasm_(\w+)_set$")


class WasmBindingError(RuntimeError):
    """The installed ``wasmtime`` binding cannot provide the engine Capa
    requires: it is older than the declared floor, or it lacks a setter
    for a feature the engine policy decides."""


def _feature_setters(bindings) -> dict[str, object]:
    """Every Wasm feature setter the binding exposes, by row name."""
    found = {}
    for name in dir(bindings):
        m = _SETTER.match(name)
        if m is not None:
            found[m.group(1)] = getattr(bindings, name)
    return found


def _decisions(setters) -> dict[str, bool]:
    """The value applied to each exposed setter. Fails closed on a table
    row the binding cannot switch."""
    missing = sorted(set(ENGINE_FEATURES) - set(setters))
    if missing:
        raise WasmBindingError(
            "the installed wasmtime binding cannot switch the Wasm "
            f"feature(s) {', '.join(missing)}, so Capa cannot keep them "
            "off; refusing to build an engine. Install a wasmtime "
            "version within the range capa-language declares: "
            'pip install --upgrade "capa-language[wasm]"'
        )
    return {name: ENGINE_FEATURES.get(name, False) for name in setters}


def new_engine(*, fuel: bool):
    """Build a wasmtime engine under Capa's policy. ``fuel`` turns on
    fuel metering (the untrusted foreign-component engine)."""
    import wasmtime
    from wasmtime import _bindings

    _require_binding_floor()
    config = wasmtime.Config()
    setters = _feature_setters(_bindings)
    for name, enabled in _decisions(setters).items():
        setters[name](config.ptr(), enabled)
    config.consume_fuel = fuel
    return wasmtime.Engine(config)


def engine_identity(*, fuel: bool) -> str:
    """A stable name for the configuration :func:`new_engine` applies,
    for artifacts that are only valid under the engine that built them
    (AOT). Derived from the decisions themselves, never restated."""
    from wasmtime import _bindings

    applied = _decisions(_feature_setters(_bindings))
    on = ",".join(sorted(n for n, v in applied.items() if v))
    off = ",".join(sorted(n for n, v in applied.items() if not v))
    return f"on={on};off={off};fuel={int(bool(fuel))}"


# ---- the binding floor -------------------------------------------------

_FLOOR = re.compile(r"wasmtime\s*>=\s*([0-9]+(?:\.[0-9]+)*)")
_WASM_EXTRA_LINE = re.compile(r"(?m)^\s*wasm\s*=\s*\[([^\]]*)\]")


def floor_from_declaration(text: str) -> Optional[str]:
    """The ``>=`` floor in a ``wasmtime`` requirement, in either form the
    floor is declared: the ``wasm = [...]`` line of ``pyproject.toml`` or a
    ``Requires-Dist`` entry of the installed metadata."""
    m = _FLOOR.search(text)
    return m.group(1) if m is not None else None


def _adjacent_pyproject() -> Optional[bytes]:
    from .. import _adjacent_pyproject_bytes
    return _adjacent_pyproject_bytes()


def _distribution_requires() -> Optional[list[str]]:
    from importlib.metadata import PackageNotFoundError, requires
    from .. import _DIST_NAMES
    for name in _DIST_NAMES:
        try:
            return requires(name) or []
        except PackageNotFoundError:
            continue
    return None


def binding_floor() -> Optional[str]:
    """The floor declared for the ``[wasm]`` extra, from the same sources
    and in the same order as the package version: the ``pyproject.toml``
    beside the package (a source checkout), then the installed metadata."""
    raw = _adjacent_pyproject()
    if raw is not None:
        m = _WASM_EXTRA_LINE.search(raw.decode("utf-8", errors="replace"))
        if m is not None:
            return floor_from_declaration(m.group(1))
    for req in _distribution_requires() or []:
        if req.split(";")[0].strip().startswith("wasmtime"):
            return floor_from_declaration(req)
    return None


@functools.lru_cache(maxsize=None)
def _installed_binding_version() -> Optional[str]:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("wasmtime")
    except PackageNotFoundError:
        return None


def _release(text: str) -> Optional[tuple[int, ...]]:
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)", text or "")
    if m is None:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def check_binding_version(installed: Optional[str], floor: Optional[str]) -> None:
    """Refuse a binding older than ``floor``; refuse too when either
    version cannot be read, since then the code cannot know it fits."""
    have, need = _release(installed), _release(floor)
    if need is None:
        raise WasmBindingError(
            "cannot determine the wasmtime version range this Capa "
            "supports (no pyproject.toml beside the package and no "
            "installed capa-language metadata); reinstall with "
            'pip install "capa-language[wasm]"'
        )
    if have is None:
        raise WasmBindingError(
            f"cannot read the installed wasmtime version ({installed!r}); "
            f'install a supported one: pip install "wasmtime>={floor}"'
        )
    width = max(len(have), len(need))
    pad = (0,) * width
    if (have + pad)[:width] < (need + pad)[:width]:
        raise WasmBindingError(
            f"the installed wasmtime binding is {installed}, older than "
            f"the {floor} this Capa requires for Wasm execution. Upgrade "
            f'it: pip install --upgrade "wasmtime>={floor}"'
        )


@functools.lru_cache(maxsize=None)
def _declared_floor() -> Optional[str]:
    return binding_floor()


def _require_binding_floor() -> None:
    check_binding_version(_installed_binding_version(), _declared_floor())
