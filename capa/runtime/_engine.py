"""The one place a wasmtime engine is configured.

Every engine Capa builds comes from :func:`new_engine`: the core-Wasm host,
the Component host (default and ``--wasi``), the fuel-metered engine for
untrusted foreign components, and AOT build and load. Before this module
each of those took whatever the installed ``wasmtime`` binding enabled by
default, and the binding's defaults move between releases, so which Wasm
features a guest could use was decided by the binding, not by Capa.

Two decisions live here, each in one place:

* :data:`ENGINE_FEATURES`, the allow-list over the Wasm feature setters the
  binding exposes. Every such setter is applied: the rows marked ``True``
  are on, every other setter is switched off, including one the table does
  not name yet (a new binding's new setter starts off, never on). A row
  whose setter the installed binding lacks refuses to build the engine,
  because a feature that cannot be switched off cannot be kept off. A
  feature the binding gives no setter for is not decided here and stays as
  wasmtime sets it (today the extended constant expressions and the Wasm
  2.0 baseline, such as sign extension and saturating conversions).
* The binding range, read back from the ``[wasm]`` extra declared in
  ``pyproject.toml`` (or from the installed distribution's metadata): a
  ``>=`` floor and exact ``!=`` exclusions. A binding outside it is refused
  with a message naming the declared range instead of failing later inside
  a binding call, and so is a declaration that uses any other operator.

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
    # Needed by the component model itself: a component composed from
    # inner components that each own a memory passes strings and lists
    # between those memories through adapter code wasmtime generates, and
    # that code uses more than one memory. The foreign store limits still
    # allow a child one memory unless its memory ceiling is opted out.
    "multi_memory": True,
    # Every other setter is off.
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
    requires: it is outside the declared range (older than the floor, or
    a release the declaration excludes), or it lacks a setter for a
    feature the engine policy decides."""


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

    _require_binding_range()
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


# ---- the binding range -------------------------------------------------

_REQUIREMENT = re.compile(r"wasmtime\s*\(?\s*([^;\"')\]]*)")
_CLAUSE = re.compile(r"^(>=|!=)\s*([0-9]+(?:\.[0-9]+)*)$")
_EXTRAS_TABLE = re.compile(
    r"(?ms)^\[project\.optional-dependencies\][ \t\r]*$(.*?)(?=^\[|\Z)"
)
_WASM_EXTRA_LINE = re.compile(r"(?m)^\s*wasm\s*=\s*\[([^\]]*)\]")
_WASMTIME_NAME = re.compile(r"\s*wasmtime(?![A-Za-z0-9._-])")
_WASM_MARKER = re.compile(r"""extra\s*==\s*["']wasm["']""")


def requirement_from_declaration(text: str) -> Optional[str]:
    """The version specifier of the ``wasmtime`` requirement (for example
    ``>=10.1,!=10.2.0``), in either form it is declared: the ``wasm = [...]``
    line of ``pyproject.toml`` or a ``Requires-Dist`` entry of the
    installed metadata. None when it names no version."""
    m = _REQUIREMENT.search(text)
    if m is None:
        return None
    return m.group(1).strip() or None


def requirement_clauses(requirement: str) -> list[tuple[str, str]]:
    """The ``(operator, version)`` clauses of a declared specifier. Only a
    ``>=`` floor and an exact ``!=`` exclusion are understood, and a floor
    is required; any other form refuses, since then this code cannot know
    which bindings fit."""
    clauses = [_CLAUSE.match(part.strip()) for part in requirement.split(",")]
    if None in clauses or ">=" not in [m.group(1) for m in clauses]:
        raise WasmBindingError(
            "cannot interpret the wasmtime requirement this Capa declares "
            f"(wasmtime{requirement}): only a '>=' floor and exact '!=' "
            "exclusions are understood, so Capa cannot tell which bindings "
            "fit; refusing to build an engine"
        )
    return [(m.group(1), m.group(2)) for m in clauses]


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


def binding_requirement() -> Optional[str]:
    """The ``wasmtime`` specifier declared for the ``[wasm]`` extra, from
    the same sources and in the same order as the package version: the
    ``pyproject.toml`` beside the package (a source checkout), then the
    installed metadata."""
    raw = _adjacent_pyproject()
    if raw is not None:
        table = _EXTRAS_TABLE.search(raw.decode("utf-8", errors="replace"))
        m = _WASM_EXTRA_LINE.search(table.group(1)) if table else None
        if m is not None:
            return requirement_from_declaration(m.group(1))
    for req in _distribution_requires() or []:
        name, _, marker = req.partition(";")
        if _WASMTIME_NAME.match(name) and _WASM_MARKER.search(marker):
            return requirement_from_declaration(name)
    return None


@functools.lru_cache(maxsize=None)
def _installed_binding_version() -> Optional[str]:
    from importlib.metadata import PackageNotFoundError, version
    try:
        return version("wasmtime")
    except PackageNotFoundError:
        return None


_PRE_RELEASE = re.compile(
    r"^[0-9]+(?:\.[0-9]+)*[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview|dev)"
)


def _release(text: str) -> Optional[tuple[int, ...]]:
    m = re.match(r"^([0-9]+(?:\.[0-9]+)*)", text or "")
    if m is None:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def _is_pre_release(text: str) -> bool:
    """A pre-release or dev release sorts below its own release number,
    as pip orders it, so it does not meet a floor set at that number."""
    return _PRE_RELEASE.match(text or "") is not None


def _padded(a: tuple[int, ...], b: tuple[int, ...]):
    """Both releases zero-padded to one length, so ``10`` equals
    ``10.0.0`` and ``10.1`` compares above ``10.0.6``."""
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def check_binding_version(
    installed: Optional[str], requirement: Optional[str],
) -> None:
    """Refuse a binding outside ``requirement`` (the declared specifier,
    for example ``>=10.1,!=10.2.0``); refuse too when the requirement or
    the installed version cannot be read, since then the code cannot know
    it fits."""
    if not requirement:
        raise WasmBindingError(
            "cannot determine the wasmtime version range this Capa "
            "supports (no pyproject.toml beside the package and no "
            "installed capa-language metadata); reinstall with "
            'pip install "capa-language[wasm]"'
        )
    clauses = requirement_clauses(requirement)
    declared = f"wasmtime{requirement}"
    have = _release(installed)
    if have is None:
        raise WasmBindingError(
            f"cannot read the installed wasmtime version ({installed!r}); "
            f'install a supported one: pip install "{declared}"'
        )
    for op, version in clauses:
        mine, bound = _padded(have, _release(version))
        if op == ">=" and (mine < bound or (
                mine == bound and _is_pre_release(installed))):
            why = "older than the floor of"
        elif op == "!=" and mine == bound:
            why = "a release excluded by"
        else:
            continue
        raise WasmBindingError(
            f"the installed wasmtime binding is {installed}, {why} the "
            f"range this Capa supports for Wasm execution ({declared}). "
            f'Install a supported one: pip install --upgrade "{declared}"'
        )


@functools.lru_cache(maxsize=None)
def _declared_requirement() -> Optional[str]:
    return binding_requirement()


def _require_binding_range() -> None:
    check_binding_version(_installed_binding_version(), _declared_requirement())
