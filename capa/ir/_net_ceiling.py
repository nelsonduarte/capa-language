"""Static Net authority-ceiling analysis for the ``--wasi`` mode.

Phase 1 of ``docs/design/wasi-attenuation.md`` for the Net capability,
GUEST-SIDE only (the ASYMMETRY, see below): collect the HOSTS of the
literal URLs the program passes to ``Net.get`` so the guest-side
``$Net_get`` wrapper can refuse any host the program never names as a
literal. Unlike the Fs preopen ceiling and the Env env-set ceiling --
both Level 1, imposed by the WASI host at instantiate time -- the Net
ceiling is NOT runtime-enforced by stock WASI: wasmtime's C-API for
``wasi:http`` (``wasmtime_context_set_wasi_http``) is ALLOW-ALL with no
allowed-hosts configuration surface in this release, so there is no host
ceiling to map onto. The ceiling is therefore enforced GUEST-SIDE
(codegen, Level 2-style) and is honest about that limitation.

The ceiling is computed from the CIR (after the loader has inlined
imported functions, so every reachable ``net.get`` call site is visible)
by scanning every ``MethodCall`` whose receiver is a ``Net`` and whose
method is ``get`` (Phase 1) or ``post`` (Phase 2) -- the two request-
building ops, each of which reaches the url's host:

- a STRING-LITERAL url argument (``Value(kind="lit_str")``) contributes
  the HOST component of its URL (``urlparse(url).hostname``, lowercased
  to match the case-insensitive DNS host) to the ceiling;
- any NON-LITERAL argument (a local / param / computed value) makes the
  host indeterminable at compile time, so the ceiling is marked NOT
  CLOSED.

POLICY for a NON-CLOSED ceiling (a dynamic Net url): FAIL CLOSED. The
guest ``$Net_get`` wrapper refuses (returns ``Err(IoError)`` WITHOUT
calling the handler) every host not in the static ceiling, and a dynamic
url is never in the ceiling, so a dynamic-url program's ``net.get`` is
always denied at runtime. This mirrors the Fs fail-closed rule
(a dynamic Fs path denies) rather than the Env degrade-to-inherit rule,
because a wrongly-admitted host is real outbound network authority. A
program that genuinely needs dynamic Net hosts must use the default
``capa:host`` backend (drop ``--wasi``).

Why ``Net.get`` and ``Net.post`` define the ceiling:

- both build an outgoing request to the url's host, so each literal url
  they pass contributes that host to the reachable set.
- ``Net.restrict_to`` / ``Net.allows`` only NARROW or QUERY the host
  set; they can never make the program reach a host it does not already
  pass to ``net.get`` / ``net.post``. They are not migrated yet (Phase 3)
  and contribute no host.

A literal bound through an intermediate ``let`` (``let u = "http://h/"``
then ``net.get(u)``) appears as a local at the call site, so it is
treated CONSERVATIVELY as dynamic and makes the ceiling NOT CLOSED
(fail-closed). Folding constants into the scan is a possible future
refinement, not a correctness requirement.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from .. import capa_ast as A
from ._lower import Lowerer
from ._nodes import MethodCall, Module
from ._walk import walk_module


# Capability class name and the methods that define the Net host ceiling.
# Both ``get`` (Phase 1) and ``post`` (Phase 2) build an outgoing request
# to the url's host, so each literal url they name contributes a host to
# the ceiling; ``restrict_to`` / ``allows`` only narrow or query the set
# and never widen reachability, so they do not.
_NET_CAP = "Net"
_NET_REQUEST_METHODS = frozenset({"get", "post"})


def url_host(url: str) -> str:
    """Return the HOST component of ``url`` (no port), lowercased.

    Mirrors the oracle's host extraction (``Net.get`` uses
    ``urlparse(url).hostname``, which strips the port and lowercases the
    host, ``capa/runtime/_capabilities.py:578-579``). An unparseable URL
    or a URL with no host yields ``""`` (which no literal ceiling host
    equals, so such a call is denied, the same fail-closed shape the
    oracle's empty-host ``allows("")`` produces under a restriction)."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


@dataclass(frozen=True)
class NetCeiling:
    """The result of the static Net host-ceiling analysis.

    ``closed`` is True when every reachable ``net.get`` url is a string
    literal, so ``hosts`` is the exact, complete set of hosts the program
    can reach. When ``closed`` is False at least one ``net.get`` url is
    computed at runtime; the ceiling cannot be materialised and the guest
    wrapper FAILS CLOSED (denies every host not in ``hosts``, and a
    dynamic url is never in ``hosts``). ``hosts`` still holds the literal
    hosts seen (informational when not closed)."""
    closed: bool
    hosts: frozenset[str]


def compute_net_ceiling_from_cir(cir: Module) -> NetCeiling:
    """Scan a lowered CIR module for the Net host ceiling.

    Walks every function and impl-method body (the loader has already
    inlined imported functions into the AST the CIR was lowered from, so
    this covers the whole reachable program) and inspects every
    ``net.get`` call site. See the module docstring for the literal /
    dynamic rule and the host derivation."""
    hosts: set[str] = set()
    closed = True
    for _owner, instr in walk_module(cir):
        if not isinstance(instr, MethodCall):
            continue
        cap = instr.cap_used or (instr.receiver.ty or "")
        if cap != _NET_CAP or instr.method not in _NET_REQUEST_METHODS:
            continue
        # net.get takes one arg (url); net.post takes two (url, body). The
        # FIRST arg is the url for both. Defensive: a missing url arg is
        # treated as dynamic (cannot prove the literal), never silently
        # narrowing the ceiling.
        if not instr.args:
            closed = False
            continue
        arg = instr.args[0]
        if arg.kind == "lit_str" and isinstance(arg.literal, str):
            hosts.add(url_host(arg.literal))
        else:
            # A computed / local / param url: the program may reach a
            # host decided at runtime, so the ceiling cannot be
            # materialised. Fail-closed.
            closed = False
    return NetCeiling(closed=closed, hosts=frozenset(hosts))


def compute_net_ceiling(
    module: A.Module, types: dict | None = None,
) -> NetCeiling:
    """Lower ``module`` to CIR and compute its Net host ceiling.

    Convenience wrapper over :func:`compute_net_ceiling_from_cir` that
    runs the same lowering the Wasm pipeline uses (so the ceiling is
    computed from the exact instruction tree that will be emitted)."""
    cir = Lowerer(types=types or {}).lower_module(module)
    return compute_net_ceiling_from_cir(cir)
