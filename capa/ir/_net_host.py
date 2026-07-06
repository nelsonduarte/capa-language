"""Host normalization shared by the Net ceiling, the ``--wasi`` Net
call-site emitter, and the operator ``--allow-host`` grant.

The SECURITY CORE of the Net host allowlist: the operator-declared grant
value and the URL host the guest gate compares MUST normalize through the
SAME function, or the allowlist is bypassable (a grant for ``api.com``
that fails to match a URL for ``api.com.`` would silently under- or
over-approve). :func:`normalize_host` canonicalizes an operator-supplied
host (a bare authority or a full URL), and :func:`strip_trailing_dot`
applies the SAME trailing-dot normalization to the URL-derived host on the
check side (``url_host`` / ``split_net_url``) so both sides agree.

Normalization rules (validated by the oracle matrix in
``tests/test_allow_host_oracle.py``):

- extract the host: a value that looks like a URL (has ``://`` or ``/``)
  goes through ``urlparse().hostname``; a bare authority goes through
  ``urlsplit("//" + s).hostname`` (so ``host``, ``host:port`` -> host,
  ``[::1]`` -> ``::1``, ``user@host`` -> host all resolve);
- lowercase (DNS is case-insensitive);
- strip a SINGLE trailing dot (``api.com.`` -> ``api.com``), the FQDN
  root label, applied identically on the URL side so the grant matches;
- return ``None`` (a rejectable, clearly-messaged failure) when the
  result is empty or the input still carried a path/scheme the host
  extraction could not resolve.

NOTE (DNS rebinding, honest residual): this is a HOSTNAME allowlist.
wasmtime's ``wasi:http`` is allow-all host-side in this release, so Capa
cannot filter the IP a granted hostname resolves to at connect time. A
granted host that resolves to an internal address at runtime is NOT
defended here; ``--allow-host`` is a name-level grant only. See
``docs/design/wasi_mode.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Union
from urllib.parse import urlparse, urlsplit


@dataclass(frozen=True)
class NetGrant:
    """The operator ``--allow-host`` grant, scoped PER HTTP METHOD
    (Phase 2, 2026-07-06).

    ``get_hosts`` are hosts the operator granted READ (GET) network
    authority; ``post_hosts`` are hosts granted WRITE (POST) authority.
    A grant with NO method suffix (``--allow-host h``) places the host in
    BOTH sets, backward-compatible with Phase 1 where a grant meant
    get+post; ``--allow-host h:get`` grants GET only, ``h:post`` POST
    only. This is LEAST-AUTHORITY: an operator can grant read-only network
    to a host without also permitting a write (POST).

    The guest-side gate the emitter materialises is likewise split: the
    ``$Net_host_allowed_get`` gate admits ``ceiling | get_hosts`` and the
    ``$Net_host_allowed_post`` gate admits ``ceiling | post_hosts`` (the
    compiler-derived literal ceiling is COMBINED into both; the operator
    grant is the only per-method scope). So a ``h:get`` grant lets a
    dynamic ``net.get`` to ``h`` through but a dynamic ``net.post`` to
    ``h`` is denied, and vice versa for ``h:post``."""

    get_hosts: frozenset[str] = field(default_factory=frozenset)
    post_hosts: frozenset[str] = field(default_factory=frozenset)

    @property
    def all_hosts(self) -> frozenset[str]:
        """The union of the get- and post-granted hosts (the membership
        keys the emitter interns; a host granted for either method needs a
        data segment)."""
        return self.get_hosts | self.post_hosts

    def access_of(self, host: str) -> str:
        """The SBOM access label for ``host``: ``"connect"`` when granted
        for BOTH methods (the no-suffix / get+post grant), else ``"get"``
        or ``"post"`` for a method-scoped grant."""
        in_get = host in self.get_hosts
        in_post = host in self.post_hosts
        if in_get and in_post:
            return "connect"
        return "get" if in_get else "post"

    def __bool__(self) -> bool:
        return bool(self.get_hosts or self.post_hosts)


def coerce_net_grant(
    value: Union["NetGrant", Iterable[str], None],
) -> NetGrant:
    """Coerce a caller-supplied grant value into a :class:`NetGrant`.

    Accepts a :class:`NetGrant` (returned unchanged), ``None`` / empty
    (an empty grant), or any iterable of host strings -- the Phase-1
    BACKWARD-COMPATIBLE form, where every host is granted BOTH get and
    post (a bare ``frozenset({"h"})`` still means get+post). The library
    callers and the ``--allow-host``-free CLI path never construct a
    ``NetGrant`` themselves; only the CLI's per-method parse does."""
    if value is None:
        return NetGrant()
    if isinstance(value, NetGrant):
        return value
    hosts = frozenset(value)
    return NetGrant(hosts, hosts)


def strip_trailing_dot(host: str) -> str:
    """Strip a single trailing dot from an already-lowercased host.

    ``api.com.`` -> ``api.com`` (the FQDN root label). Applied on BOTH the
    operator-grant side (via :func:`normalize_host`) and the URL side
    (``url_host`` / ``split_net_url``) so a grant for ``api.com`` matches a
    URL for ``api.com.`` and vice versa (the trailing-dot bypass, closed
    symmetrically)."""
    if host.endswith("."):
        return host[:-1]
    return host


# The ASCII whitespace bytes the runtime extractor trims from the ends of a
# dynamic URL (space / tab / LF / CR). Kept as an explicit set so the Python
# reference and the WAT extractor strip EXACTLY the same bytes (a full
# ``str.strip()`` would strip Unicode whitespace the WAT does not).
_URL_TRIM = " \t\n\r"


def extract_url_parts(url: str) -> tuple[str, bool, str, str]:
    """The EXECUTABLE SPEC of the guest-side runtime URL extractor.

    Returns ``(host, is_https, authority, path)`` for a runtime (dynamic)
    URL under ``--wasi``. ``host == ""`` means FAIL-CLOSED: the extractor
    refuses this URL and the guest denies it (no host matches ``""`` in the
    allowlist, and no request is built). This is a DELIBERATELY CONSERVATIVE
    subset of :func:`capa.ir._emit_wasm._net.split_net_url` (the compile-time
    literal splitter): on every URL it does NOT fail-close, its ``host`` is
    byte-identical to ``split_net_url``'s (and to the ceiling / grant key), so
    a dynamic URL to a granted host behaves exactly like the literal path;
    on the hard cases it denies rather than guess.

    The security contract (proven by ``tests/test_allow_host_oracle.py`` and
    the differential WAT-vs-Python harness): the ``authority`` is built from
    the SAME extracted ``host`` (host, optionally ``:port``), so the host the
    guest VERIFIES against ``$Net_host_allowed`` is exactly the host the
    wasi:http request CONTACTS (wasi:http receives this authority, never a
    re-parsed raw URL). No URL-parsing quirk can make the guest verify one
    host and contact another.

    FAIL-CLOSED (returns ``("", False, "", "/")``) on:

    - no ``://`` (a scheme-relative ``//host`` or a bare ``host/path``);
    - a scheme other than ``http`` / ``https`` (wasi:http speaks neither);
    - a bracketed IPv6 authority (``[::1]``) -- rare, and a loopback /
      link-local grant is warned about anyway;
    - a non-numeric port, or an empty host after normalization.

    HANDLED (matches ``split_net_url``): case-folding, a single trailing dot,
    ``user@host`` userinfo (stripped at the LAST ``@``, matching urlsplit),
    ``host:port``, ``?query`` (kept) and ``#fragment`` (dropped), and leading
    / trailing ASCII whitespace."""
    if not url:
        return ("", False, "", "/")
    # Trim ASCII whitespace (same bytes the WAT extractor trims).
    s = url.strip(_URL_TRIM)
    if not s:
        return ("", False, "", "/")
    i = s.find("://")
    if i < 0:
        return ("", False, "", "/")            # no scheme -> deny
    scheme = s[:i].lower()
    if scheme == "https":
        is_https = True
    elif scheme == "http":
        is_https = False
    else:
        return ("", False, "", "/")            # non-http(s) -> deny
    rest = s[i + 3:]
    # Authority region ends at the first path / query / fragment delimiter.
    end = len(rest)
    for j, c in enumerate(rest):
        if c in "/?#":
            end = j
            break
    authority_region = rest[:end]
    tail = rest[end:]
    # Strip userinfo at the LAST '@' (matches urlsplit's hostname).
    at = authority_region.rfind("@")
    if at >= 0:
        authority_region = authority_region[at + 1:]
    # Bracketed IPv6 -> fail-closed (see docstring).
    if "[" in authority_region or "]" in authority_region:
        return ("", False, "", "/")
    colon = authority_region.find(":")
    if colon >= 0:
        host = authority_region[:colon]
        port = authority_region[colon + 1:]
    else:
        host = authority_region
        port = ""
    if port and not port.isdigit():
        return ("", False, "", "/")            # weird port -> deny
    host = strip_trailing_dot(host.lower())
    if not host:
        return ("", False, "", "/")
    authority = host if not port else f"{host}:{port}"
    # Path: drop the fragment; keep path + ?query; empty -> "/".
    frag = tail.find("#")
    region = tail if frag < 0 else tail[:frag]
    if not region:
        path = "/"
    elif region[0] == "?":
        path = "/" + region
    else:
        path = region
    return (host, is_https, authority, path)


def normalize_host(s: str) -> str | None:
    """Canonicalize an operator-supplied host to the guest allowlist key.

    Returns the normalized host (lowercased, port/userinfo/brackets
    stripped, single trailing dot removed) or ``None`` when ``s`` does not
    name a host (empty, or still carrying an unresolved path/scheme). The
    caller rejects a ``None`` with an actionable message.

    Accepts both a bare authority (``api.com``, ``api.com:443``, ``[::1]``,
    ``user@api.com``) and a full URL (``https://api.com/x``); the URL host
    it extracts equals the value ``url_host`` derives from the same URL, so
    an operator may paste either form and get the same allowlist entry."""
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    # A value with a scheme or a path component is a URL: let urlparse
    # pull the authority out (and drop the path/scheme). A bare token is
    # an authority; urlsplit("//" + token) resolves host / host:port /
    # user@host / [::1] uniformly.
    try:
        if "://" in s or "/" in s:
            host = urlparse(s).hostname
        else:
            host = urlsplit("//" + s).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = strip_trailing_dot(host.lower())
    if not host:
        return None
    return host
