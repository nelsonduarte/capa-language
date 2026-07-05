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

from urllib.parse import urlparse, urlsplit


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
