"""Literal-URL splitting for the ``--wasi`` Net.get call-site emitter.

``wasi:http`` builds an ``outgoing-request`` from its component parts --
method (always GET here), scheme (HTTP / HTTPS), authority (host:port),
and path-with-query -- rather than a single URL string. The Capa surface
takes a single URL, so the compiler resolves a LITERAL url into those
parts at compile time (mirroring how the Fs call site resolves a literal
path to ``(preopen_index, basename)``), and the guest wrapper sends the
parts. A DYNAMIC url cannot be split at compile time and is FAIL-CLOSED
at the call site (no request is built; an ``Err(IoError)`` is
materialised directly).

The split mirrors the Python oracle's ``urlparse`` (``Net.get`` at
``capa/runtime/_capabilities.py:574-597``):

- ``host`` is ``urlparse(url).hostname`` (lowercased, no port) -- the
  ceiling-membership key and the value the gate compares.
- ``is_https`` is True for an ``https`` scheme, False otherwise (the
  wrapper selects the wasi:http ``scheme`` variant HTTP=0 / HTTPS=1).
- ``authority`` is ``host:port`` when the url carries an explicit port,
  else just ``host`` (wasi:http's ``set-authority`` wants the full
  authority; the default port is implied by the scheme, matching
  ``urlopen``).
- ``path_with_query`` is the path plus ``?query`` plus ``#``-less
  fragment handling: ``urlparse`` drops the fragment from the request
  line exactly as an HTTP client does, so we send path + query only. An
  empty path becomes ``/`` (the request-target a client sends for a
  bare authority).
"""

from __future__ import annotations

from urllib.parse import urlsplit


def split_net_url(url: str) -> tuple[str, bool, str, str]:
    """Split a literal URL into ``(host, is_https, authority,
    path_with_query)``.

    ``host`` is lowercased and port-stripped (the ceiling key);
    ``authority`` keeps the explicit port when present; ``path_with_query``
    is ``path`` + ``?query`` (fragment dropped, empty path -> ``/``).
    An unparseable URL yields ``("", False, "", "/")`` so the gate denies
    it (no literal host matches ``""``), the same fail-closed shape the
    oracle's empty-host check produces."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ("", False, "", "/")
    host = (parts.hostname or "").lower()
    is_https = (parts.scheme or "").lower() == "https"
    # Authority: host:port when an explicit port is present, else host.
    if parts.port is not None:
        authority = f"{host}:{parts.port}"
    else:
        authority = host
    path = parts.path or "/"
    if parts.query:
        path_with_query = f"{path}?{parts.query}"
    else:
        path_with_query = path
    return (host, is_https, authority, path_with_query)
