"""WASI / net operator-grant parsers for the Capa CLI.

Leaf module for :mod:`capa.cli`: it parses the ``--preopen`` and
``--allow-host`` operator grants (and classifies internal IPs for the SSRF
warning). Shared by the emitter path (``_operator_grants_from_args``, for
the SBOM operator-declared block) and the execute path
(``_normalize_allow_hosts``, for the runtime net gate), so it lives in one
leaf both import rather than being duplicated between them. It must not
import from :mod:`capa.cli`; the dependency runs one way,
``capa.cli`` -> ``capa.cli._grants``.
"""


def _parse_preopen_spec(spec: str) -> tuple[str, bool]:
    """Parse one ``--preopen`` value ``<dir>[:ro|:rw]`` into
    ``(host_dir, read_write)``.

    The default permission is READ_WRITE (``rw``), the WASI ``--dir``
    default; an explicit ``:ro`` suffix makes it READ_ONLY and ``:rw`` is
    READ_WRITE. Only a trailing ``:ro`` / ``:rw`` is treated as a
    permission suffix, so a directory name that itself contains a colon
    (or a Windows drive ``C:\\...``) is preserved -- the split is on the
    LAST ``:`` and only when the tail is exactly ``ro`` / ``rw``."""
    read_write = True
    host_dir = spec
    if ":" in spec:
        head, _, tail = spec.rpartition(":")
        if tail in ("ro", "rw") and head:
            host_dir = head
            read_write = tail == "rw"
    return (host_dir, read_write)


def _classify_internal_ip(host: str) -> str | None:
    """Return the kind of internal address ``host`` is (``loopback`` /
    ``link-local`` / ``unspecified`` / ``private``) when it is an IP
    LITERAL in a non-routable range, else None.

    Drives the ``--allow-host`` SSRF warning: an operator who grants
    169.254.169.254 (cloud metadata), 127.0.0.1, 10.x, 192.168.x, ::1,
    fc00::/7, 0.0.0.0, etc. is warned it is almost always an SSRF footgun.
    A domain name (not an IP literal) returns None (no warning): its
    resolved address is not knowable here (the DNS-rebinding residual).
    ``is_loopback`` / ``is_link_local`` / ``is_unspecified`` are checked
    BEFORE ``is_private`` because Python folds them into ``is_private``
    too; the more specific label is the useful one."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_unspecified:
        return "unspecified"
    if ip.is_private:
        return "private"
    return None


class _AllowHostSpecError(ValueError):
    """A ``--allow-host`` value whose method suffix is malformed (a
    near-miss of ``:get`` / ``:post`` the operator plainly intended as a
    scope). Raised rather than silently broadened to a both-methods grant,
    the least-authority posture: never grant more authority than asked."""


def _parse_allow_host_spec(spec: str) -> tuple[str | None, str]:
    """Parse one ``--allow-host`` value ``<host>[:get|:post]`` into
    ``(normalized_host_or_None, access)`` where ``access`` is ``"get"``,
    ``"post"``, or ``"both"`` (no method suffix, the Phase-1 get+post
    grant).

    Mirrors :func:`_parse_preopen_spec`: a trailing ``:get`` / ``:post`` is
    treated as the method suffix ONLY when the head before the LAST ``:``
    is itself a valid host (``normalize_host`` does not reject it). This
    keeps a host that carries a genuine ``:`` intact -- ``h:8080`` is host
    ``h`` port 8080 (``8080`` is not a suffix), ``[::1]:get`` grants GET to
    ``::1`` (``[::1]`` is a valid host), and ``[::1]:8080`` is host ``::1``
    port 8080. The head is normalized through the SAME
    :func:`capa.ir._net_host.normalize_host` the guest gate's URL-host
    normalization uses, so the operator's spelling and the URL host land on
    the same allowlist key.

    A MALFORMED method suffix -- a last colon-segment that READS as a
    method keyword (ignoring case / surrounding whitespace) but is not
    EXACTLY ``:get`` / ``:post`` on a valid single-suffix host -- raises
    :class:`_AllowHostSpecError` rather than falling through to a
    both-methods grant. This catches ``h:GET`` / ``h:Get`` (mis-cased),
    ``h:get `` / ``  h:get`` (surrounding whitespace), and ``h:get:post``
    (two method segments / ambiguous): granting BOTH when the operator
    clearly meant ONE is a least-authority footgun. A genuine port
    (``h:8080``) or IPv6 authority (``[::1]:8080``) never reads as a method
    keyword, so it is untouched. Returns ``(None, access)`` (not an error)
    only when the host itself cannot be parsed AND no method suffix was
    attempted (the caller collects it as a bad spec)."""
    from capa.ir._net_host import normalize_host
    if ":" in spec:
        head, _, tail = spec.rpartition(":")
        # Does the last colon-segment read as a method keyword? If so the
        # operator plainly intended a scoped grant, so require it to be
        # WELL-FORMED; anything else is a rejectable near-miss.
        if tail.strip().lower() in ("get", "post"):
            prior_segment = head.rpartition(":")[2].strip().lower()
            well_formed = (
                tail in ("get", "post")            # exact, lowercase
                and spec == spec.strip()           # no surrounding space
                and bool(head)                     # non-empty host head
                and normalize_host(head) is not None
                and prior_segment not in ("get", "post")  # single suffix
            )
            if not well_formed:
                raise _AllowHostSpecError(
                    f"{spec!r}: malformed method suffix; use "
                    "'<host>:get' or '<host>:post' (lowercase, no "
                    "surrounding spaces, a single suffix), or omit the "
                    "suffix to grant both"
                )
            return normalize_host(head), tail
    return normalize_host(spec), "both"


def _normalize_allow_hosts(specs):
    """Normalize each ``--allow-host`` value to a per-method
    :class:`capa.ir._net_host.NetGrant`.

    Returns ``(grant, bad)`` where ``grant`` is a ``NetGrant`` (get-hosts /
    post-hosts, each normalized) and ``bad`` holds the raw values
    :func:`_parse_allow_host_spec` could not resolve to a host (empty, or
    still carrying a path/scheme). A ``h:get`` spec adds ``h`` to the
    get-set only, ``h:post`` to the post-set only, and a suffix-less ``h``
    to BOTH (backward-compatible with Phase 1). A MALFORMED method suffix
    PROPAGATES as :class:`_AllowHostSpecError` (a near-miss of ``:get`` /
    ``:post`` is rejected, not silently broadened to both). The caller
    catches that error and rejects a non-empty ``bad`` with an actionable
    message, and emits the internal-IP SSRF warning for each accepted
    host."""
    from capa.ir._net_host import NetGrant
    get_hosts: set[str] = set()
    post_hosts: set[str] = set()
    bad: list[str] = []
    for spec in specs or []:
        host, access = _parse_allow_host_spec(spec)
        if host is None:
            bad.append(spec)
            continue
        if access in ("get", "both"):
            get_hosts.add(host)
        if access in ("post", "both"):
            post_hosts.add(host)
    grant = NetGrant(frozenset(get_hosts), frozenset(post_hosts))
    return grant, bad


def _operator_grants_from_args(
    preopen_specs, allow_host_specs=None,
) -> dict | None:
    """Build the SBOM ``operator_declared_grants`` block from the
    ``--preopen`` and ``--allow-host`` specs, or None when none were
    declared.

    Each ``--preopen`` spec ``<dir>[:ro|:rw]`` becomes an fs preopen entry;
    each ``--allow-host`` spec becomes a net entry ``{"kind": "net",
    "host": "<normalized>", "access": "get"|"post"|"connect"}`` -- the
    method SCOPE of the grant, ``"connect"`` for a suffix-less (get+post)
    grant, else the granted method. The block is honestly labelled
    operator-declared (Level 2) by
    :func:`capa.manifest.build_operator_declared_grants`, distinct from the
    compiler-derived surface."""
    from capa.manifest import build_operator_declared_grants
    specs = preopen_specs or []
    host_specs = allow_host_specs or []
    if not specs and not host_specs:
        return None
    preopens = []
    for spec in specs:
        host_dir, read_write = _parse_preopen_spec(spec)
        preopens.append({
            "kind": "fs",
            "host_dir": host_dir,
            "permission": "rw" if read_write else "ro",
        })
    grant, _bad = _normalize_allow_hosts(host_specs)
    net_grants = [
        {"kind": "net", "host": h, "access": grant.access_of(h)}
        for h in sorted(grant.all_hosts)
    ]
    return build_operator_declared_grants(preopens, net_hosts=net_grants)
