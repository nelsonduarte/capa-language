"""Oracle matrix for the ``--allow-host`` host normalization.

The security core of the Net host allowlist: the operator-declared grant
value (``normalize_host``) and the URL host the guest gate compares
(``url_host`` / ``split_net_url``) MUST land on the SAME canonical string,
or the allowlist is bypassable. This matrix proves that agreement across
casing, trailing-dot, userinfo, port, IPv6, and full-URL forms, and pins
the ``None`` rejection for non-hosts.
"""

import unittest

from capa.ir._net_host import (
    normalize_host, strip_trailing_dot, extract_url_parts,
)
from capa.ir._net_ceiling import url_host
from capa.ir._emit_wasm._net import split_net_url


# The adversarial corpus shared by the Python-reference consistency check
# and the differential WAT-vs-Python harness. Each entry is a URL a runtime
# (dynamic) value could carry; the extractor must produce the SAME host as
# the literal splitter OR fail-close (deny), and MUST NEVER extract a host
# different from the one the request would contact.
ADVERSARIAL_URL_CORPUS = [
    "http://api.example.com/x",
    "https://API.EXAMPLE.COM./x",
    "http://api.example.com:8080/a?b=1#frag",
    "http://allowed@169.254.169.254/",
    "http://api.example.com@169.254.169.254/",     # userinfo bypass attempt
    "http://169.254.169.254#allowed.com",          # fragment bypass attempt
    "http://[::1]:8080/",                          # IPv6 -> fail-closed
    "http://host:80/",
    "http://host/",
    "http://host",
    "https://host",
    "//host/path",                                 # no scheme -> fail-closed
    "host/path",                                   # no scheme -> fail-closed
    "",                                            # empty -> fail-closed
    "   http://api.example.com/x   ",              # surrounding whitespace
    "http://a\\@b/",                               # backslash + userinfo
    "ftp://api.example.com/x",                     # non-http(s) -> fail-closed
    "http://user:pw@api.example.com:443/p",
    "http://[fe80::1%25eth0]/",                    # IPv6 zone -> fail-closed
    "http://EXAMPLE.com/",
    "http://api.example.com:notaport/x",           # bad port -> fail-closed
    "http://api.example.com.:443/x",               # trailing dot + port
    "http://api.example.com?q=1",                  # query, no path
    "HtTp://API.example.com/x",                    # mixed-case scheme
    "HTTPS://host/",                               # mixed-case https
    "http://",                                     # empty authority -> deny
    "http://:80/",                                 # empty host -> deny
    "http://@host/",                               # empty userinfo
    "\thttp://host/\n",                            # tab / newline trim
    "http://host:/",                               # empty port -> no port
    "http://xn--bcher-kva.example/",               # punycode host
    "http://host.:8080",                           # trailing dot + port, no path
    "http://user@@host/",                          # double '@'
]


class ExtractUrlPartsReference(unittest.TestCase):
    """Phase B0 part 1: the runtime extractor reference (``extract_url_parts``)
    agrees with the literal splitter on every host it admits, fails CLOSED on
    the hard cases, and never extracts a host different from the one it would
    contact (authority prefix == verified host)."""

    def test_admitted_host_matches_literal_splitter(self):
        for u in ADVERSARIAL_URL_CORPUS:
            host, is_https, authority, path = extract_url_parts(u)
            if host == "":
                continue  # fail-closed: deny is always safe
            # SECURITY: an admitted host is byte-identical to the literal
            # splitter's host (the ceiling / grant key), so a dynamic URL to
            # a granted host behaves exactly like the literal path.
            self.assertEqual(
                host, split_net_url(u)[0],
                f"extract_url_parts host diverges from split_net_url for {u!r}",
            )

    def test_verified_host_equals_contacted_host(self):
        # The ironclad invariant: the authority sent to wasi:http is built
        # from the SAME host that is verified, so the authority's host part
        # is exactly the verified host (no second parser can disagree).
        for u in ADVERSARIAL_URL_CORPUS:
            host, is_https, authority, path = extract_url_parts(u)
            if host == "":
                self.assertEqual(authority, "", f"{u!r} denied but authority set")
                continue
            self.assertTrue(
                authority == host or authority.startswith(host + ":"),
                f"authority {authority!r} not built from host {host!r} ({u!r})",
            )

    def test_bypass_vectors_never_admit_a_foreign_host(self):
        # An operator grants ONLY api.example.com. None of the bypass
        # spellings may cause the extractor to admit api.example.com while
        # the URL's real target (per the literal splitter) is a different
        # host -- that would be the SSRF the whole design prevents.
        granted = {"api.example.com"}
        for u in ADVERSARIAL_URL_CORPUS:
            host, *_ = extract_url_parts(u)
            if host in granted:
                # If admitted as the granted host, the literal splitter must
                # agree the URL's host IS that granted host.
                self.assertEqual(
                    split_net_url(u)[0], host,
                    f"{u!r} admitted as {host!r} but splitter disagrees",
                )

    def test_fail_closed_cases_deny(self):
        for u in ("//host/path", "host/path", "", "ftp://api.example.com/x",
                  "http://[::1]:8080/", "http://[fe80::1%25eth0]/",
                  "http://api.example.com:notaport/x"):
            self.assertEqual(
                extract_url_parts(u)[0], "",
                f"{u!r} should fail-closed (empty host)",
            )

    def test_handled_cases_parts(self):
        # Spot-check the full (host, is_https, authority, path) tuple on the
        # handled cases the WAT extractor must reproduce byte-for-byte.
        self.assertEqual(
            extract_url_parts("http://api.example.com:8080/a?b=1#frag"),
            ("api.example.com", False, "api.example.com:8080", "/a?b=1"),
        )
        self.assertEqual(
            extract_url_parts("https://API.EXAMPLE.COM./x"),
            ("api.example.com", True, "api.example.com", "/x"),
        )
        self.assertEqual(
            extract_url_parts("http://api.example.com?q=1"),
            ("api.example.com", False, "api.example.com", "/?q=1"),
        )
        self.assertEqual(
            extract_url_parts("http://api.example.com.:443/x"),
            ("api.example.com", False, "api.example.com:443", "/x"),
        )
        self.assertEqual(
            extract_url_parts("http://user:pw@api.example.com:443/p"),
            ("api.example.com", False, "api.example.com:443", "/p"),
        )


class NormalizeHostMatrix(unittest.TestCase):
    def test_operator_input_forms_collapse_to_canonical(self):
        # Every operator spelling of the same host normalizes identically.
        cases = {
            "api.com": "api.com",
            "API.COM": "api.com",
            "Api.Com": "api.com",
            "api.com.": "api.com",
            "API.COM.": "api.com",
            "u@api.com": "api.com",
            "user:pw@api.com": "api.com",
            "api.com:443": "api.com",
            "api.com:8080": "api.com",
            "http://api.com/x": "api.com",
            "https://api.com:443/a/b?q=1": "api.com",
            "https://api.com./x": "api.com",
            "  api.com  ": "api.com",
            "[::1]": "::1",
            "[::1]:443": "::1",
            "169.254.169.254": "169.254.169.254",
            "EXAMPLE.COM.": "example.com",
        }
        for raw, expected in cases.items():
            self.assertEqual(
                normalize_host(raw), expected,
                f"normalize_host({raw!r})",
            )

    def test_non_hosts_reject_to_none(self):
        for raw in ("", "   ", "/", "/path/only", "api.com/foo", "://",
                    "http://", None):
            self.assertIsNone(
                normalize_host(raw), f"normalize_host({raw!r}) should be None",
            )

    def test_operator_grant_and_url_host_agree(self):
        # The load-bearing property: for a set of hosts, the operator's
        # (possibly decorated) spelling and the URL the program passes to
        # net.get both normalize to the SAME allowlist key. If these ever
        # disagree the guest gate silently under- or over-approves.
        pairs = [
            # (operator spelling, full URL the program uses)
            ("api.com", "https://api.com/path"),
            ("API.COM", "http://api.com/"),
            ("api.com", "https://api.com./trailing"),   # trailing-dot URL
            ("api.com.", "https://api.com/x"),           # trailing-dot grant
            ("api.com:443", "https://api.com:443/x"),
            ("u@api.com", "http://u@api.com/x"),
            ("[::1]", "http://[::1]:8080/x"),
            ("169.254.169.254", "http://169.254.169.254/latest/meta-data"),
            ("EXAMPLE.COM.", "https://example.com/"),
        ]
        for op_spelling, url in pairs:
            grant = normalize_host(op_spelling)
            host_from_url = url_host(url)
            host_from_split = split_net_url(url)[0]
            self.assertIsNotNone(grant, op_spelling)
            self.assertEqual(
                grant, host_from_url,
                f"grant {op_spelling!r} vs url_host({url!r})",
            )
            self.assertEqual(
                grant, host_from_split,
                f"grant {op_spelling!r} vs split_net_url({url!r})[0]",
            )

    def test_trailing_dot_symmetric_both_directions(self):
        # The closed bug, stated as an equivalence in both directions.
        self.assertEqual(normalize_host("api.com"), url_host("https://api.com./x"))
        self.assertEqual(normalize_host("api.com."), url_host("https://api.com/x"))
        self.assertEqual(
            split_net_url("https://api.com./x")[0],
            split_net_url("https://api.com/x")[0],
        )

    def test_strip_trailing_dot_single_only(self):
        self.assertEqual(strip_trailing_dot("api.com."), "api.com")
        self.assertEqual(strip_trailing_dot("api.com"), "api.com")
        # Only ONE trailing dot is stripped (a pathological double dot
        # keeps the inner one; such a host never resolves anyway).
        self.assertEqual(strip_trailing_dot("api.com.."), "api.com.")


if __name__ == "__main__":
    unittest.main()
