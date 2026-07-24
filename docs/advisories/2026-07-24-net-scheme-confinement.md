# Capa security advisory, 2026-07-24: an unrestricted `Net` could read local files and reach non-HTTP schemes

> **Status.** Published with the `1.20.0` release. `Net.get` and
> `Net.post` handed the request URL to Python's default `urllib`
> opener, which registers `FileHandler`, `DataHandler` and
> `FTPHandler`. A program holding only a `Net` capability, with no `Fs`
> parameter, could therefore read a local file over `file://`, decode a
> `data:` payload, or open an FTP control connection, and a redirect
> could steer a request to a host the capability never permitted because
> the host check ran only on the initial URL. This is a
> capability-confinement bypass: one capability (`Net`) exercised
> another's authority (filesystem read, and arbitrary-scheme egress).
> The fix bounds `Net` to `http` / `https` on the first request and on
> every redirect hop, which refuses `file:` / `data:` / `ftp:` URLs that
> a previous version accepted. That is a change to the observable
> behaviour of a covered surface, claimed under the
> [`STABILITY.md`](../../STABILITY.md) **security exception** and
> therefore shipping as a **MINOR** bump, not a MAJOR one. The rationale
> is stated below.

This advisory satisfies the `STABILITY.md` requirement that a security
fix changing observable behaviour without a major bump "ships with a
security advisory ... [that] states explicitly what changed and why the
change is not subject to the major-bump rule."

Affected versions: every shipped version that has a `Net` capability,
`v0.2.0-alpha` through `v1.19.0`. The `urlopen`-based transport that
carries the defect landed in commit `455eaf8` ("Implement first-class
capability attenuation on `Net`", 2026-05-11) and has been present on
every release since.
Fixed in: `1.20.0`.
Reporter / process: found internally during adversarial review of the
`Net` capability, and reproduced against the downloaded,
checksum-verified `1.19.0` release binary, not only from source.
Channel: this advisory; cross-referenced from
[`SECURITY.md`](../../SECURITY.md) and the `1.20.0` `CHANGELOG.md`
entry.

## The finding

A `Net` capability is supposed to grant one authority: outbound network
requests, narrowed by attenuation to the hosts a program is allowed to
reach. `Net.get` and `Net.post` parsed the URL, checked
`allows(host)`, then handed the request to `urllib`'s **default
opener**. That opener is assembled by `urllib.request.build_opener()`,
which registers a `FileHandler`, a `DataHandler` and an `FTPHandler`
alongside the HTTP ones. Nothing downstream restricted the scheme, and
the redirect handler re-checked no host on a hop.

Four consequences were measured, each of them exiting 0:

- **A `file://` URL read the local filesystem with no `Fs` capability
  present.** A program declared `fun main(stdio: Stdio, net: Net)`, with
  no `Fs` parameter, called `net.get("file:///path/to/secret")`, and
  received the file's contents back as the response body. This was
  reproduced in the downloaded, checksum-verified `1.19.0` release
  binary, not only from a source checkout.

- **`--manifest` on that same program certified the filesystem was
  excluded.** The emitted manifest listed `Fs` in
  `provably_excluded_capabilities` while the program was reading a local
  file. This is the part that matters most for what Capa claims. The
  central promise is that the manifest is a true, machine-checkable
  statement of the authority a program can exercise. Here the artifact
  stated the filesystem was provably out of reach and the program read
  from it on the same run, so the manifest was not merely incomplete, it
  was wrong in the exact direction a consumer of the SBOM would trust.

- **`data:` and `ftp:` schemes were reachable too.** A `data:` URL
  returned its decoded payload. An `ftp:` URL opened a real FTP control
  connection, including through a `Net` that had been restricted to the
  FTP host, so the scheme was unbounded independently of the host
  attenuation.

- **A redirect could cross a host boundary the capability denied.** The
  host check ran only against the initial URL. A program restricted to
  `127.0.0.1` reported `allows("localhost") == false` and then, on the
  next line, served a body fetched from `localhost` via a `302`, because
  `urllib` followed the redirect with nothing re-checking the target of
  the hop.

## Threat model: who has to do what for this to bite

This is a **capability-confinement bypass**, not remote code execution,
and it is worth stating the trigger precisely rather than rounding it up
or down.

It bites whenever a program that already holds a `Net` capability
processes a URL it did not fully control. The most direct case is an
**attacker-influenced URL**: any program that fetches a
caller-supplied, config-supplied or otherwise externally-influenced
address with `Net.get` / `Net.post` could be steered at a `file://`
target and made to return local file contents to the caller, or steered
across a redirect to a host its attenuation was meant to forbid. It also
bites with **no attacker at all**: a developer who passes a `file://` or
`data:` URL by mistake gets filesystem read out of a capability that the
type signature, and the manifest, both said could not touch the
filesystem.

What it does **not** require, in the common framings, is control of the
Capa source. The program does not have to be malicious; it only has to
hold `Net` and act on a URL whose scheme or redirect target it did not
pin. What it does **not** grant is code execution or authority beyond
filesystem *read* and arbitrary-scheme *egress* through the process's
own ambient network and file access. It is a real confinement bypass,
and it is bounded to that.

## The fix

Both methods now run through an opener built explicitly, by hand,
**without** `urllib`'s `FTPHandler`, `FileHandler` or `DataHandler`, so
`file:` / `data:` / `ftp:` are unreachable rather than merely
unrequested. The scheme is bounded to `http` / `https`, checked against
`_NET_ALLOWED_SCHEMES`, on the first request and again on every redirect
hop. The redirect handler re-checks the **same** capability's
`allows(host)` on each hop, so a redirect to a permitted host is
followed as before and any other hop returns the ordinary host-deny
`Err(IoError)` instead of being fetched. The Python pipeline and the
`capa:host` bridge share one `Net` object and behave identically. This
lives in [`capa/runtime/_capabilities.py`](../../capa/runtime/_capabilities.py).

One residual on the redirect path is stated in the `1.20.0`
`CHANGELOG.md` entry and in the design docs rather than left silent: a
redirect to a **permitted** host. A `--wasi` guest cannot reach even
that, because its scheme, authority and path come from a compile-time
literal.

## Why this is a security fix and not a breaking change

Refusing `file:` / `data:` / `ftp:` and denying a cross-host redirect
changes observable behaviour: a program that previously fetched those
now gets an `Err`. Under `STABILITY.md` that would ordinarily be a
major-bump surface. It ships as a minor under the **security
exception**, because the previous behaviour was itself the
vulnerability. A `Net` capability that can read the filesystem, reach
arbitrary schemes, and cross a host boundary its attenuation denied is
not a smaller confinement than intended, it is a broken one, and the
manifest it produced misreported the program's authority. The direction
of the change is strictly narrowing: a request that only succeeded by
escaping the intended scheme or host set now fails, and no request that
was already `http` / `https` to a permitted host is affected.

## Who is affected, and what to do

You are affected if you shipped or ran a program on `v0.2.0-alpha`
through `v1.19.0` that holds a `Net` capability and fetches a URL whose
scheme or redirect target it does not fully pin.

**Remediation is to upgrade to `1.20.0`.** There is no mitigation short
of upgrading. The `file:` / `data:` / `ftp:` schemes were reachable on a
fresh, unrestricted `Net` with no configuration that could turn them
off, and the redirect host-recheck did not exist to be enabled, so on an
affected version there is no flag, setting or attenuation that closes
the bypass. Host attenuation (`restrict_to`) does not help against
`file://`, which carries no host the check would see, and does not help
against a redirect, which was checked only on the initial URL.

On an affected version you can, at most, audit rather than mitigate:
treat any program holding `Net` that acts on an externally-influenced
URL as exposed, and do not rely on a `--manifest`
`provably_excluded_capabilities` entry for `Fs` from an affected build,
since that exclusion could be certified while the program read local
files. After upgrading, re-emit any published manifest or SBOM for an
affected release; the previous one may have reported the filesystem as
excluded for a program that could reach it.

## Denial-of-service bounds shipped in the same release

`1.20.0` also gave `Net` reads a wall-clock deadline and a default
32 MiB size ceiling, closing a separate axis where a slow or oversized
endpoint could hold or exhaust the host. Two residuals remain, and both
are **DoS residuals, not confinement residuals**: neither affects the
`file://` bypass or the redirect recheck above.

- The **connect / header phase** of a request is not held to the
  wall-clock deadline. It gets a per-operation timeout equal to the
  remaining budget, which a slow-header server can reset, so such a
  server can still hold a call. This is stated in the `1.20.0`
  `CHANGELOG.md` entry and documented on the `Net` class.
- The **peak host allocation** for a `Net` read is about twice the size
  cap, a property of the buffered read path recorded against the
  result-cap mechanism in `CHANGELOG.md`.

These bound resource use, not authority, and are disclosed here so the
size-and-timeout part of the release is not read as more than it is.
