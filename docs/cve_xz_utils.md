# Where Capa partially loses (different shape): the xz-utils backdoor

A concrete walkthrough of CVE-2024-3094, the multi-year backdoor
operation against `xz-utils` / `liblzma`, and an honest
discussion of how Capa's capability discipline relates to it.
This is the fourth CVE case study in the repo and the second
that is *deliberately* a partial loss; the partial loss has a
different shape from
[node-ipc 2022](cve_node_ipc.md).

> The full runnable Capa side of this writeup is in
> [`examples/cve_xz_utils.capa`](../examples/cve_xz_utils.capa).

---

## What happened

In late March 2024, Andres Freund noticed unusual CPU usage from
`sshd` on a Debian sid system and traced it to `liblzma`, the
compression library bundled with `xz-utils`. The discovery
unfolded into one of the most sophisticated supply-chain
operations on public record:

- The attacker, pseudonym "Jia Tan", spent roughly two years
  earning co-maintainer status on the upstream `xz-utils`
  project through legitimate-looking contributions.
- Two release tarballs, `xz-utils 5.6.0` (Feb 24 2024) and
  `5.6.1` (Mar 9 2024), shipped with a backdoor that activated
  only in specific packaging environments (dpkg, rpm) and only
  for binaries linked to the systemd-provided
  `libsystemd → liblzma` chain (most notably `sshd` on
  Debian / Ubuntu / Fedora).
- The payload chain:
  1. Obfuscated bytes hidden inside *test fixture files*
     (`tests/files/bad-3-corrupt_lzma2.xz` and a sibling) in
     the source tree.
  2. A modified `build-to-host.m4` autotools snippet that, at
     `make` time, extracted the payload from those test
     files into shared-object code.
  3. `IFUNC` indirection (a GNU dynamic-linker feature) used
     to swap `RSA_public_decrypt`'s resolved function pointer
     at load time, routing it through malicious logic in
     `liblzma`.
  4. The malicious resolver checked for specific RSA payloads;
     if a hard-coded key was presented, authentication
     succeeded without verification, granting the attacker
     pre-authentication remote code execution as root on
     sshd hosts.
- Andres Freund's [public disclosure on 29 Mar 2024][freund]
  caught the exposure window before Debian unstable had
  promoted the affected version to a release. The blast radius
  was contained to bleeding-edge distros; the *intended* blast
  radius was the entire Linux server fleet running modern
  systemd-based sshd.

Primary sources:

- [Andres Freund's oss-security post (29 Mar 2024)][freund]
- [Gynvael Coldwind's reverse-engineering analysis][gynvael]
- [Russ Cox's "research/2024-03-30 xz backdoor reading list"][russ]
- [The Register's overview][register]

[freund]: https://www.openwall.com/lists/oss-security/2024/03/29/4
[gynvael]: https://gynvael.coldwind.pl/?lang=en&id=782
[russ]: https://research.swtch.com/xz-script
[register]: https://www.theregister.com/2024/03/29/malicious_backdoor_xz/

---

## Why xz is different from the other partial-loss case (node-ipc)

[`docs/cve_node_ipc.md`](cve_node_ipc.md) makes Capa lose by
giving a rogue maintainer the *legitimate* authority their
library needed. Capa cannot tell two `Net.get()` calls apart;
both are legitimate at the type level.

xz loses Capa's bet for a *different* reason: **the attack did
not run at the language level at all**. The malicious code:

- Was not in `.c` source files as obvious malicious code.
- Was not in any function with a suspicious signature.
- Was packed into binary test fixtures committed to the source
  tree.
- Was assembled into shared-library bytes by *autotools build
  scripts* that activated only under specific packager
  conditions.
- Replaced a function pointer through *GNU IFUNC* dynamic-linker
  metadata, before any high-level language runtime had observed
  anything.

Even if `xz-utils` had been written in Capa, with the cleanest
possible capability discipline, the backdoor's load path would
have lived in:

- `.m4` autotools macros (executed by `autoconf`, before any
  source file is compiled).
- The build-time `Makefile` and packager hooks (executed by
  `make` and `dpkg-buildpackage`, neither of which is Capa).
- The dynamic linker's IFUNC resolver (executed by `ld.so`, in
  C, on every shared-library load).

Capa is a source-level discipline. It says nothing about the
build system, nothing about the packaging system, nothing about
the dynamic linker. The threat model the xz attacker was
exploiting starts *below* the layer Capa operates on.

---

## The Capa version

The legitimate role of `xz-utils` is bytes-in, bytes-out: a
compression / decompression API. In Capa, that surface is
*pure*, no capabilities at all
([cve_xz_utils.capa](../examples/cve_xz_utils.capa)):

```capa
fun compress(data: List<Int>, level: Int) -> List<Int>
    ...

fun decompress(data: List<Int>) -> List<Int>
    ...
```

The SBOM derived from these signatures lists no capabilities.
A `liblzma`-shaped library has, by construction, no path to
the network, the filesystem, the environment, or process
control. The downstream consumer reading the SBOM cannot be
confused into thinking the library asked for authority it did
not need.

```bash
$ capa --run examples/cve_xz_utils.capa
compressed 5 bytes -> 5 -> 5
authentication result for alice: True
```

The example also includes a small `authenticate` function:

```capa
fun authenticate(req: AuthRequest, allowed_keys: List<List<Int>>) -> Bool
    ...
```

This is the function the xz attack subverted: in the real
incident, `RSA_public_decrypt` (called from `sshd` during
authentication) was hijacked at dynamic-linker time. In Capa,
the `authenticate` function has no capabilities, no
side-effects, no externally-injectable resolver. The signature
*is* the contract.

---

## What Capa *would* have caught

The narrow source-level case where Capa contributes:

- **Signature widening would be loud.** If `liblzma`'s public
  API had legitimately been `bytes -> bytes` and a malicious
  contributor extended it to take, say, `Net` (perhaps under
  the guise of "telemetry"), the signature change would have
  been visible in every dependent project's call sites, in the
  SBOM diff between releases, and in the audit
  ([`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa)).

- **Compression-shaped attacks on Capa-compiled code do not have
  an IFUNC equivalent.** Capa's transpiled output is plain
  Python today, and a future native backend would use a calling
  convention that does not expose dynamic-linker indirection at
  the language level. The class of attack that targets shared-
  library resolution at load time would need a different
  primitive in a Capa ecosystem.

- **Test-fixture-as-payload would be detected by any reproducible-
  build pipeline** that the language ecosystem is plugged into.
  This is not Capa's contribution per se, but the language
  cleanly separates "code" from "test data" by type, and the
  build system reading a Capa project can refuse to compile
  test data into the deployable artefact.

---

## What Capa does *not* catch

Honestly, the bulk of what xz did:

- **Build-script execution at packaging time.** `dpkg`, `rpm`,
  `make`, `autoconf` — none of these are Capa. A malicious
  contributor who lands logic in those scripts has unlimited
  authority before any Capa code runs.

- **Binary test fixtures.** A `.xz` file checked into a git
  repository is data; Capa does not (and should not) read it.
  The malicious payload was inside that data.

- **Dynamic-linker indirection.** IFUNC, `LD_PRELOAD`,
  `__attribute__((constructor))`, and the broader ABI plumbing
  live below the language. Even a sound capability discipline
  inside the language cannot inspect a function pointer table
  that the OS dynamic linker controls.

- **The maintainer-takeover phase**. Jia Tan's two-year
  patience-and-trust attack is the same shape as the
  [node-ipc](cve_node_ipc.md) protestware story: orthogonal
  defences (multi-maintainer review, code signing, transparency
  logs, sandboxed CI for releases) have to cover this layer.

---

## The honest lesson

There is a stack of supply-chain attack layers:

| Layer                   | xz exploited it | Capa addresses it |
|-------------------------|-----------------|-------------------|
| Source-code authority   | no              | **yes**           |
| Maintainer takeover     | yes (Jia Tan)   | no (orthogonal)   |
| Build-script execution  | yes (`.m4`)     | no                |
| Binary test fixtures    | yes             | no                |
| Dynamic-linker IFUNC    | yes             | no                |
| Source-code legitimate
  authority misuse        | no              | partial (attenuation reduces blast radius) |

Capa addresses **one row** of this table well, and **one row**
partially. The xz operation chose every other row.

A defensible position acknowledges this explicitly. The Capa
contribution is *one defence in a stack*, not a sufficient
defence. The honest claim in
[positioning.md](positioning.md) is "Capa narrows the
authority graph, it does not eliminate trust"; xz is the
sharpest illustration that "the authority graph" is only one
of several attack surfaces.

For the **EU Cyber Resilience Act** (in force December 2027),
this matters because the CRA requires manufacturers to address
the *full* supply chain, not just the language layer. A
manufacturer ticking the "we use Capa" box still needs
reproducible builds, code signing, multi-maintainer release
processes, and transparency logs. Capa makes one row of the
checklist mechanically verifiable; the rest of the rows are
unchanged.

---

## Run it yourself

```bash
# Source-level demo (pure: zero capabilities required):
capa --run examples/cve_xz_utils.capa

# Inspect the SBOM and verify that compress / decompress / authenticate
# carry no capa:declared_capability entries:
capa --cyclonedx examples/cve_xz_utils.capa | grep declared_capability
# (empty output: the library legitimately needs no authority)
```
