# Where Capa partially loses: the node-ipc protestware incident

A concrete walkthrough of how Capa's capability discipline responds
to a class of supply-chain incident that it **does not fully
prevent**. This case study is in the repo deliberately, the
honesty matters more than only showing wins.

> The full runnable Capa side of this writeup is in
> [`examples/cve_node_ipc.capa`](../examples/cve_node_ipc.capa).

---

## What happened

In March 2022, the maintainer of [`node-ipc`][nodeipc] (~1 million
weekly downloads on npm, used transitively by Vue CLI and dozens
of other tools) shipped versions of his own packages that were
deliberately malicious. The maintainer was protesting the Russian
invasion of Ukraine.

The malicious behaviour evolved over several patch versions:

1. **`node-ipc@10.1.1`** introduced a new dependency,
   `peacenotwar`, that wrote `WITH-LOVE-FROM-AMERICA.txt`
   (heart-shaped emoji content) to the user's Desktop.
2. **`node-ipc@10.1.2`** added a transitive dependency,
   `colors-cli`, that contained code which (in shorter-lived
   versions) fetched the host's geolocation via
   `api.ipgeolocation.io` and, **if the host was in Russia or
   Belarus**, overwrote arbitrary files on disk with the
   `❤️` emoji.

The malicious version was *legitimately published* by the package
owner. It was not a credential theft, not a typosquat, not a
maintainer takeover. The exposure window before the community
caught it was several days; tens of thousands of CI builds and
developer workstations downloaded the package in that time.

Primary sources:

- [Snyk advisory CVE-2022-23812 (node-ipc)][cve]
- [The Liberapay blog: "Protestware on the rise"][liberapay]
- [GitHub thread on RIAEvangelist/node-ipc issues][issue]

[nodeipc]: https://github.com/RIAEvangelist/node-ipc
[cve]: https://security.snyk.io/vuln/SNYK-JS-NODEIPC-2426370
[liberapay]: https://liberapay.com/blog/12
[issue]: https://github.com/RIAEvangelist/node-ipc/issues/233

---

## Why this is different from the other case studies

The two preceding case studies in this repo
([event-stream](demo-event-stream.md) and
[eslint-scope](cve_eslint_scope.md)) share a structural property:
the malicious code lived inside a library **whose legitimate
job did not require the authority the malicious code abused**.

- A stream-transformation library does not need `Net` to
  transform streams.
- An AST scope analyser does not need `Fs` to walk an AST.

Capa's structural rule, *every external authority must appear in
the function signature*, made the attempted attacks visible in the
type system. The malicious widening of the signature was the
loud signal an auditor (human or automated) could act on.

node-ipc breaks this property. **node-ipc legitimately needs `Net`
and `Fs`**. It is an inter-process-communication library; that is
the whole point. A version that declares `Net` and `Fs` in its
signatures is not malicious-on-its-face the way an
`analyse_scopes(fs: Fs, net: Net, …)` would be.

The attacker here was the legitimate maintainer with the
legitimate authority. Capa's structural discipline cannot
distinguish "the maintainer used `Fs` to write `❤️` to user
files" from "the maintainer used `Fs` to write framed IPC
messages to a Unix socket".

This is the regime where capability typing **partially loses**.

---

## The Capa version

The natural shape of an IPC API in Capa is one where every
function that touches the wire declares the capability it needs:

```capa
fun connect(_net: Net, host: String, port: Int) -> IpcConnection
    ...

fun send(_net: Net, _conn: IpcConnection, _msg: String) -> Unit
    ...
```

Compiles and runs:

```bash
$ capa --run examples/cve_node_ipc.capa
sent via unrestricted Net to 127.0.0.1:8000
sent via attenuated Net to api.example.com
(project_fs is bound to /var/run/capa-ipc/ only)
log_message holds only Stdio, by design
```

A maintainer who controls these functions can put anything inside
them that the type `Net` permits. The same `Net` value that opens
the IPC socket can also `Net.get("https://api.ipgeolocation.io")`,
or open any other socket the underlying runtime allows.

---

## What Capa still does for you in this regime

The structural discipline does not vanish, it just shifts shape.
Three things remain useful:

### 1. The authority surface is explicit and SBOM-visible

A node-ipc-like library's manifest (`capa --cyclonedx`) lists
`capa:declared_capability=Net` and `capa:declared_capability=Fs`
on every function that touches them. There is no ambient access,
no hidden import; every place that can reach the network is
discoverable by reading the SBOM. The auditor reading the SBOM
sees "this library has Net authority; budget accordingly".

In npm, the equivalent declaration is absent or hand-authored
(the `permissions` field on some manifests, or a separate
SECURITY.md). The Capa SBOM is *derived from the type system*, so
it cannot be wrong about what authority the library uses
internally.

### 2. The caller can attenuate before passing

The example shows the attenuated pattern:

```capa
let api = net.restrict_to("api.example.com")
let project_fs = fs.restrict_to("/var/run/capa-ipc/")
let conn2 = connect(api, "api.example.com", 443)
```

`api` is a narrowed `Net`: it allows TCP to `api.example.com` and
nothing else. `project_fs` is a narrowed `Fs`: it allows reads
and writes under `/var/run/capa-ipc/` and nothing else.
Attenuation is monotonic, chained `restrict_to` calls intersect
the allowed sets, they never widen.

A node-ipc-shaped library handed `api` and `project_fs` cannot:

- Reach `api.ipgeolocation.io` to determine the host's country.
- Write `❤️` to `~/Desktop/WITH-LOVE-FROM-AMERICA.txt`.
- Open a connection to a Pastebin drop to exfiltrate anything.

The blast radius shrinks dramatically. The malicious version still
"works" in the type sense (compiles, has the right capabilities),
but its capability values are bounded sets that exclude every
target the original attack went after.

### 3. The audit catches policy violations before the deploy

The CRA-aligned audit
([`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa))
runs on the SBOM and compares it to a per-function policy. If a
project's policy says `node-ipc` may only have `Net`
attenuated to `api.example.com`, and a future version of
`node-ipc` widens its declared capability to include unrestricted
`Net` again, the audit fires. The widening is visible in source
control as a signature change, and visible in the SBOM as a
property change.

A maintainer who wants to ship malicious code from inside the
legitimate authority **must not change the signature**. So a
policy that pins the *attenuation* (not just the presence of the
capability) catches the widening that any "I need a wider Net now"
move would force.

---

## What Capa cannot do

Honestly, in this regime:

- **Capa cannot tell two `Net.get(host)` calls apart** when both
  go to allowed hosts. A maintainer who legitimately owns the
  domain the policy allows can still misuse the authority *within
  the allowed set*. If `api.example.com` is the allowed host and
  the maintainer also owns that domain, the discipline does not
  help.
- **Capa cannot detect the geofencing logic itself**. The
  malicious code checked the host's country and chose a payload.
  That branch is just a normal `if` over a normal HTTP response.
- **Attenuation only works if the caller actually does it**. The
  Capa version of the demo shows both unattenuated and attenuated
  patterns. If everyone takes the path of least resistance and
  passes the full `Net` to every dependency, Capa's leverage
  collapses to "the SBOM says Net" and nothing more.

This is consistent with the
[positioning document](positioning.md): Capa narrows the
authority graph, it does not eliminate trust. Maintainer takeover
attacks, and protestware-style author-as-attacker attacks, need
defences orthogonal to capability typing: code signing, reproducible
builds, transparency logs, multi-maintainer review.

---

## The thesis lesson

The honest version of the Capa claim is:

> Capa structurally rules out the class of supply-chain attack
> where the malicious code requires authority the function's
> declared role does not need. Attacks that fit within the
> *legitimate* authority surface of a library are not prevented;
> they are made *visible*, *bounded* (via attenuation), and
> *machine-comparable to a policy*.

The first class (event-stream, eslint-scope, torchtriton, most
typosquats) is structurally impossible. The second class
(node-ipc, xz-utils where the malicious code mimics legitimate
authority) is mitigated, not solved.

A defensible thesis acknowledges both. Capa raises the bar; the
height to which it raises the bar is the thesis contribution; the
ceiling above which it does not reach is the honest scope limit.

---

## Run it yourself

```bash
# Both paths in one run:
capa --run examples/cve_node_ipc.capa

# Inspect the SBOM that the build would emit, and see that Net
# and Fs are explicit per-function:
capa --cyclonedx examples/cve_node_ipc.capa | jq .
```
