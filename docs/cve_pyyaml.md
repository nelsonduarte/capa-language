# Capa would have caught: the PyYAML `yaml.load()` design-pattern CVE

A walkthrough of how Capa's capability discipline structurally
rules out the bug class behind PyYAML's CVE-2017-18342 (and the
long tail of related CVEs across deserialisation libraries in
many languages).

> The full runnable Capa side of this writeup is in
> [`examples/cve_pyyaml.capa`](../examples/cve_pyyaml.capa).

This case study is **different in kind** from the supply-chain
CVEs already in the repository (event-stream, eslint-scope,
ua-parser-js, torchtriton, node-ipc, xz-utils). Those were
*delivery* attacks: malicious code reached the user through a
trusted distribution channel. PyYAML's `yaml.load()` is a
**design-pattern vulnerability**: the legitimate library's own
API offered a way to execute arbitrary code, and the attacker
just supplied an input that used it.

---

## What happened

For most of PyYAML's history, the headline deserialisation
function was `yaml.load(stream, Loader=yaml.Loader)`. The
default `Loader` recognised YAML tags like
`!!python/object/apply:os.system [arg]` and constructed the
corresponding Python objects, executing arbitrary code as a
side effect of "parsing".

A user who wrote

```python
import yaml
config = yaml.load(open("config.yml"))
```

believed they were parsing structured data. They were in fact
running every Python construct the YAML document declared:
function calls, class instantiations, attribute lookups,
imports.

The fix, distributed in PyYAML 5.1 (March 2019) and
backported under CVE-2017-18342, was to deprecate the unsafe
default and steer users to `yaml.safe_load()` (or
`Loader=yaml.SafeLoader`), which restricts the deserialisable
type set to pure data shapes: strings, numbers, sequences,
maps.

Primary sources:

- [CVE-2017-18342 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2017-18342)
- [PyYAML changelog, version 5.1](https://github.com/yaml/pyyaml/blob/master/CHANGES)
- [Trail of Bits, "Python YAML Hazards"](https://blog.trailofbits.com/2024/07/24/python-yaml-hazards/)

---

## The bug class is endemic

The same shape recurs across language ecosystems:

- **Python**: `pickle.loads`, `marshal.loads`, `shelve.open`,
  `pyyaml.load` (pre-5.1).
- **Java**: `ObjectInputStream.readObject`, Apache Commons
  Collections gadget chains, Spring Expression Language.
- **.NET**: `BinaryFormatter`, `LosFormatter`,
  `ObjectStateFormatter`.
- **Ruby**: `Marshal.load`, YAML.unsafe_load.
- **PHP**: `unserialize`.
- **Node.js**: `serialize-javascript`, `node-serialize`.

The shared design pattern is "the deserialiser is given enough
authority to construct any runtime object". That authority is
indistinguishable from arbitrary code execution; once a
deserialiser can call constructors and `__reduce__` methods,
the format is a Turing-complete instruction set delivered as
data.

The CVE database tracks dozens of incidents in this family
every year. The Trail of Bits article above documents three
new exploitable patterns in PyYAML alone, in code that
ostensibly migrated to `safe_load`.

---

## The Capa version

Here is a Capa-shaped structured-data parser
([cve_pyyaml.capa](../examples/cve_pyyaml.capa)). The
signature is the contract:

```capa
fun parse_structured(text: String) -> Result<JsonValue, ParseError>
    return match parse_json(text)
        Err(e) -> Err(ParseError { line: 0, column: 0, message: e })
        Ok(v) -> Ok(v)
```

Run it:

```bash
$ capa --run examples/cve_pyyaml.capa
safe input: object with 3 keys
malicious input parsed as data: object with 1 keys
  command field stays a String, never executed
```

The function takes a `String` and returns a `Result<JsonValue,
ParseError>`. **No capability is declared.** No `Unsafe`, no
`py_import`, no `py_invoke`. Capa's type system does not
permit a function with this signature to construct arbitrary
runtime types or invoke arbitrary methods. The compiler
literally cannot emit code that calls `os.system` from inside
`parse_structured`, because the name `os` is not in scope and
neither is the `py_invoke` escape hatch.

A malicious input that, in PyYAML, would have executed
`os.system("whoami")`, is parsed by this function as a string
of bytes. The `command` field holds the literal text
`"!!python/object/apply:os.system [whoami]"` and the program
never touches anything else.

## What an attacker would try

The PyYAML-style attack, transliterated into Capa, would look
like:

```capa
fun parse_structured(text: String) -> Result<JsonValue, ParseError>
    // === Attack attempt: walk the tag space and instantiate ===
    let tag = extract_tag(text)
    if tag == "!!python/object/apply:os.system"
        let arg = extract_arg(text)
        let _ = py_invoke("os.system", arg)   // execute the payload
    ...
```

And here is what the analyzer says when you try to compile it:

```
error: undefined name 'py_invoke'
   5 |         let _ = py_invoke("os.system", arg)
                       ^

note: 'py_invoke' is part of the Unsafe capability surface;
      it can only be invoked from a function that declares an
      Unsafe parameter in its signature.
```

To make the attack compile, the attacker has to widen the
signature:

```capa
fun parse_structured(unsafe: Unsafe, text: String) -> Result<JsonValue, ParseError>
    // now compiles, but...
```

And **every caller of `parse_structured`** would now have to
hold an `Unsafe` capability to invoke it. The `Unsafe` widening
is precisely what:

- shows up in the CycloneDX SBOM as `capa:has_unsafe = true`
  on the function record
- shows up in the audit pipeline
  ([`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa))
  as a policy violation for any function the policy did not
  permit Unsafe on
- shows up in the SBOM diff tool
  ([`examples/sbom_diff.capa`](../examples/sbom_diff.capa))
  as a widening between releases
- is exactly the alarm bell a CRA auditor or a NIS2-bound
  supplier-due-diligence process is meant to surface

The attack is not invisible; it is made categorically loud.

---

## Why this is *strictly* stronger than `safe_load`

PyYAML's `safe_load` is a mitigation: a sub-mode of the
library that restricts the deserialisable type set. The
library itself still exposes the unsafe variant; a developer
who picks the wrong function, or a downstream caller who
configures `Loader=yaml.Loader` explicitly, gets the unsafe
behaviour back. Trail of Bits' 2024 audit found three new
exploit chains in code that thought it was using `safe_load`
correctly.

Capa's discipline is not opt-in. There is no "unsafe variant"
of `parse_structured` available unless the function declares
`Unsafe` in its signature, and that declaration is visible in:

- the function's source (the parameter list)
- the manifest (`capa --manifest`)
- the CycloneDX SBOM (`capa:has_unsafe = true`)
- the SPDX SBOM (`capa:has_unsafe=true` annotation)
- the function's call sites (every caller must hold `Unsafe`
  to pass it in)

A reviewer reading any of those surfaces sees the same fact:
this function escapes the capability discipline. There is no
hidden mode.

---

## What Capa does *not* solve

The same honest limits as the other case studies. Listing
once more:

- **A function that legitimately declares `Unsafe` can still
  do anything inside it.** Capa rules out *implicit* unsafe
  behaviour, not *all* unsafe behaviour. A library that
  declares `Unsafe` is making an honest declaration that a
  reviewer must trust at a higher bar.

- **Capa is not a sandbox.** A process running a Capa program
  inherits the OS-level authority of that process. Capa's
  guarantees are source-level.

- **The bug class extends beyond deserialisation.** Template
  injection (Jinja2 SSTI), XXE in XML parsers, and SQL
  injection are all "design-pattern vulnerabilities" in the
  same family. Each would need its own case study; the same
  structural argument applies. See the
  [roadmap](../docs/roadmap.html) for the multi-library
  empirical study.

- **Capa does not retro-fit existing libraries.** A Python
  project using PyYAML today is not made safer by Capa
  existing. The case study claim is "a library written in
  Capa cannot have this bug class"; it is not "Capa fixes
  PyYAML".

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_pyyaml.capa

# The attack version: copy the malicious parse_structured from
# above into a file, run --check, observe the "undefined name
# 'py_invoke'" error.
```

The full CycloneDX SBOM for the file:

```bash
capa --cyclonedx examples/cve_pyyaml.capa
```

Every function record carries `capa:has_unsafe = "false"`.
That is the property a CRA Annex I Part I (2)(f) (integrity
of data and programs) auditor wants in writing.
