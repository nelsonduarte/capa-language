# Capa would have caught: the XXE design-pattern CVE class

A walkthrough of how Capa's capability discipline structurally
rules out the XML external entity (XXE) bug class canonicalised
by Python's lxml but endemic across XML parsers in every major
language.

> The full runnable Capa side of this writeup is in
> [`examples/cve_lxml_xxe.capa`](../examples/cve_lxml_xxe.capa).

Third case study in the **design-pattern CVE** arc, after
[PyYAML](cve_pyyaml.md) (deserialisation) and
[Jinja2 SSTI](cve_jinja2_ssti.md) (template injection). All
three share the shape "the library's own API offers a side-
channel to arbitrary code execution or data exfiltration"; XXE
is the XML-parsing instance.

---

## What the bug class looks like

XML allows entity declarations inside a `<!DOCTYPE>` block. An
external entity references a URL or file path. A parser that
resolves external entities by default will, when it sees:

```xml
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

open `/etc/passwd`, read its contents, and substitute them at
the `&xxe;` reference. The "parser" has been recruited as an
arbitrary-file-read primitive. Variants include:

- **File read**: `file://` URIs as above.
- **SSRF**: `http://` URIs (the parser fetches a URL the
  attacker chose, often used to read AWS / GCP / Azure
  metadata services).
- **Blind XXE**: parameter entities with out-of-band channels
  for data exfiltration when the result is not echoed back.
- **Billion laughs / quadratic blow-up**: nested entity
  expansion as a denial-of-service.

The bug class is endemic. Representative CVEs:

- **Python lxml**: CVE-2021-43818, CVE-2021-28957, CVE-2018-19787.
- **Python xml.etree** (expat backend): historical
  vulnerabilities, mitigated by `defusedxml`.
- **Java**: javax.xml.parsers default behaviour requires
  manual setting of `disable_external_entities` and several
  related features.
- **.NET**: XmlReader / XmlDocument default-resolver behaviour
  before security defaults were tightened.
- **PHP**: libxml required `libxml_disable_entity_loader`
  globally; removed in PHP 8.0 as the default became safe.
- **Ruby**: Nokogiri has the `NONET` option for blocking
  external entities; opt-in.

OWASP tracks XXE as a recurring entry in the Top 10; the 2017
edition had it as its own category, which folded into A05:2021
"Security Misconfiguration" not because the bug went away but
because every library now has a flag to disable the behaviour.
The flag being opt-in is itself the misconfiguration.

---

## The structural problem

An XML parser is, ostensibly, a function from `String` to a
tree. Resolving an external entity is a function from `URI`
to `String`, which crosses into either the filesystem
(`file://`) or the network (`http://`, `ftp://`). The two
operations are categorically different; they have different
authority requirements; one is pure data manipulation and the
other is I/O.

XML's specification permits external entities, and every
mainstream XML library implements them. The library cannot
ship "XML parser" without also shipping "file fetcher" because
the parser's API surface is "the whole XML 1.0 grammar". The
result is a library that has, for every consumer, a
file-system and network capability that the consumer never
asked for. The CVE record is the consequence.

---

## The Capa version

Here is a Capa-shaped XML parser
([cve_lxml_xxe.capa](../examples/cve_lxml_xxe.capa)). The
signature is the contract:

```capa
fun parse_xml(source: String) -> Result<XmlNode, ParseError>
```

Run it:

```bash
$ capa --run examples/cve_lxml_xxe.capa
safe: tag=user text=alice
xxe attempt rejected: external entity declarations are not resolved
ssrf-via-xxe attempt rejected: external entity declarations are not resolved
```

The function takes a `String` and returns a tree or a typed
parse error. **No capability is declared.** The body cannot
reach `Fs`, `Net`, or `Unsafe`. The string
`"file:///etc/passwd"` appearing inside the input is just
text; there is no path in the type system from that text to
an open-file operation.

For added clarity, the example also rejects DOCTYPE-with-ENTITY
shapes at parse time so callers get an explicit signal. But the
structural argument holds even if it did not: a function
without `Fs` cannot read `/etc/passwd` regardless of whether
its input asked it to.

## What an attacker would try

To make a Capa XML parser actually resolve external entities,
the signature would have to widen to take `Fs` and `Net`:

```capa
fun parse_xml(fs: Fs, net: Net, source: String) -> Result<XmlNode, ParseError>
    // Now it CAN fetch file:// and http:// references...
    if uri.starts_with("file://")
        let path = strip_prefix(uri, "file://")
        let content = fs.read(path)?
        ...
    if uri.starts_with("http://")
        let body = net.get(uri)?
        ...
```

And then **every caller of `parse_xml`** would need to hold
both `Fs` and `Net`. The widening surfaces in:

- The function signature (`fs: Fs, net: Net` parameters).
- The CycloneDX SBOM as
  `capa:declared_capability = "Fs"` and `"Net"` on the
  function record.
- The SPDX SBOM as matching `annotations[]`.
- The audit pipeline as a policy violation for any policy
  that did not permit Fs+Net on a "parser".
- Every PR / dependency-upgrade diff that introduces such a
  widening.

The XXE-equipped XML parser is not invisible; it is made
**categorically loud**. A CRA auditor reading the SBOM sees,
on the function record for an XML parser, two ambient-
authority capabilities the function should not need. That is
exactly the signal regulators want a defender to be able to
extract from the artefact.

---

## Comparison with the existing mitigations

| Property | lxml (default) | lxml + `resolve_entities=False` | `defusedxml` | Capa parse_xml |
|---|---|---|---|---|
| External entity resolution | yes | no | no | **impossible** |
| Mechanism | parser API surface | configuration flag | wrapper library | type system |
| Opt-in | unsafe is default | safe is opt-in | safe is opt-in | safe is the only option |
| Bypass surface | XML 1.0 features | misconfiguration | wrapper bypass | none: no `Fs` / `Net` in scope |
| CVE history | long | tightening | smaller | none possible at the type level |

The `defusedxml` Python library is the most defensive of the
mitigations, but it is still a wrapper around the standard
library; a developer who skips `defusedxml` and uses
`xml.etree` directly is back at the default. The Capa parser
does not have an "unsafe variant available if you opt in"; the
"unsafe variant" would have a different signature, visible
across the call graph.

---

## What this case study generalises

XXE is one instance of a broader pattern: **"parsers should
parse, not fetch"**. Other instances:

- **YAML aliases / anchors with file-include extensions** (PHP
  Symfony YAML, some Ruby YAML wrappers).
- **JSON Schema `$ref` URLs**: many schema validators
  dereference `$ref: "https://example.com/schema.json"` by
  default.
- **CSV with formula evaluation** in spreadsheet imports
  (CVE-2014-3524 family).
- **Markdown extensions with `include` directives** in static-
  site generators.
- **Configuration loaders with `!include` / `!env` directives**
  (Docker Compose, Ansible Vault, some Kubernetes manifests).

In every case the library does more than its surface API
suggests. The Capa argument is uniform: separate the parser
from the fetcher. A `(String) -> Result<Document, ParseError>`
function cannot fetch; if you need fetching, the signature
must say so, and the caller must pass the capabilities.

---

## What Capa does *not* solve

- **Capa does not fix existing XML parsers.** A Python project
  using lxml today is not made safer by Capa existing. The
  claim is that an XML parser *written in Capa* cannot have
  this bug class.

- **Billion-laughs / quadratic-blowup DoS is partially out of
  scope.** Capa's structural rule rules out external entity
  resolution but does not by itself rule out exponential
  internal entity expansion. A production Capa XML parser
  would add an expansion-budget runtime check; this is a
  smaller, well-understood problem.

- **Schema validation and namespace handling are independent
  problems.** Capa addresses the authority surface, not the
  schema semantics. A parser that accepts a schema must still
  handle namespaces, validation, and so on correctly; those
  are different bugs.

- **The `parse_xml` demo in the example file is intentionally
  tiny.** A production XML parser is thousands of lines. The
  point is the *signature shape*, not a working production
  parser; the bug-class argument is independent of how the
  parsing internals are implemented.

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_lxml_xxe.capa

# Inspect the SBOM: parse_xml has zero declared capabilities
capa --cyclonedx examples/cve_lxml_xxe.capa | grep -B1 parse_xml
```

This is the third library in the empirical-at-scale arc,
after [PyYAML](cve_pyyaml.md) and
[Jinja2 SSTI](cve_jinja2_ssti.md). With three landed
case studies the arc has covered three distinct design-pattern
bug classes (deserialisation, template injection, XML
external entities). The fourth planned is Python pickle, which
is the canonical example of "deserialisation as gadget chain"
and complements PyYAML's "deserialisation as constructor
invocation" angle.
