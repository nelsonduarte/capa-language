# Capa would have caught: the Jinja2 SSTI design-pattern CVE class

A walkthrough of how Capa's capability discipline structurally
rules out the server-side template injection (SSTI) bug class
canonicalised by Jinja2 but endemic across template engines in
many languages.

> The full runnable Capa side of this writeup is in
> [`examples/cve_jinja2_ssti.capa`](../examples/cve_jinja2_ssti.capa).

This is the second case study in the **design-pattern CVE** arc,
after [PyYAML](cve_pyyaml.md). Both are about library APIs that
offer arbitrary code execution as a side effect of "innocent"
operations; this one is about attribute traversal in template
engines.

---

## What the bug class looks like

A template engine takes a template string with substitution
syntax (`{{var}}`, `${var}`, `<%= var %>`, etc.) and a context
mapping names to values, and produces a rendered string. The
SSTI bug class arises when the substitution syntax can express
more than name lookup: attribute access, method invocation,
indexing, arithmetic, and so on. If the template is derived
from untrusted input, the attacker can supply expressions like:

```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

The engine walks `__class__`, `__init__`, `__globals__`, indexes
`'os'`, calls `popen`. Each step is a normal language operation;
the *combination* gives arbitrary code execution. The same
shape applies to every popular template engine:

- **Python**: Jinja2 (CVE-2014-1402, ongoing), Mako, Genshi,
  Django templates (sandbox bypasses).
- **Java**: Velocity (CVE-2020-13936), Freemarker
  (CVE-2017-1000136), Apache Camel JSON-paths.
- **PHP**: Smarty (CVE-2021-26119), Twig (CVE-2019-9942).
- **Ruby**: ERB with untrusted input, Slim.
- **JavaScript**: Handlebars with prototype-pollution chains,
  Pug, EJS.

PortSwigger's research group calls this an "uncomfortably common
class of vulnerability" in their [SSTI cheat sheet][portswigger];
[OWASP Top 10][owasp] tracks template injection under A03:2021
"Injection".

[portswigger]: https://portswigger.net/research/server-side-template-injection
[owasp]: https://owasp.org/Top10/A03_2021-Injection/

---

## Jinja2's mitigation, and why it is fragile

Jinja2 ships a `SandboxedEnvironment` that blacklists
attribute traversal outside a safe set and intercepts method
calls. The blacklist is the security boundary. Each new
escape technique (a class not in the deny-list, a magic method
the sandbox forgot, a Python builtin reachable through a
different path) is a new CVE: CVE-2016-10745, CVE-2019-10906,
CVE-2024-22195, with more to come.

The structural problem is that the safe boundary lives in a
piece of mutable Python code, not in the language. A
SandboxedEnvironment misconfiguration, a regression on
upgrade, or a default change in upstream Python's object model
can re-open the hole. The sandbox is opt-in: the default
`Environment` remains unsafe and many tutorials use it.

---

## The Capa version

Here is a Capa-shaped template engine
([cve_jinja2_ssti.capa](../examples/cve_jinja2_ssti.capa)).
The signature is the contract:

```capa
fun render(template: String, ctx: Map<String, String>) -> Result<String, RenderError>
```

Run it:

```bash
$ capa --run examples/cve_jinja2_ssti.capa
safe: Welcome, alice! Your role is: admin.
ssti attempt rejected: complex expressions are not permitted: config.__class__.__init__.__globals__
method-call attempt rejected: complex expressions are not permitted: name.upper()
unknown name handled: unknown name 'nonexistent'
```

The function takes a `String` template and a `Map<String,
String>` context, and returns either a rendered string or a
typed render error. **No capability is declared.** The body
cannot reach `Unsafe`, `py_invoke`, or any escape hatch.

The substitution language inside `{{...}}` is restricted by
the *parser* to bare identifier names. Any expression
containing `.` or `(` is rejected at render time as a typed
error, before any lookup happens. This is not a blacklist of
known-bad patterns; it is an allow-list of one shape (bare
name) that maps trivially to a `Map.get`.

## What an attacker would try

The Jinja2-style attack, transliterated into Capa, would
require widening the substitution language to support
attribute access:

```capa
// Attack attempt: support attribute access in the template
// language.
fun render(unsafe: Unsafe, template: String, ctx: Map<String, JsonValue>) -> ...
    // Parse the substitution body as a small expression
    // language: name, name.attr, name.method(), index.
    // Look up name in ctx; if the result is an object,
    // traverse .attr via py_invoke; if the trailing token
    // is `()`, call the result.
    let value = py_invoke("getattr", base, attr_name)
    ...
```

This is the design that makes SSTI possible. The Capa version
above does not have it: the parser inside `render` rejects
non-name substitutions, and `ctx` is typed as `Map<String,
String>` so the values are not even objects you could call
methods on.

If a future contributor proposed widening to attribute access,
the change would be visible in three places:

1. The `render` signature would need to take an `Unsafe`
   parameter (no way to invoke Python's `getattr` without it).
2. The context type would change from `Map<String, String>` to
   `Map<String, JsonValue>` or wider, surfacing the question
   "what shape do template values have?" in code review.
3. The CycloneDX SBOM emitted by `capa --cyclonedx` would
   show `capa:has_unsafe = "true"` on the `render` function,
   triggering the audit pipeline.

The structural rule is not "Capa knows about SSTI specifically".
The structural rule is "a function with `(String, Map<String,
String>) -> Result<String, _>` cannot reach `py_invoke`". SSTI
is one consequence; many other "the parser does more than the
caller expects" bug classes are ruled out by the same property.

---

## Comparison with Jinja2's SandboxedEnvironment

| Property | Jinja2 SandboxedEnvironment | Capa `render` |
|---|---|---|
| Mechanism | Python deny-list of attributes / call patterns | Parser allow-list of one syntactic shape |
| Bypass surface | every CPython feature not yet blacklisted | none: attribute traversal does not parse |
| Default | unsafe `Environment`; sandbox must be opted in | one function shape; no unsafe variant |
| Visible in signature? | no | yes: `Unsafe` would have to be added |
| Visible in SBOM? | no | yes: `capa:has_unsafe = true` on widening |
| Maintenance cost | ongoing CVEs as escapes are found | none: a new Python builtin does not affect the parser |

The Capa version is strictly stronger because the security
boundary is *syntactic* (the parser refuses to accept the
problematic shape), not *semantic* (the runtime refuses to
execute the resulting object). Syntactic boundaries do not
have escape chains.

---

## What this case study generalises

The same argument applies to every "domain-specific
substitution language" pattern:

- **SQL parameter binding** vs string concatenation: parameter
  binding refuses to accept SQL syntax inside parameters; the
  parser is the boundary.
- **HTML / CSS / URL escaping** with `markupsafe`-style typed
  strings: a `SafeString` cannot be concatenated with a
  user-supplied `String` without an explicit unsafe coercion.
- **JSON Path / GraphQL field selection**: a query that
  accepts an expression language is structurally different from
  one that accepts a fixed list of fields; the latter rules
  out injection by typing.

The bug class is "the input language is more expressive than
the caller intended". The Capa fix is "make the input language
exactly as expressive as the type system permits, and require
`Unsafe` to widen it".

---

## What Capa does *not* solve

- **Capa does not fix existing template engines.** A Python
  project using Jinja2 today is not made safer by Capa
  existing. The claim is that a template engine *written in
  Capa* cannot have this bug class.

- **Stored XSS and reflected XSS are different bugs.** SSTI
  is "server interprets template", XSS is "browser interprets
  HTML". Capa's structural rule addresses the server side;
  the browser side needs output encoding (which Capa programs
  can implement honestly, just like any other language).

- **A `render` function that legitimately needs more
  expressive templates would honestly declare `Unsafe`.** The
  capability discipline does not prevent expressive
  templating; it makes the expressivity visible. A code
  review can then weigh the trade-off explicitly.

- **The substitution-language design space is large.** Capa
  does not prescribe a single template syntax; the example
  uses `{{name}}` for parity with Jinja2, but the same
  structural argument works for `$name`, `<%= name %>`, or
  any other shape. The relevant property is "the substitution
  body parses as one fixed shape, not as an open-ended
  expression language".

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_jinja2_ssti.capa

# Inspect the SBOM: every function has capa:has_unsafe=false
capa --cyclonedx examples/cve_jinja2_ssti.capa | grep -A1 has_unsafe
```

This is the second library in the empirical-at-scale arc,
after [PyYAML](cve_pyyaml.md). Both are design-pattern CVEs
(the library's own API is the bug). The next planned case
studies are lxml XXE, Python pickle, and the Java
`ObjectInputStream` family, which together cover the four
canonical bug classes in this category: deserialisation,
template injection, XML external entities, and gadget-chain
unserialisation.
