# Capa would have caught: the pickle gadget-chain CVE class

A walkthrough of how Capa's capability discipline structurally
rules out the deserialisation-as-gadget-chain bug class
canonicalised by Python's `pickle` and Java's
`ObjectInputStream`, endemic across binary-deserialisation
libraries in every major language.

> The full runnable Capa side of this writeup is in
> [`examples/cve_pickle.capa`](../examples/cve_pickle.capa).

Fourth case study in the **design-pattern CVE** arc, after
[PyYAML](cve_pyyaml.md), [Jinja2 SSTI](cve_jinja2_ssti.md),
and [lxml XXE](cve_lxml_xxe.md). With this fourth library the
arc has covered the four canonical bug classes in the
design-pattern category:

| Bug class | Library | Mechanism |
|---|---|---|
| Deserialisation-as-codegen | PyYAML | format names a type to instantiate |
| Template injection | Jinja2 | substitution language allows attribute traversal |
| Parser-as-fetcher | lxml | XML resolution opens files / URLs |
| **Gadget-chain unserialisation** | **pickle** | **composition of `__reduce__` hooks across installed types** |

The arc is now structurally complete; subsequent libraries
will be additional empirical data points within these four
classes, not new classes.

---

## What the bug class looks like

The Python `pickle` format is a **stack-machine bytecode**. The
decoder reads opcodes that build Python objects on a stack:
`(`, `t` (tuple), `d` (dict), `c` (find class by module +
name), `R` (call), and so on. `pickle.loads` is, literally, an
interpreter for this bytecode running with the authority of
the host process.

A minimal hostile pickle:

```python
import pickle
pickle.loads(b"cposix\nsystem\n(S'id'\ntR.")
# Output: uid=1000(alice) gid=1000(alice) groups=...
```

Five opcodes total. The decoder imports `posix`, looks up
`system`, builds the argument tuple `('id',)`, calls it via the
`R` opcode. No "load arbitrary class" attack surface as in
PyYAML; the format itself is a call instruction set.

**Gadget chains** are the more pernicious variant. Python's
`__reduce__` protocol lets any class describe how to be
pickled. When the decoder sees a pickled instance of class
`C`, it calls `C.__reduce__()` to determine how to rebuild it.
Many classes in standard Python (`subprocess.Popen`, parts of
`os`, large parts of `numpy` / `pandas` / `pickle` itself) have
`__reduce__` methods that, in composition, are
Turing-equivalent. An attacker who knows what packages the
victim has installed picks gadgets from those packages'
`__reduce__` chains.

The bug class is endemic:

- **Python pickle**: the canonical example. `pickle.loads` is
  treated as roughly synonymous with `eval` by the security
  community.
- **Java ObjectInputStream**: the Apache Commons Collections
  CVE-2015-4852 family, the most famous Java
  deserialisation-as-RCE chain. Decade-long tail of CVEs in
  WebSphere, JBoss, Jenkins, OpenAM, and dozens of others.
- **.NET BinaryFormatter**: deprecated in .NET 5 specifically
  because the bug class is *unfixable* in the abstract.
  Microsoft's recommendation is "do not use".
- **Ruby Marshal.load**: same shape, smaller corpus of
  exploit research but the property is identical.
- **PHP unserialize**: POP (Property-Oriented Programming)
  chain CVEs across many frameworks.
- **Node.js**: `node-serialize`, `serialize-javascript`, and
  a long tail of npm packages that re-implement pickle.

Microsoft's documentation for the `BinaryFormatter`
deprecation says, in plain terms: "This class is dangerous
and is not recommended for processing untrusted input.
**The class cannot be made safe**".

[bf-deprecation]: https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide

---

## The structural problem

A deserialiser that produces an *untyped output* (Python
object, Java Object, .NET object) must, by construction, have
a mechanism to construct any type. The mechanism is then
indistinguishable from "interpret the input as code".

"Allow-list of safe types" fixes (Python's
`pickle.find_class`, Java's lookahead-class-validators) restrict
which classes can be named in the input. They are routinely
bypassed via classes in the allow-list whose own
`__reduce__` calls into broader machinery. The allow-list is
a deny-list of the global Python module space, and global
namespaces are large.

The structural fix is: **the deserialiser's output type must
be a fixed algebraic type, not the universe of runtime
types**. JsonValue, Protobuf-generated structs, typed Capa
records, Rust enums with `#[derive(Deserialize)]` are all
examples of the fix. Their decoders cannot produce a
`subprocess.Popen` because there is no place to put one.

---

## The Capa version

Here is a Capa-shaped deserialiser
([cve_pickle.capa](../examples/cve_pickle.capa)). Two
signatures, both with the contract baked in:

```capa
fun decode(input: String) -> Result<JsonValue, DecodeError>

fun decode_user(input: String) -> Result<User, DecodeError>
```

Run it:

```bash
$ capa --run examples/cve_pickle.capa
safe: name=alice age=30
gadget input parsed safely: name=bob age=25
typed error: 'age' is not a number
```

The first function returns a `JsonValue`: a closed algebraic
type covering numbers, strings, booleans, arrays, objects, and
null. There is no "and also an arbitrary Python class"
variant. The decoder cannot produce one because the type does
not have one.

The second function returns a `User`: a typed struct with a
known shape. Any input that does not match the shape is
rejected as a typed error. A gadget-chain payload that smuggles
an extra `__reduce__` field gets parsed as data and the field
is ignored by the consumer; the decoder never invokes anything.

**No capability is declared.** No `Unsafe`. No path from the
input bytes to method invocation on arbitrary types. The
gadget chain is, structurally, just bytes.

## What an attacker would try

To make a Capa deserialiser actually exhibit pickle's
behaviour, the signature would have to widen:

```capa
fun decode(unsafe: Unsafe, input: String) -> Result<Any, DecodeError>
    // For each opcode in the bytecode stream:
    //   c MODULE NAME  ->  py_import(MODULE).NAME
    //   R              ->  py_invoke(callable, args)
    //   ...
```

Two things widen:

1. The output type goes from `JsonValue` (or `User`) to
   `Any` (which Capa does not even have at the type level;
   the closest is `JsonValue`, which is bounded). To return
   "arbitrary runtime objects" the function would have to
   sidestep the type system altogether through `Unsafe`.

2. The signature adds an `Unsafe` parameter, surfacing the
   widening across the entire call graph.

A reviewer reading the SBOM sees `capa:has_unsafe = true` on
the `decode` function and stops there. A pickle-style decoder
is not just dangerous to use; it is structurally a *different
function* than a JSON-style decoder. The Capa SBOM makes the
two impossible to confuse.

---

## Comparison with the existing mitigations

| Property | pickle (default) | pickle + find_class allow-list | Protobuf / JSON | Capa decode |
|---|---|---|---|---|
| Output type | arbitrary Python object | restricted but still object | typed struct | typed algebraic |
| Code execution from input | yes | yes (via gadget chains) | no | no |
| Bypass surface | full Python | classes in allow-list with hooks | none | none |
| Maintenance cost | unfixable | ongoing CVE tail | low | none |
| Default | unsafe | unsafe is still possible | safe | safe is the only option |

Protobuf / JSON / typed deserialisers and Capa's `decode` are
on the same side of this table; the difference is that Capa
makes the property a language-level guarantee rather than a
library-author discipline.

---

## What this case study generalises

The four canonical design-pattern bug classes, now all covered
in the repository:

1. **Deserialisation-as-codegen** ([PyYAML](cve_pyyaml.md)):
   format names a type to instantiate.
2. **Template injection** ([Jinja2](cve_jinja2_ssti.md)):
   substitution language allows attribute traversal /
   method invocation.
3. **Parser-as-fetcher** ([lxml XXE](cve_lxml_xxe.md)):
   parser resolves URIs or file paths during parsing.
4. **Gadget-chain unserialisation** (this case study): decoder
   produces unbounded runtime types whose methods compose into
   code execution.

The Capa argument across all four is the same:

> The library's API surface declares more authority than its
> nominal job description requires. If the type system enforces
> the nominal job description, the extra authority cannot be
> reached.

Other bug classes that fit the same shape (not yet case-
studied in the repository, but where the structural argument
applies identically): SQL injection (parameter-bound queries
vs string concatenation), HTML/JavaScript injection (typed
`SafeString` vs raw string), file-path traversal in archive
extractors (typed normalised paths vs raw `os.path.join`),
header-injection in HTTP clients (typed `Url` vs raw `String`).

---

## What Capa does *not* solve

- **Capa does not fix `pickle`, `BinaryFormatter`, or
  `ObjectInputStream`.** A Python project that uses `pickle`
  today is not made safer by Capa existing. The claim is that
  a deserialiser *written in Capa* cannot have the gadget-
  chain bug class.

- **The four-bug-class taxonomy is not exhaustive.** It
  covers the design-pattern category, where the legitimate
  library's API is the bug. Other categories (logic bugs,
  cryptographic mistakes, race conditions, memory-safety
  issues in C code) are independent.

- **A `decode` function that legitimately needs to construct
  user-defined runtime types declares `Unsafe`.** Capa does
  not prevent expressive deserialisation; it makes the
  expressivity visible. A code review weighs the trade-off
  explicitly.

- **Protobuf is already safe in this dimension.** The Capa
  argument restates, at the language level, what Protobuf
  achieves at the library level: a closed algebraic output
  type rules the bug class out. The structural difference is
  that Capa applies the same rule uniformly across every
  parser written in the language, including ones whose
  authors did not specifically think about deserialisation
  security.

---

## Run it yourself

```bash
# The safe version (compiles and runs):
capa --run examples/cve_pickle.capa

# Inspect the SBOM: decode and decode_user have zero
# declared capabilities; the SBOM shows them as
# capa:has_unsafe = "false".
capa --cyclonedx examples/cve_pickle.capa | grep -B1 has_unsafe | head -10
```

This is the fourth library in the empirical-at-scale arc,
completing coverage of the four canonical design-pattern bug
classes. The arc's structural argument is now built; the
quantitative empirical study (transliterating ~10-20 real-
world libraries and measuring the SBOM diff) referenced in
[`docs/paper-draft.md`](paper-draft.md) future-work item 2 can
proceed from this base.
