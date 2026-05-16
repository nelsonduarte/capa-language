# LLM tool-use sandboxing with capabilities

## The 2026 problem

LLM agents that call external tools (search the web, send email,
run code, query a database) have no good story for "this tool can
do X but not Y". The function-calling APIs from OpenAI and
Anthropic hand the model a list of tools and trust the
application to do the right thing with the model's output. The
result, in practice:

- **Prompt injection** can convince the model to call a tool with
  arguments the application never intended. The famous example:
  an email summarisation agent that follows instructions in the
  email body and exfiltrates the inbox.
- **Jailbreaks** bypass model-level safety policies and trigger
  tool calls outside the original task.
- **Confused-deputy attacks**: the agent has legitimate
  authority over tool *A* and is induced to use it on behalf of a
  malicious caller.

The industry mitigations are all at the application layer:
allow-lists, regex on tool arguments, output filtering, OS-level
sandboxing (Firecracker, gVisor) for code execution. Each is
useful, none is principled. The model can always be tricked into
emitting *some* tool call the application accepts.

Capa's capability discipline operates one layer down. Each tool
becomes a *capability*. The function that interprets the LLM's
tool-call sequence declares which capabilities it has. The
compiler proves the function cannot call tools it did not
declare. The SBOM emits that declaration as an audit artefact.
No prompt, no matter how cleverly crafted, can convince the
runtime to dispatch to a tool the function does not have in
scope, because the dispatch site is statically checked.

## The pattern in three pieces

**One capability per tool**. Tool surface becomes part of the
type system:

```capa
capability SearchWeb
    fun search(self, query: String) -> Result<String, IoError>

capability SendEmail
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>

capability RunCode
    fun run(self, code: String) -> Result<String, IoError>
```

**One implementor per backend**, wrapping the low-level capability
it actually uses. The cap-bearing struct pattern (a struct that
implements a user-defined capability is allowed to hold a
built-in capability as a field) lets the implementor carry the
authority it needs:

```capa
type StubSearch { net: Net, allowed_domain: String }
type StubMailer { net: Net }
type StubRunner { u: Unsafe }

impl SearchWeb for StubSearch
    fun search(self, query: String) -> Result<String, IoError>
        return self.net.get("https://${self.allowed_domain}/search?q=${query}")

impl SendEmail for StubMailer
    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>
        return self.net.post("smtp://${self.net}/", body)

impl RunCode for StubRunner
    fun run(self, code: String) -> Result<String, IoError>
        // routes through self.u (Unsafe) to a sandboxed runtime
        ...
```

**The agent function declares its tool surface as parameters**.
Whatever the LLM tells the agent to do, the agent can only call
methods on the values in scope:

```capa
fun process_request(
    stdio: Stdio,
    search: SearchWeb,
    mail: SendEmail,
    query: String
) -> Result<Unit, IoError>
    let results = search.search(query)?
    mail.send("user@example.com", "Summary", results)?
    return Ok(())
```

This function takes `SearchWeb` and `SendEmail`. It does not take
`RunCode`. There is no way for the body to obtain a `RunCode`
instance: capabilities cannot be returned from functions (except
user-defined ones via factories, which themselves require the
backing built-in caps the agent does not have), they cannot be
read from a global, they cannot be conjured from thin air.

The agent is *provably* incapable of running arbitrary code,
even if the LLM emits a tool call sequence that includes
`{"tool": "run_code", "args": {...}}`. The dispatch site does
not exist; the call does not compile; the program does not
run a code execution path.

## Attenuation at the boundary

The second pillar of the discipline applies to the tool backends
themselves. `SearchWeb` could be implemented over the full `Net`,
but the factory narrows the underlying authority before wrapping
it:

```capa
pub fun make_search(net: Net, domain: String) -> StubSearch
    return StubSearch {
        net: net.restrict_to(domain),
        allowed_domain: domain
    }
```

The `StubSearch` value carried inside `SearchWeb` can only reach
`domain`. If a future refactor accidentally introduces a request
to a different host, the runtime rejects it before any system
call is made (`fail-closed`). The same shape applies to the
mailer (narrowed to one SMTP host).

Authority decreases monotonically as it flows down. The agent
gets a `SearchWeb` whose underlying `Net` is locked to a single
domain. The agent cannot widen it back; intersections in the
narrowing chain only shrink.

## The audit artefact

The Capa manifest emits, per function, both the declared
capabilities and the **provably excluded** capabilities:

```bash
$ capa --manifest agent.capa
```

For `process_request`, the relevant fields:

```json
{
  "name": "process_request",
  "declared_capabilities": ["Stdio", "SearchWeb", "SendEmail"],
  "provably_excluded_capabilities": [
    "Clock", "Db", "Env", "Fs", "Net", "Proc",
    "Random", "RunCode", "Unsafe"
  ],
  "has_unsafe": false
}
```

The exclusion is sound because Capa's discipline makes the
declared set an upper bound on what the function can exercise.
For an LLM-tool-use review this is the artefact:

- A reviewer looking at the SBOM learns that `process_request`
  is provably incapable of executing arbitrary code, opening
  network connections to arbitrary hosts, reading the
  filesystem, or accessing environment variables.
- A diff between two SBOM versions surfaces any change to the
  agent's tool surface (`capa --cyclonedx old.capa > old.json;
  capa --cyclonedx new.capa > new.json; diff` and look for the
  `capa:declared_capability` / `capa:provably_excluded_capability`
  properties).
- A policy gate at CI time can fail the build when an agent
  function gains a tool it should not have, via the per-function
  audit pipeline in
  [`examples/sbom_capability_audit.capa`](../examples/sbom_capability_audit.capa).

## How this compares to existing approaches

| Approach | Granularity | Sound? | Visible to reviewer? |
|---|---|---|---|
| Function-calling API (OpenAI / Anthropic) | Per agent, fully trusted | No | Application code only |
| Allow-list / regex on tool args | Per call, runtime | Partial | Application code |
| OS-level sandbox (Firecracker, gVisor) | Per process | Yes, coarse | Infrastructure config |
| Capa capability discipline | **Per function** | **Yes** | **Type signature + SBOM** |

The capability approach is **structural**: the discipline holds
regardless of what the LLM emits, because the dispatch is
constrained at the source level. Allow-list approaches are
checked at runtime and can be bypassed by any tool call that
matches the regex; OS-level sandboxes are sound but coarse (the
agent process either has a syscall or not) and operationally
expensive.

The capability approach is **composable**: a library that
exposes `capability SendEmail` can be used by many agents, each
with its own narrowing. No new infrastructure is needed to add a
new tool; declaring `capability NewTool` is one line.

The capability approach is **auditable from source**: the SBOM
is a deterministic function of the source. The same compile
produces the same manifest. A reviewer never has to read the
agent's code to know its tool surface; the manifest is enough.

## Honest limits

The discipline is a precise tool. It does what it does, no more.

- **Does not prevent the LLM from being prompted.** Capa controls
  what happens *after* the model decides to call a tool. If the
  model decides to call `mail.send` to an inbox the application
  intended for legitimate use, the call goes through. Argument-
  level controls (only mail addresses ending in `@example.com`)
  are a separate concern, addressable by narrowing the
  capability further or by argument-level validation inside the
  tool's implementation.
- **Does not address content-level attacks.** A summariser that
  forwards an email body containing a malicious link is doing
  exactly what it was authorised to do.
- **Does not extend across `Unsafe` boundaries.** A `RunCode`
  implementor that uses `Unsafe` to invoke a Python interpreter
  can do anything the interpreter can do. The discipline marks
  the boundary (`has_unsafe: true`); content beyond it is for
  separate sandboxing (OS-level or VM-level).
- **Does not solve agent goal hijacking.** If the model decides
  to call `search` with a query the user did not ask for, the
  discipline does not catch it. Application-level review of the
  model's plan is still warranted; what the discipline prevents
  is the *escalation* from "wrong query" to "wrong tool".

The point of capability discipline in this setting is to reduce
the trusted surface from "the entire application logic" to
"the small set of tools the agent actually needs". Everything
else, the model literally cannot reach.

## See it for yourself

The runnable demo is at
[`examples/llm_tool_sandbox.capa`](../examples/llm_tool_sandbox.capa):

```bash
$ capa --run examples/llm_tool_sandbox.capa
=== running agent ===
agent received query: 'Capa language news'
  > (stub) results for 'Capa language news' on capa-language.com
  > email sent
done
```

And the manifest, showing the discipline at work:

```bash
$ capa --manifest examples/llm_tool_sandbox.capa | jq '.functions[] | select(.name=="process_request")'
```

The same pattern scales. Adding a new tool is one `capability X`
declaration plus an implementor. Wiring it into an agent is
adding one parameter to the agent's signature. Excluding it is
not passing it. The contract lives in the type system; the audit
artefact follows for free.
