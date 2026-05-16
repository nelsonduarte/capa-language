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

## End-to-end runner: the agent loop

The static demo above shows the discipline. The runtime
counterpart is an agent loop that actually talks to an LLM,
dispatches tool calls based on the model's response, and feeds
results back. The same capability discipline applies to the
loop: the agent function declares its tool surface as parameters
and provably cannot escalate beyond it, whatever the LLM emits.

The full runnable example is at
[`examples/llm_agent_runner.capa`](../examples/llm_agent_runner.capa).
The shape:

```capa
// The LLM is itself a capability: it makes network calls,
// holds an API key, is rate-limited. The agent receives one
// as a parameter, the same way it receives the tools.
capability LlmClient
    fun chat(self, history: List<Message>) -> Result<LlmResponse, IoError>

// LlmResponse: a final reply, or a tool call to dispatch.
type LlmResponse =
    Reply(String)
    Tool(ToolCall)

// The agent loop. Note the signature: Stdio + LlmClient +
// (search, mail). RunCode is not in scope; the LLM cannot
// escalate to it.
pub fun agent_loop(
    stdio: Stdio,
    llm: LlmClient,
    search: SearchWeb,
    mail: SendEmail,
    user_prompt: String
) -> Result<Unit, IoError>
    var history: List<Message> = []
    history.push(Message { role: "user", content: user_prompt })

    var step = 0
    while step < 10
        step = step + 1
        match llm.chat(history)
            Err(e) ->
                return Err(e)
            Ok(Reply(text)) ->
                stdio.println("assistant: ${text}")
                return Ok(())
            Ok(Tool(call)) ->
                let result = dispatch(call, search, mail)
                history.push(Message { role: "tool", content: result })

    return Err(IoError("agent loop step limit reached"))
```

The `dispatch` function is the only place that translates an
LLM-emitted tool name into a Capa method call:

```capa
fun dispatch(call: ToolCall, search: SearchWeb, mail: SendEmail) -> String
    if call.name == "search_web"
        match search.search(call.args.get("query").unwrap_or(""))
            Ok(r) -> return r
            Err(e) -> return "error: ${e}"
    if call.name == "send_email"
        match mail.send(call.args.get("to").unwrap_or(""), ..., ...)
            Ok(_) -> return "email sent"
            Err(e) -> return "error: ${e}"
    return "unknown tool: ${call.name}"
```

If the LLM emits `{"tool": "run_code", "args": {...}}`, the
dispatcher returns `"unknown tool: run_code"` and the LLM
sees that string in the next turn. The agent did not have
`RunCode` in scope; there was nowhere to dispatch to. The
discipline is preserved even though dispatch is string-keyed
at the wire level, because the *legal targets* are statically
known: the dispatch function can only call methods on the cap
parameters it receives.

Run the demo with a scripted mock LLM (offline, deterministic):

```bash
$ capa --run examples/llm_agent_runner.capa
=== running agent ===
user: what is new with the Capa language?
  > tool_use: search_web
  < tool_result: (stub) top result for 'Capa language news' on capa-language.com
  > tool_use: send_email
  < tool_result: email sent
assistant: Done. Searched for news, emailed the summary.
=== done ===
```

The manifest tells the audit story:

```bash
$ capa --manifest examples/llm_agent_runner.capa | jq '.functions[] | select(.name=="agent_loop")'
{
  "declared_capabilities": ["Stdio", "LlmClient", "SearchWeb", "SendEmail"],
  "provably_excluded_capabilities": [
    "Clock", "Db", "Env", "Fs", "Net",
    "Proc", "Random", "Unsafe"
  ],
  "has_unsafe": false
}
```

`agent_loop` is provably incapable of touching the filesystem,
the network, environment variables, or `Unsafe`, regardless of
what the model emits.

### Plugging in a real LLM

The `MockLlmClient` in the example scripts a fixed conversation
to keep the demo offline. A real `AnthropicLlmClient` (or
`OpenAILlmClient`) routes through `Unsafe` to call the API:

```capa
type AnthropicLlmClient {
    u: Unsafe,
    api_key: String,
    model: String
}

impl LlmClient for AnthropicLlmClient
    fun chat(self, history: List<Message>) -> Result<LlmResponse, IoError>
        let urllib = py_import(self.u, "urllib.request")
        let json   = py_import(self.u, "json")
        // 1. Build the request body: convert history + tool schemas
        //    into the API's JSON shape.
        // 2. POST to api.anthropic.com with x-api-key and
        //    anthropic-version headers via urllib.Request.
        // 3. Parse the JSON response. Extract a text block (-> Reply)
        //    or a tool_use block (-> Tool).
        return Ok(parsed)
```

The factory takes `Unsafe` and the configuration:

```capa
fun make_anthropic_client(u: Unsafe, env: Env) -> AnthropicLlmClient
    let key = env.get("ANTHROPIC_API_KEY").unwrap_or("")
    return AnthropicLlmClient {
        u: u,
        api_key: key,
        model: "claude-sonnet-4-5"
    }
```

Wiring at the top:

```capa
fun main(stdio: Stdio, u: Unsafe, env: Env)
    let llm    = make_anthropic_client(u, env)
    let search = make_search("capa-language.com")
    let mail   = make_mailer()
    // agent_loop's signature has not changed; it still receives
    // a LlmClient, a SearchWeb, and a SendEmail. The fact that
    // the LlmClient is now real instead of mocked is invisible
    // to the agent, by design.
    agent_loop(stdio, llm, search, mail, "what is new?")
```

Two things to notice about this. First, `agent_loop`'s signature
does not change when the LLM client is swapped from mock to
real. The agent is decoupled from the LLM implementation
through the `LlmClient` capability. Second, the manifest for
`agent_loop` still declares only `(Stdio, LlmClient, SearchWeb,
SendEmail)`. The fact that `make_anthropic_client` needed
`Unsafe` is visible at the construction site, *not* at the
agent's signature. The agent itself remains free of `Unsafe`.

### A working real-API round-trip

A complete, runnable demo of the real-API path is at
[`examples/llm_anthropic_real.capa`](../examples/llm_anthropic_real.capa),
paired with a tiny Python bridge at
[`examples/llm_anthropic_helper.py`](../examples/llm_anthropic_helper.py).
The bridge takes care of the HTTP+auth dance that Capa's
built-in `Net` does not cover in v1; the Capa side does the rest
through the same `LlmClient` capability shape.

The demo is single-turn (no tool dispatch, just a chat
round-trip) to keep the wire format minimal. Combining it with
the multi-turn tool-dispatch loop from `llm_agent_runner.capa`
is mechanical: swap `MockLlmClient` for `AnthropicClient`,
extend the helper to handle the `tool_use` content-block shape,
and the rest stays the same.

To run the real demo, set your API key and run from the project
root:

```bash
$ export ANTHROPIC_API_KEY=sk-ant-...
$ capa --run examples/llm_anthropic_real.capa
user: In one sentence: what is capability-based security?
assistant: Capability-based security restricts a program's authority by
giving each component only the specific permissions (capabilities) it needs,
rather than relying on ambient privileges granted by the surrounding system.
```

Without the key the helper returns a structured error and the
Capa side handles it gracefully through the regular `Result`
chain (no Python exception leaks out). The error path is what
the CI test exercises; the success path requires a live API
key.

The manifest still tells the audit story:

```bash
$ capa --manifest examples/llm_anthropic_real.capa | jq '.functions[] | select(.name=="run_chat")'
{
  "declared_capabilities": ["Stdio", "LlmClient"],
  "provably_excluded_capabilities": [
    "Clock", "Db", "Env", "Fs", "Net",
    "Proc", "Random", "Unsafe"
  ],
  "has_unsafe": false
}
```

The agent-equivalent function `run_chat` is `Unsafe`-free, even
though the program as a whole uses `Unsafe` for the network
call. The discipline has contained the `Unsafe` to its
implementor; the function that does the actual conversation
work cannot reach it.

### The full end-to-end: real Anthropic + tool dispatch

The capstone of the arc is at
[`examples/llm_anthropic_agent.capa`](../examples/llm_anthropic_agent.capa).
It combines the real Anthropic Messages API with the
tool-dispatch loop from `llm_agent_runner.capa`: a real model
decides which tools to call, the agent's dispatcher routes each
tool call through Capa-typed capabilities, the model continues
based on the result.

The wire format is the real Anthropic tool-use shape: tool
schemas are sent as JSON, responses come back as content blocks
that are either `text` or `tool_use`, and tool results are
appended to history as `tool_result` content blocks. The
Python helper (`chat_with_tools`) does the JSON wrangling and
exposes a small envelope shape back to Capa:

```json
{"ok": true, "kind": "reply",
 "text": "...", "assistant_msg_json": "..."}

{"ok": true, "kind": "tool_use",
 "tool_use_id": "...", "tool_name": "...",
 "tool_input_json": "...",
 "assistant_msg_json": "..."}

{"ok": false, "error": "..."}
```

The Capa side maps these to a sum type and pattern-matches:

```capa
type TurnOutcome =
    Reply(ReplyData)
    ToolUse(ToolUseData)
    Failed(String)

// ... inside agent_loop ...
match parse_turn(raw)
    Failed(msg) -> return Err(IoError(msg))
    Reply(r)    -> stdio.println("assistant: ${r.text}")
                   return Ok(())
    ToolUse(t)  -> let result = dispatch(t.tool_name, t.tool_input_json, search)
                   history.push(t.assistant_msg)
                   history.push(build_tool_result_msg(t.tool_use_id, result))
```

The headline audit claim still holds:

```bash
$ capa --manifest examples/llm_anthropic_agent.capa | jq '.functions[] | select(.name=="agent_loop")'
{
  "declared_capabilities": ["Stdio", "LlmClient", "SearchWeb"],
  "provably_excluded_capabilities": [
    "Clock", "Db", "Env", "Fs", "Net",
    "Proc", "Random", "Unsafe"
  ],
  "has_unsafe": false
}
```

Even though a real model is in the loop deciding which tools
to call, `agent_loop` provably cannot escalate beyond
`(Stdio, LlmClient, SearchWeb)`. Whatever the model emits, the
dispatcher's only legal targets are the cap parameters the
agent received. A `tool_use` for `run_code` returns
`"unknown tool: run_code"` and the model sees that string;
there is nowhere for the call to land.

Run it with your API key:

```bash
$ export ANTHROPIC_API_KEY=sk-ant-...
$ capa --run examples/llm_anthropic_agent.capa
user: Use the search_web tool to find information about Capa language. Then summarise what you found.
  > tool_use: search_web({"query": "Capa language"})
  < tool_result: [stub] top result on capa-language.com: 'Capa language' is documented at https://capa-language.com/docs
assistant: Based on the search, Capa is a programming language...
```

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
