"""Anthropic Messages API bridge for the Capa LLM-tool-sandbox demo.

Pure stdlib so it works on a fresh install. Capa's built-in ``Net``
capability does not support custom headers in v1, which the
Anthropic API needs (``x-api-key``, ``anthropic-version``); this
helper takes the dance in Python and exposes one function back to
Capa over the ``Unsafe`` boundary.

The function does its own exception handling and always returns a
JSON string so the Capa side can pattern-match the outcome via
the regular ``parse_json`` path rather than crash on a Python
exception.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


def chat(api_key: str, model: str, prompt: str, max_tokens_str: str) -> str:
    """Send a single user prompt to the Anthropic Messages API and
    return the response as a JSON string.

    On success, the returned object has the shape::

        {"ok": true, "text": "...the model's reply text...",
         "stop_reason": "end_turn"}

    On failure, it has::

        {"ok": false, "error": "<message>"}

    The two-shape design keeps the Capa side from having to
    distinguish "the model said something" from "the call itself
    failed" by inspecting whether a JSON field exists.
    """
    if not api_key:
        return json.dumps({"ok": False, "error": "ANTHROPIC_API_KEY is empty"})

    try:
        max_tokens = int(max_tokens_str)
    except (ValueError, TypeError):
        max_tokens = 256

    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.dumps({
            "ok": False,
            "error": f"http {e.code}: {e.read().decode('utf-8', errors='replace')}",
        })
    except urllib.error.URLError as e:
        return json.dumps({"ok": False, "error": f"network: {e.reason}"})
    except json.JSONDecodeError as e:
        return json.dumps({"ok": False, "error": f"malformed json: {e}"})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"})

    # Extract the first text content block. The Messages API can
    # return tool_use blocks too, but this single-prompt helper
    # only handles plain text replies; the full tool-use path is
    # demonstrated by the mock client in llm_agent_runner.capa.
    text = ""
    for block in payload.get("content", []):
        if block.get("type") == "text":
            text = block.get("text", "")
            break

    return json.dumps({
        "ok": True,
        "text": text,
        "stop_reason": payload.get("stop_reason", ""),
    })


def chat_with_tools(
    api_key: str,
    model: str,
    history_json: str,
    tools_json: str,
    max_tokens_str: str,
) -> str:
    """Multi-turn tool-using call to the Anthropic Messages API.

    ``history_json`` is a JSON array of messages already in
    Anthropic format (the caller builds this up as the conversation
    progresses). ``tools_json`` is a JSON array of tool schemas in
    Anthropic format ({name, description, input_schema}).

    Returns a JSON envelope with one of three shapes:

      {"ok": true, "kind": "reply",
       "text": "...assistant's final reply...",
       "assistant_msg_json": "..."}   # to append to history

      {"ok": true, "kind": "tool_use",
       "tool_use_id": "...", "tool_name": "...",
       "tool_input_json": "...",
       "assistant_msg_json": "..."}   # to append to history

      {"ok": false, "error": "<message>"}

    The ``assistant_msg_json`` is the raw assistant message the
    caller should append to history before either (a) printing the
    reply and stopping or (b) dispatching the tool and appending a
    tool_result message back into history. Keeps all
    Anthropic-format-specific shape handling inside this helper.
    """
    if not api_key:
        return json.dumps({"ok": False, "error": "ANTHROPIC_API_KEY is empty"})

    try:
        max_tokens = int(max_tokens_str)
    except (ValueError, TypeError):
        max_tokens = 1024

    try:
        history = json.loads(history_json)
        tools = json.loads(tools_json)
    except json.JSONDecodeError as e:
        return json.dumps({"ok": False, "error": f"malformed input: {e}"})

    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "tools": tools,
        "messages": history,
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return json.dumps({
            "ok": False,
            "error": f"http {e.code}: {e.read().decode('utf-8', errors='replace')}",
        })
    except urllib.error.URLError as e:
        return json.dumps({"ok": False, "error": f"network: {e.reason}"})
    except json.JSONDecodeError as e:
        return json.dumps({"ok": False, "error": f"malformed json: {e}"})
    except Exception as e:  # noqa: BLE001
        return json.dumps({"ok": False, "error": f"{type(e).__name__}: {e}"})

    # Walk the content blocks. Prefer a tool_use block (the model
    # is asking us to do something); fall back to text (the model
    # is done).
    content_blocks = payload.get("content", [])
    assistant_msg = {
        "role": "assistant",
        "content": content_blocks,
    }
    assistant_msg_json = json.dumps(assistant_msg)

    tool_use_block = next(
        (b for b in content_blocks if b.get("type") == "tool_use"),
        None,
    )
    if tool_use_block is not None:
        return json.dumps({
            "ok": True,
            "kind": "tool_use",
            "tool_use_id": tool_use_block.get("id", ""),
            "tool_name": tool_use_block.get("name", ""),
            "tool_input_json": json.dumps(tool_use_block.get("input", {})),
            "assistant_msg_json": assistant_msg_json,
        })

    # No tool_use: collect text blocks into a single reply.
    text_parts = [
        b.get("text", "")
        for b in content_blocks
        if b.get("type") == "text"
    ]
    return json.dumps({
        "ok": True,
        "kind": "reply",
        "text": "".join(text_parts),
        "assistant_msg_json": assistant_msg_json,
    })
