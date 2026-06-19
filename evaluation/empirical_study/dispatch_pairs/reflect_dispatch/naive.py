"""Reflection dispatch: a handler method is selected by NAME built
at runtime via getattr.

This is the message/RPC handler shape that recurs across Python
servers and frameworks:

  * `xmlrpc.server` / `SimpleXMLRPCServer`: dispatches an incoming
    method name to `getattr(self, "export_" + name)` (or a
    registered instance's attribute of that name).
  * `cmd.Cmd.onecmd`: `getattr(self, "do_" + command)`.
  * JSON-RPC and many homegrown RPC servers: `getattr(handler,
    "rpc_" + method)(params)`.
  * `unittest`'s test loader: `getattr(case, "test_" + name)`.
  * Visitor patterns that pick `visit_<nodetype>` by name.

The defining feature: the method NAME is computed from runtime
input (`"handle_" + msg_type`), so the call target is not a value
a points-to analysis can enumerate -- it is a string the engine
would have to predict. Different handler methods exercise
different capabilities; `dispatch` reaches whichever one the
runtime name resolves to.

This file is the hand-Python comparison artefact; it is not run
by the test suite.
"""

import urllib.request


class MessageHandler:
    def handle_sync(self, payload: str) -> str:
        # Net: push the payload to a sync endpoint. Real authority.
        data = payload.encode("utf-8")
        req = urllib.request.Request("https://api.example.com/sync", data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8", "replace")

    def handle_persist(self, payload: str) -> str:
        # Fs: persist the payload to disk. Real authority.
        with open("messages.db", "a", encoding="utf-8") as f:
            f.write(payload + "\n")
        return "persisted"

    def dispatch(self, msg_type: str, payload: str) -> str:
        # The method name is BUILT from runtime input and resolved by
        # reflection. The call target is not a value any scan or
        # points-to pass can enumerate from this line; it is the
        # string "handle_" + msg_type. Calling it exercises Net or Fs
        # depending on the runtime message type.
        method = getattr(self, "handle_" + msg_type)
        return method(payload)
