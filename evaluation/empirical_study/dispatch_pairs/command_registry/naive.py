"""A command/handler registry dispatched by a runtime name.

This is the shape of every CLI subcommand router and HTTP URL
router in production Python: a module-level dict maps a string
key to a handler function, and a dispatcher looks the key up at
runtime and calls the resolved handler.

Real instances of exactly this pattern:

  * `argparse` / `click` subcommand tables (`COMMANDS = {"add":
    cmd_add, "rm": cmd_rm}`; the parsed subcommand name indexes
    the table).
  * Django / Flask URL routing (`urlpatterns` / `@app.route`
    build a name -> view table; the matched route name selects
    the view).
  * `cmd.Cmd` (`do_<name>` lookup), `aws-cli` / `gcloud` command
    trees, every plugin host that keeps a `{name: plugin_fn}`
    registry.

The authority each handler exercises is NOT visible at the
dispatch site. `dispatch(name, arg)` reads the disk or opens the
network depending ONLY on the runtime value of `name`, which the
dispatcher's signature does not constrain. A line-level pattern
scan of `dispatch` sees no `open` and no `urlopen` -- the sinks
live in the handlers, reached through `HANDLERS[name](arg)`.

This file is the hand-Python comparison artefact; it is not run
by the test suite.
"""

import urllib.request


def _fetch(arg: str) -> str:
    # Net: GET the URL and return the body. The authority is real.
    with urllib.request.urlopen(arg, timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def _save(arg: str) -> str:
    # Fs: write the argument to a file on disk. The authority is real.
    with open("dispatch_out.txt", "w", encoding="utf-8") as f:
        f.write(arg)
    return "saved"


# Module-level registry: a constant string -> handler table. This is
# the canonical CLI-router / URL-router shape. The values are
# capability-bearing functions; the keys are the runtime selector.
HANDLERS = {
    "fetch": _fetch,
    "save": _save,
}


def dispatch(name: str, arg: str) -> str:
    # The sink is selected at runtime: HANDLERS[name] resolves to a
    # handler the dispatcher cannot name. Calling it exercises Net OR
    # Fs depending on `name`. A reviewer reading `dispatch(name, arg)`
    # sees neither `open` nor `urlopen`; both are reached only through
    # the runtime-keyed call below.
    handler = HANDLERS[name]
    return handler(arg)
