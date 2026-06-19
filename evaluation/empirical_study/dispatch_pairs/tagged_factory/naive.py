"""A factory whose authority is selected by a TAG field read from
deserialized data.

This is the shape of every plugin/action dispatcher driven by a
serialized document: the input carries a `type` / `tag` / `method`
field, and a factory picks a handler from that field's runtime
value.

Real instances of exactly this pattern:

  * JSON-RPC: the request's `"method"` field selects the procedure.
  * `yaml.load` / `pickle` payloads whose tag drives object
    construction -- the CVE class this repo already studies
    (`examples/cve_pickle.capa`, `examples/cve_pyyaml*.capa`): a
    tag in the data chooses which constructor / reducer runs.
  * Celery / RQ task messages: a `"task"` name in the message body
    selects the task function.
  * Event-sourcing / CQRS command buses keyed on an `"action"`
    field in the event JSON.

The defining feature for this study: the selector is DATA read
from external input (`doc["type"]`), so the chosen handler is not
knowable from the code -- it depends on the bytes that arrive.
Different actions exercise different capabilities; `run_action`
reaches whichever the data names.

This file is the hand-Python comparison artefact; it is not run
by the test suite.
"""

import json
import urllib.request


def _action_export(doc: dict) -> str:
    # Net: ship the document's body to an export endpoint. Real authority.
    body = json.dumps(doc.get("body", {})).encode("utf-8")
    req = urllib.request.Request("https://export.example.com/v1", data=body)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return resp.read().decode("utf-8", "replace")


def _action_archive(doc: dict) -> str:
    # Fs: archive the document to disk. Real authority.
    with open("archive.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(doc) + "\n")
    return "archived"


_ACTIONS = {
    "export": _action_export,
    "archive": _action_archive,
}


def run_action(raw: str) -> str:
    # Deserialize untrusted input, then let a DATA field choose the
    # handler. The capability exercised depends entirely on the bytes
    # that arrive: `doc["type"]` is not a value the code fixes.
    doc = json.loads(raw)
    tag = doc["type"]
    handler = _ACTIONS[tag]
    return handler(doc)
