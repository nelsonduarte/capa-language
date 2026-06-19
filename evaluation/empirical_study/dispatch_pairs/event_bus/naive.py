"""An event bus / observer registry: callbacks carried in data,
registered at runtime, and invoked in a loop.

This is the publish/subscribe shape that appears in essentially
every event-driven Python system:

  * `blinker` / Django signals / Flask signals: subscribers
    register a callable against a signal; `send()` iterates the
    receiver list and calls each.
  * `pluggy` (pytest / tox plugin hooks): hook implementations
    are collected into a list and the hook caller invokes each
    in turn.
  * webhook dispatchers, `asyncio`/`pyee` `EventEmitter.emit`,
    GUI signal/slot tables, the observer pattern in general.

The defining feature for this study: the subscriber list is
populated by RUNTIME registration calls, not a literal. The bus's
`emit` walks `self._subscribers` and calls each callback. The
authority any subscriber exercises is invisible at the emit site:
`emit` has no `open` and no `urlopen`; the sinks live in the
subscribers, reached through `cb(event)` in the dispatch loop.

This file is the hand-Python comparison artefact; it is not run
by the test suite.
"""

import urllib.request


def audit_to_disk(event: str) -> None:
    # Fs: append the event to an on-disk audit log. Real authority.
    with open("events.log", "a", encoding="utf-8") as f:
        f.write(event + "\n")


def forward_to_webhook(event: str) -> None:
    # Net: POST the event to a webhook endpoint. Real authority.
    data = event.encode("utf-8")
    req = urllib.request.Request("https://hooks.example.com/ingest", data=data)
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


class EventBus:
    def __init__(self) -> None:
        # The subscriber list is empty at construction and filled by
        # runtime `subscribe` calls. Its contents are data, not a
        # literal a scanner can read off the page.
        self._subscribers = []

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def emit(self, event: str) -> None:
        # The dispatch loop: invoke every registered callback. Each
        # `cb(event)` may read the disk or open the network depending
        # on what was subscribed. No sink is lexically present here.
        for cb in self._subscribers:
            cb(event)


def run(event: str) -> None:
    # Wiring: a caller registers subscribers at runtime, then emits.
    bus = EventBus()
    bus.subscribe(audit_to_disk)
    bus.subscribe(forward_to_webhook)
    bus.emit(event)
