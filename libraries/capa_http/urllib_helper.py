"""Python bridge for capa-http's urllib_client implementor.

Imported from Capa via ``py_import(unsafe, "urllib_helper")``.
The Capa side adds ``libraries/capa_http/`` to ``sys.path`` so
the import resolves. All exceptions are caught and surface to
Capa as a JSON envelope; nothing raises across the Unsafe
boundary.

The protocol is intentionally string-only (py_invoke requires a
homogeneous list) and JSON-wrapped where structure is needed.

Inputs (all strings):
    method           "GET" / "POST" / ...
    url              "https://api.example.com/path"
    headers_json     JSON-encoded list of [k, v] pairs
    body_json        JSON-encoded body: "null" for no body,
                     or a JSON string ("text") for a string body
    timeout_secs_str "30.0" -> float seconds

Returns (one JSON string):
    {"ok": true,  "status": int, "headers": [[k, v], ...], "body": "..."}
    {"ok": false, "kind": "network" | "invalid", "msg": "..."}

The 4xx/5xx case is "ok": true with the corresponding status;
only transport-level failures map to "ok": false.
"""

import json
import urllib.error
import urllib.request


def send(method, url, headers_json, body_json, timeout_secs_str):
    try:
        headers_pairs = json.loads(headers_json)
        if not isinstance(headers_pairs, list):
            return json.dumps({
                "ok": False,
                "kind": "invalid",
                "msg": "headers_json is not a JSON array",
            })
        # Real HTTP allows duplicate headers; urllib's Request
        # accepts a dict that collapses them, which is fine for
        # the 99% case. ``Set-Cookie``-style duplicates on the
        # request side are uncommon; on the response side we
        # preserve every header as a separate [k, v] pair.
        headers_dict = {}
        for pair in headers_pairs:
            if not isinstance(pair, list) or len(pair) < 2:
                return json.dumps({
                    "ok": False,
                    "kind": "invalid",
                    "msg": "header pair must be a 2-element array",
                })
            headers_dict[str(pair[0])] = str(pair[1])

        body_value = json.loads(body_json)
        if body_value is None:
            data = None
        elif isinstance(body_value, str):
            data = body_value.encode("utf-8")
        else:
            return json.dumps({
                "ok": False,
                "kind": "invalid",
                "msg": "body must be null or a JSON string",
            })

        timeout = float(timeout_secs_str)
    except (ValueError, TypeError, json.JSONDecodeError) as e:
        return json.dumps({
            "ok": False,
            "kind": "invalid",
            "msg": f"failed to parse inputs: {e}",
        })

    try:
        req = urllib.request.Request(
            url, data=data, headers=headers_dict, method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_body_bytes = resp.read()
                resp_body = resp_body_bytes.decode("utf-8", errors="replace")
                resp_headers = [
                    [str(k), str(v)] for k, v in resp.headers.items()
                ]
                return json.dumps({
                    "ok": True,
                    "status": int(resp.status),
                    "headers": resp_headers,
                    "body": resp_body,
                })
        except urllib.error.HTTPError as e:
            # 4xx / 5xx: the server DID respond. Treat as a
            # successful Response so the caller can read the
            # body and act on the status.
            try:
                err_body_bytes = e.read() if e.fp is not None else b""
            except Exception:
                err_body_bytes = b""
            err_body = err_body_bytes.decode("utf-8", errors="replace")
            err_headers = (
                [[str(k), str(v)] for k, v in e.headers.items()]
                if e.headers is not None else []
            )
            return json.dumps({
                "ok": True,
                "status": int(e.code),
                "headers": err_headers,
                "body": err_body,
            })
    except urllib.error.URLError as e:
        return json.dumps({
            "ok": False,
            "kind": "network",
            "msg": str(e.reason),
        })
    except (ValueError, TypeError) as e:
        return json.dumps({
            "ok": False,
            "kind": "invalid",
            "msg": str(e),
        })
    except Exception as e:
        # Catch-all so the Unsafe boundary stays leak-tight; the
        # Capa side will not see a Python exception, only a JSON
        # error envelope.
        return json.dumps({
            "ok": False,
            "kind": "network",
            "msg": f"unexpected error: {e}",
        })
