"""Status fetcher: reads a JSON config, fetches a status URL, writes the
response to disk.

This is the Python starting point for the Python->Capa gradual hardening
walkthrough at docs/migration.md. The paired files in this directory show
three stages of moving this code into Capa:

  step1_unsafe   one Capa entry point that calls back into this file
                 via py_import / py_invoke; capability discipline not
                 yet engaged.
  step2_mixed    pure / Fs-only helpers moved into typed Capa; the
                 Env + Net work is still done by py_invoke.
  step3_typed    every function carries an explicit capability
                 signature; Unsafe is gone.

The Python file itself stays unchanged across the three steps; only the
.capa file changes.
"""

import json
import os
import urllib.request


def load_config(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def get_api_key():
    key = os.environ.get("LOGS_API_KEY")
    if not key:
        raise ValueError("LOGS_API_KEY not set")
    return key


def build_url(base, service, api_key):
    return f"{base}/status?service={service}&key={api_key}"


def fetch_status(url):
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode("utf-8")


def save_response(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    config = load_config("config.json")
    api_key = get_api_key()
    url = build_url(config["base_url"], config["service"], api_key)
    response = fetch_status(url)
    save_response(config["output_path"], response)
    print(f"wrote {len(response)} bytes to {config['output_path']}")


if __name__ == "__main__":
    main()
