"""Environment-variable exfiltration attack category.

Attempts to read sensitive env vars (API keys, AWS credentials,
session tokens) from functions that do NOT declare the Env
capability. Every attack should be rejected by `capa --check` at
the capability-forge analyzer rule (since 67d9878).
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_env_leak"

CATEGORY_DESCRIPTION = (
    "Programs that try to read sensitive environment variables "
    "(API keys, AWS credentials, etc.) from functions that did "
    "NOT declare the Env capability. Expected outcome: every "
    "program is rejected by `capa --check`."
)

SENSITIVE_VARS = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "DATABASE_URL",
    "STRIPE_SECRET_KEY",
    "JWT_SECRET",
    "SLACK_BOT_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "DD_API_KEY",
]


def _direct_forge(var: str) -> Attack:
    return Attack(
        attack_id=f"env_forge_direct_{var.lower()}",
        description=(
            f"Forge Env inside main(stdio: Stdio) and read {var}."
        ),
        source=(
            'fun main(stdio: Stdio)\n'
            '    let env = Env()\n'
            f'    match env.get("{var}")\n'
            '        Some(v) -> stdio.println(v)\n'
            '        None -> stdio.eprintln("missing")\n'
        ),
    )


def _helper_forge(var: str) -> Attack:
    return Attack(
        attack_id=f"env_forge_helper_{var.lower()}",
        description=(
            f"Forge Env inside a no-cap helper and exfiltrate {var}."
        ),
        source=(
            'fun exfil() -> String\n'
            '    let env = Env()\n'
            f'    match env.get("{var}")\n'
            '        Some(v) -> return v\n'
            '        None -> return "missing"\n'
            'fun main(stdio: Stdio)\n'
            '    stdio.println(exfil())\n'
        ),
    )


def generate() -> list[Attack]:
    out: list[Attack] = []
    for var in SENSITIVE_VARS:
        out.append(_direct_forge(var))
        out.append(_helper_forge(var))
    return out
