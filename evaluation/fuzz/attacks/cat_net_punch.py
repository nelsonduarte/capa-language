"""Network exfiltration attack category.

Attempts to open outbound connections from functions that do NOT
declare the Net capability. Every attack should be rejected by
`capa --check` at the capability-forge analyzer rule.
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_net_punch"

CATEGORY_DESCRIPTION = (
    "Programs that try to open outbound network connections "
    "from functions that did NOT declare the Net capability. "
    "Expected: every program rejected by `capa --check`."
)

EXFIL_HOSTS = [
    "evil.example.com:443",
    "attacker-c2.invalid:8080",
    "169.254.169.254:80",  # AWS IMDS
    "metadata.google.internal:80",  # GCP metadata
    "10.0.0.1:22",
    "127.0.0.1:6379",  # local Redis
    "169.254.169.254:80",  # IMDSv1
    "burpcollaborator.net:80",
]


def _direct_forge(host: str, kind: str) -> Attack:
    return Attack(
        attack_id=f"net_forge_{kind}_{host.replace(':', '_').replace('.', '_')}",
        description=(
            f"Forge Net and {kind} to {host} from a no-Net function."
        ),
        source=(
            'fun main(stdio: Stdio)\n'
            '    let net = Net()\n'
            f'    match net.connect("{host}")\n'
            '        Ok(_) -> stdio.println("connected")\n'
            '        Err(_) -> stdio.eprintln("blocked")\n'
        ),
    )


def _helper_forge(host: str) -> Attack:
    return Attack(
        attack_id=f"net_helper_{host.replace(':', '_').replace('.', '_')}",
        description=f"Forge Net in helper, attempt {host}.",
        source=(
            'fun phone_home() -> Bool\n'
            '    let net = Net()\n'
            f'    match net.connect("{host}")\n'
            '        Ok(_) -> return true\n'
            '        Err(_) -> return false\n'
            'fun main(stdio: Stdio)\n'
            '    if phone_home()\n'
            '        stdio.println("connected")\n'
        ),
    )


def generate():
    out = []
    for host in EXFIL_HOSTS:
        out.append(_direct_forge(host, "connect"))
        out.append(_helper_forge(host))
    return out
