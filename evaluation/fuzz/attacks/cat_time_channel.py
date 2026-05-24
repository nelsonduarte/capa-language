"""Clock side-channel attack category.

Attempts to read the wall-clock from functions that did NOT
declare the Clock capability. Timing channels are a class of
covert channels Capa's discipline explicitly addresses (a function
that does not declare Clock cannot measure latency).
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_time_channel"

CATEGORY_DESCRIPTION = (
    "Programs that try to read the wall-clock from functions "
    "without the Clock capability. Expected: rejected by "
    "`capa --check`."
)


def generate():
    variants = [
        ("now",          'clock.now()'),
        ("monotonic",    'clock.monotonic()'),
        ("now_helper",   'clock.now()'),
        ("nested_call",  'clock.now()'),
    ]
    out = []
    for kind, expr in variants:
        out.append(Attack(
            attack_id=f"clock_forge_{kind}",
            description=f"Forge Clock and call {expr} from no-Clock function.",
            source=(
                'fun main(stdio: Stdio)\n'
                '    let clock = Clock()\n'
                f'    let t = {expr}\n'
                '    stdio.println("got time")\n'
            ),
        ))
    # Helper-side forge variants.
    for i in range(6):
        out.append(Attack(
            attack_id=f"clock_helper_{i}",
            description=f"Forge Clock inside helper variant {i}.",
            source=(
                f'fun timing_attack_{i}() -> Int\n'
                '    let clock = Clock()\n'
                '    let t = clock.now()\n'
                '    return 42\n'
                'fun main(stdio: Stdio)\n'
                f'    let _ = timing_attack_{i}()\n'
                '    stdio.println("done")\n'
            ),
        ))
    # Read-via-immediate-method variants (cover different shapes).
    for i in range(6):
        out.append(Attack(
            attack_id=f"clock_immediate_{i}",
            description=f"Use Clock() expression result immediately (no let), variant {i}.",
            source=(
                'fun main(stdio: Stdio)\n'
                f'    let t{i} = Clock().now()\n'
                '    stdio.println("got time")\n'
            ),
        ))
    return out
