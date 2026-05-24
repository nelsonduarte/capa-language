"""Capability-aliasing attack category.

Tries to pass the same capability twice to a single call, which
the discipline forbids (each call uses each capability at most
once). Each program must surface 'capability X appears as
argument N but was already used as ...' or similar.
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_capability_aliasing"

CATEGORY_DESCRIPTION = (
    "Programs that try to alias a capability inside a single "
    "call (same cap as arg1 + arg2, same cap as receiver + arg, "
    "etc.). Must be rejected by the non-aliasing discipline."
)


def generate():
    attacks: list[Attack] = []

    # 1. same cap as arg1 + arg2 of a helper
    attacks.append(Attack(
        attack_id="alias_two_args_stdio",
        description="Stdio passed as both arg1 and arg2.",
        source=(
            'fun pair(a: Stdio, b: Stdio)\n'
            '    a.println("a")\n'
            '    b.println("b")\n'
            'fun main(stdio: Stdio)\n'
            '    pair(stdio, stdio)\n'
        ),
    ))
    attacks.append(Attack(
        attack_id="alias_two_args_fs",
        description="Fs passed twice to a 2-arg helper.",
        source=(
            'fun pair(a: Fs, b: Fs)\n'
            '    let _ = a.exists("x")\n'
            '    let _ = b.exists("y")\n'
            'fun main(stdio: Stdio, fs: Fs)\n'
            '    pair(fs, fs)\n'
            '    stdio.println("done")\n'
        ),
    ))
    attacks.append(Attack(
        attack_id="alias_three_args_stdio",
        description="Stdio passed three times.",
        source=(
            'fun triple(a: Stdio, b: Stdio, c: Stdio)\n'
            '    a.println("a")\n'
            '    b.println("b")\n'
            '    c.println("c")\n'
            'fun main(stdio: Stdio)\n'
            '    triple(stdio, stdio, stdio)\n'
        ),
    ))

    # 2. cap as receiver + same cap as argument
    attacks.append(Attack(
        attack_id="alias_receiver_arg",
        description="Same cap as receiver and method argument.",
        source=(
            'fun main(stdio: Stdio)\n'
            '    stdio.helper(stdio)\n'
        ),
    ))

    # 3. attenuated call shape (Net.restrict_to + Net both in args)
    attacks.append(Attack(
        attack_id="alias_attenuated_net",
        description="Net + restricted Net into same call.",
        source=(
            'fun pair(a: Net, b: Net)\n'
            '    let _ = a\n'
            '    let _ = b\n'
            'fun main(stdio: Stdio, net: Net)\n'
            '    pair(net, net)\n'
            '    stdio.println("done")\n'
        ),
    ))

    # 4-10. Many variants for distinct caps + helper shapes.
    for cap_name, cap_ty, method in [
        ("env", "Env", 'get("X")'),
        ("clock", "Clock", "now()"),
        ("random", "Random", "int(0, 100)"),
        ("db", "Db", 'query("select 1")'),
    ]:
        attacks.append(Attack(
            attack_id=f"alias_pair_{cap_name}",
            description=f"{cap_ty} aliased into 2-arg call.",
            source=(
                f'fun helper(a: {cap_ty}, b: {cap_ty})\n'
                f'    let _ = a.{method}\n'
                f'    let _ = b.{method}\n'
                f'fun main(stdio: Stdio, {cap_name}: {cap_ty})\n'
                f'    helper({cap_name}, {cap_name})\n'
                '    stdio.println("done")\n'
            ),
        ))

    return attacks
