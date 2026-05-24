"""Capability-hidden-in-data-structure attack category.

Tries every shape Capa's structural discipline is supposed to
forbid: capabilities stuffed in struct fields, variant payloads,
tuples, generics, constants, let bindings. Each of these has its
own analyzer check (see capa/analyzer/_discipline.py).
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_capability_in_data"

CATEGORY_DESCRIPTION = (
    "Programs that try to hide a built-in capability inside a "
    "data structure (struct field, variant payload, tuple, list, "
    "const, let binding) to smuggle it past the discipline. "
    "Every shape must be rejected by the analyzer."
)


def generate():
    attacks: list[Attack] = []

    # 1. struct fields
    for cap in ("Stdio", "Fs", "Net", "Env", "Clock", "Proc", "Db"):
        attacks.append(Attack(
            attack_id=f"data_struct_field_{cap.lower()}",
            description=f"Struct field of type {cap}.",
            source=f"type S {{ inner: {cap} }}\n",
        ))

    # 2. variant payloads
    for cap in ("Stdio", "Fs", "Net", "Env"):
        attacks.append(Attack(
            attack_id=f"data_variant_payload_{cap.lower()}",
            description=f"Variant payload of type {cap}.",
            source=(
                "type R =\n"
                "    NoCap\n"
                f"    HasCap({cap})\n"
            ),
        ))

    # 3. return-as-tuple
    for cap in ("Stdio", "Fs"):
        attacks.append(Attack(
            attack_id=f"data_tuple_return_{cap.lower()}",
            description=f"Function returning ({cap}, Int) tuple.",
            source=(
                f"fun smuggle() -> ({cap}, Int)\n"
                '    return (Stdio { }, 0)\n'
            ),
        ))

    # 4. capability in generic argument
    for cap in ("Stdio", "Fs", "Net"):
        attacks.append(Attack(
            attack_id=f"data_list_of_{cap.lower()}",
            description=f"List<{cap}> as return type.",
            source=(
                f"fun smuggle() -> List<{cap}>\n"
                "    return []\n"
            ),
        ))

    # 5. capability in `let` binding (aliasing)
    for cap_param in ("stdio: Stdio", "fs: Fs", "net: Net"):
        cap_name = cap_param.split(":")[0].strip()
        attacks.append(Attack(
            attack_id=f"data_let_alias_{cap_name}",
            description=f"`let alias = {cap_name}` aliasing.",
            source=(
                f"fun f({cap_param})\n"
                f"    let alias = {cap_name}\n"
                f'    alias.println("x")\n'
                if cap_name == "stdio" else
                f"fun f({cap_param})\n"
                f"    let alias = {cap_name}\n"
            ),
        ))

    # 6. capability as constant
    for cap in ("Fs", "Stdio"):
        attacks.append(Attack(
            attack_id=f"data_const_{cap.lower()}",
            description=f"`const G: {cap} = ...` constant.",
            source=f"const G: {cap} = {cap} {{ }}\n",
        ))

    # 7. capability as a free-function return
    for cap in ("Fs", "Stdio", "Net"):
        attacks.append(Attack(
            attack_id=f"data_return_type_{cap.lower()}",
            description=f"Function returning bare {cap}.",
            source=(
                f"fun smuggle() -> {cap}\n"
                f"    return {cap} {{ }}\n"
            ),
        ))

    return attacks
