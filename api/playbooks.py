"""
Larkspur Retail Group — Remediation Playbooks
=============================================
Provides predefined, allowlisted, and auditable remediation actions.

Safety model:
- Only actions in ALLOWED_ACTIONS can be executed
- Every action (including rejections) is written to the audit log
- Every action has a corresponding rollback function
- Verification is performed after every execution
"""

import logging
import datetime
import subprocess

AUDIT_LOG = "/app/logs/audit.log"

# Strict allowlist — no action outside this set can execute
ALLOWED_ACTIONS = {
    "disable_account",
    "block_ip",
    "kill_process",
    "remove_scheduled_task"
}


def audit(action: str, target: str, result: str):
    """Write a timestamped entry to the persistent audit log."""
    entry = (
        f"{datetime.datetime.utcnow().isoformat()} "
        f"| ACTION={action} "
        f"| TARGET={target} "
        f"| RESULT={result}\n"
    )
    with open(AUDIT_LOG, "a") as f:
        f.write(entry)
    logging.info(entry.strip())


def _nsenter(cmd: list) -> subprocess.CompletedProcess:
    """
    Run a command in the host's namespaces via nsenter.
    Requires: container privileged=true, pid=host
    """
    return subprocess.run(
        ["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p"] + cmd,
        capture_output=True,
        text=True
    )


def execute_playbook(action: str, target: str) -> dict:
    """
    Execute a remediation action against the specified
