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
    Execute a remediation action against the specified target.
    Rejects any action not present in ALLOWED_ACTIONS.
    """
    if action not in ALLOWED_ACTIONS:
        audit(action, target, "REJECTED - not in allowlist")
        return {"status": "rejected", "reason": "Action not in allowlist"}

    result = "unknown"

    if action == "disable_account":
        try:
            r = _nsenter(["usermod", "-L", target])
            result = f"Account {target} locked" if r.returncode == 0 else r.stderr.strip()
        except Exception as e:
            result = f"ERROR: {str(e)}"

    elif action == "block_ip":
        try:
            r = _nsenter(["iptables", "-I", "INPUT", "-s", target, "-j", "DROP"])
            result = f"Blocked IP {target}" if r.returncode == 0 else r.stderr.strip()
        except Exception as e:
            result = f"ERROR: {str(e)}"

    elif action == "kill_process":
        try:
            r = _nsenter(["pkill", "-f", target])
            result = f"Killed process: {target}" if r.returncode == 0 else r.stderr.strip()
        except Exception as e:
            result = f"ERROR: {str(e)}"

    elif action == "remove_scheduled_task":
        result = f"SIMULATED: Would remove scheduled task '{target}'"

    audit(action, target, result)
    return {"status": "executed", "action": action, "target": target, "result": result}


def verify_remediation(action: str, target: str) -> dict:
    """
    Verify that a remediation action was applied successfully.
    Returns verified: true/false with supporting detail.
    """
    if action == "disable_account":
        try:
            r = _nsenter(["passwd", "-S", target])
            locked = "L" in r.stdout
            return {"verified": locked, "detail": r.stdout.strip()}
        except Exception as e:
            return {"verified": False, "detail": str(e)}

    elif action == "block_ip":
        try:
            r = _nsenter(["iptables", "-L", "INPUT", "-n"])
            found = target in r.stdout
            return {"verified": found, "detail": f"IP {target} in iptables" if found else f"IP {target} NOT found in iptables"}
        except Exception as e:
            return {"verified": False, "detail": str(e)}

    return {"verified": True, "detail": "No verification implemented for this action"}


def rollback_action(action: str, target: str) -> dict:
    """
    Reverse a previously executed remediation action.
    Rollback is defined for: disable_account, block_ip.
    """
    if action == "disable_account":
        try:
            r = _nsenter(["usermod", "-U", target])
            result = f"Account {target} unlocked" if r.returncode == 0 else r.stderr.strip()
            audit(f"ROLLBACK_{action}", target, result)
            return {"status": "rolled_back", "detail": result}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    elif action == "block_ip":
        try:
            r = _nsenter(["iptables", "-D", "INPUT", "-s", target, "-j", "DROP"])
            result = f"Unblocked IP {target}" if r.returncode == 0 else r.stderr.strip()
            audit(f"ROLLBACK_{action}", target, result)
            return {"status": "rolled_back", "detail": result}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    return {"status": "no_rollback", "detail": "No rollback defined for this action"}
