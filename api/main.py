"""
Larkspur Retail Group — AI Security Remediation API
====================================================
FastAPI application providing:
  POST /alert      — Receive Wazuh alert, LLM triage, conditional remediation
  POST /remediate  — Manual remediation trigger
  POST /rollback   — Reverse a remediation action
  GET  /audit      — Retrieve the persistent audit log
  GET  /health     — Stack health check
"""

from fastapi import FastAPI
from pydantic import BaseModel
import httpx
import os
import json
from playbooks import execute_playbook, verify_remediation, rollback_action

app = FastAPI(
    title="Larkspur AI Security Stack",
    description="Automated alert triage and predefined remediation for Larkspur Retail Group",
    version="1.0.0"
)

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://ollama:11434")
LLM_MODEL = "llama3.2"
LLM_TIMEOUT = 120


class WazuhAlert(BaseModel):
    rule_id: str
    rule_description: str
    agent_name: str
    agent_ip: str
    full_log: str
    level: int


class RemediationRequest(BaseModel):
    action: str
    target: str


@app.get("/health")
async def health():
    return {"status": "ok", "service": "Larkspur AI Security Stack", "version": "1.0.0"}


@app.post("/alert")
async def receive_alert(alert: WazuhAlert):
    prompt = f"""You are a security operations analyst at Larkspur Retail Group.
Analyse this Wazuh SIEM alert and respond ONLY with a JSON object.

Required JSON fields:
- summary: one sentence plain English description of what happened
- severity: one of [low, medium, high, critical]
- recommended_action: one of [disable_account, block_ip, kill_process, remove_scheduled_task, monitor_only]
- target: the specific username, IP address, process name, or task name to act on
- reasoning: one sentence justification for the recommended action

Alert details:
Rule ID: {alert.rule_id}
Description: {alert.rule_description}
Agent: {alert.agent_name} ({alert.agent_ip})
Log: {alert.full_log}
Wazuh Severity Level: {alert.level}"""

    async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
        try:
            response = await client.post(
                f"{OLLAMA_HOST}/api/generate",
                json={"model": LLM_MODEL, "prompt": prompt, "stream": False}
            )
            llm_data = response.json()
            raw = llm_data.get("response", "{}")
            clean = raw.strip().replace("```json", "").replace("```", "").strip()
            triage = json.loads(clean)
        except Exception as e:
            triage = {
                "summary": alert.rule_description,
                "severity": "high" if alert.level >= 12 else "medium" if alert.level >= 8 else "low",
                "recommended_action": "monitor_only",
                "target": "unknown",
                "reasoning": f"LLM triage unavailable ({str(e)}); classified by alert level."
            }

    remediation_result = None
    verification_result = None

    if (
        triage.get("severity") in ["high", "critical"]
        and triage.get("recommended_action") != "monitor_only"
        and triage.get("target") != "unknown"
    ):
        remediation_result = execute_playbook(
            action=triage["recommended_action"],
            target=triage["target"]
        )
        verification_result = verify_remediation(
            action=triage["recommended_action"],
            target=triage["target"]
        )

    return {
        "alert_received": alert.dict(),
        "llm_triage": triage,
        "remediation": remediation_result,
        "verification": verification_result
    }


@app.post("/remediate")
async def manual_remediate(req: RemediationRequest):
    result = execute_playbook(req.action, req.target)
    verification = verify_remediation(req.action, req.target)
    return {"result": result, "verification": verification}


@app.post("/rollback")
async def rollback(req: RemediationRequest):
    return rollback_action(req.action, req.target)


@app.get("/audit")
async def get_audit_log():
    try:
        with open("/app/logs/audit.log", "r") as f:
            return {"log": f.read()}
    except FileNotFoundError:
        return {"log": "No audit entries yet."}
