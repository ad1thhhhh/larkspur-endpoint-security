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
- reasoning: one
