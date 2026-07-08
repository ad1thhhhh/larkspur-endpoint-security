# Larkspur Endpoint Security — Incident Response and Automated Remediation Lab


## Overview

This repository contains the complete implementation of an endpoint security monitoring and automated remediation architecture for the fictitious **Larkspur Retail Group**, developed as part of a continuous assessment in endpoint security incident response.

The project builds an isolated three-VM lab environment, configures endpoint telemetry pipelines into **Wazuh SIEM**, develops eight custom **MITRE ATT&CK-mapped detection rules**, and implements a **Dockerised AI security stack** using Ollama (llama3.2) and FastAPI for automated alert triage and remediation.

---

## Repository Structure

larkspur-endpoint-security/
├── README.md
├── docker-compose.yml          # AI remediation stack
├── api/
│   ├── Dockerfile
│   ├── main.py                 # FastAPI application
│   ├── playbooks.py            # Remediation playbooks
│   └── requirements.txt
├── wazuh/
│   └── larkspur_rules.xml      # 8 custom MITRE ATT&CK detection rules
├── linux/
│   └── larkspur.rules          # auditd rule set
└── docs/
├── lab-topology.md         # Network diagram and IP plan
├── vulnerable-configs.md   # Intentional weakness documentation
└── runbook.md              # How to start and reproduce the demo

---

## Lab Environment

| VM | OS | IP | RAM | Role |
|---|---|---|---|---|
| wazuh-manager | Ubuntu 26.04 LTS | 192.168.100.10 | 7.3 GB | Wazuh SIEM + Docker AI Stack |
| linux-endpoint | Ubuntu 26.04 LTS | 192.168.100.6 | 2 GB | Linux victim endpoint |
| win-endpoint | Windows 10 (10.0.19045.3803) | 192.168.100.20 | 4 GB | Windows victim endpoint |

All VMs are connected on a VirtualBox host-only network (192.168.100.0/24) with no exposure to public networks.

---

## Detection Rules

Eight custom Wazuh rules mapped to MITRE ATT&CK:

| Rule ID | Description | ATT&CK Technique | Severity |
|---|---|---|---|
| 100001 | Shadow file accessed via sudo | T1548.003 | High (12) |
| 100002 | Sudo bash privilege escalation | T1548.003 | High (12) |
| 100003 | Shell script executed from /tmp | T1059 | Medium (10) |
| 100004 | SSH brute force (5+ failures/60s) | T1110 | High (12) |
| 100005 | Cron-based persistence mechanism | T1053 | Medium (11) |
| 100006 | New local account created (Windows) | T1136.001 | Critical (14) |
| 100007 | User added to Administrators group | T1136.001 | Critical (14) |
| 100008 | Scheduled task created (Windows) | T1053.005 | Medium (11) |

---

## AI Remediation Stack

### Allowed Actions

```python
ALLOWED_ACTIONS = {
    "disable_account",
    "block_ip",
    "kill_process",
    "remove_scheduled_task"
}
```

No action outside this set can execute regardless of LLM output.

### API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Stack health check |
| `/alert` | POST | Receive Wazuh alert, LLM triage, conditional remediation |
| `/remediate` | POST | Manual remediation trigger |
| `/rollback` | POST | Reverse a remediation action |
| `/audit` | GET | Retrieve audit log |

### Quick Test

```bash
# Start the stack
cd ~/larkspur-ai-stack
docker compose up -d
docker exec larkspur-ollama ollama pull llama3.2

# Disable account
curl -X POST http://localhost:8000/remediate \
  -H "Content-Type: application/json" \
  -d '{"action":"disable_account","target":"testuser"}'

# Block IP
curl -X POST http://localhost:8000/remediate \
  -H "Content-Type: application/json" \
  -d '{"action":"block_ip","target":"192.168.100.5"}'

# View audit log
curl http://localhost:8000/audit
```

---

## MITRE ATT&CK Coverage

| Technique | ID | Platform | Simulation Method |
|---|---|---|---|
| Sudo and Sudo Caching | T1548.003 | Linux | sudo cat /etc/shadow |
| Command and Scripting | T1059 | Linux | Shell script from /tmp |
| Brute Force | T1110 | Linux | sshpass SSH brute force |
| Scheduled Task/Job | T1053 | Linux | cron entry |
| Create Local Account | T1136.001 | Windows | net user /add |
| Scheduled Task | T1053.005 | Windows | schtasks /create |
| PowerShell | T1059.001 | Windows | -EncodedCommand |

---

## Quick Start

See [docs/runbook.md](docs/runbook.md) for the full step-by-step demo reproduction guide.

---

## Safety and Ethics

- No real malware was used at any point
- All simulations use standard OS utilities only
- The lab network is fully isolated on a VirtualBox host-only adapter
- No data was exfiltrated to any external endpoint
- All remediation actions are reversible
- The audit log provides a complete timestamped record of all automated actions

---

## References

- [Wazuh Documentation](https://documentation.wazuh.com)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Ollama](https://ollama.com)
- NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide
- NIST SP 800-53 Rev 5 — Security and Privacy Controls
- CIS Controls v8
