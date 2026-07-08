## Port Reference

| Port | Protocol | Service |
|---|---|---|
| 1514 | TCP (TLS) | Wazuh agent communication |
| 443 | HTTPS | Wazuh Dashboard |
| 55000 | HTTPS | Wazuh API |
| 8000 | HTTP | FastAPI remediation API |
| 11434 | HTTP | Ollama LLM (internal only) |

## Trust Zones

| Zone | Members | Description |
|---|---|---|
| Endpoint Zone | win-endpoint, linux-endpoint | Monitored endpoint estate |
| Management Zone | wazuh-manager | SIEM, detection, and remediation |
