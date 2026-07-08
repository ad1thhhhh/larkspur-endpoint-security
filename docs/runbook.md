# Larkspur Endpoint Security — Runbook

Step-by-step guide to start the stack and reproduce the full demo.

---

## Step 1 — Start All VMs

Boot in this order:
1. `wazuh-manager` — wait 2 minutes
2. `linux-endpoint`
3. `win-endpoint`

---

## Step 2 — Start Wazuh Services

```bash
ssh wazuh@192.168.100.10
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager
```

If any service is stopped:
```bash
sudo systemctl start wazuh-manager wazuh-indexer wazuh-dashboard
```

---

## Step 3 — Start AI Remediation Stack

```bash
cd ~/larkspur-ai-stack
docker compose up -d
docker compose ps
curl http://localhost:8000/health
```

---

## Step 4 — Verify Both Agents Are Active

```bash
sudo /var/ossec/bin/agent_control -l
```

Both `linux-endpoint` and `win-endpoint` should show **Active**.

---

## Step 5 — Run Linux Simulations

```bash
ssh linux@192.168.100.6
su - labuser    # password: password123

# T1548.003 — Shadow file access
sudo cat /etc/shadow

# T1548.003 — Sudo bash privilege escalation
sudo bash -c "id && whoami"

# T1059 — Script execution from /tmp
cd /tmp
echo '#!/bin/bash' > test.sh
echo 'whoami' >> test.sh
chmod +x test.sh
sudo ./test.sh

# T1110 — SSH brute force
for i in {1..10}; do
  sshpass -p "wrongpassword" ssh -o StrictHostKeyChecking=no labuser@192.168.100.6 exit 2>/dev/null
done

# T1053 — Cron persistence
echo "* * * * * root echo 'larkspur' > /tmp/persist.txt" | sudo tee /etc/cron.d/larkspur-persist
```

---

## Step 6 — Run Windows Simulations

```powershell
# T1136.001 — New local admin account
net user backdoor P@ssw0rd123 /add
net localgroup Administrators backdoor /add

# T1053.005 — Scheduled task
schtasks /create /sc daily /tn "LarkspurUpdate" /tr "powershell.exe -WindowStyle Hidden -Command 'echo pwned'" /st 09:00

# T1059.001 — Encoded PowerShell
$cmd = "whoami /all"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded
```

---

## Step 7 — Verify Alerts

```bash
sudo grep -A 5 "larkspur" /var/ossec/logs/alerts/alerts.log | tail -50
```

In Wazuh Dashboard → Security Events → filter: `rule.groups: larkspur`

---

## Step 8 — Demonstrate Remediation

```bash
# Disable account
curl -X POST http://localhost:8000/remediate \
  -H "Content-Type: application/json" \
  -d '{"action":"disable_account","target":"testuser"}'

# Block IP
curl -X POST http://localhost:8000/remediate \
  -H "Content-Type: application/json" \
  -d '{"action":"block_ip","target":"192.168.100.5"}'
```

---

## Step 9 — Demonstrate Rollback

```bash
# Unlock account
curl -X POST http://localhost:8000/rollback \
  -H "Content-Type: application/json" \
  -d '{"action":"disable_account","target":"testuser"}'

# Unblock IP
curl -X POST http://localhost:8000/rollback \
  -H "Content-Type: application/json" \
  -d '{"action":"block_ip","target":"192.168.100.5"}'
```

---

## Step 10 — Show Audit Log

```bash
curl http://localhost:8000/audit
```

---

## Cleanup

```bash
# Linux endpoint
sudo rm /etc/cron.d/larkspur-persist
sudo rm /tmp/test.sh /tmp/persist.txt

# Windows endpoint (PowerShell)
net user backdoor /delete
schtasks /delete /tn "LarkspurUpdate" /f

# Stop Docker stack
cd ~/larkspur-ai-stack
docker compose down
```
