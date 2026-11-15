# Wazuh SIEM Home Lab on Proxmox

A self-hosted Security Information and Event Management (SIEM) lab built on Proxmox VE. I deployed Wazuh as a central SIEM, enrolled Windows and Linux endpoints as agents, simulated common attacks from a Kali Linux VM, and investigated the resulting alerts the way a Tier 1 SOC analyst would.

**Skills demonstrated:** SIEM deployment, log collection, alert triage, detection rule writing, file integrity monitoring, vulnerability detection, MITRE ATT&CK mapping, Proxmox virtualization, Linux and Windows administration.

---

## Lab Architecture

```
                 ┌──────────────────────── Proxmox VE host (Dell OptiPlex) ────────────────────────┐
                 │                                                                                 │
                 │   ┌──────────────────┐        alerts / logs        ┌──────────────────────┐    │
                 │   │  Wazuh Server     │ ◄────────── 1514/1515 ───── │  Windows 11 VM        │    │
                 │   │  Ubuntu 24.04     │                             │  (Wazuh agent)        │    │
                 │   │  manager+indexer+ │ ◄────────── 1514/1515 ───── ┌──────────────────────┐    │
                 │   │  dashboard        │                             │  Ubuntu Server VM     │    │
                 │   └──────────────────┘                             │  (Wazuh agent, SSH)   │    │
                 │            ▲                                        └──────────────────────┘    │
                 │            │ HTTPS 443 (dashboard)                         ▲                     │
                 │            │                                               │ simulated attacks   │
                 │      My workstation                                ┌──────────────────────┐    │
                 │                                                    │  Kali Linux VM        │    │
                 │                                                    │  (attacker)           │    │
                 │                                                    └──────────────────────┘    │
                 └─────────────────────────────────────────────────────────────────────────────────┘
```

| VM | OS | vCPU | RAM | Disk | Role |
|----|----|------|-----|------|------|
| wazuh-server | Ubuntu Server 24.04 | 4 | 8 GB | 60 GB | Wazuh manager, indexer, dashboard |
| win-endpoint | Windows 11 | 2 | 4 GB | 64 GB | Monitored endpoint (agent) |
| linux-endpoint | Ubuntu Server 24.04 | 1 | 2 GB | 20 GB | Monitored endpoint (agent), SSH target |
| kali | Kali Linux | 2 | 4 GB | 40 GB | Attacker / traffic generator |

![Proxmox VMs](screenshots/01-proxmox-vms.png)

> All attacks were run only against VMs I own, inside my isolated home lab network. The Wazuh dashboard is not exposed to the internet.

---

## 1. Deploying the Wazuh Server

Created an Ubuntu Server 24.04 VM in Proxmox (4 vCPU / 8 GB RAM / 60 GB disk, VirtIO NIC, static IP), then installed the Wazuh central components with the official installation assistant:

```bash
sudo apt update && sudo apt upgrade -y
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

The assistant installs the Wazuh indexer, manager, and dashboard on one host and prints the admin credentials when it finishes. The dashboard is then available at `https://<wazuh-server-ip>`.

![Wazuh dashboard](screenshots/02-wazuh-dashboard.png)

---

## 2. Enrolling Endpoints

Used **Agents → Deploy new agent** in the dashboard to generate the install command for each OS.

**Linux endpoint (Ubuntu):** ran the generated `apt`/`dpkg` install command, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

**Windows endpoint:** ran the generated PowerShell command as Administrator, then started the service:

```powershell
NET START Wazuh
```

Made sure Windows was logging the security events I wanted to detect:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
```

![Active agents](screenshots/03-active-agents.png)

---

## 3. Attack Simulations and Detections

For each scenario I ran the activity, found the alert in Wazuh, and wrote up a short triage note like I would in a SOC ticket.

### Scenario 1: SSH brute force (Linux)

**MITRE ATT&CK:** T1110 – Brute Force

From Kali, using a small custom password list against a test account on the Linux endpoint:

```bash
printf "password\n123456\nletmein\nadmin\nwelcome\nqwerty\nsummer2026\nchangeme\n" > passwords.txt
hydra -l labuser -P passwords.txt ssh://<linux-endpoint-ip> -t 4
```

**What Wazuh showed:** _[TODO: rule IDs, alert levels, number of events, source IP]_

![SSH brute force alerts](screenshots/04-ssh-bruteforce.png)

**Triage notes:** _[TODO: e.g., Multiple failed SSH logins from 192.168.x.x against user `labuser` within 1 minute. Source is the Kali VM (known lab host). In a real environment I would check whether any login succeeded, block the source IP, and escalate if a success followed the failures.]_

### Scenario 2: Failed logons + new admin account (Windows)

**MITRE ATT&CK:** T1110 – Brute Force, T1136.001 – Create Local Account, T1098 – Account Manipulation

1. Entered the wrong password at the Windows sign-in screen several times (Event ID 4625).
2. Created a new local user and added it to Administrators from an elevated prompt:

```powershell
net user backdoor P@ssw0rd123! /add
net localgroup Administrators backdoor /add
```

(Event IDs 4720 – user created, 4732 – member added to security-enabled local group.) Removed the account afterward with `net user backdoor /delete`.

**What Wazuh showed:** _[TODO]_

![Windows account alerts](screenshots/05-windows-accounts.png)

**Triage notes:** _[TODO: Why a new admin account is high-priority, what I would verify (who created it, from which session), and the response.]_

### Scenario 3: File Integrity Monitoring

**MITRE ATT&CK:** T1565.001 – Stored Data Manipulation

Added a real-time monitored folder to the Linux agent's `/var/ossec/etc/ossec.conf` inside the `<syscheck>` block:

```xml
<directories realtime="yes" check_all="yes" report_changes="yes">/opt/sensitive</directories>
```

Restarted the agent, then created, modified, and deleted a file in `/opt/sensitive`.

**What Wazuh showed:** _[TODO: added / modified / deleted alerts, and the diff from report_changes]_

![FIM alerts](screenshots/06-fim.png)

### Scenario 4: Vulnerability detection

Reviewed the **Vulnerability Detection** module to see known CVEs on the enrolled endpoints, then patched one and confirmed the finding cleared.

**What Wazuh showed:** _[TODO: number of critical/high CVEs before and after patching]_

![Vulnerability detection](screenshots/07-vulnerabilities.png)

---

## 4. Custom Detection Rule

Wrote a custom rule (`rules/local_rules.xml`) on the Wazuh server in `/var/ossec/etc/rules/local_rules.xml` that raises a higher-severity alert when one source IP fails SSH authentication repeatedly in a short window, then validated it by re-running the brute-force scenario.

```bash
sudo systemctl restart wazuh-manager
```

![Custom rule firing](screenshots/08-custom-rule.png)

---

## What I Learned

_[TODO: 3–5 honest bullet points, e.g. sizing the indexer's memory on limited hardware, the difference between raw events and alerts, tuning noisy rules, how MITRE mapping helps prioritize, what you'd add next.]_

## Next Steps

- Add Sysmon on the Windows endpoint for richer process and network telemetry
- Add Suricata IDS to detect network scans (e.g., Nmap)
- Configure Wazuh active response to automatically block brute-force source IPs
