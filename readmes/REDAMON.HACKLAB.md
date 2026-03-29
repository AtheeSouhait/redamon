# RedAmon HackLab
### 50 Agentic Attack Prompts — Powered by RedAmon AI Agent
### Target: AltoroJ — intentionally vulnerable banking app deployed on your own EC2 instance

> **How it works:**
> Each prompt is intentionally short and generic -- no hardcoded URLs, no specific parameters.
> The agent autonomously searches the recon data, selects the right tools, chains them across phases,
> and executes the full attack -- just like a real human operator would.
>
> **Prerequisites:**
> - AltoroJ deployed and running on your EC2 instance
> - Full recon pipeline executed and stored in the graph database
> - RedAmon agent configured with your EC2 IP as the target

---

## CATEGORY 1 — SQL INJECTION (1–5)

### #1 — SQL Injection Login Bypass → Full Database Dump
```
Find login forms on the target and test them for SQL injection auth bypass.
If successful, escalate to a full database dump of the users table.
```

### #2 — SQLi → File Read → OS Shell
```
Find injectable parameters on the target and exploit SQL injection to read
sensitive files, write a web shell, and escalate to OS-level shell access.
```

### #3 — Blind SQLi + Out-of-Band DNS Exfiltration
```
Find injectable parameters on the target and perform blind SQL injection
using out-of-band DNS exfiltration. Show what data was extracted via DNS callbacks.
```

### #4 — Time-Based Blind SQLi with WAF Bypass Tamper Scripts
```
Find injectable parameters on the target and test for time-based blind SQL injection.
If filtering is detected, bypass it with appropriate tamper techniques.
Explain which bypass was chosen and why based on the target's stack.
```

### #5 — SQLi → Web Shell Upload → Remote Code Execution
```
Exploit SQL injection on the target to upload a web shell to the web root
and confirm remote code execution. Transition to post-exploitation after shell access.
```

---

## CATEGORY 2 — XSS & CLIENT-SIDE ATTACKS (6–8)

### #6 — Reflected XSS → Stored XSS → Cookie Theft Simulation
```
Find user-input endpoints on the target and test for reflected and stored XSS.
Build a cookie-theft payload and explain the session hijacking impact.
```

### #7 — HTTP Response Header Injection + XSS via HTTP Headers
```
Find endpoints on the target where HTTP headers are reflected or logged.
Test for CRLF injection and XSS via HTTP headers.
Document all injection points with request/response evidence.
```

### #8 — DOM-Based XSS + JavaScript Sink Analysis
```
Analyze the target's JavaScript files for dangerous sinks and test for DOM-based XSS.
Explain why DOM XSS evades server-side WAFs.
```

---

## CATEGORY 3 — AUTHENTICATION & SESSION ATTACKS (9–12)

### #9 — Hydra Brute Force Login → Session Takeover
```
Find login endpoints on the target and brute force credentials with Hydra.
On success, authenticate and capture a valid session cookie.
```

### #10 — Session Fixation + Cookie Security Audit
```
Analyze the target's session management: check if session IDs rotate after login,
audit cookie security flags, and test if logout properly invalidates sessions.
```

### #11 — IDOR + Horizontal Privilege Escalation
```
Find account-related endpoints on the target and test for IDOR by accessing
other users' data through parameter manipulation. Check for privilege escalation.
```

### #12 — Forced Browsing + Admin Panel Exposure + Config File Disclosure
```
Search for hidden admin panels, management interfaces, and sensitive config files
on the target. Report anything accessible without authentication.
```

---

## CATEGORY 4 — CVE EXPLOITATION WITH METASPLOIT (13–17)

### #13 — Nuclei CVE Scan → Auto-Select → Metasploit Exploitation
```
Find known CVEs on the target, confirm them with Nuclei, and exploit
the highest-impact one using Metasploit. Transition to post-exploitation on session open.
```

### #14 — Tomcat Manager Brute Force → WAR Deployment → Meterpreter
```
Find the Tomcat Manager interface on the target, brute force credentials,
and deploy a malicious WAR file to get a Meterpreter session.
```

### #15 — Java Deserialization RCE — No MSF Module Fallback via execute_code
```
Find Java deserialization vulnerabilities on the target and exploit them.
If no Metasploit module exists, write a custom exploit and deliver the payload manually.
```

### #16 — Log4Shell (CVE-2021-44228) → JNDI Callback → Reverse Shell
```
Check if the target is vulnerable to Log4Shell and exploit it
by injecting JNDI payloads to get a reverse shell.
```

### #17 — Metasploit Auxiliary Chain → Exploit → Post Module
```
Use Metasploit auxiliary scanners to enrich the attack surface on the target,
then find and execute the best exploit module. Run post-exploitation on the opened session.
```

---

## CATEGORY 5 — REVERSE SHELL & RCE (18–20)

### #18 — Command Injection → Reverse Bash Shell
```
Find injectable endpoints on the target and test for OS command injection.
If confirmed, deliver a reverse shell and transition to post-exploitation.
```

### #19 — SSTI Detection → Template Engine Fingerprint → RCE
```
Find input fields on the target and test for Server-Side Template Injection.
Fingerprint the template engine and escalate to remote code execution.
```

### #20 — File Upload Bypass → Web Shell → Reverse Shell
```
Find file upload endpoints on the target, bypass upload restrictions
to deploy a web shell, and escalate to a reverse shell.
```

---

## CATEGORY 6 — POST-EXPLOITATION (21–24)

### #21 — Meterpreter Full Enumeration: System + Credentials + File Exfil
```
Starting from an active Meterpreter session on the target.
Perform full post-exploitation enumeration: system info, credentials, network,
and exfiltrate sensitive configuration files.
```

### #22 — Privilege Escalation: SUID + Sudo Abuse → Root
```
Starting from a low-privilege shell on the target.
Find and exploit privilege escalation vectors to get root.
Dump /etc/shadow after root is obtained.
```

### #23 — Persistence: Backdoor User + Crontab Reverse Shell
```
Starting from a root shell on the target.
Establish persistence using multiple techniques and verify
the backdoor works by catching a callback.
```

### #24 — Network Pivoting: MSF Route + Internal Subnet Scan
```
Starting from an active Meterpreter session on the target.
Pivot into the internal network, scan for live hosts and services,
and probe any discovered internal services.
```

---

## CATEGORY 7 — DENIAL OF SERVICE (25–27)

### #25 — Slowloris HTTP DoS → Service Disruption + Recovery Check
```
Launch a Slowloris attack against the target's web application.
Verify service impact during the attack and check recovery after stopping.
```

### #26 — TCP SYN Flood + UDP Flood with hping3
```
Perform L4 flood attacks (SYN, UDP, ICMP) against the target.
Verify port availability before and after each attack vector.
Explain L4 vs L7 DoS and which defenses mitigate each.
```

### #27 — Application Logic DoS: XML Bomb + Concurrent Request Exhaustion
```
Find XML-processing or API endpoints on the target and test application-layer DoS:
XML bomb payloads and concurrent request flooding.
Monitor response time degradation as evidence of impact.
```

---

## CATEGORY 8 — PHISHING & PAYLOAD GENERATION (28–29)

### #28 — msfvenom Linux ELF Payload → Handler → Meterpreter
```
Generate a Linux Meterpreter payload for the target, deliver it,
and catch the session. Explain staged vs stageless payloads.
```

### #29 — Fileless Web Delivery → Python Meterpreter (No Binary on Disk)
```
Use Metasploit web_delivery to get a fileless Python Meterpreter session on the target.
Prove no file was written to disk and explain why fileless execution bypasses AV.
```

---

## CATEGORY 9 — FULL AUTONOMOUS KILL CHAIN (30)

### #30 — Full Pentest: Recon → Exploit → Root → Persist → Report
```
Perform a complete autonomous penetration test against the target.
Gain initial access, escalate to root, establish persistence, and harvest credentials.
Generate a full pentest report with executive summary, attack path,
CVSS-scored vulnerabilities, remediation, and MITRE ATT&CK mapping.
```

---

## CATEGORY 10 — ADVANCED & BONUS (31–40)

### #31 — SSL/TLS Misconfiguration Audit
```
Audit the target's SSL/TLS configuration for weak ciphers, outdated protocols,
and certificate issues. Rate each finding by exploitability and explain the MITM risk.
```

### #32 — SSH Brute Force → Shell Access → sudo Escalation
```
Find the SSH service on the target and brute force credentials.
On success, check for privilege escalation paths.
```

### #33 — Information Disclosure via Error Messages + Stack Trace Harvesting
```
Send malformed inputs to the target's endpoints and collect all information leaks:
stack traces, database errors, internal paths, framework versions.
Build a target profile from the disclosed information alone.
```

### #34 — CSRF Token Bypass + Unauthorized State-Changing Request
```
Find state-changing endpoints on the target and analyze CSRF protections.
Craft a request that succeeds without a valid CSRF token and document the impact.
```

### #35 — Password Reset Flow Abuse + Account Takeover
```
Analyze the target's password reset flow for weaknesses and demonstrate
account takeover via the most viable attack vector.
```

### #36 — Malicious Word Document (VBA Macro) → Meterpreter
```
Generate a weaponized Word document with a VBA macro payload using Metasploit.
Set up the handler and simulate delivery.
Explain how the macro catches the Meterpreter callback.
```

### #37 — Credential Reuse Attack: Dump → SSH → Database → Lateral Move
```
Starting from credentials harvested during a prior exploitation step.
Test them against all services on the target (SSH, databases, admin panels)
and attempt lateral movement on each successful reuse.
```

### #38 — CVE Research → OSINT Correlation → Exploit Prioritization Report
```
Find all CVEs and technologies on the target, enrich them with OSINT
(CVSS scores, public exploits, patch status), and produce a prioritized
exploitation roadmap ranked by impact and ease of exploitation.
```

### #39 — Stealth Mode Attack: Slow Scan + Minimal Footprint + Log Evasion
```
Perform SQL injection and CVE exploitation against the target in stealth mode
with rate limiting and evasion techniques. Compare the noise level vs a normal run
and explain what a SIEM would see.
```

### #40 — Strategic Planning: Agent Self-Designs the Full Attack
> 💡 **Enable Deep Think before running this prompt**
```
Analyze the full recon data on the target. Before executing any tool,
design the optimal attack strategy with vectors, order of operations,
fallback paths, and post-exploitation goals.
Present the plan, then execute it and report any deviations.
```

---

## CATEGORY 11 — ALTOROJ-SPECIFIC ATTACKS (41–50)

### #41 — REST API Weak Token Decode → Credential Extraction
```
Find REST API authentication on the target, capture an auth token,
and analyze it for weak encoding. Extract credentials and reuse them
against other services.
```

### #42 — REST API IDOR: Access Any Account Without Authorization
```
Authenticate to the target's REST API as a low-privilege user and test
for IDOR on account endpoints. Document all accessible accounts
and explain the broken access control root cause.
```

### #43 — XPath Injection → Authentication Bypass + Data Extraction
```
Find search or query endpoints on the target and test for XPath injection.
Attempt auth bypass and data extraction.
Compare XPath injection to SQL injection and explain the detection challenges.
```

### #44 — Open Redirect → Phishing Landing Page Delivery
```
Find open redirect vulnerabilities on the target and demonstrate
how a trusted domain can be abused to deliver a phishing link.
```

### #45 — REST API SQL Injection in Transaction Date Filter → Full Data Dump
```
Find REST API endpoints on the target that accept date or range parameters
and test for SQL injection. Dump the database to show REST APIs are
equally vulnerable to SQLi as traditional web forms.
```

### #46 — Swagger UI Discovery → Full API Surface Mapping → Targeted Attack
```
Find exposed API documentation on the target, map the full API surface,
and attack the most dangerous endpoint directly.
```

### #47 — Plaintext Password Extraction via SQLi → Credential Spray
```
Exploit SQL injection on the target to extract plaintext passwords
and spray the credentials against all available services.
Explain the compounding risk of SQLi + plaintext storage + credential reuse.
```

### #48 — CSRF: Unauthorized Fund Transfer Without Token
```
Find the fund transfer functionality on the target, analyze CSRF protections,
and craft a proof-of-concept that performs an unauthorized transfer.
```

### #49 — OS Command Injection via Static Page Processing → RCE
```
Find content-processing endpoints on the target and test for OS command injection.
Escalate to a reverse shell and transition to post-exploitation.
```

### #50 — Log4j 1.x Deserialization (CVE-2019-17571) → Remote Code Execution
> 💡 **Enable Deep Think before running this prompt**
```
Check if the target runs Log4j 1.x and is vulnerable to CVE-2019-17571.
Research the vulnerability, craft a deserialization exploit,
and achieve remote code execution. Transition to post-exploitation.
```

---

## Quick Reference

| Category | Demos | Key Tools |
|----------|-------|-----------|
| SQL Injection | #1–5 | `kali_shell` (sqlmap), `execute_curl` |
| XSS & Client-Side | #6–8 | `execute_curl` |
| Auth & Sessions | #9–12 | `execute_hydra`, `execute_curl` |
| CVE with Metasploit | #13–17 | `execute_nuclei`, `metasploit_console` |
| Reverse Shell & RCE | #18–20 | `execute_curl`, `execute_code`, `metasploit_console` |
| Post-Exploitation | #21–24 | `metasploit_console`, `kali_shell` |
| Denial of Service | #25–27 | `kali_shell` (slowhttptest, hping3), `execute_code` |
| Phishing & Payloads | #28–29 | `kali_shell` (msfvenom), `metasploit_console` |
| Full Kill Chain | #30 | ALL |
| Advanced & Bonus | #31–40 | Mixed |
| AltoroJ-Specific | #41–50 | Mixed |

> 💡 = Enable Deep Think in agent settings before running
