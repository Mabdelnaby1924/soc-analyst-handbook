# Device Attributes Reference

---

## 1. Firewall

**Position:** 
sits between security zones: 
- **LAN** (internal), 
- **DMZ** (public-facing apps: mail, web), 
- **WAN** (internet/untrusted). 
Visibility = whatever crosses a zone boundary.

| Field                               | What it tells you                        | Investigation use                                                                                     |
| ----------------------------------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Log Timestamp**                   | When                                     | First question in any investigation; basis for cross-log correlation                                  |
| **Source IP**                       | Who initiated                            | Identify infected/attacking host for containment                                                      |
| **Source Port**                     | Origin port (usually random, 1024–65535) | A **fixed** source port across many requests is a scanning-tool signature (e.g., NMAP)                |
| **Destination IP**                  | Target                                   | Reputation check (AbuseIPDB/X-Force/VirusTotal); IOC to scope other infected hosts talking to same IP |
| **Destination Port**                | Requested service                        | Reveals attacker intent — see port table below                                                        |
| **Source Interface Zone**           | Zone of origin: LAN / DMZ / WAN          | Flag zone-crossing anomalies (e.g., DMZ host initiating outbound to WAN)                              |
| **Destination Interface Zone**      | Zone of target: LAN / DMZ / WAN          | Flag abnormal zone paths (e.g., DMZ → LAN RDP)                                                        |
| **Device Action**                   | Allowed / Denied                         | Did the attempt succeed? Also: many Denies from one host in short time = scanning use case            |
| **Sent Bytes**                      | Src → Dst volume                         | Lateral movement: size of pushed binary. Exfil: size of stolen data                                   |
| **Received Bytes**                  | Dst → Src volume                         | Malware/tool download size                                                                            |
| **Sent Packets**                    | Count, src→dst                           | Volume spikes to external systems                                                                     |
| **Received Packets**                | Count, dst→src                           | Volume spikes from external/internal systems                                                          |
| **Source Geolocation Country**      | Origin country (vendor-dependent)        | Unexpected-geolocation detection                                                                      |
| **Destination Geolocation Country** | Target country (vendor-dependent)        | Unexpected-geolocation detection                                                                      |

### Ports commonly targeted for lateral movement

|Port|Protocol|
|---|---|
|445|SMB (file sharing)|
|3389|RDP (remote desktop)|
|5985, 5986|WinRM (PowerShell Remoting)|
|22|SSH|
|23|Telnet|
|20, 21|FTP|
|5900, 5800|VNC|

### Analyst heuristics

- **The Allow buried in a flood of Deny/Drop is the event that matters** — that's the successful pivot/access.
- **Sent >> Received** = pushing tools/exfil out. **Received >> Sent** = pulling tools/malware in.
- Zone fields let you catch traffic that technically has valid IPs but takes an **illogical path** (DMZ initiating to WAN, WAN reaching LAN directly).
- Firewall logs tell you **what crossed**, never **what executed** — every finding needs endpoint confirmation (Event IDs / EDR / Sysmon).

---

## 2. Web Proxy

**Position:** 
- sits between internal clients and the web; proxies the request on the client's behalf. 
Adds visibility the firewall doesn't have: domain, URL, category, user identity, user agent.

**Prefix key:** 
- `cs` = client→server, 
- `sc` = server→client, 
- `src`/`dst` = source/destination.

| Field                        | What it tells you                                           | Investigation use                                                                                                                                     |
| ---------------------------- | ----------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| **src / srcport**            | Client IP/port                                              | Identify host; srcport sequence helps build a timeline                                                                                                |
| **username**                 | Authenticated account (via proxy auth, not the HTTP packet) | Mismatch between machine owner and username = possible stolen credentials                                                                             |
| **devicetime**               | When                                                        | Correlation anchor                                                                                                                                    |
| **dst**                      | Server IP                                                   | Reputation, IOC scoping                                                                                                                               |
| **dstport**                  | Requested service                                           | Non-standard ports (4444 = Meterpreter default) are a red flag; most attackers still use 80/443                                                       |
| **s-action** (device action) | ALLOWED / DENIED / FAILED / SERVER_ERROR                    | Did the request succeed?                                                                                                                              |
| **sc-status**                | HTTP response code family (1xx–5xx)                         | 2xx success, **3xx = redirect chain** (phishing/malware relay), 4xx/5xx failure, 407 = proxy auth required                                            |
| **cs-method**                | GET / POST / HEAD / DELETE / CONNECT / OPTIONS              | GET = download, POST/PUT = upload/exfil, CONNECT = HTTPS tunnel (opaque to inspection)                                                                |
| **cs-uri-scheme**            | http / https                                                | —                                                                                                                                                     |
| **cs-host**                  | Domain requested                                            | Reputation, DGA pattern check, category                                                                                                               |
| **cs-uri-path / cs-uri**     | Full resource path                                          | Exact malware/tool/phishing page location                                                                                                             |
| **cs-uri-extension**         | File extension                                              | Combine with Content-Type to confirm file type                                                                                                        |
| **cs-auth-group**            | AD group of the user                                        | Context on privilege level                                                                                                                            |
| **sc-bytes**                 | Received (server→client)                                    | Large + GET + executable Content-Type = tool/malware download                                                                                         |
| **cs-bytes**                 | Sent (client→server)                                        | Large + POST/PUT = exfiltration                                                                                                                       |
| **rs(Content-Type)**         | MIME type of the response                                   | `text/csv` (leaked sheet), `application/octet-stream` (binary/exe), `application/msword`, `application/gzip`                                          |
| **cs(User-Agent)**           | The actual client software                                  | Non-browser (Python/PowerShell/CMD), empty, or random-per-request values need deep-dive                                                               |
| **cs(Referer)**              | How the user arrived                                        | Malware C2 normally has **no Referer** since a program, not a click, made the request                                                                 |
| **filter-category**          | Proxy's domain classification                               | Malicious/Phishing/Spam explicit hits; **Uncategorized/Unknown often = newly registered C2 domain**. Miscategorization happens — don't fully trust it |

### Analyst heuristics

- A single field rarely proves anything — **combinations** do:
    - **Malware/tool download**: GET + high sc-bytes + executable Content-Type + 2xx + allowed
    - **Exfiltration**: POST/PUT + high cs-bytes + external or cloud-storage destination
    - **C2**: no Referer + non-browser/odd User-Agent + new or DGA-looking domain + unusual port
    - **Phishing**: 3xx redirect chain into a login-style page; logs show exactly who visited
- **URL may be missing** if SSL interception isn't enabled or the client used `CONNECT` — you're then limited to `cs-host` + bytes + timing.
- User-Agent and Referer **can both be spoofed/hardcoded** by malware — verify by comparing against the host's other traffic or checking installed browsers via EDR.
- `application/octet-stream` means "generic binary," not automatically `.exe` — confirm with extension + hash.

---

## 3. WAF (Web Application Firewall)

**Position:** 
- in front of a web application (often reverse-proxy style), inspecting HTTP(S) requests against the app itself — layer 7, application-aware, unlike a network firewall.

|Field|What it tells you|Investigation use|
|---|---|---|
|**Timestamp**|When|Correlation anchor|
|**Client IP (+ X-Forwarded-For)**|True origin, even behind CDN/load balancer|Attribution; watch for spoofed/forged XFF headers|
|**Request Method**|GET/POST/PUT/DELETE...|POST-heavy against login/upload endpoints = brute-force or injection attempts|
|**URI / Endpoint**|Exact path targeted|Reveals recon (`/admin`, `/.env`, `/wp-login.php`) or exploitation target|
|**Query string / Request body**|Payload content|Where the actual attack string lives (SQLi, XSS, path traversal, command injection)|
|**Rule ID / Signature matched**|Which WAF rule fired|Maps directly to attack category (OWASP Top 10 class)|
|**Action taken**|Blocked / Allowed / Logged-only (detection mode)|Did the payload actually reach the app?|
|**Response status code**|App's response|200 after a malicious payload = potential successful exploitation, not just an attempt|
|**User-Agent**|Client software|Scanners (sqlmap, nikto, dirbuster) often leave a distinctive UA unless evaded|
|**Host header**|Target vhost/domain|Confirms which app was targeted on a shared WAF|
|**Bot/Reputation score**|Vendor threat-intel scoring|Prioritization signal, not proof|
|**Session/Cookie ID**|Ties requests together|Build a single attacker session's full request sequence|

### Analyst heuristics

- **Blocked ≠ safe.** A blocked payload still tells you the attacker is probing; check for the same source trying variations (WAF bypass attempts — encoding, case-mixing, comment-injection).
- **A burst of 4xx from one IP across many different endpoints** = directory/endpoint enumeration (recon), not exploitation yet.
- **One endpoint hit repeatedly with slightly mutated payloads** = active exploitation attempt (fuzzing a specific vuln).
- If in **detection-only mode**, "logged" traffic still reached the backend — treat it as if it succeeded until the app/DB logs say otherwise.
- WAF logs alone can't confirm impact — pair with **application/DB logs** to know if the payload actually executed.

---

## 4. IDS / IPS

**Position:** 
- IDS = out-of-band, sees a copy of traffic, alerts only. 
- IPS = inline, can block. 
Both work off signatures/rules (Snort/Suricata-style) and/or anomaly detection.

|Field|What it tells you|Investigation use|
|---|---|---|
|**Timestamp**|When|Correlation anchor|
|**Signature ID / Rule name**|Which detection fired|Maps to a known technique/CVE/tool; look it up before triaging|
|**Classification / Severity**|Vendor's own risk rating|Triage priority — but re-validate, defaults are often noisy|
|**Source IP / Port, Destination IP / Port**|Communication pair|Same as firewall — who talked to whom|
|**Protocol**|TCP/UDP/ICMP/etc.|Context for the signature|
|**Packet payload / matched pattern**|The actual bytes that tripped the rule|Ground truth — confirms it's not a false positive|
|**Action**|Alert-only (IDS) / Dropped-Blocked (IPS)|Did it actually stop the traffic?|
|**Flow/session ID**|Groups related packets|Reconstruct the full exchange, not just one packet|
|**MITRE ATT&CK mapping** (if the ruleset provides it)|Technique tied to the alert|Direct pivot into TTP-based hunting|

### Analyst heuristics

- **A signature hit is a hypothesis, not a verdict** — always pull the matched payload/packet and read it yourself before acting.
- **One alert = maybe noise. The same signature repeatedly from one host, or the same host tripping multiple different signatures in sequence, = a real chain worth full investigation.**
- Signature-based detection **misses anything novel** — a clean IDS/IPS feed doesn't mean a clean network; correlate with proxy/firewall/EDR regardless.
- For IPS in blocking mode: confirm the block actually happened (action field) — some deployments run key rulesets in alert-only for performance, silently turning your "IPS" into an IDS for those rules.
- Full packet capture (if available) attached to the alert is worth more than the alert text itself.

---

## 5. AV (Antivirus)

**Position:** 
- host-based, signature/heuristic/behavioral scanning of files and (in modern suites) some process activity. 
Narrower scope than EDR — mainly file-centric.

|Field|What it tells you|Investigation use|
|---|---|---|
|**Timestamp**|When detected|Correlation anchor|
|**Hostname / Endpoint ID**|Which machine|Identify affected host|
|**Detection name / Signature**|What the AV thinks it is (e.g., `Trojan.GenericKD`, `Meterpreter.A`)|Search the name for public threat intel — generic names ("Generic", "Heur") mean low-confidence detection worth deeper look|
|**File path**|Where the malicious file sits/sat|Was it in Downloads/Temp (likely user-delivered) or a system path (likely dropped by another stage)?|
|**File hash (MD5/SHA1/SHA256)**|Unique identity of the file|Pivot into VirusTotal/threat intel; IOC to hunt across the fleet|
|**Action taken**|Quarantined / Deleted / Blocked / **Allowed (detected only)**|Critical — "detected but not remediated" leaves the file live|
|**User context**|Which account triggered the scan/execution|Correlate with logon activity|
|**Scan type**|Real-time vs. scheduled/full scan|Real-time catch = active attempt; scheduled-scan catch = file sat undetected until the next sweep|
|**Parent process** (if the AV logs it)|What launched the malicious file|Early pivot toward the delivery mechanism (browser, email client, script host)|

### Analyst heuristics

- **"Allowed" or "detected only" outcomes are the ones that need the most attention** — the threat wasn't actually removed.
- A single AV hit that was quarantined cleanly can still mean initial access happened — check what delivered the file (browser download, email attachment, USB, network share) even after a clean quarantine.
- **Repeated detections of the same family on the same host** = quarantine isn't fixing root cause (reinfection loop — check persistence, scheduled tasks, startup items).
- AV is the **weakest layer against custom/fileless/living-off-the-land attacks** — a clean AV console does not clear a host; that's exactly what EDR and the other logs are for.
- Don't stop at the AV alert — pull the file hash and check EDR/Sysmon for what that process did _before_ it got caught, not just the fact it got caught.

---

## 6. EDR (Endpoint Detection & Response)

**Position:** 
- host-based, continuous telemetry (process, file, registry, network, memory) plus behavioral detection and response actions (isolate, kill process, roll back). 
The deepest and broadest host visibility you'll have.

|Field|What it tells you|Investigation use|
|---|---|---|
|**Timestamp**|When|Correlation anchor — EDR timelines are usually your most granular source|
|**Hostname / Device ID**|Which machine|Scope|
|**Process name + PID**|What ran|The core unit of EDR investigation|
|**Parent process / Process tree (lineage)**|What launched what|**The single most valuable EDR field** — reveals the full execution chain (e.g., `winword.exe → cmd.exe → powershell.exe → rundll32.exe`)|
|**Command line arguments**|Exact command executed|Reveals intent directly — encoded/obfuscated PowerShell, LOLBins usage, download cradles|
|**File hash of the executable**|Identity|Threat intel pivot, IOC for fleet-wide hunt|
|**Network connections made by the process**|Where it talked|Ties directly back to firewall/proxy logs for the same process|
|**File system events** (created/modified/deleted)|Dropped files, ransomware activity, persistence artifacts|Confirms tool-drop or data-staging behavior|
|**Registry events**|Persistence (Run keys, services), config changes|ASEP (Auto-Start Extensibility Point) hunting|
|**Detection/Alert name + MITRE ATT&CK technique**|What behavior triggered it|Direct technique mapping for the playbook|
|**User/logon context**|Which account ran the process|Ties to AD/Windows logon events|
|**Response actions taken**|Isolated host / Killed process / Quarantined file|What containment already happened automatically vs. what you still need to do manually|

### Analyst heuristics

- **Always pull the full process tree, never just the flagged process** — the alert is usually a late step in the chain; the interesting part is what's above it (delivery) and below it (impact).
- **Command-line arguments are gold** — Base64-encoded PowerShell, `-nop -w hidden`, unusual LOLBins (`rundll32`, `regsvr32`, `mshta`, `certutil`) calling out to the internet are near-instant red flags.
- Cross-reference the process's **network connections** against Firewall/Proxy logs for the same timestamp — you get the "why" (proxy: what domain) and the "how much" (firewall: bytes) for the "what ran" (EDR).
- **A killed/isolated alert still needs full investigation** — automated response stopped this instance, not necessarily the root cause, persistence, or lateral spread that already happened before detection.
- EDR is your primary source for confirming what firewall/proxy/WAF/IDS could only infer — always close the loop back to the endpoint before writing a final verdict.

---

## Cross-device pivot cheat sheet

| **You have this...**                  | **...pivot to this to get...**                                                    |
| --------------------------------- | ----------------------------------------------------------------------------- |
| Suspicious IP from Firewall/Proxy | EDR: which process on which host talked to it                                 |
| Suspicious process from EDR       | Firewall/Proxy: full network activity of that process (domain, bytes, timing) |
| File hash from AV/EDR             | Threat intel (VirusTotal/X-Force) + fleet-wide EDR hunt for the same hash     |
| WAF rule hit on a web app         | App/DB logs to confirm actual impact, not just the attempt                    |
| IDS/IPS signature hit             | Full packet payload + EDR on the source/destination host for ground truth     |
| Any IOC (IP/domain/hash)          | Sweep across **all** device logs above, not just the one that first alerted   |
