
# using firewall logs

```mermaid
flowchart TD
    A[Internal host talks to external IP] --> B{What pattern?}

    B --> C[Suspicious traffic]
    C --> C1[Check dest IP reputation<br/>VirusTotal / X-Force]
    C1 --> C2[Suspicious port?<br/>4444 Meterpreter, 6660-7000 IRC]
    C2 --> C3[Beaconing - fixed interval requests]

    B --> D[DNS tunneling]
    D --> D1[External DNS instead of internal]
    D1 --> D2[High # of DNS requests/host]
    D2 --> D3[High DNS byte volume/day]
    D3 --> D4[Unexpected resolver geolocation]

    B --> E[Data exfiltration]
    E --> E1[High connections/day to same dest]
    E1 --> E2[Sent bytes >> Received bytes]
    E2 --> E3[Dest = cloud storage category<br/>e.g. MEGA, Dropbox]
```




# using web proxy 

#### The mental model

When you receive:

```
Internal Host → Suspicious External Domain/IP
```

don't immediately conclude **C2**.

Build the story through:

```
Domain Reputation
        ↓
Target Domain Characteristics
        ↓
Requested Resource
        ↓
Referrer
        ↓
User-Agent
        ↓
Destination Port
        ↓
Bytes + HTTP Method + Content-Type
        ↓
C2 Communication Pattern
        ↓
Correlate Findings
        ↓
Verdict
```

The chapter explicitly divides the investigation into these areas.

---

#### Q1 — What is the domain reputation and category?

> - **Unknown ≠ malicious.**
> - **Reputation is a starting point, not the final verdict.**

Also check the proxy's own domain categorization.


```mermaid 
flowchart TD
    A["Q1: What is the domain reputation & category?"]
    
    A --> B["Extract Domain from Proxy Log"]
    B --> C["Check:
    • Reputation / Threat Intel
    • Proxy Category
    • Known or Unknown
    • Domain Age"]

    C --> D{"Result?"}

    D -->|Legitimate / Known| E["Known Legitimate Domain
    • Clean reputation
    • Normal website"]
    E --> F["Hypothesis:
    Likely False Positive
    → Consider Detection Tuning"]

    D -->|Unknown / Newly Created| G["Unknown / New Domain"]
    G --> H["H1: Attacker-created
    domain for campaign"]
    G --> I["H2: Legitimate
    newly created business"]
    H --> J["More Investigation Required"]
    I --> J

    D -->|Known Malicious / C2| K["Known Malicious Domain
    / Known C2"]
    K --> L["Hypothesis:
    Internal Host may be Compromised
    → Communicating with Attacker"]


```



---

#### Q2 — What did we find when investigating the requested web resource?

```mermaid
flowchart TD
    A["Q2: What did we find when investigating the requested web resource?"]
    
    A --> B["Extract URL from Proxy Log"]
    B --> C["Analyze URL in Sandbox"]
    C --> D{"What happened?"}

    D -->|Normal Page| E["Normal Website
    • No malicious behavior"]
    E --> F["Hypothesis:
    Legitimate Browsing
    / Software Retrieval"]

    D -->|404 / Inaccessible| G["Resource Not Accessible"]
    G --> H["Possible:
    • API / Background Communication
    • Tracking
    • C2 Endpoint
    • Header-dependent Response"]
    H --> I["Continue Investigation
    → Other Communication Attributes"]

    D -->|Executable Downloaded
    + Malicious Behavior| J["Malicious Activity Observed"]
    J --> K["Possible:
    • Compromised Host
    • User clicked Phishing Link
    • Compromised Website Redirect"]
    K --> L["Next:
    Investigate Referrer URL
    + User-Agent"]
```




---

#### Q3 — Is there a referrer URL?

The purpose is:

> **How did the system reach the suspicious URL?**

##### Q4 — Did the source machine actually visit the referrer?

This is a **correlation check**.

Search the SIEM/proxy logs for:

> The suspected referrer URL as a **real requested URL** from the same source machine **before** the suspicious request.

##### Q5 — What is the referrer URL's behavior?

Run the suspected referrer in a sandbox and simulate normal browsing.


```mermaid
flowchart TD
    A["Q3: Is there a Referrer URL?"]

    A --> B{"Referrer?"}

    B -->|Yes| C["Referrer Found"]
    C --> D["Example: Search Engine / Website"]
    D --> E["Hypothesis:
    Could be Normal Browsing
    ⚠ Referrer may be Faked"]

    B -->|No| F["No Referrer"]
    F --> G["Possible:
    • Application Traffic
    • Executable Traffic
    • Malware C2"]
    G --> H["⚠ Not Automatically Malicious"]

    C --> I["Q4: Did the Source Machine
    Actually Visit the Referrer?"]
    F --> I

    I --> J{"Direct Request
Before Suspicious URL?"}

    J -->|Yes| K["Real Referrer Confirmed"]
    K --> L["Hypothesis:
    More Consistent with
    Normal Browsing"]

    J -->|No| M["No Direct Request Found"]
    M --> N["Hypothesis:
    Referrer May Be
    Hardcoded / Fake"]
    N --> O["Suspicion ↑"]

    L --> P["Q5: What is the Referrer
    URL's Behavior?"]
    O --> P

    P --> Q["Analyze Referrer
    in Sandbox + Simulate Browsing"]

    Q --> R{"Behavior?"}

    R -->|Normal Redirect / Content| S["Ads / Tracking / Forms
    / Normal Website Behavior"]
    S --> T["Hypothesis:
    Likely Benign"]

    R -->|Redirect → Executable
    → Malicious Execution| U["Malicious Behavior"]
    U --> V["Possible:
    • Compromised Referrer Website
    • Attacker Redirect
    • Malware Delivery"]
    V --> W["Suspicion ↑↑
    Continue Investigation"]
```

---

#### Q6 — What is the User-Agent?

Goal:

> Determine **what initiated the communication**.

```mermaid
flowchart TD
    A["Q6: What is the User-Agent?"]
    
    A --> B["Extract User-Agent
    from Proxy Log"]
    
    B --> C{"What does it look like?"}

    C -->|Browser UA| D["Chrome / Firefox / Edge"]
    D --> E["Hypothesis:
    May be Normal Browsing"]
    E --> F["⚠ Malware can
    Fake Browser UA"]

    C -->|Empty UA| G["No User-Agent"]
    G --> H["Possible:
    • Application
    • Executable
    • Updater
    • Malware"]
    H --> I["⚠ Interesting,
    but NOT proof of malware"]

    C -->|PowerShell UA| J["PowerShell-generated
    HTTP Request"]
    J --> K["Possible:
    • PowerShell C2
    • Stage-2 Download
    • Attacker Activity"]
    K --> L["Suspicion ↑"]

    C -->|Random / Changing UA| M["Random UA
    per Request"]
    M --> N["Possible Malware
    trying to evade
    IOC-based detection"]
    N --> O["Suspicion ↑"]

    D --> P["Compare with
    Normal UAs of Same Host"]
    G --> P
    J --> P
    M --> P

    P --> Q{"Is Suspicious UA
    Unique / Abnormal?"}

    Q -->|No| R["More Consistent
    with Normal Activity"]
    Q -->|Yes| S["Suspicion ↑
    Investigate Source Process
    + Other Telemetry"]
```



---


#### Q7 — What is the destination port?

```mermaid
flowchart TD
    A["Q7: What is the Destination Port?"]
    
    A --> B["Extract Destination Port
    from Proxy Log"]
    
    B --> C{"What Port?"}
    
    C -->|80 / 443| D["Legitimate Web Port"]
    D --> E["⚠ Do NOT assume benign"]
    E --> F["C2 can use
    legitimate web ports
    to evade detection"]
    
    C -->|Non-Standard Port| G["Unusual Port"]
    G --> H["Investigate Port Reputation
    / Known Service / Framework"]
    
    H --> I{"Associated with
    Known Tool / C2?"}
    
    I -->|Yes| J["Suspicion ↑
    Possible C2 / Attacker Activity"]
    I -->|No| K["Port Alone
    Is Not Conclusive
    → Continue Investigation"]
    
    F --> L["Correlate with:
    Domain + UA + URL + Traffic Pattern"]
    J --> L
    K --> L
```



---

#### Q8 — What are the bytes, HTTP method, and Content-Type telling us?

This is where you start asking:

> **What is actually happening over the communication?**



The chapter also uses byte direction to reason about:

```
Sent high
→ possible upload / exfiltration

Received high
→ possible download / tools / malware
```

### Content-Type

Useful for understanding **what kind of content is moving**:

```
text/csv
application/msword
application/gzip
application/octet-stream
```

```mermaid 
flowchart TD
    A["Q8: What are the Bytes, HTTP Method & Content-Type telling us?"]

    A --> B["Check:
    • Sent Bytes
    • Received Bytes
    • HTTP Method
    • Content-Type"]

    B --> C{"Traffic Pattern?"}

    C -->|"Received > Sent
    Mostly GET"| D["Likely Normal Browsing
    / Content Retrieval"]

    C -->|"Sent > Received
    POST / CONNECT
    Little or No GET"| E["Suspicious Communication"]
    E --> F["Possible:
    • C2
    • Data Transfer"]

    C -->|"High Sent Bytes"| G["Possible Upload
    / Exfiltration"]

    C -->|"High Received Bytes"| H["Possible Download
    / Tools / Malware"]

    G --> I["Check Content-Type"]
    H --> I
    E --> I

    I --> J{"What is being transferred?"}

    J -->|"Document / Data"| K["Possible Data Transfer"]
    J -->|"Executable / Archive"| L["Possible Malware
    / Tool Download"]

    D --> M["Correlate with
    Domain + UA + Referrer + Timeline"]
    K --> M
    L --> M
```



---



#### Q8 — What if the byte pattern changes over time?

This is especially important.

The chapter gives a behavioral narrative:

```
Initial small communications
        ↓
Small data collection/exfiltration
        ↓
Download additional tools
        ↓
Actual data exfiltration
```

This is an example of reconstructing **attacker activity from communication patterns**, rather than relying on one log.

---

#### 10. C2 Techniques to Look For
```mermaid
flowchart TD
    A["C2 Techniques to Look For"]

    A --> B["A. Malware Beaconing"]
    A --> C["B. Fast Flux"]

    %% Beaconing
    B --> D["Same Source Host"]
    D --> E["Same Destination"]
    E --> F["Repeated Communications"]
    F --> G["Regular Time Intervals"]
    G --> H["Example:
    10:00 → 11:00 → 12:00
    → 13:00 → 14:00"]
    H --> I["Hypothesis:
    Possible Malware Heartbeat
    / C2 Beaconing"]

    %% Fast Flux
    C --> J["Same Domain"]
    J --> K["Many Changing IP Addresses"]
    K --> L["Very Short DNS TTL"]
    L --> M["IP Mapping Changes
    Frequently"]
    M --> N["Hypothesis:
    Possible Fast Flux
    C2 Infrastructure"]

    I --> O["Correlate with
    Other Proxy / DNS Evidence"]
    N --> O
```




#### The Entire Investigation as a SOC Analyst

I'd reduce the whole chapter to this:

```
Suspicious Outbound Communication
            ↓
     WHO is the source?
            ↓
   WHAT domain/IP was contacted?
            ↓
     Reputation / Category
            ↓
     Is the domain suspicious?
            ↓
       What URL/resource?
            ↓
     What happened there?
            ↓
       Referrer?
            ↓
  Did the host really visit it?
            ↓
      User-Agent?
            ↓
What process/application may have generated it?
            ↓
      Destination Port?
            ↓
     Bytes / Methods / Content-Type
            ↓
      What was transferred?
            ↓
   Is there a communication pattern?
            ↓
      Beaconing / Fast Flux?
            ↓
         CORRELATE
            ↓
      SCOPE THE HOST
            ↓
         VERDICT
```

---

####  Detection: What Makes C2 More Convincing?

**No single indicator is enough.**

The strongest investigation happens when several independent observations line up:

```
Rare / suspicious domain
+
Unusual domain age
+
Suspicious URL
+
No genuine browsing/referrer history
+
Non-browser / PowerShell User-Agent
+
Repeated periodic communication
+
POST / CONNECT pattern
+
Outbound bytes > expected
+
Additional malware/tool download
```

The chapter's final message is explicitly to **correlate the findings from all these stages to determine the final classification**.

```mermaid
flowchart LR
    A["Suspicious Outbound Traffic"]

    A --> B["Suspicious Domain"]
    A --> C["Suspicious URL"]
    A --> D["Abnormal User-Agent"]
    A --> E["Periodic Communication"]
    A --> F["Unusual HTTP / Byte Pattern"]
    A --> G["Malware / Tool Download"]

    B --> H["Multiple Indicators"]
    C --> H
    D --> H
    E --> H
    F --> H
    G --> H

    H --> I["C2 Becomes More Convincing"]
```


---



### Response 

1. **Determine severity**: 
	- did the connection succeed or get blocked (action/status)? 
	- How many bytes moved, and in which direction?
2. **Containment**: 
	- isolate the src host, and block on the proxy/DNS by **Domain/FQDN, not just IP** 
	  (especially with Fast Flux and DDNS), plus the URL and the UA if it's unique.
3. **Scope**: 
	- search proxy/DNS logs for the same 
		- domain/IP/URL/UA/beaconing pattern from any other src.
4. **Endpoint**: 
	- the proxy won't tell you which process sent the traffic. 
	- Pull the responsible process from EDR, 
	- plus the persistence (like the ASEP registry keys seen in the sandbox), and 
	- preserve evidence (memory/disk) before any rebuild.
5. **Data loss**: 
	- use the byte phases from Q8 to determine what leaked (timing, volume, type), and confirm from the endpoint.
6. **Credentials**: 
	- review the `username` in the logs, and 
	- reset the account if the machine was under attacker control.
7. **Eradication + Tuning**: 
	- rebuild/cleanup, 
	- add the IOCs, and 
	- build Detection Use Cases (DDNS list, UA mismatch, beaconing, sent>received). 
	- If it was an FP, exclude the domain precisely.


```mermaid
flowchart TD
    A["Suspicious Outbound Communication"]
    
    A --> B["Validate"]
    B --> C["Identify Source Host"]
    C --> D["Determine What Generated Traffic"]
    D --> E["Determine What Was Sent / Received"]
    E --> F["Correlate Activity"]
    F --> G["Determine Scope"]
    G --> H["Escalate / Continue IR"]

    A --> I{"Benign?"}
    I -->|Yes| J["Document Finding
    + Tune Detection if Needed"]
    I -->|No / Suspicious| B
```



#### Investigation Mindset (Combinations)

A single field rarely tells you anything. The **combination** is what reveals the attack:

| Scenario                    | Signals together                                                                                              |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Malware / tool download** | GET + high sc-bytes + executable Content-Type + <br>status 2xx + action allowed                               |
| **Exfiltration**            | POST/PUT + high cs-bytes + external or cloud-storage destination                                              |
| **C2**                      | No Referer + odd/non-browser User-Agent + <br>new or DGA domain + unusual port                                |
| **Phishing**                | URL with a typo/unusual extension + 3xx chain + <br>login page. From the logs you can identify who visited it |
| **Stolen credentials**      | username doesn't match the machine's owner                                                                    |
| **Insider**                 | Many requests to restricted resources, hacking-tool downloads, bypass attempts                                |



# Investigating WAF Logs

**WHO?**
- Source IP / Geo
**WHAT?**
- URL / Request / Violation Type / Matched Signature
**WHERE?**
- Destination IP / Target Application
**HOW?**
- HTTP Method / User-Agent / Request Pattern
**WHAT HAPPENED AFTER?**
- Allowed? Blocked? Web Shell? Exfiltration? Internal connection?

```mermaid
flowchart TD
    A["Suspicious WAF Request"]
    A --> B["Source IP + Geo"]
    B --> C["Target Application / Destination IP"]
    C --> D["Inspect URL / Request"]
    D --> E["Violation Type + Matched Signature"]
    E --> F["HTTP Method + User-Agent"]
    F --> G["WAF Action: Allowed or Blocked"]

    G --> H{"Any Suspicious Behavior?"}

    H -->|No| I["Likely Benign / False Positive"]
    H -->|Yes| J["Correlate + Scope"]

    J --> K["Check:
    • Repeated exploitation
    • Web shell access
    • Excessive requests
    • Data transfer
    • Internal callbacks"]
```


