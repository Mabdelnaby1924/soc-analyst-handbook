

# The Common Investigation Pattern

```mermaid
flowchart LR
    A["Alert / Flow"]
    A --> B["Identify Entities"]
    B --> C["Understand Behavior"]
    C --> D["Check Time + Context"]
    D --> E["Correlate with Other Telemetry"]
    E --> F["Was Activity Allowed or Blocked?"]
    F --> G["Check Execution / Follow-on Activity"]
    G --> H["Scope"]
    H --> I["Verdict"]
    I --> J["Escalate / Respond"]
```
### NetFlow
> **Who talked to whom, when, over what port, and how much?**
### IDS/IPS
> **What triggered the rule, was it blocked, and did the attack succeed anyway?**
### AV
> **What file was detected, where is it, what is it, and did it execute/spread?**
### EDR
> **What process did what, who spawned it, and what happened next?**
### Sandbox
> **What was downloaded/transferred, and what happened after that?**



## Network Flows / NetFlow

**Investigate the NetFlow to detect:** 
- Blacklisted IP communication
- Suspicious ports
- High byte transfer
- Outbound communication at unusual times

### Investigation mindset

```mermaid
flowchart TD
    A["Suspicious Network Flow"]
    A --> B["Source IP"]
    B --> C["Destination IP / Port"]
    C --> D["Time"]
    D --> E["Bytes"]
    E --> F{"Suspicious Pattern?"}

    F -->|No| G["Likely Normal"]
    F -->|Yes| H["Correlate"]
    H --> I["Check:
    • DNS
    • Firewall / Proxy
    • EDR
    • Authentication"]
    I --> J["Scope → Verdict"]
```



## IDS / IPS Alerts

> **Don't trust the alert alone; investigate the packet/rule and what happened after it.**

```mermaid
flowchart TD
    A["IDS / IPS Alert"]
    A --> B["Severity + Source"]
    B --> C["Rule / Signature + Packet"]
    C --> D["Blocked or Allowed?"]

    D -->|Blocked| E["Attack Attempt"]
    D -->|Allowed| F["Investigate for Successful Exploitation"]

    E --> G["Check Repetition / Scope"]
    F --> G

    G --> H["If Internal → Internal"]
    H --> I["Check Lateral Movement"]

    G --> J["If File Transfer / Download"]
    J --> K["Check File Creation + Execution"]
```


## AV Alerts

> **Is the detected file actually malicious?**

**AV Containing:** 
- Host
- Filename
- Path
- Hash
- Malware Name
- Category

```
Malware on critical/high-value host
Hacking tool on non-admin workstation
Malware in TEMP / user profile
Malware in remote share
Legitimate Windows name in abnormal path
Same malware on many hosts
Ransomware / InfoStealer / RAT / Web Shell
```

```mermaid
flowchart TD
    A["AV Alert"]
    A --> B["Host + File + Path + Hash"]
    B --> C["Hash Reputation"]
    C --> D{"Context?"}

    D -->|Normal Context| E["Validate / Possible False Positive"]
    D -->|Suspicious Context| F["Investigate Further"]

    F --> G["Check:
    • Execution
    • Process
    • Network
    • Persistence
    • Other Hosts"]

    G --> H["Scope → Verdict → Escalate"]
```

## EDR

#### Office → Suspicious Process
### Investigation
```
Which Office document?
What command line?
What child process?
What did the child process do?
Did it download anything?
Did it create persistence?
Did it communicate externally?
```

```mermaid
flowchart TD
    A["Office → Suspicious Child Process"]
    A --> B["Identify Document"]
    B --> C["Command Line"]
    C --> D["Child Processes"]
    D --> E["What did it do?"]

    E --> F["Download?"]
    E --> G["Persistence?"]
    E --> H["Network?"]
    E --> I["Additional Execution?"]

    F --> J["Correlate + Scope"]
    G --> J
    H --> J
    I --> J
```



#### Suspicious LSASS Access
> **Who accessed LSASS, and is that source process trustworthy?**

check: 
```
Source process hash
Digital signature
Process path
PowerShell command/script
```

```mermaid
flowchart TD
    A["Suspicious Process → LSASS"]
    A --> B["Identify Source Process"]
    B --> C["Hash Reputation"]
    C --> D["Digital Signature"]
    D --> E["Process Path"]
    E --> F["Command Line / PowerShell"]
    F --> G{"Credential Dumping Evidence?"}

    G -->|No| H["Continue Context Investigation"]
    G -->|Yes| I["High Suspicion
    → Credential Theft"]

    I --> J["Scope + Escalate"]
```



## Network Sandbox / Network AV
#### A. External download
```mathematica
External Server
      ↓
Internal Host
      ↓
Malicious File
```

- attacker stage-two download
- user tricked by phishing
- compromised website redirect


> **Was the file actually downloaded and executed?**

#### B. Internal file transfer
```mathematica
Host A
  ↓ SMB
Host B
```

```mermaid
flowchart TD
    A["Sandbox / Network AV Alert"]
    A --> B{"What happened?"}

    B -->|External Malware Download| C["Check:
    • Allowed Connection
    • File Created
    • File Executed
    • Process Activity"]

    B -->|Malicious File Internal Transfer| D["Check:
    • Source Host
    • Destination Host
    • SMB Activity
    • Execution on Target"]

    C --> E["Correlate + Scope"]
    D --> E
    E --> F["Verdict → Escalate / Respond"]
```



## Response / IR Mindset

```mathematica 
Validate
   ↓
Identify affected host/user
   ↓
Determine successful compromise
   ↓
Scope
   ↓
Preserve relevant evidence
   ↓
Escalate / Contain according to IR procedure
```

```mathematica 
IPS Blocked
→ Attempt

IPS Alert + Allowed Traffic
→ Investigate Success

AV Detection
→ Determine execution / spread

EDR Alert
→ Reconstruct process behavior

Network Download
→ Check file creation + execution
```

