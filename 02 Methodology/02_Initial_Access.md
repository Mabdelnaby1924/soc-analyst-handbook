## Brute Force 

![[brute_forcing.png]]


## Phishing Attacks
![[ChatGPT Image Sep 10, 2026, 05_16_53 AM.png]]


## Unauthorized VPN / RDP Access

> **Was this remote access legitimate for this account, source, time, and behavior?**

```mermaid
flowchart TD
    A["Suspicious VPN / RDP Access"]

    A --> B["Login Failures"]
    B --> C["Successful Authentication"]
    C --> D["Source IP + Geolocation"]
    D --> E["Time / Location Consistency"]
    E --> F["Post-Login Activity"]
    F --> G["Data Transfer"]

    G --> H{"Suspicious?"}

    H -->|No| I["Likely Legitimate"]
    H -->|Yes| J["Possible Unauthorized Access"]
    J --> K["Scope + Escalate"]
```

### Investigate:
```
1. Multiple failed logins?
2. Successful login after failures?
3. Unexpected country/location?
4. Same account authenticated from two locations quickly?
5. Was large data transferred after VPN/RDP access?
6. What happened after login?
```

```
Failed Logins
     ↓
Successful Login
     ↓
Unusual Geo / Source
     ↓
Large Data Transfer
```



## Compromised Mailboxes

> **Is the mailbox being used by its legitimate owner?**

```mermaid
flowchart TD
    A["Suspicious Mailbox Activity"]

    A --> B["Login Failures"]
    B --> C["Successful Access"]
    C --> D["Source IP + Geo"]
    D --> E["Mailbox Activity"]
    
    E --> F["Sent Emails"]
    E --> G["Mail Rules / Forwarding"]
    
    F --> H["Who received them?"]
    F --> I["Suspicious Subject / Content?"]
    F --> J["Large External Emails?"]

    G --> K["Unexpected Rule / Forwarding?"]

    H --> L["Scope"]
    I --> L
    J --> L
    K --> L

    L --> M["Possible Compromised Mailbox"]
```

#### Mental shortcut
> **Authenticate → Geo → Mailbox Behavior → Scope**



## Suspicious Authentication to Web Services

```mermaid
flowchart TD
    A["Suspicious Web Service Authentication"]

    A --> B["Login Failures"]
    B --> C["Successful Login"]
    C --> D["Source IP + Geo"]
    D --> E["User-Agent"]
    E --> F["Post-Login Activity"]

    F --> G["Excessive Browsing?"]
    F --> H["Unusual Actions?"]

    G --> I["Scope + Context"]
    H --> I

    I --> J["Check:
    VPN Usage?
    Shared Account?
    Expected Location?"]

    J --> K["Verdict"]
```


1. Are there multiple login failures?
2. Is the successful login from an unexpected geo?
3. Are there two locations in a short timeframe?
4. Did the user-agent change?
5. Is there excessive browsing/activity after login?
6. Could the customer be using a VPN?
7. Is the account legitimately shared?


# The Common Methodology

```mermaid
flowchart TD
    A["Suspicious External Activity"]
    A --> B["Authentication / Request"]
    B --> C["Source"]
    C --> D["Time / Geo"]
    D --> E["Behavior"]
    E --> F["Context"]
    F --> G["Correlation"]
    G --> H["Scope"]
    H --> I["Verdict"]
    I --> J["Escalate / Respond"]
```

#### WAF
```
Source → Request → WAF Decision → Behavior → Scope
```
#### VPN / RDP
```
Authentication → Source/Geo → Timing → Post-login Behavior → Scope
```
#### Mailbox
```
Authentication → Geo → Mail Activity → Rules/Recipients → Scope
```
#### Web Services
```
Authentication → Geo → User-Agent → Activity → Context → Scope
```

> **WHO accessed?**  
> **FROM WHERE?**  
> **WHEN?**  
> **WHAT did they access/do?**  
> **Was it normal for this account/source?**  
> **What happened after access?**  
> **Did the same behavior happen elsewhere?**

