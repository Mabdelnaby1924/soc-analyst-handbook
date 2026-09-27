# Active Directory Event IDs — SOC Investigation Reference

---

## How to Use This Reference

Event IDs are **telemetry signals**, not indicators of compromise. Their security significance depends entirely on **context**, **correlation**, **baseline comparison**, and **behavioral analysis**.

- A single Event ID does not prove an attack is occurring.
- Normal administrative operations generate the same Event IDs as attack activity.
- Investigation requires correlating multiple events across time, accounts, and systems.

---

## 1. Kerberos Authentication

> All Kerberos authentication events are logged on **Domain Controllers** in the **Security** log.  
> **Provider**: Microsoft-Windows-Security-Auditing  
> **Audit Policy**: Audit Kerberos Authentication Service / Audit Kerberos Service Ticket Operations  
> These audit subcategories must be enabled; they are not fully enabled by default in all configurations.

---

### Event ID 4768 — A Kerberos authentication ticket (TGT) was requested

**What It Represents:**  
The Authentication Service (AS) exchange — a client requests a Ticket Granting Ticket from the KDC. A successful 4768 means the user's credentials were validated and a TGT was issued.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | The account requesting the TGT |
| `Client Address` | Source IP of the authentication request |
| `Result Code` | `0x0` = success; non-zero = failure (see Kerberos error codes) |
| `Ticket Encryption Type` | `0x17` = RC4-HMAC; `0x12` = AES256; `0x11` = AES128 |
| `Certificate Information` | Present if smartcard/certificate authentication was used |
| `Pre-Authentication Type` | Method of pre-authentication (e.g., 2 = PA-ENC-TIMESTAMP, 15 = PA-PK-AS-REQ) |

**SOC Investigation Relevance:**
- Baseline event for Kerberos authentication — every domain logon begins here
- RC4 encryption type (`0x17`) is a flag for potential AS-REP Roasting or legacy compatibility issues
- Anomalous `Client Address` values (external IPs, unexpected subnets) warrant investigation
- TGT requests for disabled accounts or at unusual hours indicate possible credential misuse
- High volume of 4768 events with failures from a single source = potential brute-force over Kerberos

**Typical Investigation Questions:**
- Is this account expected to authenticate from this IP?
- Is the encryption type consistent with organizational policy (AES preferred over RC4)?
- Does the timing match normal user behavior?

**Related Event IDs:** 4769, 4771, 4770

---

### Event ID 4769 — A Kerberos service ticket was requested

**What It Represents:**  
The Ticket Granting Service (TGS) exchange — a client with a valid TGT requests a service ticket to access a specific service (identified by SPN).

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | The account requesting the service ticket |
| `Service Name` | The target Service Principal Name (SPN) |
| `Client Address` | Source IP |
| `Ticket Encryption Type` | Encryption algorithm requested |
| `Failure Code` | `0x0` = success |
| `Ticket Options` | Flags like renewable, forwardable, etc. |

**SOC Investigation Relevance:**
- **Kerberoasting detection**: Abnormal volume of service ticket requests, especially with RC4 encryption (`0x17`), from a single account to multiple SPNs is a classic Kerberoasting indicator
- A single account requesting tickets for services it doesn't normally access
- Service ticket requests for sensitive service accounts (SQL, Exchange, AD-related SPNs)
- Failure codes indicate authentication or authorization issues

**Typical Investigation Questions:**
- Is this user expected to access this service?
- Is the volume of TGS requests abnormal for this account?
- Was RC4 encryption specifically requested when AES should be available?

**Related Event IDs:** 4768, 4770, 4771

---

### Event ID 4770 — A Kerberos service ticket was renewed

**What It Represents:**  
A service ticket renewal. Typically occurs when a previously issued ticket is about to expire and the client renews it rather than requesting a new one.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | Account renewing the ticket |
| `Service Name` | Target SPN |
| `Client Address` | Source IP |
| `Ticket Encryption Type` | Encryption algorithm |

**SOC Investigation Relevance:**
- Generally low-priority in isolation
- Excessive renewals may indicate long-lived sessions or persistence mechanisms
- Correlate with 4769 to understand the full service ticket lifecycle

**Related Event IDs:** 4768, 4769

---

### Event ID 4771 — Kerberos pre-authentication failed

**What It Represents:**  
The KDC rejected the authentication request during the pre-authentication phase. The TGT was NOT issued.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | Account that failed authentication |
| `Client Address` | Source IP of the failed request |
| `Failure Code` | `0x18` = wrong password; `0x6` = unknown principal; `0x12` = policy restriction (hours/workstation); `0x17` = password expired; `0x25` = clock skew |
| `Pre-Authentication Type` | Authentication method attempted |

**SOC Investigation Relevance:**
- Kerberos-specific equivalent of a failed logon (complements Event ID 4625)
- High volume of `0x18` failures from a single source = brute-force or password spraying over Kerberos
- `0x6` failures may indicate account enumeration attempts
- `0x12` failures may indicate attempts to use an account outside allowed logon hours or workstations
- Correlate with 4768 success events to see if the attacker eventually succeeded

**Typical Investigation Questions:**
- What is the rate of failures vs. successes from this source IP?
- Is the targeted account a high-value account (admin, service account)?
- Does the failure code suggest credential guessing or policy issues?

**Related Event IDs:** 4768, 4769

---

### Event ID 4773 — A Kerberos service ticket request failed

**What It Represents:**  
A TGS request was rejected by the KDC. Less common than 4771 in practice.

**Key Fields:** Account Name, Service Name, Client Address, Failure Code

**SOC Investigation Relevance:**
- May indicate attempts to access services without proper authorization
- Correlate with 4769 for the success/failure ratio

> **Note**: This event is not logged on all Windows Server versions by default. Verify auditing configuration.

**Related Event IDs:** 4769

---

## 2. NTLM Authentication

> NTLM events are logged on the system that **validates** the credentials — the Domain Controller for domain accounts, the local machine for local accounts.  
> **Provider**: Microsoft-Windows-Security-Auditing  
> **Audit Policy**: Audit Credential Validation

---

### Event ID 4776 — The computer attempted to validate the credentials for an account

**What It Represents:**  
The NTLM authentication package (MICROSOFT_AUTHENTICATION_PACKAGE_V1_0) was used to validate credentials against the SAM database (local) or Active Directory (domain). Records both success and failure.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Authentication Package` | Always `MICROSOFT_AUTHENTICATION_PACKAGE_V1_0` (NTLM) |
| `Logon Account` | Account whose credentials were validated |
| `Source Workstation` | Machine that originated the authentication request |
| `Error Code` | `0x0` = success; `0xC000006A` = wrong password; `0xC0000064` = non-existent user; `0xC0000234` = locked out; `0xC0000072` = disabled; `0xC000006D` = bad username or authentication info |

**SOC Investigation Relevance:**
- NTLM usage in modern environments where Kerberos should be the default may indicate:
  - Fallback due to misconfiguration
  - NTLM relay attacks
  - Legacy application requirements
  - NTLM downgrade attacks
- On Domain Controllers, high volumes of 4776 events for a single account from various workstations = password spraying
- Correlate with 4624/4625 on endpoints for the complete authentication chain
- Track which workstations are still generating NTLM traffic for NTLM deprecation initiatives

**Typical Investigation Questions:**
- Why is NTLM being used instead of Kerberos?
- What is the source workstation — is it a known system?
- Is this a brute-force pattern (high failure rate against one or many accounts)?

**Distinction from Generic Logon Events:**  
Event ID 4776 is specifically an NTLM credential validation event. It is NOT a logon event — it represents the credential check itself. Event IDs 4624/4625 represent the logon/failure at the endpoint level, regardless of protocol.

**Related Event IDs:** 4624, 4625

---

### Event ID 4774 — An account was mapped for logon

**What It Represents:**  
During NTLM authentication, an account was successfully mapped by the authentication package.

**SOC Investigation Relevance:** Low-priority in most investigations. Useful for audit trail completeness.

---

### Event ID 4775 — An account could not be mapped for logon

**What It Represents:**  
The NTLM authentication package could not map an account during logon — typically due to a non-existent or mistyped account name.

**SOC Investigation Relevance:** May complement 4776 failure analysis for account enumeration detection.

---

### NTLM Auditing and Restriction Events

> The following events help organizations track and reduce NTLM usage. They are logged under specific Group Policy auditing settings.

| Event ID | Log | What It Records | Notes |
|---|---|---|---|
| **8001** | Microsoft-Windows-NTLM/Operational | NTLM authentication in domain — outgoing | Requires NTLM audit policy: `Network Security: Restrict NTLM: Audit NTLM authentication in this domain` |
| **8002** | Microsoft-Windows-NTLM/Operational | NTLM authentication in domain — incoming | Same audit policy as 8001 |
| **8003** | Microsoft-Windows-NTLM/Operational | NTLM authentication to this server | Requires: `Network Security: Restrict NTLM: Audit incoming NTLM traffic` |
| **8004** | Microsoft-Windows-NTLM/Operational | NTLM authentication blocked | Requires NTLM restriction policy to be in audit or block mode |

> **Prerequisite**: These events require specific NTLM auditing Group Policy settings to be enabled. They are NOT logged by default.

---

## 3. Active Directory / Directory Services

> Directory Service events are logged on **Domain Controllers**.  
> **Log**: Directory Service (DS Access category) or Security log  
> **Audit Policy**: Audit Directory Service Access / Audit Directory Service Changes  
> **Provider**: Microsoft-Windows-Security-Auditing

---

### Event ID 4662 — An operation was performed on an object

**What It Represents:**  
An operation was performed on an Active Directory object. This is a low-level audit event that records access to AD objects based on SACL configuration.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | Who performed the operation |
| `Object Type` (GUID) | The schema class of the accessed object |
| `Object Name` | Distinguished Name of the object |
| `Operation Type` | Object Access |
| `Accesses` | Specific access rights exercised (e.g., Write Property, Read Property) |
| `Properties` | GUIDs of specific attributes accessed |

**SOC Investigation Relevance:**
- Detect DCSync attacks: An attacker using Mimikatz DCSync will trigger 4662 with the `Replicating Directory Changes All` access right (GUID: `{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}`) from a non-DC account
- Detect unauthorized reads of sensitive AD attributes (e.g., `ms-Mcs-AdmPwd` for LAPS passwords)
- High noise — requires careful SACL configuration and filtering

**Prerequisite:** Requires Directory Service Access auditing AND appropriate SACLs on AD objects.

**Related Event IDs:** 5136, 5137, 5138, 5139, 5141

---

### Event ID 4661 — A handle to an object was requested

**What It Represents:**  
A handle was requested to an Active Directory or SAM object.

**Key Fields:** Account Name, Object Type, Object Name, Access Mask

**SOC Investigation Relevance:** Lower-priority than 4662 for most investigations. Useful for audit completeness.

---

### Event ID 5136 — A directory service object was modified

**What It Represents:**  
An attribute of an AD object was changed. The event logs both the old and new values.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | Who made the change |
| `Object DN` | Distinguished Name of the modified object |
| `Attribute LDAP Display Name` | Which attribute was changed (e.g., `member`, `servicePrincipalName`, `userAccountControl`) |
| `Attribute Value` | The new value written |
| `Operation Type` | Value Added or Value Deleted |

**SOC Investigation Relevance:**
- **Critical for detecting AD persistence and privilege escalation:**
  - Modification of `servicePrincipalName` = potential Kerberoasting setup (targeted Kerberoasting)
  - Modification of `userAccountControl` = enabling/disabling accounts, setting "Do not require Kerberos preauthentication" (AS-REP Roasting setup)
  - Modification of `member` attribute on privileged groups = privilege escalation
  - Modification of `msDS-AllowedToDelegateTo` = delegation abuse
  - Modification of `msDS-KeyCredentialLink` = Shadow Credentials attack
- Changes to `AdminSDHolder` or `GPO` objects
- Changes to trust objects

**Prerequisite:** Audit Directory Service Changes must be enabled.

**Related Event IDs:** 5137, 5138, 5139, 5141

---

### Event ID 5137 — A directory service object was created

**What It Represents:**  
A new object was created in Active Directory (e.g., user, group, computer, OU, GPO).

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | Who created the object |
| `Object DN` | Distinguished Name of the new object |
| `Object Class` | Type of object (user, group, computer, organizationalUnit, etc.) |

**SOC Investigation Relevance:**
- Detect creation of rogue user/computer accounts
- Detect creation of new GPOs for persistence
- Creation of objects in unexpected OUs

**Related Event IDs:** 5136, 5141

---

### Event ID 5138 — A directory service object was undeleted

**What It Represents:**  
An object was restored from the AD Recycle Bin or recovered from a tombstoned state.

**SOC Investigation Relevance:** Uncommon event — may indicate recovery operations or unauthorized restoration of deleted objects.

---

### Event ID 5139 — A directory service object was moved

**What It Represents:**  
An AD object was moved between OUs or containers.

**Key Fields:** Account Name, Old Object DN, New Object DN

**SOC Investigation Relevance:**
- Moving objects between OUs can change which GPOs apply, potentially weakening security
- Moving computer accounts to an OU with weaker policies

---

### Event ID 5141 — A directory service object was deleted

**What It Represents:**  
An AD object was deleted.

**Key Fields:** Account Name, Object DN, Object Class

**SOC Investigation Relevance:**
- Detect deletion of security groups, GPOs, or user accounts
- Destructive actions during an attack (e.g., deleting audit configurations, GPOs)
- Correlate with 5137 (creation) for object lifecycle tracking

---

### Replication Events

| Event ID | Event Name | Investigation Value |
|---|---|---|
| **4928** | An Active Directory replica source naming context was established | New replication partnership — investigate if unexpected DCs appear |
| **4929** | An Active Directory replica source naming context was removed | Replication partnership removed |
| **4930** | An Active Directory replica source naming context was modified | Replication configuration change |
| **4931** | An Active Directory replica destination naming context was modified | Replication configuration change |
| **4932** | Synchronization of a replica of an AD naming context has begun | Normal replication activity |
| **4933** | Synchronization of a replica of an AD naming context has ended | Normal replication activity |
| **4936** | Replication failure begins | Replication health issue — may indicate DC isolation or network problems |
| **4937** | Replication failure ends | Resolution of replication failure |

**SOC Investigation Relevance:**
- DCSync attacks use the Directory Replication Service (DRS) protocol, but the attack is better detected through Event ID 4662 (with replication-related access rights) than through replication events themselves
- Unexpected replication partnerships (4928) from non-DC IPs may indicate rogue DC registration (DCShadow attack)
- Replication failures may indicate network segmentation issues or active interference

---

## 4. Account Management (AD-Specific)

> **Log**: Security  
> **Provider**: Microsoft-Windows-Security-Auditing  
> **Audit Policy**: Audit User Account Management / Audit Computer Account Management  
> Logged on the Domain Controller that processes the change.

---

### User Account Lifecycle

| Event ID | Event Name | Key Fields | Investigation Notes |
|---|---|---|---|
| **4720** | A user account was created | Account Name, SAM Account Name, Account Domain, Creator (Subject) | Detect rogue account creation. Check if the creator is an authorized admin. |
| **4722** | A user account was enabled | Account Name, Subject | Re-enabling previously disabled accounts. Investigate context. |
| **4723** | An attempt was made to change an account's password | Account Name, Subject | Subject = same as Account = user changed own password. Subject ≠ Account = another user (admin) changed it. |
| **4724** | An attempt was made to reset an account's password | Account Name, Subject | Password reset by administrator. Verify the resetting admin is authorized. |
| **4725** | A user account was disabled | Account Name, Subject | Part of offboarding or incident response containment. |
| **4726** | A user account was deleted | Account Name, Subject | Permanent account removal. Verify authorization. |
| **4738** | A user account was changed | Account Name, Changed Attributes, Subject | Broad event — covers any user account attribute change. Check what changed. |
| **4740** | A user account was locked out | Account Name, Caller Computer Name | Trace Caller Computer Name to find lockout source. Correlate with 4625/4771. |
| **4767** | A user account was unlocked | Account Name, Subject | Verify the unlock was authorized. Repeated lock/unlock cycles are suspicious. |
| **4781** | The name of an account was changed | Old Account Name, New Account Name, Subject | Account renaming — may be used to disguise rogue accounts. |

---

### Computer Account Management

| Event ID | Event Name | Investigation Notes |
|---|---|---|
| **4741** | A computer account was created | New domain join. Verify the computer and the user performing the join. Check for unauthorized domain joins. |
| **4742** | A computer account was changed | Attribute changes to computer objects. Monitor for SPN changes or delegation modifications. |
| **4743** | A computer account was deleted | Computer account removal — verify authorization. |

> **Note**: The `ms-DS-MachineAccountQuota` attribute (default: 10) allows any authenticated user to join up to 10 computers to the domain. Attackers can exploit this to create machine accounts for use in resource-based constrained delegation attacks.

---

### Security Group Management

| Event ID | Event Name | Group Scope |
|---|---|---|
| **4727** | A security-enabled global group was created | Global |
| **4728** | A member was added to a security-enabled global group | Global |
| **4729** | A member was removed from a security-enabled global group | Global |
| **4730** | A security-enabled global group was deleted | Global |
| **4731** | A security-enabled local group was created | Domain Local |
| **4732** | A member was added to a security-enabled local group | Domain Local |
| **4733** | A member was removed from a security-enabled local group | Domain Local |
| **4734** | A security-enabled local group was deleted | Domain Local |
| **4754** | A security-enabled universal group was created | Universal |
| **4755** | A security-enabled universal group was changed | Universal |
| **4756** | A member was added to a security-enabled universal group | Universal |
| **4757** | A member was removed from a security-enabled universal group | Universal |
| **4758** | A security-enabled universal group was deleted | Universal |

**SOC Investigation Relevance:**
- **Highest priority**: Additions to privileged groups:
  - Domain Admins, Enterprise Admins, Schema Admins, Administrators (built-in)
  - Account Operators, Backup Operators, Server Operators, Print Operators
  - DNS Admins (can be abused for privilege escalation)
  - Group Policy Creator Owners
- Track both additions AND removals — attackers may add, act, then remove themselves
- Correlate the Subject (who made the change) with authorized administrative accounts
- Changes outside change management windows or by unexpected accounts are high-priority

---

### Distribution Group Management

| Event ID | Event Name |
|---|---|
| **4744** | A security-disabled local group was created |
| **4745** | A security-disabled local group was changed |
| **4746** | A member was added to a security-disabled local group |
| **4747** | A member was removed from a security-disabled local group |
| **4748** | A security-disabled local group was deleted |
| **4749** | A security-disabled global group was created |
| **4750** | A security-disabled global group was changed |
| **4751** | A member was added to a security-disabled global group |
| **4752** | A member was removed from a security-disabled global group |
| **4753** | A security-disabled global group was deleted |
| **4759** | A security-disabled universal group was created |
| **4760** | A security-disabled universal group was changed |
| **4761** | A member was added to a security-disabled universal group |
| **4762** | A member was removed from a security-disabled universal group |
| **4763** | A security-disabled universal group was deleted |

> Distribution groups are "security-disabled" groups. While they cannot be used for access control, converting a distribution group to a security group is possible and should be monitored.

---

## 5. Domain Trust and Policy Changes

> **Log**: Security  
> **Audit Policy**: Audit Authentication Policy Change / Audit Policy Change

| Event ID | Event Name | Investigation Notes |
|---|---|---|
| **4706** | A new trust was created to a domain | New domain trust — verify authorization. Rogue trusts can provide lateral movement paths across domains. |
| **4707** | A trust to a domain was removed | Trust removal — verify authorization. |
| **4713** | Kerberos policy was changed | Changes to Kerberos ticket lifetime, renewal settings. May indicate policy weakening. |
| **4716** | Trusted domain information was modified | Existing trust relationship changed — check what attributes were modified. |
| **4717** | System security access was granted to an account | Specific logon rights granted (e.g., "Allow log on locally", "Allow log on through Remote Desktop Services"). |
| **4718** | System security access was removed from an account | Logon rights removed from an account. |
| **4739** | Domain Policy was changed | Changes to domain-level security policy (password policy, lockout policy, etc.). |
| **4864** | A namespace collision was detected | Indicates potential SID-History/trust abuse or configuration conflict. |
| **4865** | A trusted forest information entry was added | Forest trust relationship change. |
| **4866** | A trusted forest information entry was removed | Forest trust relationship change. |
| **4867** | A trusted forest information entry was modified | Forest trust relationship change. |

---

## 6. LDAP / Directory Access

> **Important Distinction**: LDAP is a protocol used to query and modify Active Directory. There is no dedicated "LDAP Event ID" in the Windows Event Log system. LDAP activity is audited through:
> 1. **Directory Service Access events** (Event IDs 4662, 5136, etc.) in the Security log
> 2. **LDAP diagnostic logging** (field engineering / directory service diagnostics)
> 3. **Network-level monitoring** (packet capture, NDR solutions)

### LDAP-Related Event IDs

| Event ID | Log | What It Records |
|---|---|---|
| **4662** | Security | Operations on AD objects (accessed via LDAP or other protocols) |
| **5136** | Security | AD object attribute modifications |
| **1644** | Directory Service | Expensive, inefficient, or long-running LDAP searches (**diagnostic only**) |
| **2889** | Directory Service | LDAP unsigned or unencrypted bind attempts |
| **3040** | Directory Service | LDAP over SSL/TLS connection statistics (Server 2019+) |
| **3041** | Directory Service | LDAP channel binding token requirement events (Server 2019+) |

### Event ID 2889 — LDAP Unsigned Bind

**Key Fields:** Client IP, Account Name, Bind Type

**SOC Investigation Relevance:**
- Detects clients performing LDAP simple binds without signing or encryption
- Important for LDAP signing enforcement initiatives
- May indicate legacy applications or misconfigured clients

> **Prerequisite for Event ID 1644**: Requires setting the registry value `HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics\15 Field Engineering` to `5`. This enables **verbose** LDAP query logging and should be used carefully in production due to performance impact.

> **Note**: Do NOT confuse LDAP protocol-level logging with Windows Event IDs. Tools like `ldapsearch` queries or LDAP-based enumeration tools generate 4662 events (if SACL is configured) rather than dedicated "LDAP events."

---

## 7. IIS (Internet Information Services)

> **Critical Distinction**: IIS logging has TWO fundamentally different systems:
> 1. **Windows Event Log** — Standard Event IDs logged in the System/Application logs
> 2. **IIS W3C/HTTP Access Logs** — Text-based log files stored on disk (typically under `C:\inetpub\logs\LogFiles\`)
>
> IIS W3C access logs contain fields like HTTP method, URI, status code, client IP, user agent, etc. These are **NOT Windows Event IDs**.  
> HTTP status codes (200, 401, 403, 500, etc.) are **NOT Event IDs**.

### IIS Windows Event IDs

| Event ID | Log | Source | What It Records |
|---|---|---|---|
| **1000** | Application | Application Error | Application crash (relevant when IIS application pool crashes) |
| **1001** | Application | Windows Error Reporting | Error report details for application crashes |
| **5011** | System | WAS (Windows Process Activation Service) | A process serving application pool failed to respond to a ping — worker process recycling |
| **5138** | System | WAS | A listener channel for protocol received a listener channel notification |
| **5009** | System | WAS | A process serving application pool suffered a fatal communication error |

### IIS W3C Access Log Fields (Not Event IDs)

For reference, key fields in IIS HTTP access logs that are useful during investigation:

| Field | Description | Investigation Value |
|---|---|---|
| `c-ip` | Client IP address | Source of requests |
| `cs-uri-stem` | URI stem (path) | Identify targeted endpoints, webshells, suspicious paths |
| `cs-uri-query` | URI query string | Detect SQLi, command injection, parameter tampering |
| `sc-status` | HTTP status code | 401 (unauthorized), 403 (forbidden), 500 (server error) — not Event IDs |
| `cs(User-Agent)` | User-Agent string | Detect automated tools, unusual agents |
| `cs-method` | HTTP method | Unusual methods (PUT, DELETE) to sensitive paths |
| `time-taken` | Request processing time (ms) | Anomalously long requests may indicate exploitation |
| `cs-username` | Authenticated username | Track authenticated attacker activity |

> **Reminder**: IIS HTTP log entries like `401` or `500` are **HTTP status codes**, not Windows Event IDs. Do not confuse them.

---

## 8. NPS (Network Policy Server)

> **Log**: Security  
> **Provider**: Microsoft-Windows-Security-Auditing  
> **Audit Policy**: Audit Network Policy Server (NPS must be configured for Windows Security log logging)  
> NPS can also log to its own text-based accounting logs or a SQL database, depending on configuration.

---

### Event ID 6272 — Network Policy Server granted access to a user

**What It Represents:**  
NPS authenticated and authorized a connection request (e.g., VPN, 802.1X, RADIUS).

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | Authenticated user |
| `Client IP Address` | RADIUS client (e.g., VPN concentrator, wireless AP) |
| `Calling Station ID` | The end-user's source (MAC address, phone number, etc.) |
| `NAS IP Address` | Network Access Server handling the request |
| `Authentication Type` | EAP, MS-CHAPv2, PAP, etc. |
| `Network Policy Name` | Which NPS policy matched |

**SOC Investigation Relevance:** Baseline for normal VPN/remote access authentication. Correlate with 6273 failures for the same account.

---

### Event ID 6273 — Network Policy Server denied access to a user

**What It Represents:**  
NPS denied a connection request. This is the NPS equivalent of a "failed logon."

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Account Name` | User who was denied |
| `Client IP Address` | RADIUS client |
| `Calling Station ID` | End-user source identifier |
| `NAS IP Address` | Network Access Server |
| `Authentication Type` | Authentication method attempted |
| `**Reason Code**` | **The most critical field** — see table below |

#### Reason Code Field — Why It Matters

The `Reason Code` is the single most important field in Event ID 6273. It provides the **specific technical reason** why access was denied. Without understanding the Reason Code, you cannot determine whether the denial is due to:
- Bad credentials (credential attack)
- Policy mismatch (misconfiguration)
- Certificate issues (PKI problems)
- Account restrictions (disabled account, expired password)

**Common Reason Codes:**

| Reason Code | Meaning                                                                       | Investigation Action                                       |
| ----------- | ----------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `16`        | Authentication failed due to user credentials mismatch                        | Wrong password — correlate with brute-force patterns       |
| `22`        | Client could not be authenticated because the EAP type cannot be processed    | Certificate or EAP configuration issue                     |
| `23`        | EAP authentication failed                                                     | Certificate validation failure; check PKI chain            |
| `48`        | Connection request did not match any configured NPS network policy            | Policy misconfiguration or unexpected client type          |
| `49`        | Connection request did not match any configured NPS connection request policy | Policy gap — no matching policy for this request           |
| `65`        | The remote access permission for the user account is set to "Deny access"     | Account-level denial — verify account configuration        |
| `66`        | The connection request did not match any network policy conditions            | No matching policy — may indicate unauthorized device/user |
| `263**      | The certificate's purpose does not include smartcard authentication           | Certificate issue                                          |
| `0**        | IAS_SUCCESS — but included in denied event                                    | May indicate partial success with later policy denial      |

> **Note**: The full list of NPS Reason Codes is extensive. Microsoft documents them at: [NPS Reason Codes](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd197570(v=ws.10)). The codes listed above are the most commonly encountered during SOC investigations.

**SOC Investigation Relevance:**
- High volume of Reason Code 16 from the same account = VPN brute-force attack
- Reason Code 16 from multiple accounts from the same Calling Station ID = password spraying through VPN
- Reason codes 48/49 may indicate attackers attempting to use unauthorized authentication methods or devices
- Always check the Reason Code before escalating — many 6273 events are benign configuration issues

---

### Event ID 6274 — Network Policy Server discarded the request for a user

**What It Represents:** NPS discarded the request without processing it (e.g., malformed request, NPS overloaded).

---

### Event ID 6275 — Network Policy Server discarded the accounting request for a user

**What It Represents:** Accounting (session tracking) request was discarded.

---

### Event ID 6276 — Network Policy Server quarantined a user

**What It Represents:** The user was placed in quarantine (e.g., failed NAP health check). Primarily relevant in legacy Network Access Protection deployments.

---

### Event ID 6278 — Network Policy Server granted full access to a user (after quarantine)

**What It Represents:** User transitioned from quarantine to full access.

---

### Event ID 6279 — Network Policy Server locked the user account due to repeated failed authentication attempts

**What It Represents:** NPS-initiated account lockout after multiple failed attempts.

**SOC Investigation Relevance:** Direct evidence of repeated authentication failure — investigate as potential brute-force.

---

### Event ID 6280 — Network Policy Server unlocked the user account

**What It Represents:** Previously locked account was unlocked by NPS.

---

## 9. Group Policy Events

> **Log**: System or Microsoft-Windows-GroupPolicy/Operational  
> Useful for detecting GPO-based persistence and policy manipulation.

| Event ID | Log | What It Records |
|---|---|---|
| **1006** | Microsoft-Windows-GroupPolicy/Operational | Processing of Group Policy completed — for computer |
| **1502** | Microsoft-Windows-GroupPolicy/Operational | Group Policy processing failed |
| **4719** | Security | System audit policy was changed |
| **4907** | Security | Auditing settings on an object were changed (SACL modification) |
| **4912** | Security | Per-user audit policy was changed |

### Event ID 4719 — System audit policy was changed

**SOC Investigation Relevance:**
- **Critical**: Attackers may disable or reduce auditing to cover their tracks
- Any change to audit policy outside of approved change management is a high-priority investigation trigger
- Verify the Subject (who changed the policy) and what subcategories were modified
- Compare before/after audit settings

### Event ID 4907 — Auditing settings on object were changed

**SOC Investigation Relevance:**
- SACL changes on critical objects (AD objects, registry keys, file shares) may indicate an attacker removing audit trails
- Monitor for SACL removal on sensitive paths

---

## 10. Privilege Use and Special Logon

| Event ID | Log | What It Records |
|---|---|---|
| **4672** | Security | Special privileges assigned to new logon (detailed in Section 1) |
| **4673** | Security | A privileged service was called |
| **4674** | Security | An operation was attempted on a privileged object |

### Event ID 4673 — A privileged service was called

**Key Fields:** Account Name, Service Name, Privilege (e.g., `SeTcbPrivilege`, `SeDebugPrivilege`)

**SOC Investigation Relevance:**
- Tracks use of sensitive privileges like SeDebugPrivilege (used for process injection, credential dumping)
- High volume — filter to sensitive privileges only

### Event ID 4674 — An operation was attempted on a privileged object

**SOC Investigation Relevance:** Similar to 4673 but tracks object-level privileged operations. Generally lower priority.

---

## 11. Other High-Value DC/Security Events

### Audit Log Cleared

| Event ID | Log | What It Records |
|---|---|---|
| **1102** | Security | The audit log was cleared |
| **104** | System | The Application/System log was cleared |

**SOC Investigation Relevance:**
- **High-priority alert**: Clearing event logs is a classic anti-forensics technique
- Always investigate who cleared the log (Subject field) and why
- Event ID 1102 is self-referencing — it is the last event written before the Security log is cleared, and the first event in the new log

---

### Security State Changes

| Event ID | Log | What It Records |
|---|---|---|
| **4608** | Security | Windows is starting up |
| **4609** | Security | Windows is shutting down |
| **4616** | Security | The system time was changed |
| **4697** | Security | A service was installed in the system |

### Event ID 4616 — System time was changed

**SOC Investigation Relevance:**
- Time manipulation can be used to confuse forensic timelines or to bypass time-based Kerberos protections
- Verify whether the change was from NTP synchronization (normal) or manual manipulation

---

### SID History

| Event ID | Log | What It Records |
|---|---|---|
| **4765** | Security | SID History was added to an account |
| **4766** | Security | An attempt to add SID History to an account failed |

**SOC Investigation Relevance:**
- SID History injection is a persistence technique (Golden Ticket variant) that allows an attacker to add a privileged SID (e.g., Domain Admins SID) to a regular account's SID History
- Event ID 4765 from a non-migration context is a high-priority alert

---

## Quick Reference: Audit Policy Requirements

Many Event IDs in this document require specific audit policy subcategories to be enabled. The following table summarizes the most critical ones:

| Audit Subcategory                        | Key Event IDs Enabled             |
| ---------------------------------------- | --------------------------------- |
| Audit Logon Events                       | 4624, 4625, 4634, 4647            |
| Audit Account Logon Events               | 4768, 4769, 4771, 4776            |
| Audit Credential Validation              | 4776                              |
| Audit Kerberos Authentication Service    | 4768, 4771                        |
| Audit Kerberos Service Ticket Operations | 4769, 4770                        |
| Audit User Account Management            | 4720–4726, 4738, 4740, 4767, 4781 |
| Audit Computer Account Management        | 4741–4743                         |
| Audit Security Group Management          | 4727–4734, 4754–4758              |
| Audit Directory Service Access           | 4662                              |
| Audit Directory Service Changes          | 5136, 5137, 5138, 5139, 5141      |
| Audit Other Object Access Events         | 4698                              |
| Audit Policy Change                      | 4719, 4739                        |
| Audit Security System Extension          | 4697                              |
| Audit Special Logon                      | 4672                              |
| Audit Process Creation                   | 4688, 4689                        |
| Audit File Share                         | 5140                              |
| Audit Detailed File Share                | 5145                              |
| Audit Other Logon/Logoff Events          | 4778, 4779                        |

> **Important**: Default audit policies on Windows Server vary by version and role. A hardened or recommended audit configuration (e.g., Microsoft's baseline, CIS benchmarks) enables significantly more subcategories than the default. Always verify your environment's effective audit policy with `auditpol /get /category:*`


