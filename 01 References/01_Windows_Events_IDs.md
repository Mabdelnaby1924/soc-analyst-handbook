# Windows Event IDs — SOC Investigation Reference



---

## How to Use This Reference

Event IDs are **telemetry**, not verdicts. A single Event ID does not confirm malicious activity.  
Security meaning depends on **context**, **correlation**, **sequence**, and **behavioral analysis**.

Use this reference to:
- Quickly identify what an Event ID represents during triage
- Understand which fields to examine for investigative leads
- Identify related events that must be correlated to reconstruct activity

---

## 1. Authentication / Logon / Logoff

### Event ID 4624 — An account was successfully logged on

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Logon/Logoff |
| **Audit Policy** | Audit Logon Events |

**Key Fields for Investigation:**
- `Logon Type` — Numeric code indicating the authentication method (2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive/RDP, etc.)
- `Account Name` / `Account Domain` — Who authenticated
- `Source Network Address` / `Source Port` — Where the connection originated
- `Logon ID` — Unique session identifier; use to correlate all activity within this session
- `Workstation Name` — Name of the source machine (note: for RDP logins, this field refers to the target machine, not the source)
- `Logon Process` / `Authentication Package` — How authentication was handled (e.g., NtLmSsp, Kerberos, Negotiate)

**SOC/DFIR Relevance:**
- Foundation event for tracking all authenticated access to a system
- Correlate with Event ID 4672 to identify privileged sessions
- Correlate with Event IDs 4634/4647 to calculate session duration
- Logon Type 10 indicates RDP; Logon Type 3 indicates network logon (file shares, PsExec, WinRM)
- Correlate Source Network Address with known infrastructure to detect lateral movement

**Related Event IDs:** 4625, 4634, 4647, 4672

---

### Event ID 4672 — Special privileges assigned to new logon

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Privilege Use |
| **Audit Policy** | Audit Special Logon |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — The account that received special privileges
- `Logon ID` — Links to the corresponding 4624 event
- `Privileges` — List of specific privileges assigned (e.g., SeDebugPrivilege, SeTcbPrivilege, SeBackupPrivilege)

**SOC/DFIR Relevance:**
- Typically follows immediately after Event ID 4624 for admin/privileged logons
- High-value for detecting privileged account usage
- Attackers must obtain administrative access to achieve advanced objectives — tracking 4672 events helps detect this
- Unexpected accounts receiving special privileges may indicate privilege escalation

**Related Event IDs:** 4624

---

### Event ID 4625 — An account failed to log on

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Logon/Logoff |
| **Audit Policy** | Audit Logon Events |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — Target account
- `Logon Type` — Method attempted
- `Failure Reason` — Human-readable explanation
- `Status` / `Sub Status` — Hexadecimal codes providing precise technical failure reason (e.g., `0xC000006D` = bad username or password, `0xC000006A` = wrong password, `0xC0000064` = non-existent account)
- `Source Network Address` — Origin of the failed attempt
- `Workstation Name` — Source machine name

**SOC/DFIR Relevance:**
- Primary indicator for brute force, password spraying, and credential stuffing attempts
- High volume from a single source IP or targeting a single account warrants investigation
- Correlate with Event ID 4740 (account lockout) to identify lockout causes
- Status/Sub Status codes differentiate between wrong password vs. non-existent account — this distinction matters for attack classification

**Related Event IDs:** 4624, 4740

---

### Event ID 4634 — An account was logged off

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Logon/Logoff |
| **Audit Policy** | Audit Logon Events |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — Who logged off
- `Logon ID` — Matches the Logon ID from the corresponding 4624 event
- `Logon Type` — Type of session that ended

**SOC/DFIR Relevance:**
- Used with Event ID 4624 to calculate session duration (subtract logon timestamp from logoff timestamp using matching Logon ID)
- System-generated logoff; complements Event ID 4647

**Related Event IDs:** 4624, 4647

---

### Event ID 4647 — User initiated logoff

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Logon/Logoff |
| **Audit Policy** | Audit Logon Events |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — Who initiated the logoff
- `Logon ID` — Matches the corresponding 4624 session

**SOC/DFIR Relevance:**
- Indicates the user explicitly initiated a logoff (vs. 4634 which may be system-generated)
- Used with 4624 to calculate session duration
- Useful for timeline reconstruction

**Related Event IDs:** 4624, 4634

---

## 2. Account Lockout

### Event ID 4740 — A user account was locked out

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Account Management |
| **Audit Policy** | Audit User Account Management |

**Key Fields for Investigation:**
- `Account Name` — The locked account
- `Caller Computer Name` — The machine that generated the lockout (origin of the failed authentication attempts)

**SOC/DFIR Relevance:**
- Triggered when an account exceeds the failed logon attempt threshold defined by organizational policy
- Correlate with Event ID 4625 to determine the source and pattern of failed logon attempts that caused the lockout
- Frequent lockouts on service accounts or admin accounts may indicate brute-force activity
- On Domain Controllers, the Caller Computer Name field helps trace which machine originated the attack

**Related Event IDs:** 4625

---

## 3. Login Validation Events (Credential Verification)

> These events are logged by the **authoritative authentication system** (Domain Controller for domain accounts, local SAM for local accounts), as opposed to the endpoint logon events above.

### Event ID 4776 — The computer attempted to validate the credentials for an account (NTLM)

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Account Logon |
| **Audit Policy** | Audit Credential Validation |

**Key Fields for Investigation:**
- `Authentication Package` — Always MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 (NTLM)
- `Logon Account` — The account whose credentials were validated
- `Source Workstation` — The machine that sent the authentication request
- `Error Code` — `0x0` = success; non-zero = failure with specific reason code

**SOC/DFIR Relevance:**
- Records credential validation specifically over the NTLM protocol
- Logged on the system that performed the validation (DC for domain accounts, local machine for local accounts)
- Both successful and failed attempts are recorded
- NTLM usage in environments that should use Kerberos may indicate downgrade attacks or legacy system issues
- Correlate with 4624/4625 on endpoints for a complete authentication picture

**Related Event IDs:** 4624, 4625

---

### Event ID 4768 — A Kerberos authentication ticket (TGT) was requested

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Account Logon |
| **Audit Policy** | Audit Kerberos Authentication Service |
| **Logged On** | Domain Controller |

**Key Fields for Investigation:**
- `Account Name` — The account requesting the TGT
- `Client Address` — Source IP of the request
- `Result Code` — `0x0` = success; other values indicate specific failure reasons
- `Ticket Encryption Type` — Encryption type used for the ticket
- `Certificate Information` — Present if smartcard authentication was used

**SOC/DFIR Relevance:**
- Indicates successful Kerberos authentication and TGT grant
- Logged on Domain Controllers
- Unusual encryption types (e.g., RC4 / `0x17`) may indicate AS-REP Roasting or Kerberoasting preparation
- Anomalous client addresses or accounts requesting TGTs at unusual times are investigation leads

**Related Event IDs:** 4769, 4771

---

### Event ID 4769 — A Kerberos service ticket was requested

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Account Logon |
| **Audit Policy** | Audit Kerberos Service Ticket Operations |
| **Logged On** | Domain Controller |

**Key Fields for Investigation:**
- `Account Name` — The account requesting the service ticket
- `Service Name` — The target service/SPN
- `Client Address` — Source IP
- `Ticket Encryption Type` — Encryption type requested
- `Failure Code` — `0x0` = success

**SOC/DFIR Relevance:**
- Records requests for service tickets (TGS) to access server resources such as shared files and folders
- Unusual service ticket requests, especially with RC4 encryption, may indicate Kerberoasting attacks
- Volume of service ticket requests from a single account may indicate reconnaissance or attack activity

**Related Event IDs:** 4768, 4771

---

### Event ID 4771 — Kerberos pre-authentication failed

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Account Logon |
| **Audit Policy** | Audit Kerberos Authentication Service |
| **Logged On** | Domain Controller |

**Key Fields for Investigation:**
- `Account Name` — The account that failed pre-authentication
- `Client Address` — Source IP of the failed request
- `Failure Code` — Specific Kerberos failure reason (e.g., `0x18` = wrong password, `0x6` = unknown principal)
- `Pre-Authentication Type` — Type of pre-authentication attempted

**SOC/DFIR Relevance:**
- Indicates that the Domain Controller will NOT grant a TGT or TGS
- The Kerberos equivalent of failed logon for credential validation purposes
- High volume from a single source may indicate brute-force or password spraying over Kerberos
- Correlate with Event ID 4768 to track the ratio of failed to successful Kerberos authentications

**Related Event IDs:** 4768, 4769

---

## 4. Account Management

> The source material references account management events through screenshots. The following Event IDs are explicitly listed in the text.

### Event ID 4728 — A member was added to a security-enabled global group

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Account Management |
| **Audit Policy** | Audit Security Group Management |

**Key Fields:** Account Name (member added), Group Name, Subject (who made the change)

---

### Event ID 4729 — A member was removed from a security-enabled global group

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Account Management |

**Key Fields:** Account Name (member removed), Group Name, Subject

---

### Event ID 4732 — A member was added to a security-enabled local group

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Account Management |

**Key Fields:** Account Name (member added), Group Name, Subject

---

### Event ID 4733 — A member was removed from a security-enabled local group

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Account Management |

**Key Fields:** Account Name (member removed), Group Name, Subject

---

### Event ID 4756 — A member was added to a security-enabled universal group

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Account Management |

**Key Fields:** Account Name (member added), Group Name, Subject

---

### Event ID 4757 — A member was removed from a security-enabled universal group

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Account Management |

**Key Fields:** Account Name (member removed), Group Name, Subject

---

**SOC/DFIR Relevance (all group management events):**
- Critical for detecting privilege escalation through group membership manipulation
- Adding accounts to privileged groups (Domain Admins, Enterprise Admins, local Administrators) is a high-priority alert
- Correlate the Subject (who made the change) with known administrative accounts
- Unexpected group changes outside change management windows are investigation triggers
- Track both additions and removals — attackers may add themselves, perform actions, then remove themselves

**Related Event IDs:** 4728–4733, 4756–4757 should be monitored as a set

---

## 5. Process Creation / Process Execution

### Event ID 4688 — A new process has been created

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Detailed Tracking |
| **Audit Policy** | Audit Process Creation |

**Key Fields for Investigation:**
- `New Process Name` — Full path of the created process
- `Process Command Line` — Command-line arguments (**requires explicit enablement**: Group Policy → Administrative Templates → System → Audit Process Creation → Include command line in process creation events)
- `Creator Process Name` — Parent process (who spawned this process)
- `Creator Process ID` — PID of the parent
- `Token Elevation Type`:
  - `%%1936` (Type 1 / Full Token) — Full access; UAC disabled or built-in privileged account
  - `%%1937` (Type 2 / Elevated Token) — User explicitly ran as administrator
  - `%%1938` (Type 3 / Limited Token) — Standard user token, admin privileges removed
- `Mandatory Label` — Process integrity level (Low, Medium, High, System)
- `Account Name` / `Account Domain` — User context
- `Logon ID` — Links to the authentication session (4624)
- `Target Subject` — If different from Creator Subject, indicates the process was created under a different user context

**SOC/DFIR Relevance:**
- Core event for process execution monitoring
- Detect suspicious parent-child relationships (e.g., `WINWORD.EXE` → `cmd.exe` → `powershell.exe`)
- Detect LOTL (Living Off The Land) attacks using legitimate binaries (see LOLBAS project)
- Detect typosquatting (e.g., `svch0st.exe`, `lssas.exe`)
- Detect processes running from unusual paths (user profile, Temp folders, attacker working directories)
- Key event for tracking lateral movement tools: `mstsc.exe` (RDP source), `rdpclip.exe`/`tstheme.exe` (RDP target), `net.exe`/`net1.exe` (share mapping), `psexec.exe` (source), `PSEXESVC.exe` (target), `wsmprovhost.exe` (WinRM target), `PowerShell.exe`
- Command-line logging is essential — without it, the Process Command Line field is empty

**Related Event IDs:** 4689

---

### Event ID 4689 — A process has exited

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Detailed Tracking |
| **Audit Policy** | Audit Process Creation |

**Key Fields for Investigation:**
- `Process Name` — The process that exited
- `Process ID` — PID of the exited process
- `Account Name` — User context
- `Logon ID` — Session link

**SOC/DFIR Relevance:**
- Used to calculate process execution duration (correlate with 4688 using Process ID)
- Short-lived processes may indicate reconnaissance commands or malware droppers

**Related Event IDs:** 4688

---

## 6. Object Access / Registry

> These events are designed to record access to any object (files, registry keys, SAM). Event ID 4657 is specifically designed for registry key value changes.

### Event ID 4656 — A handle to an object was requested

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Object Access |
| **Audit Policy** | Audit File System / Audit Registry / Audit Handle Manipulation |

**Key Fields for Investigation:**
- `Object Server` — Always "Security"
- `Object Type` — Type of accessed object: `File`, `Key` (registry), or `SAM`
- `Object Name` — Full path of the accessed object
- `Process Name` — Process that requested the handle
- `Access Mask` — Requested access permissions
- `Account Name` — User context

**Prerequisite:** Requires SACL (System Access Control List) configured on the target object.

---

### Event ID 4658 — The handle to an object was closed

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Object Access |

**Key Fields:** Handle ID (correlates with 4656), Process Name, Account Name

---

### Event ID 4660 — An object was deleted

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Object Access |

**Key Fields:** Handle ID (correlates with 4656), Process Name, Account Name

---

### Event ID 4663 — An attempt was made to access an object

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Category** | Object Access |

**Key Fields:** Object Type, Object Name, Process Name, Access Mask, Account Name

---

### Event ID 4657 — A registry value was modified

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Object Access |
| **Audit Policy** | Audit Registry |

**Key Fields for Investigation:**
- `Object Name` — Registry key path
- `Object Value Name` — The registry value that was changed
- `Old Value` / `New Value` — Previous and new values
- `Process Name` — Process that made the change
- `Account Name` — User context

**Prerequisite:** Requires `Set Value` auditing to be configured in the registry key's SACL. **Not enabled by default.**

**SOC/DFIR Relevance (all object access events):**
- Critical for detecting persistence through registry run key modification
- Monitor access and changes to registry run keys:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- Events 4656, 4658, 4660, and 4663 cover any object type; filter by Object Type = `Key` for registry investigations
- Event 4657 is registry-specific and provides old/new values for change tracking

**Related Event IDs:** 4656, 4658, 4660, 4663, 4657 — these events should be correlated together using Handle ID

---

## 7. Scheduled Tasks

### Event ID 4698 — A scheduled task was created

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Object Access |
| **Audit Policy** | Audit Other Object Access Events |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — Who created the task
- `Task Name` — Name of the scheduled task
- `Task Content` (XML) — Contains:
  - The command/executable to run
  - The trigger schedule (daily, on logon, etc.)
  - The user context under which the task will execute
  - The working directory

**SOC/DFIR Relevance:**
- Key persistence detection event — attackers create scheduled tasks to maintain access
- Examine the Task Content XML for:
  - Executables in suspicious paths (Temp, user profile, Public)
  - Encoded PowerShell commands
  - Scripts stored in registry keys
  - Execution under SYSTEM or high-privilege accounts
- Task creation via `schtasks.exe` command line is also visible in Event ID 4688
- Compare task creation timestamps with known incident timeline

**Related Event IDs:** 4688 (process creation of schtasks.exe)

---

## 8. Service Installation

### Event ID 7045 — A service was installed in the system

| Attribute | Detail |
|---|---|
| **Log** | System |
| **Provider** | Service Control Manager |
| **Category** | System |

**Key Fields for Investigation:**
- `Service Name` — Name of the installed service
- `Service File Name` — Path to the service executable
- `Service Type` — Type of service
- `Service Start Type`:
  - `0` = Boot (drivers)
  - `1` = System (I/O subsystem)
  - `2` = Auto Start (**commonly abused by attackers for persistence**)
  - `3` = Manual
  - `4` = Disabled
- `Service Account` — Account context for the service

---

### Event ID 4697 — A service was installed in the system

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | System |
| **Audit Policy** | Audit Security System Extension |

**Key Fields:** Same as 7045 — Service Name, Service File Name, Service Start Type, Service Account

**SOC/DFIR Relevance (both 7045 and 4697):**
- Both events record the same activity (service installation) in different log files
- 7045 is in the System log; 4697 is in the Security log
- Critical for detecting:
  - PsExec lateral movement (creates `PSEXESVC` service on target)
  - Persistence through auto-start services
  - Malicious services executing binaries from non-standard paths (e.g., a non-Windows binary in System32)
- Investigate: Service File Name pointing to Temp folders, user profiles, or non-standard paths
- Investigate: Service Account set to LocalSystem for newly created services
- Correlate with Event ID 4688 to see the service process start and its child processes

**Related Event IDs:** 4688

---

## 9. File / Share Access

### Event ID 5140 — A network share object was accessed

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Object Access |
| **Audit Policy** | Audit File Share |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — Who accessed the share
- `Source Address` / `Source Port` — Origin of the connection
- `Share Name` — Name of the accessed share (e.g., `\\*\C$`, `\\*\ADMIN$`, `\\*\IPC$`)
- `Share Path` — Local path mapped to the share

**SOC/DFIR Relevance:**
- Tracks accessed shared folders on the system
- Does **NOT** include individual file-level access — use Event ID 5145 for that
- Critical for detecting lateral movement via Windows admin shares (`C$`, `ADMIN$`, `IPC$`)
- Aggressive share access to multiple internal systems from the same source may indicate automated share discovery tools (e.g., ShareFinder)
- Correlate with 4624 (authentication) and 5145 (file-level access)

**Related Event IDs:** 4624, 5145

---

### Event ID 5145 — A network share object was checked to see whether client can be granted desired access

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Object Access |
| **Audit Policy** | Audit Detailed File Share |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — Who accessed the file
- `Source Address` — Origin IP
- `Share Name` — The share being accessed
- `Relative Target Name` — The specific file or path within the share
- `Access Mask` — Requested permissions

**SOC/DFIR Relevance:**
- Provides file-level visibility within shared folders
- Critical for identifying what files were accessed or transferred during lateral movement
- Example: attacker accesses `\\*\ADMIN$` and writes `python.exe` to `C:\Windows\Temp\`
- Correlate with 5140 (share access) and 4624 (authentication) for full lateral movement picture
- High volume of 5145 events from a single source scanning multiple shares indicates reconnaissance

**Related Event IDs:** 4624, 5140

---

## 10. Remote Desktop (RDP) Session Tracking

### Event ID 4778 — A session was reconnected to a Window Station

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Logon/Logoff |
| **Audit Policy** | Audit Other Logon/Logoff Events |

**Key Fields for Investigation:**
- `Account Name` / `Account Domain` — User who reconnected
- `Session Name` — Session identifier (e.g., `RDP-Tcp#0`)
- `Client Name` — **Source machine name** (unlike 4624, this reliably identifies the source hostname)
- `Client Address` — Source IP address

**SOC/DFIR Relevance:**
- Records every reconnected RDP session
- Provides the source machine name that Event ID 4624 does not reliably provide for RDP sessions
- Use to map RDP lateral movement chains between hosts

**Related Event IDs:** 4779, 4624

---

### Event ID 4779 — A session was disconnected from a Window Station

| Attribute | Detail |
|---|---|
| **Log** | Security |
| **Provider** | Microsoft-Windows-Security-Auditing |
| **Category** | Logon/Logoff |
| **Audit Policy** | Audit Other Logon/Logoff Events |

**Key Fields for Investigation:**
- `Account Name` — User who disconnected
- `Session Name` — Session identifier
- `Client Name` — Source machine name
- `Client Address` — Source IP

**SOC/DFIR Relevance:**
- Records every disconnected RDP session
- Pair with 4778 to track RDP session connect/disconnect patterns
- RDP connections between two regular workstations (client-to-client) rather than to jump servers or from IT admin workstations are suspicious

**Related Event IDs:** 4778, 4624

---

## 11. PowerShell / Command Execution

### Event ID 4104 — PowerShell Script Block Logging

| Attribute | Detail |
|---|---|
| **Log** | Microsoft-Windows-PowerShell/Operational |
| **Provider** | Microsoft-Windows-PowerShell |
| **Category** | PowerShell Execution |

**Prerequisite:** Script Block Logging must be enabled via Group Policy: 
`Computer Configuration → Administrative Templates → Windows Components → Windows PowerShell → Turn on PowerShell Script Block Logging`

**Key Fields for Investigation:**
- `ScriptBlock Text` — The actual PowerShell code executed
- `ScriptBlock ID` — Unique identifier; large scripts are split across multiple 4104 events sharing the same ScriptBlock ID
- `Path` — Script file path (if executed from a file)
- `Message Number` / `Message Total` — Position within a multi-part script block

**SOC/DFIR Relevance:**
- Records the **content** of executed PowerShell script blocks
- Captures deobfuscated/decoded script content — even if the attacker used encoding, 4104 logs the decoded version
- Reconstruct full scripts by assembling events with the same ScriptBlock ID
- Critical for detecting PowerShell-based attacks, encoded commands, and fileless malware
- Key event for investigating PowerShell remoting (Invoke-Command, Enter-PSSession) on both source and target machines

**Related Event IDs:** 4103, 800

---

### Event ID 4103 — PowerShell Module Logging

| Attribute | Detail |
|---|---|
| **Log** | Microsoft-Windows-PowerShell/Operational |
| **Provider** | Microsoft-Windows-PowerShell |
| **Category** | PowerShell Execution |

**Key Fields for Investigation:**
- `Payload` — Contains the executed module/cmdlet details
- `Command Name` — The cmdlet or function invoked
- `Command Type` — Type of command (Cmdlet, Function, Script, etc.)
- `User` — Account that executed the command

**SOC/DFIR Relevance:**
- Logs executed PowerShell modules and cmdlets
- Complements 4104 (script block content) with module-level execution tracking
- Useful for identifying which cmdlets were invoked without requiring full script block reconstruction

**Related Event IDs:** 4104, 800

---

### Event ID 800 — PowerShell Pipeline Execution

| Attribute | Detail |
|---|---|
| **Log** | Windows PowerShell |
| **Provider** | PowerShell |
| **Category** | PowerShell Execution |

**Key Fields for Investigation:**
- `HostApplication` — The PowerShell host application
- `CommandLine` — The executed command
- `UserId` — User context

**SOC/DFIR Relevance:**
- Records PowerShell command executions made through the PowerShell console
- Note: Logged in the **Windows PowerShell** log (legacy log), not the Microsoft-Windows-PowerShell/Operational log
- Provides another layer of PowerShell execution telemetry alongside 4104 and 4103
- Available without the Script Block Logging prerequisite, but provides less detail than 4104

**Related Event IDs:** 4104, 4103

---

## 12. WMI Activity

### Event ID 5861 — WMI Event Consumer Creation

| Attribute | Detail |
|---|---|
| **Log** | Microsoft-Windows-WMI-Activity/Operational |
| **Provider** | Microsoft-Windows-WMI-Activity |
| **Category** | WMI Persistence |

**Key Fields for Investigation:**
- `Consumer Name` — Name of the WMI event consumer
- `Consumer Type` — `CommandLineEventConsumer` (executes commands) or `ActiveScriptEventConsumer` (executes scripts)
- `Bound Filter Name` — The associated WMI event filter
- `Consumer Command/Script` — The actual command or script to be executed

**SOC/DFIR Relevance:**
- Records WMI event consumer creation, which is a persistence mechanism
- WMI event subscription persistence requires three components: Event Filter → Event Consumer → Binding
- Event ID 5861 captures consumer creation and often shows the filter binding
- Investigate:
  - Consumer type (CommandLine or ActiveScript)
  - Rare or unusual consumer/filter names
  - Suspicious execution targets: encoded PowerShell, binaries from Temp paths, LOTL executables
- WMI persistence is stealthy — many organizations do not monitor WMI activity logs

**Related Event IDs:** Correlate with Event ID 4688 for subsequent process execution by the WMI consumer

---

## Quick Reference Table

| Event ID | Event Name | Log | Category |
|---|---|---|---|
| **4624** | Successful logon | Security | Authentication |
| **4625** | Failed logon | Security | Authentication |
| **4634** | Account logged off | Security | Logon/Logoff |
| **4647** | User initiated logoff | Security | Logon/Logoff |
| **4672** | Special privileges assigned | Security | Privilege Use |
| **4740** | Account locked out | Security | Account Lockout |
| **4776** | NTLM credential validation | Security | Credential Validation |
| **4768** | Kerberos TGT requested | Security | Kerberos Authentication |
| **4769** | Kerberos service ticket requested | Security | Kerberos Authentication |
| **4771** | Kerberos pre-authentication failed | Security | Kerberos Authentication |
| **4728** | Member added to global group | Security | Group Management |
| **4729** | Member removed from global group | Security | Group Management |
| **4732** | Member added to local group | Security | Group Management |
| **4733** | Member removed from local group | Security | Group Management |
| **4756** | Member added to universal group | Security | Group Management |
| **4757** | Member removed from universal group | Security | Group Management |
| **4688** | Process created | Security | Process Tracking |
| **4689** | Process exited | Security | Process Tracking |
| **4656** | Handle to object requested | Security | Object Access |
| **4657** | Registry value modified | Security | Object Access / Registry |
| **4658** | Handle to object closed | Security | Object Access |
| **4660** | Object deleted | Security | Object Access |
| **4663** | Object access attempted | Security | Object Access |
| **4698** | Scheduled task created | Security | Scheduled Tasks |
| **7045** | Service installed (System log) | System | Service Installation |
| **4697** | Service installed (Security log) | Security | Service Installation |
| **5140** | Network share accessed | Security | Share Access |
| **5145** | Share object access checked | Security | Share Access |
| **4778** | RDP session reconnected | Security | Remote Access |
| **4779** | RDP session disconnected | Security | Remote Access |
| **4104** | PowerShell Script Block Logging | PowerShell/Operational | PowerShell Execution |
| **4103** | PowerShell Module Logging | PowerShell/Operational | PowerShell Execution |
| **800** | PowerShell Pipeline Execution | Windows PowerShell | PowerShell Execution |
| **5861** | WMI consumer created | WMI-Activity/Operational | WMI Persistence |

