# Sysmon Event IDs — SOC Investigation Reference

---

## Overview

**Sysmon** (System Monitor) is a Windows system service and device driver from the Microsoft Sysinternals suite. It logs detailed system activity to the Windows Event Log under:

- **Log**: `Microsoft-Windows-Sysmon/Operational`
- **Provider**: `Microsoft-Windows-Sysmon`

### Architecture
```
Kernel-Mode Driver → Collects System Events → Sysmon Service → Windows Event Log → SIEM / Analysis
```

### Key Characteristics
- Sysmon is **not installed by default** — it must be deployed and configured
- Behavior is controlled by an **XML configuration file** — events are only logged if the configuration includes rules for them
- Without a configuration file, Sysmon logs a minimal default set of events
- The configuration file determines **what is logged** (include/exclude filters) — a poorly tuned config produces either too much noise or insufficient visibility
- Sysmon survives reboots (installed as a service + driver) and starts early in the boot process
- Sysmon events complement (not replace) native Windows Security events

### Configuration Dependencies
Throughout this document, events marked with **⚙ Config-Dependent** require explicit configuration rules to generate useful telemetry. Events without this marker are logged by default or with minimal configuration.

### Investigation Priority Levels
- 🔴 **Critical** — High-value events essential for most SOC investigations
- 🟡 **Important** — Valuable events that support correlation and context
- 🟢 **Supporting** — Lower-priority events useful for completeness and specific investigations

---

## 1. Process Execution

### 🔴 Event ID 1 — Process Creation

**What It Records:**  
Creation of a new process, including full command-line arguments, parent process information, hashes, and user context.

**Key Fields:** 

| Field | Investigation Value |
|---|---|
| `Image` | Full path of the created process |
| `OriginalFileName` | PE header original filename — survives renaming |
| `CommandLine` | Full command-line arguments |
| `ParentImage` | Full path of the parent process |
| `ParentCommandLine` | Command line of the parent process |
| `User` | Account context |
| `IntegrityLevel` | Process integrity (Low, Medium, High, System) |
| `ProcessId` | PID of the new process |
| `ParentProcessId` | PID of the parent |
| `Hashes` | File hashes (MD5, SHA1, SHA256, IMPHASH — as configured) |
| `ProcessGuid` | Sysmon-unique process identifier (survives PID reuse) |
| `LogonId` | Logon session identifier — correlates with Windows 4624 |
| `LogonGuid` | Sysmon GUID for the logon session |
| `CurrentDirectory` | Working directory |
| `FileVersion` / `Description` / `Product` / `Company` | PE metadata |

**SOC Investigation Value:**
- **The single most important Sysmon event** for threat detection
- Detect suspicious parent-child process relationships (e.g., `winword.exe` → `cmd.exe` → `powershell.exe`)
- Detect LOTL attacks using legitimate binaries (cmd.exe, powershell.exe, wscript.exe, mshta.exe, certutil.exe, etc.)
- `OriginalFileName` field defeats process renaming — if `Image` says `update.exe` but `OriginalFileName` says `powershell.exe`, it's suspicious
- Detect execution from suspicious paths (Temp, AppData, Public, Recycle Bin, user Downloads)
- Hash values enable immediate IOC lookup against threat intelligence
- `IntegrityLevel = System` for unexpected processes warrants investigation
- `LogonId` correlates Sysmon process events to Windows authentication events (4624)

**Common Correlation/Use Cases:**
- Correlate with Event ID 3 (network connections) to see what a process connected to
- Correlate with Event ID 11 (file creation) to see what files a process dropped
- Correlate with Event ID 7 (image load) to see what DLLs a process loaded
- Correlate with Event ID 10 (process access) to detect injection into other processes

**Related Sysmon Event IDs:** 5, 3, 7, 10, 11, 25

---

### 🟡 Event ID 5 — Process Terminated

**What It Records:**  
A process has exited.

**Key Fields:** 

| Field | Investigation Value |
|---|---|
| `Image` | Process that terminated |
| `ProcessId` | PID |
| `ProcessGuid` | Sysmon GUID |
| `UtcTime` | Termination timestamp |

**SOC Investigation Value:**
- Calculate process lifetime (Event ID 1 timestamp → Event ID 5 timestamp)
- Very short-lived processes may indicate reconnaissance commands, droppers, or staging tools
- Correlate with Event ID 1 using ProcessGuid

**Related Sysmon Event IDs:** 1

---

## 2. Network Activity

### 🔴 Event ID 3 — Network Connection Detected

**What It Records:**  
A process initiated a TCP/UDP network connection.

**⚙ Config-Dependent**: Generates extremely high volume in default configuration. Must be filtered to useful connections.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that made the connection |
| `User` | Account context |
| `Protocol` | TCP or UDP |
| `SourceIp` / `SourcePort` | Local endpoint |
| `DestinationIp` / `DestinationPort` | Remote endpoint |
| `DestinationHostname` | Resolved hostname (if available) |
| `SourceHostname` | Local hostname |
| `Initiated` | `true` = outbound; `false` = inbound (listening) |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Identify C2 (Command & Control) connections — especially from suspicious processes
- Detect beaconing patterns (regular-interval connections to the same destination)
- Detect data exfiltration (large outbound transfers from unusual processes)
- Identify lateral movement (connections to internal IPs on ports like 445, 135, 3389, 5985)
- Detect unexpected processes making network connections (e.g., `notepad.exe` connecting to external IPs)
- Common C2 ports: 80, 443, 8080, 8443, 4444, 1234 (but C2 can use any port)

**Common Correlation/Use Cases:**
- Correlate with Event ID 1 to understand what process made the connection and how it was launched
- Correlate with Event ID 22 (DNS) to map DNS queries to subsequent connections
- Correlate with firewall/proxy logs for additional context

**Related Sysmon Event IDs:** 1, 22

---

### 🔴 Event ID 22 — DNS Query

**What It Records:**  
A process performed a DNS query.

> **Availability**: Sysmon v10.0+ (released 2019). Requires Windows 8.1 / Server 2012 R2 or later.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that performed the DNS query |
| `QueryName` | Domain name queried |
| `QueryStatus` | DNS response status (0 = success, non-zero = failure) |
| `QueryResults` | Resolved IP address(es) |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- **Critical for C2 detection** — identify domains contacted by suspicious processes
- Detect DNS-based C2 tunneling (long subdomain strings, high-entropy domain names)
- Detect DGA (Domain Generation Algorithm) domains
- Identify connections to known malicious domains or newly registered domains
- Process-level DNS attribution — unlike network-level DNS logs, Sysmon tells you exactly which process queried the domain
- `QueryStatus` non-zero values may indicate sinkholed domains or DNS errors

**Common Correlation/Use Cases:**
- Correlate QueryName with threat intelligence feeds
- Correlate with Event ID 3 to map DNS resolution → network connection flow
- Correlate with Event ID 1 to trace the process lineage that led to the DNS query

**Related Sysmon Event IDs:** 3, 1

---

## 3. File Activity

### 🔴 Event ID 11 — File Created

**What It Records:**  
A new file was created or an existing file was overwritten.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that created the file |
| `TargetFilename` | Full path of the created/overwritten file |
| `CreationUtcTime` | File creation timestamp |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Detect malware drops — payloads written to disk by initial access tools
- Detect webshells dropped in web server directories
- Monitor sensitive directories: `C:\Windows\Temp\`, `C:\Users\Public\`, startup folders, web roots
- Detect suspicious file extensions in unexpected locations (`.exe`, `.dll`, `.ps1`, `.bat` in Temp/AppData)
- File creation in `C:\Windows\System32\` by non-system processes is suspicious
- Correlate with Event ID 1 to see what process subsequently executed the dropped file

**Related Sysmon Event IDs:** 1, 23, 26

---

### 🟡 Event ID 15 — FileCreateStreamHash (Alternate Data Stream)

**What It Records:**  
A named file stream (alternate data stream / ADS) was created, and its hash was logged. Also captures the Zone.Identifier stream created by browsers when files are downloaded.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that created the stream |
| `TargetFilename` | File path including stream name |
| `Hash` | Hash of the stream content |
| `Contents` | For Zone.Identifier streams: shows the HostUrl (download source) |

**SOC Investigation Value:**
- Detect ADS abuse — attackers can hide executables or data in alternate data streams
- The Zone.Identifier stream reveals **where a file was downloaded from** (HostUrl) — critical for tracing initial access
- Mark-of-the-Web (MOTW) information

**Related Sysmon Event IDs:** 11

---

### 🟡 Event ID 23 — File Delete (Archived)

**What It Records:**  
A file was deleted, and Sysmon archived a copy of the deleted file.

> **⚙ Config-Dependent**: Archiving must be enabled in the Sysmon configuration. The archive directory must have sufficient disk space.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that deleted the file |
| `TargetFilename` | Path of the deleted file |
| `Hashes` | Hash of the deleted file |
| `Archived` | Whether the file was successfully archived |
| `IsExecutable` | Whether the file was an executable |

**SOC Investigation Value:**
- Capture malware samples that the attacker deleted after execution (anti-forensics recovery)
- Track what files were cleaned up by the attacker
- Hash values of deleted files can be checked against threat intelligence

**Related Sysmon Event IDs:** 11, 26

---

### 🟡 Event ID 26 — File Delete Logged

**What It Records:**  
A file was deleted. Unlike Event ID 23, the file is NOT archived — only the deletion metadata is logged.

> **Availability**: Sysmon v13.0+

**Key Fields:** Same as Event ID 23 but without archived file copy.

**SOC Investigation Value:**
- Lightweight alternative to Event ID 23 when disk-space-intensive archiving is not feasible
- Tracks file deletion activity without the storage overhead

**Related Sysmon Event IDs:** 11, 23

---

### 🟢 Event ID 24 — Clipboard Change

**What It Records:**  
Content was placed in the system clipboard.

> **Availability**: Sysmon v12.0+  
> **⚙ Config-Dependent**: Must be explicitly enabled; can capture clipboard content.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that placed content in clipboard |
| `Session` | Session ID |
| `ClientInfo` | RDP client information (if applicable) |
| `Hashes` | Hash of clipboard content |
| `Archived` | Whether clipboard content was archived |

**SOC Investigation Value:**
- Detect data exfiltration via clipboard during RDP sessions
- Track credential copying between applications
- Very noisy — requires careful filtering

---

### 🟡 Event ID 2 — File Creation Time Changed

**What It Records:**  
A process modified the creation timestamp of a file (timestomping).

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that changed the timestamp |
| `TargetFilename` | File whose timestamp was modified |
| `CreationUtcTime` | New (modified) creation time |
| `PreviousCreationUtcTime` | Original creation time |

**SOC Investigation Value:**
- **Timestomping detection** — attackers modify file creation times to blend in with legitimate system files
- If a file in System32 has a creation time from 2019 but was actually dropped today, timestomping is likely
- Common in APT and sophisticated malware campaigns
- Compare `CreationUtcTime` vs `PreviousCreationUtcTime` for the delta

**Related Sysmon Event IDs:** 11

---

## 4. Registry Activity

### 🔴 Event ID 12 — Registry Object Added or Deleted

**What It Records:**  
A registry key or value was created or deleted.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that performed the registry operation |
| `EventType` | `CreateKey`, `DeleteKey`, `CreateValue`, `DeleteValue` |
| `TargetObject` | Full registry path |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Detect persistence through registry Run keys:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
  - `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
  - `...RunOnce`, `...RunOnceEx`, etc.
- Detect COM object hijacking (CLSID registry modifications)
- Detect Image File Execution Options (IFEO) debugger persistence
- Monitor `Services` registry keys for service-based persistence

**Related Sysmon Event IDs:** 13, 14

---

### 🔴 Event ID 13 — Registry Value Set

**What It Records:**  
A registry value was set (modified or created).

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that set the value |
| `EventType` | `SetValue` |
| `TargetObject` | Full registry path including value name |
| `Details` | The data written to the registry value |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- **Critical for persistence detection** — captures the actual data written to registry keys
- `Details` field shows what executable path, command, or data was written
- Detect registry-based persistence (Run keys, services, scheduled task modifications)
- Detect security feature disabling (e.g., setting Windows Defender exclusions, disabling AMSI)
- Detect configuration tampering (proxy settings, firewall rules stored in registry)

**Related Sysmon Event IDs:** 12, 14

---

### 🟡 Event ID 14 — Registry Object Renamed

**What It Records:**  
A registry key or value was renamed.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that performed the rename |
| `EventType` | `RenameKey` |
| `TargetObject` | New registry path |
| `NewName` | New name |

**SOC Investigation Value:**
- Less common in attacks but can be used to disguise registry-based persistence
- Correlate with Event IDs 12 and 13 for complete registry change tracking

**Related Sysmon Event IDs:** 12, 13

---

## 5. Process Access / Process Injection

### 🔴 Event ID 10 — Process Accessed

**What It Records:**  
A process opened a handle to another process, requesting specific access rights.

**⚙ Config-Dependent**: Generates extremely high volume. Must be carefully filtered to reduce noise while capturing important events.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `SourceImage` | Process that opened the handle |
| `SourceProcessGuid` | GUID of the source process |
| `TargetImage` | Process that was accessed |
| `TargetProcessGuid` | GUID of the target process |
| `GrantedAccess` | Access rights granted — **the most critical field** |
| `CallTrace` | Stack trace showing what modules initiated the access |
| `SourceUser` / `TargetUser` | User context of source and target |

**Key GrantedAccess Values:**

| Access Mask | Meaning | Threat Relevance |
|---|---|---|
| `0x1F0FFF` | `PROCESS_ALL_ACCESS` | Full access — credential dumping, injection |
| `0x1010` | `PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ` | Memory reading — credential dumping from lsass |
| `0x1FFFFF` | All possible access rights | Highly suspicious |
| `0x0040` | `PROCESS_VM_WRITE` | Memory writing — process injection |
| `0x0020` | `PROCESS_VM_READ` | Memory reading |
| `0x0800` | `PROCESS_SUSPEND_RESUME` | Process hollowing |
| `0x001F0FFF` | Full access variant | Same as PROCESS_ALL_ACCESS |

**SOC Investigation Value:**
- **Primary event for detecting credential dumping** — look for any process accessing `lsass.exe` with read access
- Detect process injection (any process writing to another process's memory space)
- Detect process hollowing (`PROCESS_SUSPEND_RESUME` + `PROCESS_VM_WRITE`)
- `CallTrace` field can reveal injection frameworks (e.g., calls from `UNKNOWN` memory regions)
- Common false positives: AV/EDR products, WMI providers, system processes — baseline your environment

**Common Correlation/Use Cases:**
- SourceImage = `mimikatz.exe` or unknown process, TargetImage = `lsass.exe` → credential dumping
- Correlate SourceProcessGuid with Event ID 1 to trace the source process lineage
- Correlate with Event ID 7 (DLL loads in the target process) for injection confirmation

**Related Sysmon Event IDs:** 1, 7, 8, 25

---

### 🟡 Event ID 8 — CreateRemoteThread Detected

**What It Records:**  
A process created a thread in another process (CreateRemoteThread API call).

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `SourceImage` | Process that created the remote thread |
| `TargetImage` | Process where the thread was created |
| `NewThreadId` | ID of the created thread |
| `StartAddress` | Memory address where the thread starts |
| `StartModule` | Module at the start address |
| `StartFunction` | Function at the start address |
| `SourceProcessGuid` / `TargetProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Classic process injection detection — legitimate remote thread creation is rare
- Common in DLL injection, code injection, and process hollowing techniques
- `StartAddress` in `UNKNOWN` or non-standard module = suspicious
- Legitimate uses: some AV products, accessibility tools, debugging tools
- Less common than Event ID 10 but higher signal-to-noise ratio for injection specifically

**Related Sysmon Event IDs:** 10, 1

---

## 6. Driver / Image Loading

### 🟡 Event ID 7 — Image Loaded

**What It Records:**  
A module (DLL, driver, or other image) was loaded into a process.

**⚙ Config-Dependent**: Extremely high volume. Must be filtered aggressively. Many organizations do not enable this event at all, or filter to specific processes or unsigned DLLs only.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that loaded the module |
| `ImageLoaded` | Full path of the loaded module |
| `Hashes` | Hash of the loaded module |
| `Signed` | Whether the module is digitally signed |
| `Signature` | Signer name |
| `SignatureStatus` | Valid, Expired, Unavailable, etc. |
| `OriginalFileName` | PE header original filename |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Detect DLL side-loading (legitimate process loading a malicious DLL)
- Detect DLL search order hijacking
- Detect unsigned or invalidly signed DLLs loaded into system processes
- `Signed = false` for modules in System32 or loaded by system processes = suspicious
- Hash values enable IOC correlation
- `OriginalFileName` mismatch with `ImageLoaded` filename = potential DLL masquerading

**Related Sysmon Event IDs:** 1, 10

---

### 🟡 Event ID 6 — Driver Loaded

**What It Records:**  
A driver was loaded into the kernel.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `ImageLoaded` | Full path of the loaded driver |
| `Hashes` | Hash of the driver |
| `Signed` | Whether the driver is signed |
| `Signature` | Signer name |
| `SignatureStatus` | Valid, Expired, Unavailable, etc. |

**SOC Investigation Value:**
- Detect rootkit installation — malicious kernel drivers
- Detect BYOVD (Bring Your Own Vulnerable Driver) attacks where attackers load legitimate but vulnerable drivers to disable security tools
- Unsigned drivers or drivers loaded from unusual paths (Temp, user directories) are highly suspicious
- All legitimate Windows drivers should be signed with a valid Microsoft or WHQL certificate
- Correlate with Event ID 1 to identify what process triggered the driver load

**Related Sysmon Event IDs:** 1

---

## 7. Named Pipes

### 🟡 Event ID 17 — Pipe Created

**What It Records:**  
A named pipe was created.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that created the pipe |
| `PipeName` | Name of the created pipe |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Named pipes are used for inter-process communication (IPC) and are commonly used by:
  - Cobalt Strike (default pipes: `\msagent_*`, `\postex_*`, `\status_*`, `\MSSE-*-server`)
  - PsExec (`\psexesvc`)
  - Metasploit (`\msf*`)
  - Other C2 frameworks
- Detect lateral movement through named pipe pivoting
- Custom or unusual pipe names warrant investigation

---

### 🟡 Event ID 18 — Pipe Connected

**What It Records:**  
A named pipe connection was made between a client and server.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process that connected to the pipe |
| `PipeName` | Name of the pipe |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- Complements Event ID 17 — shows which processes are communicating through named pipes
- Detect C2 communication through named pipes
- Detect PsExec usage (connections to `\psexesvc`)

**Related Sysmon Event IDs:** 17

---

## 8. WMI Activity

### 🟡 Event ID 19 — WMI Event Filter Activity Detected

**What It Records:**  
A WMI event filter was registered.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `EventNamespace` | WMI namespace |
| `Name` | Filter name |
| `Query` | WMI query defining the trigger condition |
| `User` | Who created the filter |
| `Operation` | Created, Modified, or Deleted |

**SOC Investigation Value:**
- Part 1 of WMI persistence detection (Filter → Consumer → Binding)
- The Query field shows the trigger condition (e.g., "every 60 seconds", "on startup")
- Rare/unusual filter names warrant investigation

---

### 🟡 Event ID 20 — WMI Event Consumer Activity Detected

**What It Records:**  
A WMI event consumer was registered.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Name` | Consumer name |
| `Type` | Consumer type (`CommandLineEventConsumer`, `ActiveScriptEventConsumer`, etc.) |
| `Destination` | The command/script to execute |
| `User` | Who created the consumer |
| `Operation` | Created, Modified, or Deleted |

**SOC Investigation Value:**
- Part 2 of WMI persistence detection
- `Destination` field shows what will be executed — inspect for encoded commands, suspicious binaries, or LOTL executables
- `CommandLineEventConsumer` and `ActiveScriptEventConsumer` types are the ones attackers use

---

### 🟡 Event ID 21 — WMI Event Consumer Filter Activity Detected (Binding)

**What It Records:**  
A WMI event filter was bound to a consumer.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Consumer` | The bound consumer path |
| `Filter` | The bound filter path |
| `User` | Who created the binding |
| `Operation` | Created, Modified, or Deleted |

**SOC Investigation Value:**
- Part 3 of WMI persistence detection — the binding activates the persistence mechanism
- All three events (19, 20, 21) must be present for a complete WMI persistence chain
- Correlate all three using matching filter/consumer names

**Related Sysmon Event IDs:** 19, 20

---

## 9. Sysmon Service and Configuration

### 🟢 Event ID 4 — Sysmon Service State Changed

**What It Records:**  
The Sysmon service started or stopped.

**Key Fields:** `State` (Started, Stopped), `Version`, `SchemaVersion`

**SOC Investigation Value:**
- Sysmon being stopped may indicate an attacker attempting to disable monitoring
- Alert on unexpected Sysmon service stops
- Version/schema information useful for troubleshooting

---

### 🟢 Event ID 16 — Sysmon Configuration Changed

**What It Records:**  
The Sysmon configuration was modified.

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Configuration` | New configuration file path or hash |
| `ConfigurationFileHash` | Hash of the new configuration |

**SOC Investigation Value:**
- **Important anti-tampering event** — attackers may modify Sysmon config to exclude their activity
- Alert on any configuration changes outside approved maintenance windows
- Track the configuration hash to detect unauthorized modifications

---

### 🟢 Event ID 255 — Sysmon Error

**What It Records:**  
An internal Sysmon error occurred.

**SOC Investigation Value:**
- May indicate Sysmon tampering, driver conflicts, or resource issues
- Persistent errors may mean Sysmon is not logging properly — a blind spot

---

## 10. Process Integrity / Tampering

### 🔴 Event ID 25 — Process Tampering (Process Image Change)

**What It Records:**  
A process image was replaced or modified in memory after creation — techniques like process hollowing or process herpaderping.

> **Availability**: Sysmon v13.0+

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process whose image was tampered with |
| `Type` | Type of tampering detected (e.g., `Image is replaced`, `Image is locked for access`) |
| `ProcessId` / `ProcessGuid` | Process identifiers |

**SOC Investigation Value:**
- **High-fidelity detection** of advanced evasion techniques:
  - Process hollowing (replace process image in memory)
  - Process herpaderping (modify the on-disk image before the security product scans it)
  - Process ghosting (create process from deleted file)
- Low false positive rate — legitimate software rarely triggers this event
- Correlate with Event ID 1 (original process creation) and Event ID 10 (process access that performed the tampering)

**Related Sysmon Event IDs:** 1, 10

---

## 11. Session / Logon-Related Telemetry

> Sysmon does not directly duplicate Windows logon events (4624, etc.), but it provides process-level correlation through the `LogonId` and `LogonGuid` fields in Event ID 1.

### 🟡 Event ID 27 — File Block Executable

**What It Records:**  
Sysmon blocked an executable file from being created (file write was blocked).

> **Availability**: Sysmon v14.0+

**Key Fields:**

| Field | Investigation Value |
|---|---|
| `Image` | Process attempting to create the executable |
| `TargetFilename` | Path where the executable was being written |
| `Hashes` | Hash of the blocked file |

**SOC Investigation Value:**
- Active blocking capability — Sysmon can prevent malware from being written to disk
- Requires explicit configuration of blocking rules
- Alert on blocked executables as they indicate attempted malware delivery

---

### 🟡 Event ID 28 — File Block Shredding

**What It Records:**  
Sysmon blocked an attempt to shred/overwrite a file.

> **Availability**: Sysmon v15.0+

**Key Fields:** Image, TargetFilename, Hashes

**SOC Investigation Value:**
- Detects anti-forensic file destruction attempts
- Blocking prevents evidence destruction

---

### 🟡 Event ID 29 — File Executable Detected

**What It Records:**  
An executable file was written to disk (detection without blocking).

> **Availability**: Sysmon v15.0+

**Key Fields:** Image, TargetFilename, Hashes

**SOC Investigation Value:**
- Passive version of Event ID 27 — detects but doesn't block
- Useful for visibility when blocking is too aggressive for the environment

---

## Quick Reference Table

| Event ID | Event Name | Priority | Category |
|---|---|---|---|
| **1** | Process Creation | 🔴 Critical | Process Execution |
| **2** | File Creation Time Changed | 🟡 Important | File Activity / Anti-Forensics |
| **3** | Network Connection | 🔴 Critical | Network Activity |
| **4** | Sysmon Service State Changed | 🟢 Supporting | Sysmon Service |
| **5** | Process Terminated | 🟡 Important | Process Execution |
| **6** | Driver Loaded | 🟡 Important | Driver / Image Loading |
| **7** | Image Loaded | 🟡 Important | Driver / Image Loading |
| **8** | CreateRemoteThread | 🟡 Important | Process Injection |
| **10** | Process Accessed | 🔴 Critical | Process Access / Injection |
| **11** | File Created | 🔴 Critical | File Activity |
| **12** | Registry Object Added/Deleted | 🔴 Critical | Registry |
| **13** | Registry Value Set | 🔴 Critical | Registry |
| **14** | Registry Object Renamed | 🟡 Important | Registry |
| **15** | File Stream Created (ADS) | 🟡 Important | File Activity |
| **16** | Sysmon Config Changed | 🟢 Supporting | Sysmon Service |
| **17** | Pipe Created | 🟡 Important | Named Pipes |
| **18** | Pipe Connected | 🟡 Important | Named Pipes |
| **19** | WMI Filter Activity | 🟡 Important | WMI |
| **20** | WMI Consumer Activity | 🟡 Important | WMI |
| **21** | WMI Consumer-Filter Binding | 🟡 Important | WMI |
| **22** | DNS Query | 🔴 Critical | Network / DNS |
| **23** | File Delete (Archived) | 🟡 Important | File Activity |
| **24** | Clipboard Change | 🟢 Supporting | Clipboard |
| **25** | Process Tampering | 🔴 Critical | Process Integrity |
| **26** | File Delete Logged | 🟡 Important | File Activity |
| **27** | File Block Executable | 🟡 Important | Active Defense |
| **28** | File Block Shredding | 🟡 Important | Active Defense |
| **29** | File Executable Detected | 🟡 Important | File Activity |
| **255** | Sysmon Error | 🟢 Supporting | Sysmon Service |

---

## Investigation Correlation Matrix

The following table shows which Sysmon events commonly need to be correlated together for specific investigation scenarios:

| Investigation Scenario | Primary Event | Supporting Events |
|---|---|---|
| **Malware execution chain** | 1 (Process Create) | 11 (File Create), 3 (Network), 22 (DNS), 7 (DLL Load) |
| **Credential dumping (LSASS)** | 10 (Process Access to lsass) | 1 (Source process), 7 (DLL load), 8 (Remote thread) |
| **Process injection** | 10 (Process Access) + 8 (Remote Thread) | 1 (Source/target process), 7 (DLL load in target) |
| **Persistence via registry** | 12 (Key create) + 13 (Value set) | 1 (Process that made the change) |
| **Persistence via WMI** | 19 + 20 + 21 (Filter/Consumer/Binding) | 1 (Subsequent process execution) |
| **Lateral movement** | 3 (Network to internal hosts) | 1 (Process), 17/18 (Named pipes) |
| **C2 communication** | 3 (Network) + 22 (DNS) | 1 (Process), 11 (Dropped files) |
| **Anti-forensics** | 2 (Timestomp) + 23/26 (File delete) | 1 (Process), 25 (Process tampering) |
| **BYOVD / Rootkit** | 6 (Driver load) | 1 (Process that loaded driver), 11 (Driver file drop) |
| **DLL side-loading** | 7 (Image load) | 1 (Process), 11 (DLL file creation) |
| **Sysmon tampering** | 4 (Service stop) + 16 (Config change) | 1 (Process that modified Sysmon), 255 (Errors) |

---

## Configuration Best Practices

1. **Start with a community configuration** — [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or [NextronSystems/sysmon-config](https://github.com/NextronSystems/sysmon-config) provide good starting points
2. **Tune aggressively** — Default configurations generate excessive volume for Event IDs 3, 7, and 10
3. **Include hashing** — Enable SHA256 at minimum for IOC correlation
4. **Monitor Event ID 4 and 16** — Detect Sysmon tampering and configuration changes
5. **Protect the Sysmon driver** — Use the `-d` flag during installation to randomize the driver name
6. **Forward to SIEM** — Sysmon events should be forwarded to a centralized SIEM for correlation
7. **Test configuration changes** — Validate tuning in a staging environment before deploying to production

---

## Version Dependencies

| Feature | Minimum Sysmon Version |
|---|---|
| DNS Query Logging (Event ID 22) | v10.0 |
| Clipboard Monitoring (Event ID 24) | v12.0 |
| Process Tampering (Event ID 25) | v13.0 |
| File Delete Logged (Event ID 26) | v13.0 |
| File Block Executable (Event ID 27) | v14.0 |
| File Block Shredding (Event ID 28) | v15.0 |
| File Executable Detected (Event ID 29) | v15.0 |

> **Note**: Sysmon versions are regularly updated. Always verify the current version's capabilities at the [official Sysinternals page](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon).
