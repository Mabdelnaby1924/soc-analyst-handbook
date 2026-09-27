# Protocols & Ports — SOC Investigation Reference

> A compact field reference for protocols and ports relevant to enterprise network security, Active Directory environments, and SOC alert investigation.  
> Ports are verified against IANA registry and Microsoft documentation where applicable.  
> A port or protocol is **not inherently malicious** — security meaning depends on source, destination, role, timing, behavior, and correlation.

---

## Authentication & Directory Services

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **Kerberos** | 88 | TCP, UDP | AD authentication — TGT/TGS ticket exchange | Correlate with Event IDs 4768/4769/4771 on DCs. Unusual source IPs requesting tickets, RC4 encryption, or high-volume TGS requests may indicate Kerberoasting or brute-force. |
| **LDAP** | 389 | TCP, UDP | Directory queries — user/group/object lookups | Correlate with Event ID 4662 / DS Access logs. Large-volume LDAP queries from non-admin hosts may indicate AD enumeration (BloodHound, SharpHound, ADFind). |
| **LDAPS** | 636 | TCP | LDAP over TLS/SSL | Same as LDAP. Encrypted channel — verify certificate validity. If organization enforces LDAPS, plaintext LDAP (389) traffic may indicate misconfiguration or downgrade. |
| **Global Catalog** | 3268 | TCP | LDAP queries across all domains in a forest | Cross-domain lookups. Unusual hosts querying GC may indicate cross-domain reconnaissance. |
| **Global Catalog (SSL)** | 3269 | TCP | Global Catalog over TLS/SSL | Same as 3268, encrypted channel. |
| **NTLM** | — | — | Authentication protocol (no dedicated port — travels over SMB, HTTP, LDAP, etc.) | Correlate with Event ID 4776. NTLM usage where Kerberos is expected may indicate relay attacks or protocol downgrade. Track via Authentication Package field in logon events. |
| **RADIUS** | 1812 (auth), 1813 (acct) | UDP | Network access authentication (VPN, 802.1X, Wi-Fi) | Correlate with NPS Event IDs 6272/6273. Failed auth spikes = VPN brute-force. Check Reason Code in 6273 for denial cause. Legacy port 1645/1646 still seen in older configs. |
| **TACACS+** | 49 | TCP | Network device AAA (authentication, authorization, accounting) | Primarily for network device admin access (switches, routers, firewalls). Unusual TACACS+ traffic from non-network-admin hosts is suspicious. |

---

## Name Resolution & Network Infrastructure

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **DNS** | 53 | TCP, UDP | Domain name resolution | Correlate with Sysmon Event ID 22 (process-level DNS). Investigate: high-entropy subdomains (DGA/tunneling), queries to rare TLDs, DNS over non-standard ports. DNS over TCP for large responses or zone transfers. |
| **DNS over HTTPS (DoH)** | 443 | TCP | Encrypted DNS over HTTPS | C2 frameworks may use DoH to bypass DNS monitoring. Traffic to known DoH providers (1.1.1.1, 8.8.8.8) from endpoints may indicate DNS evasion. |
| **DNS over TLS (DoT)** | 853 | TCP | Encrypted DNS over TLS | Similar to DoH — encrypted DNS that bypasses traditional DNS visibility. Less common in enterprise than DoH. |
| **mDNS** | 5353 | UDP | Multicast DNS — local network name resolution | Primarily local network. Can be abused for reconnaissance. Unexpected mDNS from servers is unusual. |
| **LLMNR** | 5355 | UDP | Link-Local Multicast Name Resolution | Fallback name resolution. Vulnerable to poisoning/relay attacks (Responder tool). Should be disabled in hardened environments. |
| **NetBIOS Name Service** | 137 | UDP | Legacy Windows name resolution | Same poisoning/relay risks as LLMNR. Vulnerable to Responder-style attacks. Should be disabled where possible. |
| **NetBIOS Datagram** | 138 | UDP | Legacy NetBIOS datagram distribution | Legacy browsing/discovery traffic. Unusual volume may indicate scanning. |
| **NetBIOS Session** | 139 | TCP | Legacy SMB over NetBIOS | Legacy file sharing. Modern environments should use SMB directly over 445. Traffic on 139 in a modern network may indicate legacy systems or misconfiguration. |
| **DHCP** | 67 (server), 68 (client) | UDP | Dynamic IP address assignment | Correlate DHCP leases with IP-to-hostname mapping for investigation timeline. Rogue DHCP servers = MitM risk. Useful for tying IP addresses to hosts at specific times. |
| **NTP** | 123 | UDP | Time synchronization | Critical for Kerberos (max 5-min skew). NTP manipulation can break Kerberos auth or confuse forensic timelines. Correlate with Event ID 4616 (time change). |

---

## File Sharing & Remote Execution

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **SMB** | 445 | TCP | File sharing, admin shares (C$, ADMIN$, IPC$), remote service management | Primary lateral movement channel. Correlate with Event IDs 4624 (type 3), 5140, 5145 for share access. PsExec, WMI, remote service creation all use SMB. Internal-to-internal SMB from workstation-to-workstation is suspicious. |
| **RPC Endpoint Mapper** | 135 | TCP | RPC service discovery — maps RPC services to dynamic ports | Initial contact point for DCOM, WMI, remote service management. Connections to 135 followed by dynamic high ports = RPC activity. Correlate with Event ID 4688 for spawned processes. |
| **RPC Dynamic Ports** | 49152–65535 | TCP | Dynamically assigned RPC service ports (Windows Vista+ default range) | Follow-on connections after EPM (135) negotiation. Range is configurable via registry. Legacy range (pre-Vista): 1024–65535. Firewall rules should restrict this range in segmented networks. |
| **RDP** | 3389 | TCP, UDP | Remote desktop access | Correlate with Event IDs 4624 (type 10), 4778/4779 for session tracking. Workstation-to-workstation RDP is a lateral movement indicator. Exposed RDP to the internet = high risk. Check for non-standard RDP ports as evasion. |
| **WinRM (HTTP)** | 5985 | TCP | PowerShell remoting / Windows Remote Management | Correlate with Event IDs 4624 (type 3), 4688 (wsmprovhost.exe), 4104 (PowerShell). PowerShell remoting lateral movement. Unusual source hosts using WinRM warrant investigation. |
| **WinRM (HTTPS)** | 5986 | TCP | WinRM over TLS | Same as 5985, encrypted. Preferred in hardened environments. |
| **SSH** | 22 | TCP | Secure remote shell access | Primarily Linux/network device management. SSH from Windows endpoints (not jump servers) may indicate tunneling or unauthorized access. SSH tunnels can encapsulate other protocols for evasion. |
| **FTP** | 21 (control), 20 (data) | TCP | File transfer (cleartext) | Credentials sent in plaintext. Data exfiltration channel. FTP to external IPs from internal hosts is an investigation trigger. Passive mode uses dynamic high ports. |
| **FTPS** | 990 (implicit) | TCP | FTP over TLS | Encrypted FTP. Less common than SFTP in modern environments. |
| **SFTP** | 22 | TCP | File transfer over SSH | Runs over SSH — same port. Distinguish from SSH shell sessions by context. Potential data exfiltration channel. |
| **TFTP** | 69 | UDP | Trivial file transfer — no authentication | No auth, no encryption. Used for network device firmware/config transfer. Unexpected TFTP traffic may indicate config exfiltration or malware staging. |

---

## Web & Application Layer

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **HTTP** | 80 | TCP | Unencrypted web traffic | C2 callbacks, web exploitation, webshell access. Correlate with proxy/WAF logs. HTTP to external IPs from unexpected processes (Sysmon Event ID 3) is a C2 indicator. |
| **HTTPS** | 443 | TCP | Encrypted web traffic / TLS | Most C2 frameworks use HTTPS. Certificate anomalies (self-signed, recently issued, mismatched CN) are investigation leads. JA3/JA3S fingerprinting helps identify C2 tools. |
| **HTTP Alt** | 8080, 8443, 8888 | TCP | Common alternate HTTP/HTTPS ports | Used by proxies, dev servers, web apps, and C2 frameworks. Non-standard web ports from internal hosts to external IPs warrant investigation. |
| **HTTP Proxy** | 3128, 8080 | TCP | Web proxy (Squid default: 3128) | Proxy bypass attempts — direct HTTP/HTTPS traffic bypassing the corporate proxy. Correlate with proxy logs for coverage gaps. |

---

## Email

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **SMTP** | 25 | TCP | Email submission/relay between mail servers | Direct SMTP from endpoints (not mail servers) may indicate phishing relay, spam bot, or data exfiltration. Correlate with email gateway logs. |
| **SMTP Submission** | 587 | TCP | Authenticated email submission (STARTTLS) | Standard client→server email submission. Unusual processes or hosts using 587 may indicate credential compromise or automated exfiltration. |
| **SMTPS** | 465 | TCP | SMTP over implicit TLS | Legacy implicit TLS port, re-standardized in RFC 8314. |
| **IMAP** | 143 | TCP | Email retrieval — server-side mailbox access | Cleartext. Credential interception risk. |
| **IMAPS** | 993 | TCP | IMAP over TLS | Encrypted IMAP. Standard for modern email clients. |
| **POP3** | 110 | TCP | Email retrieval — downloads to client | Cleartext. Largely replaced by IMAP in enterprise. |
| **POP3S** | 995 | TCP | POP3 over TLS | Encrypted POP3. |

---

## Network Monitoring & Management

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **Syslog** | 514 | UDP (traditional), TCP | Centralized log forwarding | Core of log pipeline. Syslog disruption = blind spot. Verify log sources are actively forwarding. UDP syslog is unreliable (no delivery guarantee); use TCP/TLS (port 6514) for reliability. |
| **Syslog over TLS** | 6514 | TCP | Encrypted, reliable syslog transport | Preferred for secure log forwarding. |
| **SNMP v1/v2c** | 161 (queries), 162 (traps) | UDP | Network device monitoring (cleartext community strings) | Community strings often default ("public"/"private"). SNMP enumeration reveals network topology. v1/v2c sends credentials in cleartext. |
| **SNMP v3** | 161, 162 | UDP | Network monitoring with authentication/encryption | Preferred over v1/v2c. Verify v3 is actually in use and not falling back to v2c. |
| **WMI** | 135 + dynamic RPC | TCP | Windows Management Instrumentation — remote system management | Lateral movement vector. Correlate with Event IDs 4688, 5861 (WMI consumer). WMI persistence = Event IDs 19/20/21 (Sysmon). Uses RPC (135 → dynamic ports). |
| **ICMP** | — | IP Protocol 1 | Ping, traceroute, network diagnostics | No TCP/UDP port. ICMP tunneling can exfiltrate data. Large/unusual ICMP payloads are suspicious. Excessive ICMP from a single host may indicate scanning (ping sweep). |

---

## VPN & Tunneling

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **IKEv1/IKEv2** | 500 | UDP | IPsec key exchange negotiation | VPN tunnel establishment. Correlate with RADIUS/NPS logs (6272/6273) for VPN authentication events. |
| **IPsec NAT-T** | 4500 | UDP | IPsec through NAT devices | VPN traffic traversing NAT. Same investigation context as IKE. |
| **IPsec ESP** | — | IP Protocol 50 | Encrypted IPsec payload | No TCP/UDP port — IP protocol 50. Encrypted tunnel payload. |
| **IPsec AH** | — | IP Protocol 51 | IPsec authentication header (integrity, no encryption) | No TCP/UDP port — IP protocol 51. Rarely used alone; usually combined with ESP. |
| **GRE** | — | IP Protocol 47 | Generic Routing Encapsulation — tunnel protocol | No TCP/UDP port — IP protocol 47. Can encapsulate arbitrary protocols. Unexpected GRE traffic may indicate tunneling for evasion. |
| **OpenVPN** | 1194 | UDP (default), TCP | Open-source VPN | Default port; often reconfigured. Unauthorized VPN tunnels from endpoints = policy violation and potential data exfiltration. |
| **WireGuard** | 51820 | UDP | Modern VPN protocol | Emerging in enterprise. Unauthorized WireGuard tunnels = same concerns as OpenVPN. |
| **SSTP** | 443 | TCP | Microsoft Secure Socket Tunneling Protocol — VPN over HTTPS | Uses port 443 — difficult to distinguish from regular HTTPS without deep inspection. Built into Windows. |

---

## Layer 2 / Non-IP Protocols

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **ARP** | — | Layer 2 (Ethernet) | IP-to-MAC address resolution | No TCP/UDP port. ARP spoofing/poisoning = MitM attacks. Gratuitous ARP from unexpected sources is suspicious. Monitor with NDR/IDS. |
| **802.1X** | — | Layer 2 (EAP over LAN) | Port-based network access control | Authentication at the switch port level. Correlate with RADIUS (1812) for auth events. Bypasses/failures may indicate rogue devices. |

---

## Other SOC-Relevant Services

| Protocol / Service | Port(s) | Transport | Purpose | SOC Correlation / Why |
|---|---|---|---|---|
| **MS-SQL** | 1433 (default), 1434 (browser/UDP) | TCP, UDP | Microsoft SQL Server | Database access. Unexpected connections from non-app-server hosts may indicate SQL injection exploitation or lateral movement. UDP 1434 used for instance discovery. |
| **MySQL** | 3306 | TCP | MySQL database | Same investigation logic as MS-SQL. Direct database connections from endpoints are unusual in tiered architectures. |
| **PostgreSQL** | 5432 | TCP | PostgreSQL database | Same as above. |
| **RDP (non-standard)** | Varies | TCP | RDP on non-default ports (evasion) | Attackers may change RDP port to evade detection. Detect via service fingerprinting rather than port number alone. |
| **Telnet** | 23 | TCP | Cleartext remote shell (legacy) | Credentials in plaintext. Should be disabled in modern environments. Any Telnet traffic in a hardened environment warrants investigation. |
| **DCOM** | 135 + dynamic RPC | TCP | Distributed Component Object Model — remote object activation | Lateral movement vector (e.g., MMC snap-ins, DCOM-based exploitation). Same RPC flow as WMI: EPM on 135 → dynamic ports. |

---

## Quick Reference: Protocols Without TCP/UDP Ports

These protocols operate below the transport layer and do **not** use TCP or UDP port numbers:

| Protocol | IP Protocol Number / Layer | Notes |
|---|---|---|
| **ICMP** | IP Protocol 1 | Ping, traceroute, error messages |
| **GRE** | IP Protocol 47 | Tunnel encapsulation |
| **ESP (IPsec)** | IP Protocol 50 | Encrypted VPN payload |
| **AH (IPsec)** | IP Protocol 51 | Authentication/integrity |
| **ARP** | Layer 2 (Ethernet) | Not an IP protocol — operates on Ethernet frames |
| **802.1X** | Layer 2 (EAP) | Port-based access control at the switch level |

---

## Windows / AD Dynamic Port Ranges

| Range | Applies To | Notes |
|---|---|---|
| **49152–65535** | Windows Vista / Server 2008 and later | Default dynamic RPC port range (IANA ephemeral range) |
| **1024–65535** | Windows XP / Server 2003 (legacy) | Legacy dynamic port range |
| **Configurable** | All Windows versions | Custom RPC range can be set via `netsh int ipv4 set dynamicport tcp` or registry |

> **Note**: In environments where the dynamic range is restricted by firewall policy, verify the effective range with `netsh int ipv4 show dynamicport tcp` on representative hosts.
