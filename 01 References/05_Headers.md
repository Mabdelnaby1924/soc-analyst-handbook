# Email Header Analysis — Quick Reference



Read `Received` headers **bottom to top** — the earliest hop is at the bottom, the latest (closest to you) is at the top.

---

## 1. Identity & Content Headers

|Header|What it gives you|Investigation use|
|---|---|---|
|**From**|Claimed sender|**Spoofable** — never trust alone, always check against SPF/DKIM/DMARC and the `Received` chain|
|**To**|Recipient(s)|Scope who was targeted|
|**Date**|When the message was sent (as claimed by sender)|Compare against `Received` timestamps for inconsistencies|
|**Subject**|Message topic|Urgency/motivation language ("Action Required", "Invoice", "Payment") is a behavioral indicator|
|**Message-ID**|Unique ID for this specific message|Pivot/search across mail servers and SEG logs for the same message|
|**References**|Chain of Message-IDs for the whole thread|Reconstruct a full conversation — critical for **thread hijacking / BEC** cases|
|**Return-Path**|Where bounces go — the actual `MAIL FROM` used in the SMTP transaction|Compare against the `From` header; a mismatch is a spoofing signal|
|**Reply-To**|Where replies are routed|Attackers set this to an address they control even when `From` looks legitimate — classic BEC/spoofing tell|
|**MIME-Version / Content-Type / Content-Transfer-Encoding**|Message format/encoding|Confirms structure; unusual encoding can hide payloads|
|**Content-Length**|Body size (when present)|Minor corroborating detail|

---

## 2. Routing Headers (built from the mail hops)

|Header|What it gives you|Investigation use|
|---|---|---|
|**Received** (one per hop)|Hostname, IP, protocol, timestamp of each server that touched the message|**The core evidence for reconstructing the email's path.** Read bottom→top. Each hop's declared source should chain logically to the previous hop's destination — breaks in that chain are suspicious|
|**Received-SPF**|Inline SPF verdict for this hop|Quick pass/fail without going to the full `Authentication-Results` block|

**What each `Received` line typically exposes:** source hostname, source IP, destination server, protocol (ESMTPS/SMTP), encryption details (TLS version/cipher), and processing timestamp.

---

## 3. Authentication Headers (SPF / DKIM / DMARC / ARC)

|Header|What it gives you|Investigation use|
|---|---|---|
|**Authentication-Results**|Combined SPF + DKIM + DMARC verdict, as evaluated by the receiving server|**First place to look** — gives you pass/fail for all three in one line|
|**Received-SPF**|SPF verdict + which IP was checked against which domain's policy|Confirms whether the sending IP was authorized by the claimed domain|
|**DKIM-Signature**|Cryptographic signature + metadata (`d=`, `s=`, `a=`, `bh=`, `h=`, `b=`)|`d=` domain claiming responsibility, `s=` selector to fetch the DNS public key, `h=` which headers were signed (integrity scope), `bh=` body hash. A DKIM **pass** confirms the signed content wasn't altered and came from a holder of that domain's private key|
|**ARC-Seal / ARC-Message-Signature / ARC-Authentication-Results**|Preserves the original authentication results across forwarding/mailing-list hops|Useful when a message was relayed through an intermediary that would otherwise break SPF/DKIM — lets you see what the _original_ receiving server concluded|

**SPF record shorthand** (from DNS, not the email itself, but needed to interpret results): 
- `-all` = hard fail,
- `~all` = soft fail, 
- `?all` = neutral, 
- `+all` = allow-all (weak).

**DMARC policy shorthand:** `p=none` (monitor only), `p=quarantine` (spam folder), `p=reject` (block).

### Reading the trio together

|SPF|DKIM|DMARC|Read as|
|---|---|---|---|
|Pass|Pass|Pass|Strong legitimacy signal for the `From` domain|
|Fail|Pass|Depends|Sending IP not authorized — investigate the actual `Received` chain|
|Pass|Fail|Depends|Envelope sender authorized but signed content/domain mismatch — possible relay abuse|
|Fail|Fail|Fail (policy=reject but still delivered)|High-confidence spoofing indicator|

---

## 4. X-Headers (custom, provider/product-dependent)

|Header|What it gives you|Investigation use|
|---|---|---|
|**X-Originating-IP**|IP of the device that originated the message|Direct pivot to the sender's real origin, when present|
|**X-Mailer**|Client software used to compose/send|Can flag automation/scripted sending vs. a normal mail client|
|**X-Provider-Filter / X-*-SpamScore / etc.** (varies by vendor)|Provider's own spam/security verdict|Extra corroborating signal — always confirm the specific meaning with the product that generated it, since naming isn't standardized|

> X-Headers are **not standardized** — treat their exact meaning as vendor-specific and confirm before relying on them.

---

## 5. SEG (Secure Email Gateway) Log Fields — not headers, but the companion data source

These come from the gateway's own logs (SMTP logs, message tracking, content filtering, spam/malware, quarantine), not from the email itself:

|Field|Investigation use|
|---|---|
|SMTP server IP|Sending server reputation, spoofing checks|
|Sender / Recipient email address|Blacklist checks, incident scoping|
|Email subject|Behavioral indicators (urgency, role-mismatch)|
|Attached filename|Common malicious patterns (Invoice, Purchase Order, Important Note)|
|Attached file hash|Threat-intel lookup, fleet-wide hunt|
|Malware category|Family/type identified by the gateway|
|Attached URL|Phishing/malicious link analysis|
|Device action|Allowed / Blocked — did it actually reach the recipient?|
|Block reason|Why the gateway acted the way it did|

---

## Investigation Order (from the notes' workflow)

1. **Sender domain & SMTP server reputation** — known-malicious infrastructure check
2. **Spoofing validation** — compare `Received`/SMTP IP against domain's authorized infrastructure (SPF/DKIM/DMARC + MX/WHOIS)
3. **Sender behavior** — prior communication with recipient, sending pattern, role relevance
4. **Subject & attachment filename** — suspicious/commonly abused patterns
5. **Content analysis** — URLs (URL scanner/threat intel) and attachments (sandbox: process behavior, commands, network activity)
6. **Correlate everything** → Benign / Suspicious / Malicious

## Analyst heuristics

- **`From` is the least trustworthy header in the whole set** — it's user-facing and the easiest to spoof. Anchor your trust in `Received` chain + SPF/DKIM/DMARC instead.
- A **DKIM pass** is stronger evidence than an SPF pass alone, because it proves content integrity, not just that _some_ authorized server sent it.
- **Reply-To ≠ From** is one of the highest-value single tells for BEC — the victim's reply goes somewhere the attacker controls even though the message "looks" like it came from the right person.
- `References`/`Message-ID` chains matter most in **thread-hijacking BEC cases** — the attacker is riding a real conversation, so the sender/domain check alone won't catch it; you need to verify _where in the chain_ things changed.
- Authentication passing (SPF/DKIM/DMARC all green) is **necessary but not sufficient** — a compromised legitimate mailbox sending a real phishing link will pass all three perfectly.