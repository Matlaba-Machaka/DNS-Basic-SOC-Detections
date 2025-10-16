# SOC Playbooks Pack
Brute-Force • Phishing • DNS Tunneling

## Shared SOP (applies to all)
**Severity rubric**
- Sev1: Confirmed compromise or lateral movement
- Sev2: Valid attack attempt w/ user impact likely
- Sev3: Suspicious/benign or blocked attempt

**Ticket fields**
`Alert ID`, `Source (SIEM/EDR/SEG)`, `Owner`, `Severity`, `Assets/Users`, `Time window`, `IOC list`, `Actions taken`, `Status`, `MITRE tags`

**Evidence pack**
Raw logs (JSON/CSV), screenshots, PCAPs, hashes, domains/URLs, headers, query exports

**Comms templates**
User notice (clickers), IT ops block request, Management summary (3–5 bullets)

**MTTR targets**
Triage ≤ 15 min • Containment ≤ 60 min • Close ≤ 24–48 h

---

## 1) Brute-Force Login (SSH/Windows)

### Triggers / Data
- >X failed logins from one IP in Y minutes; credential-stuffing pattern across many users  
- Sources: auth.log / Windows Security, VPN/IdP, FW/WAF

### Quick checks (10–15 min)
1) Confirm burst (src IP / user spray / geo-impossible)  
2) Any **successful** login on targeted accounts?  
3) IP reputation (known bad / DC)  
4) MFA status for targeted accounts

### Actions
- **Contain:** Block IP/ASN; throttle; lock accounts; enforce MFA / rotate creds  
- **If success:** Isolate host; collect artifacts; review lateral movement (4624/4672, new services, RDP)  
- **Recover:** Re-enable accounts w/ MFA; change requests  
- **LL:** Tune thresholds; geo/ASN blocks if acceptable

### Detections
- Splunk / Elastic / Sigma provided in repo folders.

---

## 2) Phishing Email

### Triggers / Data
- User-reported phish; SEG flagged; surge in identical emails  
- Sources: O365/Exchange, SEG, EDR browser, IdP sign-ins

### Quick checks (10–15 min)
1) Headers: SPF/DKIM/DMARC, Return-Path, Reply-To mismatch  
2) Indicators: brand spoof, urgency, credential lure, HTML attachments, lookalikes  
3) Safe detonation (sandbox) for URLs/attachments  
4) Who received? Who **clicked/executed**?

### Actions
- **Contain:** Purge/recall campaign; block sender/domain; URL rewrite block; SEG rule  
- **If click:** Reset password & revoke tokens; MFA reset; EDR scan/isolate  
- **Recover:** Awareness note to recipients  
- **LL:** Add domain to watch; write lookalike detection

---

## 3) DNS Tunneling / Exfil

### Triggers / Data
- Excessive TXT queries, very long subdomains, high NXDOMAIN rate, odd destinations  
- Sources: DNS resolver, firewall, EDR network, PCAP

### Quick checks (15 min)
1) Features: label > 50 chars, fqdn > 100, many unique subdomains, high TXT ratio  
2) Baseline: known app (EDR/backup/CDN)?  
3) Affected hosts, process names, time of day

### Actions
- **Contain:** Block parent domain; enforce egress DNS to corp resolver; isolate host if beaconing  
- **Eradicate:** Remove tunneling tool/malware; rotate creds/API keys  
- **Recover:** DNS policy (no external resolvers); add monitoring thresholds  
- **LL:** Add domain intel + length/NX thresholds

---

## Metrics (per ticket)
- Triage time, Containment time, MTTR  
- Users/Hosts affected  
- False positive? (Y/N) + reason  
- New detection/tuning created? (Y/N)

## Escalation Matrix (example)
- **Sev1**: Incident Commander + IR lead + IT Ops bridge (immediate)  
- **Sev2**: IR on-call + Service owner ≤ 1 h  
- **Sev3**: SOC queue; daily summary

## Automation Ideas
- Auto-enrich IPs/domains with TI and attach to ticket  
- One-click IP block / user disable via SOAR  
- Auto-notify phish clickers with reset-password link
