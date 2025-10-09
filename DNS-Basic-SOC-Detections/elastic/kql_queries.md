# Elastic KQL Queries

## SSH Brute Force (Linux)
event.dataset: "system.auth" and event.outcome: "failure" and process.name: "sshd"
# Use a 5m aggregation on source.ip and alert when count >= 10

## Windows 4625 Burst
event.code: "4625"

## Phishing - Link Clicks (M365 Advanced Hunting - KQL)
EmailUrlInfo
| where UrlDomain !in ("microsoft.com","office.com")
| summarize clicks=count() by RecipientEmailAddress, UrlDomain
| where clicks > 0

## Phishing - HTML Attachment Lure (Splunk example in splunk/)
# For Elastic, ingest messageTrace-equivalent and filter on attachment extension == html/htm

## DNS Tunneling - Long Names / TXT
dns.question.type: TXT or dns.question.registered_domain: * and event.dataset: "dns" and dns.question.name_length >= 80
