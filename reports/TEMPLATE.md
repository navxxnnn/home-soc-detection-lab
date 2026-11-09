# Investigation Report: <ATTACK NAME>

| Field | Value |
|-------|-------|
| Report ID | IR-00X |
| Date (UTC) | YYYY-MM-DD |
| Analyst | Naveen Kumar H |
| Severity | Low / Medium / High |
| MITRE ATT&CK | Txxxx - Name |
| Status | Closed (lab simulation) |

## 1. Summary (what)
Two or three sentences: what happened, which host, how it was detected.

## 2. Timeline (when)
| Time (UTC) | Source | Event |
|------------|--------|-------|
| | Suricata | |
| | Zeek | |
| | Wazuh / Sysmon | |

## 3. Technical analysis (how)
- Attack path and tool used
- Key log lines / alert JSON (sanitized)
- Screenshot: `../docs/screenshots/xx.png`

## 4. Indicators of compromise
| Type | Value | Notes |
|------|-------|-------|
| IP | 10.10.10.10 | Lab attacker |
| Port | | |
| User agent / hash / domain | | |

## 5. Detection logic
- Rule(s) that fired: `sid:` / Sigma title
- Why it works
- False positives observed and tuning applied

## 6. Impact
What an attacker would have gained in a real environment.

## 7. Response recommendation (fix)
- Containment
- Eradication
- Prevention (hardening, MFA, rate-limiting, egress filtering...)

## 8. Lessons learned
What failed, what you tuned, what you would improve.
