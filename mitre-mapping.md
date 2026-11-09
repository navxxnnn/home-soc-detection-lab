# MITRE ATT&CK Mapping

| Tactic | Technique | ID | Simulated with | Detection | Data source | Report |
|--------|-----------|----|----------------|-----------|-------------|--------|
| Discovery | Network Service Discovery | T1046 | Nmap | Suricata sid 1000010 | Network traffic | [IR-01](reports/01-port-scan.md) |
| Credential Access | Brute Force | T1110 | Hydra (SSH) | Suricata sid 1000001, Sigma `lnx_sshd_failed_password` | Network + auth.log | [IR-02](reports/02-ssh-brute-force.md) |
| Credential Access | Brute Force | T1110 | Hydra (RDP) | Suricata sid 1000002, Sigma `win_failed_logon_bruteforce` | Network + Security 4625 | |
| Command and Control | Application Layer Protocol: DNS | T1071.004 | dnscat2 / iodine | Suricata sid 1000020, 1000021 | DNS | |
| Command and Control | Application Layer Protocol | T1071 | Sliver / Metasploit | `scripts/beacon_detector.py` | Zeek conn.log | [IR-03](reports/03-c2-beaconing.md) |
| Lateral Movement | Remote Desktop Protocol | T1021.001 | Atomic Red Team | Sigma `win_rdp_logon_from_lab_attacker` | Security 4624 | |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | Atomic Red Team | Sigma `win_remote_service_install` | System 7045 | |
| Execution | PowerShell | T1059.001 | Atomic Red Team | Sigma `win_powershell_encoded_command` | Sysmon 1 / 4688 | |
| Command and Control | Ingress Tool Transfer | T1105 | Simulated web server, certutil | Suricata sid 1000030, 1000031, Sigma `win_certutil_download` | HTTP + process creation | |
| Initial Access | Phishing | T1566 | Simulated web server | Suricata sid 1000031 | HTTP | |
