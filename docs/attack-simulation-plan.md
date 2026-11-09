# Attack Simulation Plan

> ⚠️ Run every activity **only inside your isolated lab**, against VMs you own. Revert to the clean snapshot after each run.

| # | Technique | Tool (lab only) | MITRE | Target | Expected detection | PCAP |
|---|-----------|-----------------|-------|--------|--------------------|------|
| 1 | Port scan | Nmap | T1046 | 10.10.20.0/24 | Suricata `LAB TCP SYN port scan` | `pcaps/01-portscan.pcap` |
| 2 | SSH brute force | Hydra | T1110 | Ubuntu | Suricata SSH rule + Sigma `lnx_sshd_failed_password` | `pcaps/02-ssh-bruteforce.pcap` |
| 3 | RDP brute force | Hydra | T1110 | Windows | Suricata RDP rule + Sigma `win_failed_logon_bruteforce` | `pcaps/03-rdp-bruteforce.pcap` |
| 4 | DNS tunneling | dnscat2 / iodine | T1071.004 | Ubuntu → lab DNS | Suricata `LAB DNS long query` | `pcaps/04-dns-tunnel.pcap` |
| 5 | C2 beaconing | Sliver / Metasploit | T1071 | Windows | `scripts/beacon_detector.py` on Zeek conn.log | `pcaps/05-beacon.pcap` |
| 6 | Lateral movement | Atomic Red Team | T1021 | Windows | Sigma `win_remote_service_install`, `win_rdp_logon_from_lab_attacker` | `pcaps/06-lateral.pcap` |
| 7 | Payload download | Simulated web server | T1566 / T1105 | Windows | Suricata `LAB PE download`, Sigma `win_certutil_download` | `pcaps/07-download.pcap` |
| 8 | Encoded PowerShell | Atomic Red Team T1059.001 | T1059.001 | Windows | Sigma `win_powershell_encoded_command` | n/a (host logs) |

## Capture procedure (on the sensor)
```bash
sudo tcpdump -i eth1 -w pcaps/raw/02-ssh-bruteforce.pcap host 10.10.20.30
# run the attack, stop capture with Ctrl+C, then trim to < 50 MB:
editcap -c 50000 pcaps/raw/02-ssh-bruteforce.pcap pcaps/02-ssh-bruteforce.pcap
```

## Run log (fill in for each attack)
| # | Date/time (UTC) | Tool + version | Command summary | Expected | Observed | Alert fired? | Notes |
|---|-----------------|----------------|-----------------|----------|----------|--------------|-------|
| 1 | | | | | | | |
| 2 | | | | | | | |
| 3 | | | | | | | |
| 4 | | | | | | | |
| 5 | | | | | | | |
| 6 | | | | | | | |
| 7 | | | | | | | |
| 8 | | | | | | | |
