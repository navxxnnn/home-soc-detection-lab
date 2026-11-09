# Lab Setup Guide

## 1. Hardware and host
| Item | Minimum | Recommended |
|------|---------|-------------|
| RAM | 16 GB | 32 GB |
| CPU | 4 cores | 8 cores |
| Free disk | 150 GB | 250 GB SSD |
| Hypervisor | VirtualBox 7 | VMware Workstation / Proxmox |

## 2. IP plan
| Network | Purpose | Subnet | Hypervisor network |
|---------|---------|--------|--------------------|
| Attacker | Kali | 10.10.10.0/24 | Internal network `lab-attacker` |
| Victim/Server | Windows + Linux victims | 10.10.20.0/24 | Internal network `lab-victim` |
| Monitoring | Sensor + SIEM | 10.10.30.0/24 | Internal network `lab-monitor` |
| Management | Your browser → SIEM UI | Host-only | Host-only adapter |

| VM | vCPU | RAM | Disk | IP |
|----|------|-----|------|----|
| pfSense / OPNsense | 1 | 1 GB | 16 GB | .1 on each lab net |
| Kali Linux | 2 | 2–4 GB | 40 GB | 10.10.10.10 |
| Windows 10/11 victim | 2 | 4 GB | 60 GB | 10.10.20.20 |
| Ubuntu server victim | 1 | 2 GB | 25 GB | 10.10.20.30 |
| Security Onion (eval) **or** Ubuntu + Zeek + Suricata | 4 | 12 GB* | 200 GB | 10.10.30.10 |
| Wazuh (if not using Security Onion) | 2 | 4 GB | 50 GB | 10.10.30.20 |

\* On a 16 GB host, use the lighter path: Ubuntu + Zeek + Suricata (4 GB) and Wazuh (4 GB) instead of Security Onion.

## 3. Build order
1. **Firewall:** Install pfSense/OPNsense with one NIC per lab network. Allow Attacker → Victim; block all lab networks → internet once tools are installed.
2. **Victims:** Install Windows and Ubuntu. On Windows install **Sysmon** (SwiftOnSecurity or Olaf Hartong config) and enable PowerShell Script Block Logging. Enable SSH on Ubuntu.
3. **Sensor:** Give the sensor a second NIC with **promiscuous mode = Allow All** on `lab-victim`. On VirtualBox: *Settings → Network → Adapter → Advanced → Promiscuous Mode: Allow All*.
4. **Suricata + Zeek:** Point both at the sniffing interface. Copy `rules/suricata/local.rules` into the Suricata rules directory and add it to `suricata.yaml` under `rule-files`. Set `HOME_NET: "[10.10.20.0/24]"`.
5. **SIEM:** Install Wazuh agents on both victims; ship Suricata `eve.json` and Zeek logs to Wazuh/Elastic.
6. **Validate:** From Kali, run `ping` and `nmap -sn 10.10.20.0/24`. You should see traffic in Zeek `conn.log` and at least one alert in the dashboard. **Do not continue until logs flow.**
7. **Snapshot every VM** (“clean-baseline”) so you can reset after each attack.

## 4. Screenshots to capture (save in `docs/screenshots/`)
- [ ] Hypervisor network config
- [ ] pfSense interfaces and rules
- [ ] Sensor interface in promiscuous mode
- [ ] First alert visible in SIEM
- [ ] Wazuh agents connected

## 5. Testing a Suricata rule offline
```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -S rules/suricata/local.rules   # syntax test
suricata -r pcaps/ssh-bruteforce.pcap -S rules/suricata/local.rules -l ./out    # replay PCAP
grep '"event_type":"alert"' out/eve.json | jq '.alert.signature' | sort | uniq -c
```
