# SOC Lab: Wazuh SIEM, pfSense Firewall & Incident Response

Hands-on Blue Team SOC engineering and incident response lab portfolio covering SIEM deployment, FIM alert-fatigue tuning, pfSense Syslog integration, perimeter malware containment, **NIST SP 800-61 Rev. 2** response workflows, and isolated ransomware behavioral triage.

> **Author:** Ameem Akhtar  
> **Focus Areas:** SOC Operations, SIEM Tuning, Network Telemetry, Incident Response & Behavioral Triage

---

## Architecture Overview

```text
[Windows 11 Endpoint] ──(Wazuh Agent: FIM + Telemetry)──► [Wazuh Manager & Dashboard (192.168.1.10)]
                                                                       ▲
[Kali / LAN Endpoints] ──► [pfSense CE 2.8.1 (192.168.1.1)] ───────────┘
                              │   Syslog (UDP 514) + filterlog + DNSBL
                              ▼
                        [WAN / Perimeter Block Rules (GeoIP + IOC Aliases)]
```

---

## Lab Modules

| Lab | Module | Key Technologies & Outputs |
| :--- | :--- | :--- |
| **[Lab 01](./labs/01-wazuh-siem-fim/README.md)** | Wazuh SIEM & FIM Tuning | Ubuntu Wazuh Manager, Windows 11 Agent, `ossec.conf` FIM `PCRE2` exclusions (`\.tmp$`, `\.log$`), Rule `553` validation |
| **[Lab 02](./labs/02-pfsense-syslog-controls/README.md)** | pfSense CE & Syslog Integration | pfSense `2.8.1`, Syslog UDP `514` (`tcpdump` verified), `pfBlockerNG` MaxMind GeoIP Deny, `DNSBL` sinkhole (`10.10.10.1`), Admin-only WebGUI ACL |
| **[Lab 03](./labs/03-active-defense-nist-ir/README.md)** | Active Defense & NIST IR | EICAR edge block alias, custom Wazuh `filterlog` Rule `100903` (Level `12`), **NIST SP 800-61 Rev. 2** IR playbook |
| **[Lab 04](./labs/04-wannacry-behavioral-triage/README.md)** | WannaCry Behavioral Triage | Host-only VMware isolation, **IDA**, **Process Explorer**, **Procmon64**, **Regshot**, **FakeNet-NG** (Tor `127.0.0.1:9050`), **DumpIt** RAM acquisition |

---

## Repository Contents

* [`configs/wazuh/ossec-fim-syslog.xml`](./configs/wazuh/ossec-fim-syslog.xml) — Validated Wazuh Syslog (`UDP 514`) and Agent FIM regex-exclusion config snippets.
* [`configs/wazuh/local-rules-pfsense.xml`](./configs/wazuh/local-rules-pfsense.xml) — Custom Wazuh correlation rules (`100901`, `100903`) for pfSense `filterlog` blocks.
* [`scripts/validate_soc_lab.py`](./scripts/validate_soc_lab.py) — Python validator checking XML integrity, FIM regex suppression, and rule correlation.
* [`tests/test_validate_soc_lab.py`](./tests/test_validate_soc_lab.py) — Automated unit test suite.

---

## Verify Locally

```bash
# Validate XML configs, FIM regex rules, and rule correlation
python scripts/validate_soc_lab.py

# Run unit tests
python -m unittest discover -s tests -v
```

---

## Disclaimer & Safety

All malware triage and simulated block exercises were performed in isolated, Host-only lab VMs. No malware binaries, raw memory dumps, or production credentials/IPs are stored in this repository.
