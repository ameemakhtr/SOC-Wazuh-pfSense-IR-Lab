# SOC Lab: Wazuh SIEM, pfSense Firewall & Incident Response

[![CI](https://github.com/ameemakhtr/SOC-Wazuh-pfSense-IR-Lab/actions/workflows/ci.yml/badge.svg)](https://github.com/ameemakhtr/SOC-Wazuh-pfSense-IR-Lab/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

Hands-on Blue Team SOC engineering and incident response lab portfolio covering SIEM deployment, FIM alert-fatigue tuning, pfSense Syslog integration, perimeter malware containment, **NIST SP 800-61 Rev. 2** response workflows, and isolated ransomware behavioral triage.

> **Author:** Ameem Akhtar  
> **Focus Areas:** SOC Operations, SIEM Tuning, Network Telemetry, Incident Response & Behavioral Triage

---

## Problem Statement & Objective

Default SIEM and firewall deployments generate noisy File Integrity Monitoring (FIM) alerts from temporary OS/application writes while leaving perimeter block logs disconnected from endpoint visibility. This lab builds an integrated **SOC telemetry pipeline** pairing Wazuh SIEM with pfSense Syslog ingestion, `PCRE2` FIM noise filtering, automated correlation rules, and repeatable NIST SP 800-61 containment playbooks—verified offline by an automated XML and rule-matching validator.

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

* **Lab Modules & Playbooks:** [`labs/01`](./labs/01-wazuh-siem-fim/README.md) through [`labs/04`](./labs/04-wannacry-behavioral-triage/README.md) — Documented Wazuh, pfSense, NIST SP 800-61 IR, and WannaCry VM analysis labs.
* [`configs/wazuh/ossec-fim-syslog.xml`](./configs/wazuh/ossec-fim-syslog.xml) — Wazuh Syslog (`UDP 514`) and Agent FIM regex-exclusion config snippets.
* [`configs/wazuh/local-rules-pfsense.xml`](./configs/wazuh/local-rules-pfsense.xml) — Custom Wazuh correlation rules (`100901`, `100903`) for pfSense `filterlog` blocks.
* **Supporting Verification Utility:** [`scripts/validate_soc_lab.py`](./scripts/validate_soc_lab.py) & [`tests/test_validate_soc_lab.py`](./tests/test_validate_soc_lab.py) — Offline helper scripts validating XML syntax, FIM regex patterns, and sample rule matching in CI.

---

## Verify Locally

```bash
# Validate XML configs, FIM regex rules, and rule correlation
python scripts/validate_soc_lab.py

# Run unit tests
python -m unittest discover -s tests -v
```

---

## Results & Key Conclusions

* **Noise Suppression Verified:** PCRE2 `<ignore>` rules suppressed benign `.tmp` and `.log` filesystem writes while preserving real-time Rule `553` alerts on actual file deletions.
* **Perimeter-to-SIEM Visibility:** Routing pfSense `filterlog` telemetry over UDP `514` enabled real-time correlation (`Rule 100903`, Level `12`) against simulated EICAR egress blocks alongside GeoIP (`pfBlockerNG`) and `DNSBL` (`10.10.10.1`) controls.
* **Ransomware Forensics Grounding:** Isolated WannaCry execution mapped child-process spawning (`tasksche.exe`, `@WanaDecryptor@.exe`), `.WNCRYT` encryption, Run-key persistence, Tor proxy connections (`127.0.0.1:9050`), and volatile RAM capture (`DumpIt`), confirming `MS17-010` patching and SMBv1 removal as core remediations.
* **Automated Config Integrity:** `validate_soc_lab.py` and 3 unit tests validate all XML snippets and correlation rules cleanly in GitHub Actions CI.

---

## Disclaimer & Safety

All malware triage and simulated block exercises were performed in isolated, Host-only lab VMs. No malware binaries, raw memory dumps, or production credentials/IPs are stored in this repository.
