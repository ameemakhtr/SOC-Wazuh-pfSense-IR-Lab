# Lab 01 — Wazuh SIEM Deployment & FIM Noise Reduction

## Objective
Deploy a functional Security Operations Center (SOC) monitoring baseline with a **Wazuh Manager** (Ubuntu Server) and a **Windows 11 Endpoint Agent**, then configure and tune **File Integrity Monitoring (FIM)** to detect real file tampering while filtering out benign system noise.

---

## Lab Architecture
- **Wazuh Manager & Dashboard:** Ubuntu Server (`192.168.1.10`)
- **Monitored Endpoint:** Windows 11 Pro (`windows11pro`) running Wazuh Agent

---

## FIM Configuration & Alert Fatigue Tuning

Real-time FIM tracking was enabled in `ossec.conf` targeting `C:\Users\User\Desktop\FIM_Test`, paired with `<ignore type="PCRE2">` rules to suppress noisy `.tmp` and `.log` extensions:

```xml
<syscheck>
  <disabled>no</disabled>
  <directories check_all="yes" realtime="yes">C:\Users\User\Desktop\FIM_Test</directories>
  <ignore type="PCRE2">\.tmp$</ignore>
  <ignore type="PCRE2">\.log$</ignore>
</syscheck>
```

*(Full validated configuration snippet: [`configs/wazuh/ossec-fim-syslog.xml`](../../configs/wazuh/ossec-fim-syslog.xml))*

---

## Validation & Evidence

1. **Positive Detection Tests (Create / Modify / Delete):**
   - Creating, modifying, and deleting `2nd_file.txt` inside `FIM_Test` generated immediate real-time SIEM alerts.
   - Sample normalized Wazuh alert JSON (Rule `553` — `File deleted.`):
     ```json
     {
       "index": "wazuh-alerts-4.x",
       "agent": { "name": "windows11pro" },
       "decoder": { "name": "syscheck_deleted" },
       "full_log": "File 'c:\\users\\user\\desktop\\fim_test\\2nd_file.txt' deleted Mode: realtime",
       "rule": {
         "id": "553",
         "description": "File deleted."
       }
     }
     ```
2. **Noise-Exclusion Test:**
   - Creating `noise.tmp` in the same monitored directory produced **zero** FIM alerts on the Wazuh Dashboard, confirming regex suppression worked without blinding alerts for non-temporary files.
