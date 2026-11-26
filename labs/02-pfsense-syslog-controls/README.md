# Lab 02 — pfSense CE Integration, GeoIP Blocking & DNS Sinkholing

## Objective
Deploy **pfSense CE 2.8.1** at the lab network perimeter, forward firewall/system/DNS telemetry to Wazuh SIEM via **Syslog (UDP 514)**, and enforce preventive perimeter and management access controls.

---

## Network Topology
- **WAN Interface:** NAT (upstream lab gateway)
- **LAN Interface:** `192.168.1.1/24` (internal gateway)
- **SIEM Collector:** Wazuh Manager (`192.168.1.10`) listening on UDP `514`
- **Admin Workstation:** `192.168.1.100`

---

## Implemented Controls

### 1. Centralized Syslog Forwarding (`UDP 514`)
- Enabled pfSense Remote Logging (`Everything`: Firewall, System, DNS events) targeting the Wazuh Manager (`192.168.1.10:514`).
- Verified live UDP 514 syslog ingestion on the Wazuh Manager interface using **`tcpdump`** and confirmed `<remote>` ingestion rules in [`configs/wazuh/ossec-fim-syslog.xml`](../../configs/wazuh/ossec-fim-syslog.xml).

### 2. GeoIP Blocking (`pfBlockerNG-devel` + MaxMind GeoIP)
- Configured **Deny Both** (inbound & outbound) rules for high-risk country IP blocks (`CN`, `RU`) to reduce exposure to unsolicited scanning and external C2 traffic.

### 3. DNS Sinkholing (`DNSBL`)
- Configured DNS Blackhole Lists (`DNSBL`) to intercept restricted domain lookups (e.g., social media AUP categories such as Facebook and TikTok) and resolve them to a local sinkhole Virtual IP (`10.10.10.1`).

### 4. Administrative Access Isolation (Least Privilege)
- Configured LAN firewall rules restricting **pfSense WebGUI** management strictly to the designated admin host (`192.168.1.100`) and blocking administrative access from all other internal LAN hosts.

---

## Verification
- Generated test blocked requests and DNS sinkhole hits, confirming real-time firewall drop telemetry appeared inside the Wazuh Dashboard alongside pfSense system logs.
