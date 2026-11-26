# Lab 03 — Perimeter Malware Blocking & NIST SP 800-61 Incident Response

## Objective
Simulate an unauthorized payload download attempt from an isolated lab endpoint, block the egress connection at the pfSense edge, correlate the `filterlog` drop in Wazuh as a **Level 12** alert, and document a structured **NIST SP 800-61 Rev. 2** incident response playbook.

---

## Lab Configuration & Correlation
1. **Firewall Alias & Top-Priority LAN Rule:**
   - Defined an alias (`EICAR`) targeting the test malware hosting endpoint (`eicar.org` / `89.238.73.97`).
   - Placed a top-priority LAN block rule (`Possible Malware Download Blocked`) with logging enabled to drop IPv4 TCP traffic before handshake completion.
2. **Test Execution:**
   - From the isolated Kali Linux lab endpoint (assigned `192.168.1.100` in this test session), requested `http://www.eicar.org/download-anti-malware-testfile/` (redirecting to HTTPS port `443/TCP`).
   - Browser immediately timed out while pfSense `filterlog` logged blocked packets to `89.238.73.97:443`.
3. **Wazuh SIEM Correlation (`Rule ID 100903`, `Level 12`):**
   - Custom Wazuh correlation rules ([`configs/wazuh/local-rules-pfsense.xml`](../../configs/wazuh/local-rules-pfsense.xml)) matched `action=block` and `dstip=89.238.73.97`, generating a Level 12 alert (`Malware Download Attempt Blocked by pfSense`).

---

## Extracted Indicators

| Type | Indicator | Notes |
| :--- | :--- | :--- |
| **Domain** | `eicar.org` | Benign AV test hosting domain |
| **Test URL** | `http://www.eicar.org/download-anti-malware-testfile/` | Redirects to HTTPS (`443/TCP`) |
| **Destination IP / Port** | `89.238.73.97` (`443/TCP`) | Blocked at LAN egress |
| **Source Lab IP** | `192.168.1.100` | Isolated Kali Linux test endpoint |

---

## NIST SP 800-61 Rev. 2 Incident Response Playbook

1. **Detection & Analysis:**
   - Alert triggered in real time by pfSense `filterlog` and escalated by Wazuh (`Rule ID 100903`, `Level 12`).
   - Analyst verifies `data.action=block`, `srcip=192.168.1.100`, and `dstip=89.238.73.97` to confirm zero bytes transferred post-SYN.
2. **Containment:**
   - Achieved automatically at the network perimeter via the top-priority pfSense block rule; confirmed zero active firewall states in the pfSense state table.
3. **Eradication:**
   - Because ingress payload delivery was blocked at Layer 3/4, no payload landed on disk; perform a precautionary host AV/EDR scan to rule out out-of-band vectors (e.g., USB).
4. **Recovery:**
   - No host re-imaging required; place the source IP (`192.168.1.100`) on a 24-hour Wazuh watchlist for repeated outbound attempts.
5. **Post-Incident Activity:**
   - Review root cause with the endpoint operator (accidental phishing click vs. policy bypass) and evaluate adding the domain to pfBlockerNG `DNSBL` to block at DNS resolution before reaching Layer 3/4 rules.
