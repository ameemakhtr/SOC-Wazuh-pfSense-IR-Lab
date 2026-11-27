# Lab 05 — 2024–2026 Breach Intelligence, Zero Trust & ITDR Strategy

## Objective
Synthesize major 2024–2026 cyber breach and ransomware disclosures to map recurring initial-access and extortion patterns into proactive defensive architectures: **Zero Trust Architecture**, **Identity Threat Detection and Response (ITDR)**, **Vendor Risk Management**, and **OT/IT Segmentation**.

---

## Key Threat Patterns Observed (2024–2026)

* **Cloud Identity & Infostealer Exploitation (`ShinyHunters / Scattered Spider / UNC5537`):**
  * Targeted SaaS and cloud data platforms (such as Snowflake and Salesforce environments lacking universal MFA) using harvested credentials and misconfigured OAuth/third-party apps (e.g., *Ticketmaster May 2024*, *Qantas Jun 2025*).
* **Third-Party Vendor & Support Compromise:**
  * Compromised outsourced vendors or partner platforms as indirect entry vectors into core enterprise networks and loyalty systems (e.g., *Harrods Nov 2025*, *Crunchyroll Mar 2026*).
* **Operational Ransomware & Double Extortion (`SafePay`, `Black Basta`, `ALPHV`):**
  * Disrupted manufacturing, logistics, food distribution, and education sectors via IT/OT propagation and follow-up extortion demands (e.g., *PowerSchool Dec 2024*, *UNFI Jun 2025*, *Ingram Micro Jul 2025*, *Jaguar Land Rover Sep 2025*).
* **State-Sponsored Espionage & Disruptive Wipers:**
  * Long-dwell telecommunications espionage (*Salt Typhoon*) alongside destructive wiper campaigns targeting industrial infrastructure.

---

## Strategic Defensive Controls

1. **Zero Trust Architecture:** Assume continuous breach conditions by eliminating implicit network trust and requiring strict verification before allowing lateral movement.
2. **Identity Threat Detection & Response (ITDR):** Enforce phishing-resistant MFA across all centralized cloud platforms, monitor anomalous session tokens, and flag infostealer-linked credential activity.
3. **Vendor Risk Management:** Continuously audit third-party API permissions, vendor SSO access, and partner device posture before granting internal collaboration/CRM access.
4. **OT/IT Network Segmentation:** Isolate Operational Technology (OT) and manufacturing systems from general corporate IT networks so workstation infections cannot halt physical operations.
