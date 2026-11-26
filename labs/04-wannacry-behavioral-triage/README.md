# Lab 04 — WannaCry Ransomware Behavioral Triage & RAM Acquisition

> **Safety Note:** All dynamic analysis was executed strictly inside an isolated, **Host-only** VMware Windows 11 virtual machine with zero external network connectivity and snapshot rollback enabled. No malware samples are included in this repository.

---

## Tools Used
- **Static Triage & Disassembly:** PowerShell (`Get-FileHash`), **IDA**
- **Host Behavioral Monitoring:** **Process Explorer**, **Procmon64**, **Regshot**
- **Network Simulation:** **FakeNet-NG**, `netstat`
- **Volatile Memory Acquisition:** **DumpIt** (`Comae-Toolkit`)

---

## 1. Static Identification
- Verified sample hash via PowerShell:
  - **SHA-256:** `ED01EBFBC9EB5BBEA545AF4D01BF5F1071661840480439C6E5BABE8E080E41AA`
- Disassembly in **IDA** highlighted heavy `KERNEL32.dll` file-I/O imports (`CreateFileA`, `WriteFile`) consistent with mass file encryption routines.

---

## 2. Dynamic Behavioral Findings (Isolated VM)
- **Process Tree Spawning (`Process Explorer`):** Observed dropper spawning `tasksche.exe`, `taskhsvc.exe`, and `@WanaDecryptor@.exe`.
- **File Encryption (`Procmon64`):** Captured `SetRenameInformationFile` operations appending the `.WNCRYT` extension across user documents.
- **Registry Persistence (`Regshot` / `Procmon64`):** Observed Run-key persistence written to:
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\haxybydlxrggmjg341` -> `"C:\Users\User\Desktop\tasksche.exe"`
- **Recovery Sabotage:** Observed `cmd.exe` invocations deleting Volume Shadow Copies (VSS) and disabling Windows recovery options.
- **Simulated C2 / Tor Proxy (`FakeNet-NG`):** Intercepted outbound proxy connection attempts targeting **`127.0.0.1:9050`** (Tor SOCKS proxy traffic) and port `443`.

---

## 3. Volatile Memory Acquisition (`DumpIt`)
- Acquired full physical RAM (`4,094 MB`) using `DumpIt.exe` (`3.6.20230117`) while the infection was active to preserve volatile process, key, and socket artifacts before containment/wipe.

---

## 4. Enterprise Incident Response & Containment Playbook
1. **Containment:** Immediately isolate the host from the network (disable NIC / unplug Ethernet) to halt **SMBv1 (`MS17-010` / EternalBlue)** lateral movement while preserving volatile memory (do not power off before RAM acquisition).
2. **Eradication:** Terminate malicious process trees (`tasksche.exe`, `@WanaDecryptor@.exe`) and remove persistent `HKCU\...\Run` entries.
3. **Recovery:** Re-image the compromised host from clean gold media and restore data strictly from offline, immutable backups (local shadow copies are destroyed).
4. **Remediation:** Apply Microsoft security patch **MS17-010** enterprise-wide and disable legacy **SMBv1** across all endpoints.
