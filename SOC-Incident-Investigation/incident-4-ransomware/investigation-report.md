# Security Incident Response Report

**Incident Type:** Ransomware (Encryption + Recovery Inhibition)  
**Severity:** Critical  
**Affected Endpoint:** HR-LT-021 (10.20.18.21)  
**Impacted User:** ACME\\m.johnson  
**Detection Source:** EDR Ransomware Behavior Alert + File Server Audit Anomaly  
**Report Prepared By:** Security Operations Center (SOC)  

---

## Incident Summary

On **2026-03-11**, the SOC responded to a Critical EDR alert indicating ransomware-like behavior on **HR-LT-021**. Telemetry showed **Office spawning PowerShell** to download a script from an external host, followed by execution of a payload from a user-writable directory. The host attempted to **delete Volume Shadow Copies**, **disable recovery**, and **clear security logs**. File server auditing confirmed **mass file renames/encryption** on the HR file share with the extension **`.locked`** and the creation of a ransom note **`README_RESTORE_FILES.txt`**.

---

## Detection Source

- **EDR**: Behavioral ransomware detection (high-rate file modifications + shadow copy deletion + ransom note).
- **File Server Audit**: Burst of rename operations from a single workstation to a consistent encrypted extension.
- **Network Telemetry**: Outbound connections to suspicious infrastructure shortly after payload execution.

---

## Attack Timeline

| Time (UTC) | Event |
|------------|------|
| 03:14:07 | User opens `Invoice_March2026.docm` (WINWORD.EXE) |
| 03:14:19 | WINWORD spawns PowerShell with hidden window and download cradle |
| 03:15:02 | Payload executes from `AppData\\Roaming\\svchost.exe` |
| 03:14:33–03:14:40 | Shadow copy deletion, recovery disable, and security log clear commands executed |
| 03:15–03:18 | Ransom note created; files renamed/encrypted locally and on `\\\\FS-01\\HR$` |
| 03:18:44 | EDR raises Critical ransomware alert |
| 03:19+ | SOC containment begins (isolation + account actions + share lockdown) |

---

## Investigation Steps

1) **Validate alert fidelity**
- Reviewed EDR alert details and extracted the process chain.
- Confirmed ransomware behavior indicators: mass renames, ransom note, and recovery inhibition.

2) **Process & host triage**
- Identified initial execution: `.docm` opened by the user.
- Confirmed PowerShell download/execution and payload path in user profile.
- Reviewed commands executed:
  - `vssadmin delete shadows /all /quiet`
  - `bcdedit /set {default} recoveryenabled No`
  - `wevtutil cl Security`

3) **Scope and impact assessment**
- Queried file server audit logs to measure affected share path(s) and file counts.
- Searched SIEM for other hosts generating the same extension/ransom note.
- Reviewed network logs for other endpoints contacting the same IPs.

4) **Containment verification**
- Confirmed endpoint isolation and blocked outbound indicators at network controls.
- Confirmed no additional hosts showed active encryption patterns in the same time window.

---

## Root Cause

Most likely root cause is **malicious macro-enabled document execution** leading to PowerShell-based payload retrieval and execution, followed by ransomware encryption and recovery inhibition.

---

## Key Indicators of Compromise (IOC)

### Files / Artifacts
- Ransom note: `README_RESTORE_FILES.txt`
- Encrypted extension: `.locked`
- Payload path: `C:\\Users\\m.johnson\\AppData\\Roaming\\svchost.exe`

### Command Execution
- `vssadmin delete shadows /all /quiet`
- `bcdedit /set {default} recoveryenabled No`
- `wevtutil cl Security`

### Network Indicators
- Script hosting: `203.0.113.77` (HTTP)
- Suspected C2 / key exchange: `198.51.100.44` (TLS/443)

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|-------|-----------|----|----------|
| Execution | PowerShell | T1059.001 | PowerShell download cradle spawned by WINWORD |
| Initial Access | Phishing: Attachment | T1566.001 | User opened macro-enabled `.docm` attachment |
| Defense Evasion | Clear Windows Event Logs | T1070.001 | `wevtutil cl Security` |
| Impact | Inhibit System Recovery | T1490 | `vssadmin delete shadows` and `bcdedit` recovery disable |
| Impact | Data Encrypted for Impact | T1486 | Mass file renames to `.locked`, ransom note creation |

---

## Containment Actions

- Isolated **HR-LT-021** via EDR network containment.
- Disabled the user account session tokens and forced password reset (precaution).
- Blocked outbound connections to `203.0.113.77` and `198.51.100.44` at proxy/firewall.
- Temporarily restricted write access to `\\\\FS-01\\HR$` and took the share offline if active encryption continued.
- Preserved evidence (disk/memory capture if possible) before destructive remediation.

---

## Remediation Actions

### Endpoint remediation
- Reimage affected endpoint if encryption confirmed and integrity cannot be trusted.
- Remove malicious artifacts and persistence if identified.
- Restore impacted files from known-good backups; validate backup integrity prior to restore.

### Control improvements
- Disable/limit Office macros from the internet; implement ASR rules (Office → child process blocking).
- Constrain PowerShell (script block logging, AMSI, Constrained Language where feasible).
- Alert on recovery inhibition commands and mass file renames on file shares.
- Implement least privilege and tighter SMB share permissions to reduce blast radius.

---

## Outcome

Encryption activity was contained by isolating the endpoint and restricting access to the HR share. Network indicators were blocked and recovery procedures initiated using backups. Follow-on hunting did not identify additional encryption events in the simulated dataset.
