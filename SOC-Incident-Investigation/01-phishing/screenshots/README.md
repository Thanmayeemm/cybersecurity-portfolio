# Screenshots — Incident 01 (Phishing)

**Purpose:** Store visual evidence that complements the written investigation (for example SIEM triage views, EVTX Event Viewer, or SOAR dashboard after enrichment).

**Suggested captures**

1. **Security log:** Windows Event Viewer or exported view showing Event ID **4625** / **4624** sequences around the phishing execution window.
2. **Process creation:** Microsoft-Windows-Sysmon/Operational or EDR view showing **WINWORD.EXE** spawning **powershell.exe** with encoded command line.
3. **SOAR engine:** Browser or API client (`POST /analyze`) showing enrichment JSON for the C2 IP and attachment hash from [`../ioc-enrichment.md`](../ioc-enrichment.md).

**Tools:** Windows Event Viewer, Sysinternals Process Explorer (optional), browser or `curl` for the SOAR API, terminal for CLI queries documented in [`../queries.md`](../queries.md).

**Filename convention:** `01-triage-evtx.png`, `02-office-child-process.png`, `03-soar-analyze.png`.
