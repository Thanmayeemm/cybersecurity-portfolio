# Screenshot checklist — SOC Incident Investigation Lab

Use this list when building **visual evidence** for your portfolio. Save images under each incident’s **`screenshots/`** folder using the **suggested filenames** so your reports stay easy to navigate.

**General tips**

- **When:** Capture **after** you can reproduce the step (same terminal history, SOAR running, or Event Viewer filtered).
- **What to show:** Window title, command, and **enough output** to be credible; crop empty desktop space.
- **Redaction:** Blur API keys, real internal hostnames, or personal email if needed; keep IOCs consistent with the written report.
- **Format:** PNG preferred; **1080p width** or wider is fine.
- **Tools:** Windows Snipping Tool / `Win+Shift+S`, macOS screenshot, or Linux `gnome-screenshot`.

---

## Incident 01 — Phishing (`01-phishing/screenshots/`)

| # | When (in your workflow) | What to capture | Suggested filename |
|---|-------------------------|-------------------|---------------------|
| 1 | After opening a relevant Security log or EVTX in Event Viewer | Filtered view showing **4624/4625** or process **4688** around the phishing window | `01-event-viewer-security.png` |
| 2 | After locating macro → PowerShell evidence | **Sysmon Event ID 1** or **4688** showing **WINWORD.EXE** → **powershell.exe** (encoded command visible if possible) | `02-word-to-powershell.png` |
| 3 | After calling SOAR for an IOC from [`ioc-enrichment.md`](./01-phishing/ioc-enrichment.md) | Browser **or** terminal: `curl` POST to `/analyze` with **pretty-printed JSON** (verdict + scores) | `03-soar-enrichment.png` |

**Minimum viable portfolio:** shots **2** and **3** if you lack a full EVTX lab.

---

## Incident 02 — Brute force (`02-brute-force/screenshots/`)

| # | When | What to capture | Suggested filename |
|---|------|-------------------|---------------------|
| 1 | In **WSL** or Linux, after `export AUTH_LOG=.../logs/sample-auth.log` | Terminal: **Step 2** from [`queries.md`](./02-brute-force/queries.md) — **failed attempts per IP** (`uniq -c` output showing **203.0.113.15** on top) | `01-failed-per-ip.png` |
| 2 | Same session | Terminal: **Accepted password** line for **user1** (`grep Accepted`) | `02-accepted-password.png` |
| 3 | With SOAR API up | `curl` or Swagger/Postman: enrichment JSON for **203.0.113.15** | `03-soar-ip-enrichment.png` |

---

## Incident 03 — Ransomware (`03-ransomware/screenshots/`)

| # | When | What to capture | Suggested filename |
|---|------|-------------------|---------------------|
| 1 | In Event Viewer or SIEM on dataset | Multiple **file rename** / encryption-related events in a short time window | `01-mass-file-events.png` |
| 2 | Same investigation | **vssadmin**, **wbadmin**, or **bcdedit** process/command events (shadow copy / recovery tampering) | `02-recovery-inhibition.png` |
| 3 | SOAR enrichment | JSON for ransomware **hash** and/or **C2 domain** from [`ioc-enrichment.md`](./03-ransomware/ioc-enrichment.md) | `03-soar-ransomware-iocs.png` |

---

## Incident 04 — Data exfiltration (`04-data-exfiltration/screenshots/`)

| # | When | What to capture | Suggested filename |
|---|------|-------------------|---------------------|
| 1 | Running CLI from [`queries.md`](./04-data-exfiltration/queries.md) on CSV or log | Terminal: **large outbound** or **staging path** evidence (e.g. `grep`/`awk` on transfer size or IP) | `01-exfil-cli-summary.png` |
| 2 | Optional SIEM | Chart or table: **bytes out** to external IP **203.0.113.200** (or your report’s IOC) | `02-siem-outbound-volume.png` |
| 3 | SOAR | Enrichment for destination **IP/domain** | `03-soar-exfil-ioc.png` |

---

## Incident 05 — Malware infection (`05-malware-infection/screenshots/`)

| # | When | What to capture | Suggested filename |
|---|------|-------------------|---------------------|
| 1 | In Wireshark / tshark on **analyst VM** (PCAP from Malware Traffic Analysis; password: **infected**) | **Follow TCP stream** or **conversation** to C2 (IP:port visible) | `01-wireshark-c2.png` |
| 2 | From EDR or logs | Process tree **rundll32** / **regsvr32** or suspicious parent | `02-process-tree.png` |
| 3 | SOAR | Enrichment for malware **hash** and C2 **IP** | `03-soar-malware-iocs.png` |

---

## Incident 06 — Insider threat (`06-insider-threat/screenshots/`)

| # | When | What to capture | Suggested filename |
|---|------|-------------------|---------------------|
| 1 | After running time-based query from [`queries.md`](./06-insider-threat/queries.md) | Terminal: **after-hours** access lines or volume anomaly | `01-after-hours-access.png` |
| 2 | Optional | Cloud/admin or SIEM view: **sensitive path** or **large export** | `02-sensitive-access.png` |
| 3 | SOAR | Enrichment for destination IP if used in report | `03-soar-insider-ioc.png` |

---

## Linking screenshots in GitHub

1. Commit PNGs into **`screenshots/`** (or use Git LFS if files are huge).
2. In each incident **`README.md`**, the **Visual evidence** section points readers here.
3. Optional: embed in README with `![description](screenshots/01-failed-per-ip.png)` — only if you want images inline.

---

*This guide is part of the SOC Incident Investigation Lab portfolio.*
