# Screenshots — Incident 01 (Phishing)

**Purpose:** Visual proof that complements [`../README.md`](../README.md): Windows authentication/process events, Office child processes, and SOAR enrichment.

**Master checklist (when / filenames):** [`../../SCREENSHOTS-GUIDE.md`](../../SCREENSHOTS-GUIDE.md) — section **Incident 01**.

---

## What to capture (order suggested)

### 1 — Security / authentication context

**When:** After you filter **Windows Security** (or imported EVTX) for the investigation window (**2026-04-10** ~14:21–14:25 UTC in the report).

**What:** Event IDs **4624** / **4625** (or your SIEM equivalent) showing logon activity around the phishing execution.

**Save as:** `01-event-viewer-security.png`

---

### 2 — Macro → PowerShell (high value)

**When:** After you find process creation evidence for the document chain.

**What:** **Sysmon Event ID 1** or **4688** showing **WINWORD.EXE** (or **EXCEL.EXE**) spawning **powershell.exe**; encoded **-enc** or **-e** command visible if possible.

**Save as:** `02-word-to-powershell.png`

---

### 3 — SOAR enrichment

**When:** After [`../../../soar-engine/`](../../../soar-engine/) is running and you **POST /analyze** with a C2 IP or file hash from [`../ioc-enrichment.md`](../ioc-enrichment.md).

**What:** Browser DevTools, Postman, or terminal **`curl`** output with **JSON** body showing **verdict**, **combined_score**, and at least one of **vt_score** / **abuse_score**.

**Save as:** `03-soar-enrichment.png`

---

## Tools

Windows **Event Viewer**, **Sysmon** log, or EDR UI; **curl** / Postman for SOAR.

## Minimum set for a strong portfolio

**02** + **03**. Add **01** if you have EVTX lab access.
