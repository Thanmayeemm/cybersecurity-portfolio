# Screenshots — Incident 03 (Ransomware)

**Purpose:** Evidence of **mass file impact**, **recovery inhibition** commands, and **SOAR** results for binary/C2 IOCs.

**Master checklist:** [`../../SCREENSHOTS-GUIDE.md`](../../SCREENSHOTS-GUIDE.md) — section **Incident 03**.

---

## What to capture

### 1 — Mass encryption / rename activity

**When:** After loading **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)** ransomware-related EVTX in Event Viewer or SIEM.

**What:** Multiple file events (renames, mass modifications) in a **short** time window; include column headers or filter bar.

**Save as:** `01-mass-file-events.png`

---

### 2 — Recovery inhibition

**When:** After filtering for process/command lines containing **vssadmin**, **wbadmin**, **bcdedit**, or **wevtutil** (per your dataset).

**What:** At least one event showing **shadow copy** deletion or **recovery** tampering.

**Save as:** `02-recovery-inhibition.png`

---

### 3 — SOAR enrichment

**When:** After `POST /analyze` for SHA256 and/or domain from [`../ioc-enrichment.md`](../ioc-enrichment.md).

**What:** JSON with **malicious** or **suspicious** verdict and scores.

**Save as:** `03-soar-ransomware-iocs.png`

---

## Tools

**Event Viewer**, SIEM, or EDR; **curl** / Postman for SOAR.
