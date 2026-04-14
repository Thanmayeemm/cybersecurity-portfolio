# Screenshots — Incident 04 (Data exfiltration)

**Purpose:** Show **large outbound** or **staging** evidence from CLI or SIEM, plus **SOAR** for the destination IOC.

**Master checklist:** [`../../SCREENSHOTS-GUIDE.md`](../../SCREENSHOTS-GUIDE.md) — section **Incident 04**.

---

## What to capture

### 1 — CLI analysis (required if no SIEM)

**When:** After running [`../queries.md`](../queries.md) against **network_connections.csv** or equivalent (e.g. large byte count to external IP **203.0.113.200** per report).

**What:** Terminal with **`awk`/`grep`** output listing top transfers or suspicious rows; include command in history if visible.

**Save as:** `01-exfil-cli-summary.png`

---

### 2 — SIEM / dashboard (optional)

**When:** If you import the same data into Splunk, Elastic, or a spreadsheet pivot.

**What:** Bar chart or table: **bytes out** by destination IP or time bucket.

**Save as:** `02-siem-outbound-volume.png`

---

### 3 — SOAR enrichment

**When:** After submitting destination **IP** or **domain** from [`../ioc-enrichment.md`](../ioc-enrichment.md).

**What:** Full JSON response or formatted API client view.

**Save as:** `03-soar-exfil-ioc.png`

---

## Tools

Terminal, **CSV** in editor, SIEM, SOAR API.
