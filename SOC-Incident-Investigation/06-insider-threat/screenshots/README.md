# Screenshots — Incident 06 (Insider threat)

**Purpose:** **After-hours** or **anomalous access** evidence, optional admin/SIEM view, and **SOAR** if external destinations are enriched.

**Master checklist:** [`../../SCREENSHOTS-GUIDE.md`](../../SCREENSHOTS-GUIDE.md) — section **Incident 06**.

---

## What to capture

### 1 — Time-based CLI or log review

**When:** After running the **awk**/time filter examples in [`../queries.md`](../queries.md) on access logs.

**What:** Terminal output highlighting access **outside business hours** or to **sensitive** paths.

**Save as:** `01-after-hours-access.png`

---

### 2 — Admin / SIEM (optional)

**When:** If you have a lab SIEM or cloud admin export aligned with the narrative.

**What:** Single pane showing **user**, **resource**, and **timestamp** for the suspicious session.

**Save as:** `02-sensitive-access.png`

---

### 3 — SOAR (if applicable)

**When:** You submit destination IP from [`../ioc-enrichment.md`](../ioc-enrichment.md).

**Save as:** `03-soar-insider-ioc.png`

---

## Tools

Terminal, SIEM, IAM exports, SOAR API.
