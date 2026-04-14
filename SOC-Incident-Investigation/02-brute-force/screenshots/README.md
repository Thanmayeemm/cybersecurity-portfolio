# Screenshots — Incident 02 (Brute force)

**Purpose:** Show **CLI triage** on real or sample auth data, the **success** line, and **SOAR** verdict for the attacker IP.

**Master checklist:** [`../../SCREENSHOTS-GUIDE.md`](../../SCREENSHOTS-GUIDE.md) — section **Incident 02**.

---

## Setup (before screenshots)

```bash
cd /path/to/SOC-Incident-Investigation/02-brute-force
export AUTH_LOG="$(pwd)/logs/sample-auth.log"
```

Use **WSL** or Linux so `grep -oP` matches [`../queries.md`](../queries.md).

---

## What to capture

### 1 — Failed login attempts

**When:** After `grep "Failed password" "$AUTH_LOG"` (Step 1 in [`../queries.md`](../queries.md)).

**What:** Terminal showing multiple **Failed password** lines (same IP **203.0.113.15**).

**Save as:** `failed_logins.png`

---

### 2 — Attacker IP (ranked failures)

**When:** After the **per-IP failure count** pipeline (Step 2 in [`../queries.md`](../queries.md)).

**What:** Terminal showing **`uniq -c`** with **203.0.113.15** leading (e.g. **198.51.100.3** secondary).

**Save as:** `attacker_ip.png`

---

### 3 — Accepted password (successful login)

**When:** After `grep -E "Accepted (password|publickey)" "$AUTH_LOG"` (or `grep Accepted`).

**What:** Line **Accepted password for user1** from **203.0.113.15**.

**Save as:** `successful_login.png`

---

### 4 — SOAR enrichment (optional fourth image)

**When:** SOAR API is up; submit **203.0.113.15**.

**Save as:** `03-soar-ip-enrichment.png` or `soar_enrichment.png`

---

**Referenced in report:** [`../README.md`](../README.md) section **10. Evidence (screenshots)** uses **`failed_logins.png`**, **`attacker_ip.png`**, **`successful_login.png`**.

---

## Tools

**WSL** terminal, optional **Windows Terminal**; **curl** for SOAR.
