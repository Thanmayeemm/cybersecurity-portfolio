# Beginner lab guide — simulate each investigation from scratch

This guide is for analysts who are **new to hands-on log work**. You will **not** attack any real system. “Simulate” means: **replay the same analysis steps** your portfolio documents, using **sample logs**, **public datasets**, or **your own lab VM** — exactly like practicing on evidence in a SOC.

---

## 1. What you are learning

| Idea | Meaning |
|------|--------|
| **Triage** | Quickly find the noisiest or most dangerous clue (IP, user, time). |
| **Drill down** | Filter logs to answer: who, when, what happened next? |
| **IOCs** | Extract indicators (IPs, domains, hashes) for blocking and enrichment. |
| **Report** | Turn findings into a story: timeline, impact, remediation (your `README.md` per incident). |

---

## 2. Prerequisites (do these once)

### A) Get the code

- Install **Git** and clone this repository (or open the folder you already have).
- You need a **terminal that runs Bash** for most commands:
  - **Windows:** Install [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install) (Ubuntu), then open **Ubuntu** from the Start menu.
  - **macOS / Linux:** Use the built-in Terminal.

### B) Learn two navigation commands

```bash
pwd          # print current folder
cd /path     # change folder
```

Your investigations live under:

`.../cybersecurity-portfolio/SOC-Incident-Investigation/`

### C) Optional but recommended: SOAR enrichment

The [`soar-engine/`](../soar-engine/) API enriches IPs/domains/hashes. It needs **Python 3.10+** and API keys for VirusTotal and AbuseIPDB (see that project’s README). You can **skip SOAR** until you are comfortable with log commands.

### D) Safety rules

- Use **public datasets** or **repo sample files** only, unless you own the lab VM.
- **Malware / PCAP:** only on an **isolated analysis VM**; MTA archives use password **`infected`**.
- Never point tools at production servers without authorization.

---

## 3. Suggested order (easiest → harder)

| Order | Incident | Why this order |
|-------|----------|----------------|
| **1** | **02 — Brute force** | Sample log **ships in the repo**; pure CLI. |
| **2** | **04 — Data exfiltration** | Sample CSV/text **ships in the repo**; pure CLI. |
| **3** | **06 — Insider threat** | Mostly text + `awk` (use Mordor or small homemade files). |
| **4** | **01 — Phishing** | Needs **Windows + EVTX** (Event Viewer) or exported text. |
| **5** | **03 — Ransomware** | Same as 01 — **EVTX** in a VM. |
| **6** | **05 — Malware infection** | **PCAP** + Wireshark + isolation. |

---

## 4. Incident 02 — Brute force (start here)

### What you are simulating

Someone on the internet tries many SSH passwords; eventually one account logs in. You prove it from **`auth.log`**.

### Prerequisites

- WSL or Linux terminal.
- No downloads required: use **[`02-brute-force/logs/sample-auth.log`](./02-brute-force/logs/sample-auth.log)**.

### Steps

1. Open terminal (WSL Ubuntu).
2. Go to the incident folder (adjust path if your clone differs):

```bash
cd ~/.../cybersecurity-portfolio/SOC-Incident-Investigation/02-brute-force
export AUTH_LOG="$(pwd)/logs/sample-auth.log"
```

3. Run the commands in **[`02-brute-force/queries.md`](./02-brute-force/queries.md)** **in order**, from Step 1 onward.
4. After each step, ask yourself:
   - **What is the loudest IP?**
   - **Is there an “Accepted password” line after many failures?**
   - **Which user succeeded?**

### Optional: real Mordor data

Download **[Security-Datasets](https://github.com/OTRF/Security-Datasets)** and point `AUTH_LOG` at an exported `auth.log` from a brute-force scenario. Counts will be larger; the **logic is the same**.

### Evidence in this repo

Completed reports include PNGs under **`02-brute-force/screenshots/`** — see **[`02-brute-force/README.md`](./02-brute-force/README.md)** → **Evidence**.

---

## 5. Incident 04 — Data exfiltration

### What you are simulating

A host stages a zip, then uploads a large amount of data to an external IP.

### Prerequisites

- WSL/Linux Bash.
- Sample files in **[`04-data-exfiltration/logs/`](./04-data-exfiltration/logs/)** (`network_connections.csv`, `file_events.txt`, etc.).

### Steps

1. `cd` to `04-data-exfiltration`.
2. Run commands from **[`04-data-exfiltration/queries.md`](./04-data-exfiltration/queries.md)** using paths under **`logs/`** (see that folder’s `README.md` for exact filenames).
3. Answer:
   - **Which destination IP got the largest upload?**
   - **Was a zip created before the upload?**
   - **Which user/host appears in the story?**

### Optional: full Mordor / Splunk

Import real CSV exports from Mordor or BOTS into your tool of choice; keep the same **questions**.

---

## 6. Incident 06 — Insider threat

### What you are simulating

Unusual access (e.g. after hours) to sensitive paths, possible bulk access, possible email exfil.

### Prerequisites

- Bash, `awk`, `grep`.
- **[Mordor](https://github.com/OTRF/Security-Datasets)** exports **or** small text files you create that match the field layout in **[`06-insider-threat/queries.md`](./06-insider-threat/queries.md)**.

### Steps

1. Read [`06-insider-threat/README.md`](./06-insider-threat/README.md) for the narrative.
2. Run each query; if you do not have `access_log.txt` yet, build a **tiny** file with two lines that match the **after-hours** pattern in the doc, then grow it as you learn.

### Tip

Some queries expect **many** lines (e.g. “> 100 file touches”). Your first run can use a **short** file to verify the command runs; compare **shape** of output to [`queries.md`](./06-insider-threat/queries.md).

---

## 7. Incident 01 — Phishing

### What you are simulating

Email → malicious Office doc → PowerShell → credentials / C2.

### Prerequisites

- **Windows VM** (recommended) or physical Windows with test EVTX.
- Clone or download **[EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)**.
- **Event Viewer** (`eventvwr.msc`) or a tool that reads `.evtx`.

### Steps

1. Read [`01-phishing/README.md`](./01-phishing/README.md).
2. Find an EVTX that matches **spearphishing / Office / PowerShell** style activity (repo has many scenarios).
3. Export relevant events to **text** if needed for your notes.
4. Align **timestamps and IOCs** with your written report, or label the report as “based on sample X.”

### Text-based practice

[`01-phishing/queries.md`](./01-phishing/queries.md) references files like `process_creation.txt` and `proxy.log`. You can create **small mock files** with the same patterns as the **example outputs** in that file to practice `grep`/`awk` without EVTX first.

---

## 8. Incident 03 — Ransomware

Same toolchain as **01** (EVTX-focused). Focus on:

- Mass file changes / encryption-related events  
- **vssadmin** / **bcdedit** / backup tampering  
- Your [`03-ransomware/queries.md`](./03-ransomware/queries.md) and [`README.md`](./03-ransomware/README.md)

Use an isolated VM. Do not run ransomware binaries on a machine you need for school or work.

---

## 9. Incident 05 — Malware infection (network)

### What you are simulating

Traffic to C2, suspicious processes, persistence — from **PCAP** and text exports.

### Prerequisites

- **Analyst VM** (Linux or Windows with Wireshark).
- Download PCAP from **[Malware Traffic Analysis](https://www.malware-traffic-analysis.net)** (password **`infected`**).
- Wireshark or **tshark**.

### Steps

1. Read [`05-malware-infection/README.md`](./05-malware-infection/README.md).
2. Open PCAP → **Conversations** / **Follow TCP stream**; note flows that match the narrative in [`05-malware-infection/README.md`](./05-malware-infection/README.md).
3. Run text-based queries from [`05-malware-infection/queries.md`](./05-malware-infection/queries.md) on any companion `.txt` exports you generate.

---

## 10. SOAR enrichment (optional pass)

When you have an IP or hash from any incident:

1. Start the API per [`soar-engine/README.md`](../soar-engine/README.md).
2. `POST /analyze` with JSON body including your indicator.
3. Paste representative output into thinking for **`ioc-enrichment.md`** (already structured per incident).

---

## 11. Checklist before you call it “done”

- [ ] Ran **all** commands in `queries.md` for at least **02** and **04** (repo samples).
- [ ] Can explain **in one minute** what happened in each incident you completed.
- [ ] Read the **Evidence** section in each completed incident **`README.md`** (reports in this repo are finished).
- [ ] (Optional) Enriched one IOC via **SOAR**.

---

## 12. Where to get help in this repo

| Question | Where to look |
|----------|----------------|
| What goes in a report? | Each incident **`README.md`**, [`investigation-template.md`](./investigation-template.md) |
| What commands to run? | Each **`queries.md`** |
| What data is public vs sample? | [`datasets/README.md`](./datasets/README.md), each **`logs/README.md`** |
| Where is visual evidence? | Each incident **`README.md`** → **Evidence**; see also [`SCREENSHOTS-GUIDE.md`](./SCREENSHOTS-GUIDE.md) |

---

*You are practicing the same loop real SOC analysts use: **evidence → questions → queries → findings → report**.*
