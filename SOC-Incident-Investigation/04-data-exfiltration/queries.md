# Investigation Queries — Data Exfiltration

**Dataset:** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets (supplementary: Splunk BOTS v3)  
**Tools used:** Linux CLI (bash, grep, awk, sort, uniq, cut, jq)  
**Analyst:** Thanmayee Manchikanti  

---

## Step 1 — Initial triage

Goal: Surface largest outbound transfers (T1048.003 / T1567).

```bash
# Find large outbound data transfers
awk -F',' '$9 > 50000 {print $1, $3, $5, $9}' network_connections.csv | \
  sort -k4 -rn | head -20
```

**Output:**

```
2026-04-09T16:11:02Z host-42 203[.]0[.]113[.]200 91240000
2026-04-09T16:10:55Z host-42 198[.]51[.]100[.]77 20480000
```

**Finding:** **host-42** sent **~91 MB** to **203[.]0[.]113[.]200** on **443** — priority incident for DLP and proxy review.

---

## Step 2 — Staging

Goal: Correlate archive creation before upload (T1074.001).

```bash
# Detect archive creation (staging before exfil)
grep -E "\.zip|\.rar|\.7z|\.tar" file_events.txt | \
  grep -i "create\|write" | awk '{print $1, $2, $5}'
```

**Output:**

```
2026-04-09T16:09:40Z CREATE C:\\Temp\\staging\\customer_pii.zip
```

**Finding:** Staging directory **C:\\Temp\\staging** aligns with collection before exfiltration.

---

## Step 3 — Discovery activity

Goal: Identify file/directory discovery preceding staging (T1083).

```bash
grep -iE "dir |Get-ChildItem|tree " process_creation.txt | head -10
```

**Output:**

```
2026-04-09T16:08:12Z cmd.exe /c dir /s D:\\finance\\customers
```

**Finding:** Broad discovery of sensitive paths precedes archive creation — insider or compromised account.

---

## Step 4 — Unusual external connections

Goal: Highlight non-standard destinations after discovery (T1048.003).

```bash
# Find connections to unusual external IPs after discovery activity
grep -E "ESTABLISHED.*:443|ESTABLISHED.*:80" netstat_dump.txt | \
  grep -v "known_good_domains.txt" | awk '{print $5}' | \
  cut -d: -f1 | sort | uniq -c | sort -rn
```

**Output:**

```
  14 203[.]0[.]113[.]200
   2 198[.]51[.]100[.]77
```

**Finding:** Repeated connections to **203[.]0[.]113[.]200** dominate — candidate exfiltration endpoint.

---

## Step 5 — Volume by user

Goal: Tie activity to account for access review.

```bash
grep "host-42" auth.log | tail -20
```

**Output:**

```
2026-04-09T16:07:01Z session open for contractor1 by (uid=1001)
```

**Finding:** **contractor1** session open before discovery — validate legitimacy of bulk export.

---

## Step 6 — IOC enrichment

Goal: Submit destination IP/domain to SOAR (`ioc-enrichment.md`).

```bash
echo "203[.]0[.]113[.]200"
```

**Finding:** External IP enrichment supports firewall and DNS blocking decisions.
