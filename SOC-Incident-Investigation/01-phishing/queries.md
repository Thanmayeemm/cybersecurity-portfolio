# Investigation Queries — Phishing

**Dataset:** EVTX-ATTACK-SAMPLES — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  
**Tools used:** Linux CLI (bash, grep, awk, sort, uniq, cut, jq)  
**Analyst:** Thanmayee Manchikanti  

---

## Step 1 — Initial triage

Goal: Summarize failed logon activity after the suspected phishing execution window to spot credential-guessing or reuse from unusual sources.

```bash
# Extract failed logins after phishing execution window
grep -i "4625\|logon failure" security.evtx.parsed.txt | \
  awk '{print $1, $2, $NF}' | sort | uniq -c | sort -rn | head -20
```

**Output:**

```
   4 2026-04-10T14:22:01Z 203[.]0[.]113[.]88
   2 2026-04-10T14:22:03Z 203[.]0[.]113[.]88
   1 2026-04-10T14:21:58Z 198[.]51[.]100[.]12
```

**Finding:** Multiple failed logon events cluster on **203[.]0[.]113[.]88** immediately after document execution, consistent with attacker testing harvested credentials.

---

## Step 2 — Drilling into the anomaly

Goal: Identify suspicious child processes of Office applications that may indicate macro-enabled execution.

```bash
# Find suspicious process spawned by Office apps
grep -E "winword|excel|powerpnt" process_creation.txt | \
  grep -v "^#" | awk -F'|' '{print $5, $6, $7}'
```

**Output:**

```
WINWORD.EXE powershell.exe -NoP -enc JAB...
WINWORD.EXE cmd.exe /c reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateHelper
```

**Finding:** **WINWORD.EXE** spawned **powershell.exe** with an encoded command and a **Run** key persistence command — high-confidence malicious document behavior.

---

## Step 3 — Network indicators

Goal: Extract outbound connection targets from parsed proxy or firewall text aligned to the same timeline.

```bash
grep "2026-04-10T14:2" proxy.log | grep -E "CONNECT|GET" | \
  awk '{print $1, $4, $6}' | head -15
```

**Output:**

```
2026-04-10T14:23:11Z CONNECT 203[.]0[.]113[.]47:443 /updates/check
2026-04-10T14:23:14Z GET malware-update-service[.]com /stage2.bin
```

**Finding:** HTTPS connectivity to **203[.]0[.]113[.]47** and a suspicious hostname match command-and-control over web protocols.

---

## Step 4 — Credential access artifacts

Goal: Search exported event text for LSASS access patterns often tied to post-exploitation credential theft.

```bash
grep -iE "lsass|sekurlsa|credential" security.evtx.parsed.txt | head -10
```

**Output:**

```
2026-04-10T14:24:02Z EventID=4688 CommandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\Temp\\ls.dmp"
```

**Finding:** Process arguments suggest **LSASS** memory dumping (credential access), consistent with **T1003.001**.

---

## Step 5 — Registry persistence

Goal: Confirm the Run key write observed in process output against registry telemetry or a parsed export.

```bash
grep -i "CurrentVersion\\\\Run" registry_export.txt | head -5
```

**Output:**

```
HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateHelper = "C:\\Users\\jsmith\\AppData\\Local\\Temp\\svchost.exe"
```

**Finding:** Persistence under **HKCU\\Run** aligns with the macro-staged payload and supports containment (remove key, isolate host).

---

## Step 6 — IOC extraction for SOAR

Goal: Produce a single-line list of indicators for enrichment (`../ioc-enrichment.md`).

```bash
echo "203[.]0[.]113[.]47 malware-update-service[.]com sha256:..." \
  | tr ' ' '\n' | sed 's/sha256://'
```

**Finding:** IP, domain, and attachment hash are submitted to the SOAR engine (`POST /analyze`) for VirusTotal and AbuseIPDB-backed scoring.
