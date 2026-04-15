# Investigation Queries — Ransomware

**Dataset:** EVTX-ATTACK-SAMPLES — https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES  
**Tools used:** Linux CLI (bash, grep, awk, sort, uniq, cut, jq)  

---

## Step 1 — Initial triage

Goal: Identify mass file extension changes indicative of encryption (T1486).

```bash
# Detect mass file extension changes (ransomware indicator)
grep -E "\.locked|\.encrypted|\.ransom|\.crypted" file_events.txt | \
  awk '{print $3}' | sort | uniq -c | sort -rn | head -10
```

**Output:**

```
   1840 C:\\Users\\Public\\Documents\\
    412 C:\\Users\\jsmith\\Desktop\\
     88 C:\\Finance\\Shares\\
```

**Finding:** High-volume writes under user and share paths with ransomware-style extensions — prioritize host isolation.

---

## Step 2 — Recovery inhibition

Goal: Find shadow copy and backup deletion (T1490).

```bash
# Find shadow copy deletion commands
grep -iE "vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled" \
  process_creation.txt
```

**Output:**

```
2026-04-11T09:02:04Z vssadmin.exe Delete Shadows /All /Quiet
2026-04-11T09:02:07Z bcdedit /set {default} recoveryenabled No
```

**Finding:** Classic ransomware recovery inhibition — preserve process metadata for IR.

---

## Step 3 — PowerShell execution

Goal: Detect encoded PowerShell (T1059.001).

```bash
# Detect PowerShell encoded command execution
grep -E "powershell.*-enc|-encodedcommand" process_creation.txt | \
  awk -F'CommandLine: ' '{print $2}' | head -20
```

**Output:**

```
powershell.exe -NoP -enc SQBFAFAA...
```

**Finding:** Encoded command execution often stages payload or disables tooling — map parent process and user context.

---

## Step 4 — Defence evasion

Goal: Identify security-tool tampering (T1562.001) and log/file deletion (T1070.004).

```bash
grep -iE "defender|msmpeng|tamper|wevtutil.*cl" process_creation.txt | head -15
```

**Output:**

```
2026-04-11T09:01:58Z powershell.exe Add-MpPreference -ExclusionPath C:\\Temp\\payload
2026-04-11T09:03:10Z wevtutil cl Security
```

**Finding:** Tamper protection bypass and event log clearing align with **T1562.001** and **T1070.004**.

---

## Step 5 — Network C2

Goal: Extract outbound domains/IPs for SOAR enrichment.

```bash
grep "2026-04-11T09:0" dns.log | awk '{print $4, $5}' | sort -u | head -10
```

**Output:**

```
resolve pay-ransom-bc[.]onion-gate[.]net 203[.]0[.]113[.]90
```

**Finding:** C2 hostname and IP feed **`ioc-enrichment.md`**.

---

## Step 6 — Ransom note

Goal: Confirm dropped readme / note filename for case documentation.

```bash
grep -i "readme\|DECRYPT\|HOW_TO_RESTORE" file_events.txt | head -5
```

**Output:**

```
2026-04-11T09:02:15Z CREATE C:\\Users\\Public\\Desktop\\HOW_TO_RESTORE.txt
```

**Finding:** **HOW_TO_RESTORE.txt** supports user communication analysis and YARA/file hunting.
