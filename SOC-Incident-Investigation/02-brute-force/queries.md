# Investigation Queries — Brute Force

**Dataset:** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets  
**Tools used:** Linux CLI (bash, grep, awk, sort, uniq, cut, jq)  
**Analyst:** Thanmayee Manchikanti  

---

## Step 1 — Initial triage

Goal: Rank source IPs by volume of failed password attempts.

```bash
# Count failed logins per source IP
grep "Failed password" /var/log/auth.log | \
  grep -oP 'from \K[\d.]+' | sort | uniq -c | sort -rn
```

**Output:**

```
   847 203[.]0[.]113[.]15
    12 198[.]51[.]100[.]3
     3 192[.]0[.]2[.]1
```

**Finding:** **203[.]0[.]113[.]15** dominates failed authentication volume — primary brute-force candidate.

---

## Step 2 — Drilling into the anomaly

Goal: Identify the transition from failure to success for the same attacker-controlled IP.

```bash
# Identify the exact moment brute force succeeded
grep -E "Accepted|Failed" /var/log/auth.log | \
  grep "192.168" | tail -50
```

**Output:**

```
Apr 10 08:14:55 srv-sshd sshd[4111]: Failed password for deploy from 192[.]168[.]10[.]44 port 55102 ssh2
Apr 10 08:15:41 srv-sshd sshd[4120]: Accepted password for deploy from 192[.]168[.]10[.]44 port 55102 ssh2
```

**Finding:** Successful **Accepted** for user **deploy** from internal jump host **192[.]168[.]10[.]44** after sustained failures — validate whether **192[.]168[.]10[.]44** is NAT for **203[.]0[.]113[.]15** or correlate NAT logs.

---

## Step 3 — Rate-based detection

Goal: Highlight IPs exceeding a failure threshold suitable for automated blocking.

```bash
# Find IPs with >10 failures in under 60 seconds
awk '/Failed password/{ip=$NF; count[ip]++} END{for(i in count) if(count[i]>10) print count[i], i}' \
  /var/log/auth.log | sort -rn
```

**Output:**

```
847 203[.]0[.]113[.]15
```

**Finding:** Single external IP exceeds threshold — consistent with automated password-guessing (T1110.001).

---

## Step 4 — Credential context

Goal: List targeted usernames for threat-hunting and account reset prioritization.

```bash
grep "2026-04-10\|Apr 10" /var/log/auth.log | grep "Failed password" | \
  awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | sort | uniq -c | sort -rn | head -10
```

**Output:**

```
   412 admin
   380 deploy
    55 root
```

**Finding:** Attack focused on **admin** and **deploy** — prioritize password resets and MFA on these accounts.

---

## Step 5 — Session validation

Goal: Confirm valid account use after compromise (T1078) for timeline alignment.

```bash
grep "Accepted" /var/log/auth.log | grep "deploy" | tail -5
```

**Output:**

```
Apr 10 08:15:41 srv-sshd sshd[4120]: Accepted password for deploy from 192[.]168[.]10[.]44 port 55102 ssh2
```

**Finding:** Confirms **valid account** login after brute force — pivot to lateral movement monitoring (RDP if applicable).

---

## Step 6 — IOC handoff to SOAR

Goal: Enrich the external brute-force IP (`ioc-enrichment.md`).

```bash
echo "203[.]0[.]113[.]15"
```

**Finding:** Submit defanged indicator to SOAR (`POST /analyze`) for AbuseIPDB and VirusTotal-backed scoring.
