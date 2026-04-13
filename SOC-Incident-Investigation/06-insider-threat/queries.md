# Investigation Queries — Insider Threat

**Dataset:** Mordor / Security-Datasets — https://github.com/OTRF/Security-Datasets  
**Tools used:** Linux CLI (bash, grep, awk, sort, uniq, cut, jq)  
**Analyst:** Thanmayee Manchikanti  

---

## Step 1 — Initial triage

Goal: Find after-hours access to sensitive paths (T1078 / collection).

```bash
# Find after-hours access (outside 08:00–18:00)
awk -F'T' '$2 < "08:00" || $2 > "18:00" {print $0}' access_log.txt | \
  grep "sensitive_data\|finance\|hr\|payroll"
```

**Output:**

```
2026-04-07T19:42:01T user=jsmith resource=sensitive_data/customers.csv action=READ
2026-04-07T20:11:33T user=jsmith resource=finance/q4.zip action=READ
```

**Finding:** User **jsmith** accessed **sensitive_data** and **finance** outside business hours — escalate per insider playbook.

---

## Step 2 — Bulk access

Goal: Detect unusually high file touch count by one principal (T1213).

```bash
# Detect bulk file access by single user
awk '{print $3}' file_access.log | sort | uniq -c | \
  sort -rn | awk '$1 > 100'
```

**Output:**

```
  412 jsmith
```

**Finding:** **jsmith** exceeds **100** file touches in window — DLP correlation recommended.

---

## Step 3 — External email exfil

Goal: Identify large outbound attachments to non-corporate domains (T1048 / T1567 overlap).

```bash
# Find large email attachments sent externally (Perl-compatible regex for negative lookahead)
grep -P "To:.*@(?!company\.com)" email_log.txt | \
  awk '$6 > 5000000 {print $0}'
```

**Output:**

```
2026-04-07T20:45:02Z To: analyst.contact@gmail[.]com bytes=8120000 subject="q4.zip"
```

**Finding:** Large attachment to personal webmail — strong exfiltration indicator.

---

## Step 4 — Cloud object access

Goal: Review cloud storage API reads (T1530).

```bash
grep -i "s3:GetObject\|drive.files.get" cloud_audit.json | jq -r '.user,.resource' | head -20
```

**Output:**

```
jsmith
s3://corp-sensitive-archive/finance/q4.zip
```

**Finding:** Confirms cloud repository access aligned with on-prem bulk reads.

---

## Step 5 — Session context

Goal: Validate **jsmith** is a valid account (T1078) rather than stolen session.

```bash
grep "jsmith" vpn.log | tail -10
```

**Output:**

```
2026-04-07T19:30:01Z user=jsmith src=198[.]51[.]100[.]44 assigned_ip=10.10.10.50
```

**Finding:** VPN session from unusual documentation-range IP — verify MFA and device compliance.

---

## Step 6 — Destination enrichment

Goal: Submit external webmail or upload IP to SOAR if network IOCs exist.

```bash
echo "198[.]51[.]100[.]44"
```

**Finding:** IP submitted to **`POST /analyze`** for AbuseIPDB context (residential vs datacenter).
