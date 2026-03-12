# Security Incident Response Report

**Incident Type:** Data Exfiltration Attempt (Unsanctioned Cloud Storage)  
**Severity:** High  
**Affected Endpoint:** FIN-LT-033 (10.20.33.33)  
**Impacted User:** ACME\\a.nguyen (a.nguyen@acme-corp.com)  
**Detection Source:** DLP + Proxy Upload Anomaly + CASB Events  
**Report Prepared By:** Security Operations Center (SOC)  

---

## Incident Summary

On **2026-03-11**, the SOC investigated a suspected data exfiltration event involving **FIN-LT-033** and user **ACME\\a.nguyen**. Proxy and firewall telemetry showed **large outbound transfers** to cloud storage infrastructure. DLP policy enforcement triggered on attempted upload of a file matching **PII (SSN)** patterns. CASB logs confirmed login and repeated upload attempts to an **unsanctioned Dropbox personal** account from the endpoint.

Endpoint telemetry shows local **data staging** via creation of a large ZIP archive shortly before the uploads.

---

## Detection Source

- **DLP**: PII/Finance data exfiltration policy match (blocked upload attempt).
- **Proxy**: Upload anomaly (bytes out over baseline within 10 minutes).
- **CASB**: Unsanctioned cloud app login and upload events (new device context).
- **EDR**: Data staging indicator (large archive creation + immediate uploads).

---

## Attack Timeline

| Time (UTC) | Event |
|------------|------|
| 17:58 | User logs on interactively to FIN-LT-033 |
| 18:05:49–18:05:50 | Sensitive finance/PII files read (object access events) |
| 18:05:58 | `7z.exe` creates `Q1_Finance.zip` (staging) |
| 18:05:44–18:06:35 | CASB records Dropbox login and multiple upload attempts |
| 18:06–18:07 | Proxy/firewall shows large outbound transfers to Dropbox infra |
| 18:06:11 | DLP blocks upload attempt containing SSNs |
| 18:07+ | SOC containment and scoping actions initiated |

---

## Investigation Steps

1) **Validate alert correlation**
- Correlated DLP alert with proxy upload events by time/user/host.
- Verified CASB activity to Dropbox personal from the same endpoint context.

2) **Confirm exfil mechanism**
- Reviewed proxy POST requests to `content.dropboxapi.com` with large `Bytes Out`.
- Confirmed firewall sessions indicating significant outbound data volume.

3) **Determine data sensitivity**
- Confirmed DLP match on SSN patterns and finance classification.
- Identified file names accessed/staged prior to upload attempts.

4) **Assess compromise vs insider behavior**
- Reviewed endpoint process activity for malware/credential theft indicators.
- No evidence of malicious persistence or C2 in the provided dataset; activity aligns with a valid user session staging and uploading data.

5) **Scope**
- Queried for other endpoints uploading large volumes to unsanctioned cloud apps.
- Identified whether additional uploads from the same user occurred elsewhere.

---

## Root Cause

Most likely root cause is an **insider-driven attempt** to move sensitive finance/PII data to a personal cloud storage account using a valid corporate session, preceded by local staging (archive creation).

---

## Indicators of Compromise / Concern

### User / Host
- User: `ACME\\a.nguyen`
- Host: `FIN-LT-033` (10.20.33.33)

### Cloud App
- Unsanctioned: Dropbox (personal)

### Staging Artifact
- `C:\\Users\\a.nguyen\\Desktop\\Q1_Finance.zip`

### High-Risk Data
- `Customer_SSN_List.csv`
- `Payroll_Q1_2026.xlsx`
- `Vendor_Bank_Details.xlsx`

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|-------|-----------|----|----------|
| Collection | Archive Collected Data | T1560 | `7z.exe` creates ZIP of finance directory |
| Exfiltration | Exfiltration Over Web Service | T1567 | Uploads to cloud storage service endpoints |
| Exfiltration | Exfiltration to Cloud Storage | T1567.002 | Unsanctioned Dropbox upload attempts |

---

## Containment Actions

- Blocked/limited access to unsanctioned cloud storage for the user/device via proxy policy.
- Forced user re-authentication; reset password as precaution if account misuse is possible.
- Quarantined/secured staged archive and preserved evidence for HR/legal review.
- Confirmed DLP policy enforcement and verified which uploads were blocked vs allowed.

---

## Remediation Actions

### Policy & Control Improvements
- Enforce sanctioned cloud storage only (CASB governance + proxy category enforcement).
- Strengthen DLP rules for finance/PII and apply to both web uploads and endpoint removable media.
- Implement user risk scoring for unusual data transfer volumes.

### Monitoring Enhancements
- Alert on:
  - Large outbound `Bytes Out` to cloud storage categories
  - Archive creation in sensitive directories followed by immediate uploads
  - “New device” cloud logins for unsanctioned apps

---

## Outcome

The attempted transfer of sensitive data was detected quickly. DLP blocked at least one high-risk upload. Network telemetry indicates large outbound traffic to cloud storage, so the SOC performed scoping and data-loss confirmation to determine what content successfully left the environment and initiated appropriate compliance and HR escalation.
