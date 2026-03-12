# Detection Rule - Large Uploads to Unsanctioned Cloud Storage (Possible Exfiltration)

## Objective

Detect potential data exfiltration by identifying:
- Unusually large outbound uploads to cloud storage services (or unsanctioned subset)
- Correlated endpoint staging signals (archive creation) and/or DLP policy hits

---

## Example (Splunk SPL) - Proxy Upload Anomaly + DLP Correlation

```spl
(
  index=proxy sourcetype="proxy"
  | eval dest=lower(Hostname)
  | where match(dest,"dropbox|drive|box|mega|onedrive")   /* tune: focus on unsanctioned apps */
  | bucket _time span=10m
  | stats sum(Bytes_Out) as bytes_out values(Hostname) as hosts values(URI) as uris by _time user src_ip
  | where bytes_out >= 50000000   /* 50MB/10m baseline threshold; tune per environment */
  | eval mb_out=round(bytes_out/1024/1024,2)
)
| join type=left user
    [ search index=dlp sourcetype="dlp"
      | bucket _time span=10m
      | stats count as dlp_hits values(Policy) as policies values(Details) as dlp_details by _time user
    ]
| eval severity=case(isnotnull(dlp_hits) AND mb_out>=100,"high", mb_out>=200,"high", mb_out>=100,"medium", true(),"low")
| table _time user src_ip mb_out hosts uris dlp_hits policies severity
```

---

## Tuning / False Positive Reduction

- Exclude sanctioned corporate storage domains.
- Use per-user baselines (e.g., 95th percentile) rather than static thresholds.
- Require supporting signals:
  - Endpoint archive creation (`7z.exe`, `rar.exe`, `zip`)
  - DLP classification hit (PII/PCI/Finance)
  - New device/new app usage in CASB

---

## Response Guidance

- Validate if upload destination is sanctioned.
- Determine whether DLP blocked or allowed the transfer and what content was involved.
- Contain: block domain/app for the user, preserve staged files, escalate to HR/legal if policy violation suspected.
