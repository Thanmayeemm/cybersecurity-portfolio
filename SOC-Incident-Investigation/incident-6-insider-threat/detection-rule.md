# Detection Rule - Insider Threat (Privileged Change + Sensitive Export + Exfil Attempt)

## Objective

Detect high-risk insider activity by correlating:
- Privileged group membership changes (e.g., Domain Admins)
- Sensitive database access/exports
- Data staging and attempted exfiltration (USB/email/cloud)

---

## Example (Splunk SPL) - Multi-Source Correlation

```spl
(
  index=windows sourcetype="WinEventLog:Security" EventCode=4728
  | eval target_group=lower(TargetUserName)
  | where like(target_group,"%domain admins%") OR like(target_group,"%enterprise admins%")
  | stats earliest(_time) as da_change_time values(MemberName) as members values(SubjectUserName) as actors by Computer, SubjectUserName
  | rename SubjectUserName as user
)
| join type=left user
    [ search index=db_audit sourcetype="sql:audit"
      | where match(lower(Object),"payroll|employees|ssn") OR match(lower(Statement),"bulk export|select")
      | stats earliest(_time) as db_first latest(_time) as db_last count as db_events values(Object) as objects values(Statement) as statements by user ClientHost
    ]
| join type=left user
    [ search index=dlp sourcetype="dlp"
      | where match(lower(Details),"usb|removable|external recipient|attachment")
      | stats earliest(_time) as dlp_first latest(_time) as dlp_last count as dlp_events values(Policy) as policies values(Action) as actions by user host
    ]
| eval first_seen=min(da_change_time, db_first, dlp_first), last_seen=max(da_change_time, db_last, dlp_last)
| eval window=last_seen-first_seen
| where window <= 14400 AND (isnotnull(da_change_time) AND isnotnull(db_first)) AND (dlp_events>=1)
| eval severity="high"
| table user severity first_seen last_seen window Computer ClientHost host members actors objects db_events dlp_events policies actions
```

---

## Tuning Guidance

- Focus on privileged groups of concern:
  - Domain Admins, Enterprise Admins, Schema Admins, Backup Operators
- Add allowlists for approved change windows and break-glass accounts (with tight governance).
- Enrich with UEBA risk scoring and after-hours context.

---

## Response Guidance

- Validate if privileged change was approved and documented.
- Immediately revert unauthorized group changes and restrict the user pending investigation.
- Preserve evidence; coordinate with HR/legal for insider threat handling.
