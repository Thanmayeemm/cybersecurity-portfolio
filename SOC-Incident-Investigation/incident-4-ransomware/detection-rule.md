# Detection Rule - Ransomware Early Warning (Encryption + Recovery Inhibition)

## Objective

Detect likely ransomware activity by correlating:
- High-volume file renames/creates (possible encryption)
- Ransom note creation
- Recovery inhibition commands (shadow copy deletion, recovery disable)

---

## Example (Splunk SPL) - Endpoint + Fileserver Correlation

```spl
(
  index=endpoint (sourcetype="sysmon" EventID=1)
  | eval cmd=lower(CommandLine)
  | where like(cmd,"%vssadmin%delete%shadows%") OR like(cmd,"%bcdedit%recoveryenabled%no%") OR like(cmd,"%wevtutil%cl%security%")
  | stats earliest(_time) as first_cmd latest(_time) as last_cmd values(CommandLine) as commands by host user
)
| join type=left host
    [ search index=fileserver sourcetype="smb:audit"
      | eval fname=lower(file_name)
      | where like(fname,"%.locked") OR like(fname,"%readme_restore_files%")
      | stats count as file_events earliest(_time) as first_fs latest(_time) as last_fs values(share) as shares by src_host as host user
    ]
| eval window=max(last_cmd,last_fs)-min(first_cmd,first_fs)
| where file_events >= 50 AND window <= 900
| eval severity=case(file_events>=1000,"critical", file_events>=200,"high", true(),"medium")
| table host user severity first_cmd last_cmd commands first_fs last_fs file_events shares window
```

---

## Tuning Guidance

- Exclude sanctioned admin tooling hosts and backup servers.
- Add additional indicators for confidence:
  - Office spawning PowerShell or cmd
  - Execution from `AppData\\Roaming` with suspicious names (e.g., `svchost.exe`)
  - Burst SMB rename activity from one endpoint to many files

---

## Response Actions When Triggered

- Isolate host immediately.
- Disable SMB write access from the host or take shares offline if encryption is active.
- Preserve evidence; begin containment and restore planning.
