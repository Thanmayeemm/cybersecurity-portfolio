# Screenshots — Incident 03 (Ransomware)

**Purpose:** Document mass file extension changes, shadow copy deletion commands, and SOAR verdicts for binary hash and C2 domain.

**Suggested captures**

1. **File telemetry:** Many **.locked** / **.encrypted** renames in a short interval.
2. **Process:** **vssadmin** / **wbadmin** / **bcdedit** related to recovery inhibition.
3. **SOAR:** API response for ransomware binary SHA256 and C2 domain.

**Tools:** EDR console, Event Viewer, SOAR dashboard or curl.
