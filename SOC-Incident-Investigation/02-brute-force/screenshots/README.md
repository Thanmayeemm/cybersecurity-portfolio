# Screenshots — Incident 02 (Brute force)

**Purpose:** Capture evidence of failed authentication bursts, successful logon, and SOAR enrichment for the attacking IP.

**Suggested captures**

1. **Terminal:** Output of `grep` / `awk` counts showing **>10** failures from one source IP.
2. **Log excerpt:** `Accepted password` line immediately after failure window (same source IP).
3. **SOAR:** JSON from `POST /analyze` for the **203[.]0[.]113[.]15** indicator.

**Tools:** Linux terminal, text editor, browser or curl for SOAR API.
