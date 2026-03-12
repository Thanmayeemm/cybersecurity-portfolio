## Attack Diagram (Ransomware)

```text
User (ACME\\m.johnson)
   |
   | Opens malicious attachment: Invoice_March2026.docm
   v
WINWORD.EXE
   |
   | Spawns PowerShell (hidden, policy bypass)
   v
powershell.exe  ---- downloads script ----> 203.0.113.77 (payload hosting)
   |
   | Drops/executes payload from user profile
   v
AppData\\Roaming\\svchost.exe
   |
   | Inhibit recovery + reduce visibility
   | - vssadmin delete shadows
   | - bcdedit recoveryenabled No
   | - wevtutil cl Security
   v
Encrypt local + network share files
   |
   | Mass rename/encrypt -> *.locked
   | Create ransom note -> README_RESTORE_FILES.txt
   v
Impact: User data + HR share disruption
```
