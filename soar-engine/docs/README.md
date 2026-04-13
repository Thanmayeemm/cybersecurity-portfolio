# SOAR engine — docs

- **`api-response-sample.json`** — Example JSON body from `POST /analyze` (same fields drive Slack formatting).
- **`copy-screenshots.ps1`** — Copies dashboard + Slack PNGs from the Cursor asset folder into:
  - `soar-engine/docs/images/dashboard.png`
  - `soar-engine/docs/images/slack-alert.png`
  - `cyber-portfolio/public/images/dashboard.png`
  - `cyber-portfolio/public/images/slack-alert.png`

Run from the **cybersecurity-portfolio** repo root:

```powershell
.\soar-engine\docs\copy-screenshots.ps1
```

**File naming:** `151540` → dashboard (web UI), `151502` → Slack (alert message).
