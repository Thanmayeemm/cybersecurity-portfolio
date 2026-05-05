# Documentation assets

## Screenshots (`images/`)

Place portfolio screenshots in **`docs/images/`** using these filenames (referenced from the root `README.md`):

| File | Suggested content |
|------|-------------------|
| `dashboard.png` | Full SOAR web UI: analyze form + verdict card + incidents table |
| `slack-alert.png` | Slack message from a suspicious/malicious playbook run |
| `api-response.png` | Terminal or Postman showing `POST /analyze` JSON |

**Recommended:** PNG or WebP, width ~1200–1600px for readability on GitHub.

## Optional extras

- `architecture.png` — Export from Mermaid or draw.io if you want a static diagram in the README
- `demo.gif` — Short screen recording of analyze + Slack (optional asset; reference it from the README only after adding the file)

Do **not** commit `.env`, API keys, or customer data in screenshots.
