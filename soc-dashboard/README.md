# SOC Security Monitoring Dashboard

A real-time Security Operations Center (SOC) dashboard for small security teams. Simulates security alerts and displays them on a live dashboard with WebSocket updates, metrics panels, and filtering.

## Features

- **Live dashboard**: Alerts by severity, failed logins, malware counts, top suspicious IPs
- **Real-time event stream**: WebSocket-based live alert feed
- **Alert filtering**: By severity and alert type
- **Severity color coding**: Critical, high, medium, low, info
- **Log simulator**: Python script that generates fake security logs (failed logins, malware, phishing, suspicious IPs)

## Architecture

| Layer      | Tech                    |
|-----------|--------------------------|
| Backend   | Python FastAPI           |
| Database  | PostgreSQL               |
| Real-time | WebSocket                |
| REST      | `/api/v1/alerts`, `/api/v1/metrics` |
| Frontend  | React + Vite + Recharts  |
| Simulator | Python (requests)       |

## Project Structure

```
soc-dashboard/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI app, CORS, lifespan
│   │   ├── config.py        # Settings
│   │   ├── database.py      # SQLAlchemy engine, session
│   │   ├── models.py        # Alert model
│   │   ├── schemas.py       # Pydantic schemas
│   │   ├── websocket_manager.py  # WS broadcast queue
│   │   └── routers/
│   │       ├── alerts.py    # REST + WebSocket for alerts
│   │       └── metrics.py   # Aggregated metrics
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── App.jsx, App.css
│   │   ├── api/client.js
│   │   └── components/      # Panels + EventStream
│   ├── package.json
│   ├── nginx.conf
│   └── Dockerfile
├── simulator/
│   ├── log_simulator.py    # Fake security log generator
│   └── requirements.txt
├── docker-compose.yml
├── .env.example
└── README.md
```

## Database Schema

**alerts**

| Column       | Type      | Description   |
|-------------|-----------|---------------|
| id          | integer   | Primary key   |
| severity    | string    | critical, high, medium, low, info |
| timestamp   | datetime  | Alert time    |
| source_ip   | string    | Source IP     |
| alert_type  | string    | failed_login, malware_detection, phishing, suspicious_ip, etc. |
| description | text      | Optional      |
| created_at  | datetime  | Row creation  |

## Quick Start (Local)

### 1. Backend + DB

```bash
# From repo root
cd soc-dashboard

# Optional: virtualenv
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate

pip install -r backend/requirements.txt
```

Create a PostgreSQL database named `soc_dashboard` and set:

```bash
export DATABASE_URL=postgresql://postgres:postgres@localhost:5432/soc_dashboard
# Windows: set DATABASE_URL=postgresql://...
```

Run the backend:

```bash
cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173. The Vite dev server proxies `/api` and `/ws` to the backend.

### 3. Log Simulator

In another terminal:

```bash
cd simulator
pip install -r requirements.txt
python log_simulator.py
```

Options:

- `--api http://localhost:8000/api/v1` — API base URL
- `--interval 2` — seconds between alerts (default 2)
- `--count 50` — number of alerts to send (default 0 = infinite)

Alerts will appear in the dashboard and in the real-time event stream.

## Docker

From `soc-dashboard/`:

```bash
docker compose up --build
```

- **Frontend**: http://localhost:3000  
- **Backend API**: http://localhost:8000  
- **API docs**: http://localhost:8000/docs  

Run the simulator against the API:

```bash
pip install requests
python simulator/log_simulator.py --api http://localhost:8000/api/v1
```

## Deployment

### Render

1. **PostgreSQL**: Create a PostgreSQL instance on Render; note the external database URL.

2. **Backend (Web Service)**  
   - Build: `cd backend && pip install -r requirements.txt`  
   - Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`  
   - Env: `DATABASE_URL` = Render Postgres URL, `CORS_ORIGINS` = your frontend URL (e.g. `https://your-app.onrender.com`).

3. **Frontend (Static Site)**  
   - Build: `cd frontend && npm install && npm run build`  
   - Publish: `frontend/dist`  
   - Env (optional): `VITE_API_URL=https://your-backend.onrender.com`, `VITE_WS_URL=wss://your-backend.onrender.com` if the frontend is on a different domain.

4. If frontend and backend are on the same domain (e.g. backend as a subdomain or path), set `VITE_API_URL` and `VITE_WS_URL` so the frontend talks to the correct host.

### AWS

1. **RDS**: Create a PostgreSQL instance; note the endpoint and credentials.

2. **Backend (ECS/Fargate or EC2)**  
   - Use the `backend/Dockerfile` or run with uvicorn.  
   - Set `DATABASE_URL` and `CORS_ORIGINS` to your frontend URL.  
   - Expose port 8000 (and 80/443 if using a reverse proxy).

3. **Frontend (S3 + CloudFront or Amplify)**  
   - Build: `cd frontend && npm run build`.  
   - Set `VITE_API_URL` and `VITE_WS_URL` to your backend URL (e.g. `https://api.yourdomain.com`, `wss://api.yourdomain.com`).  
   - Upload `dist` to S3 and optionally put CloudFront in front; or use Amplify to build and host.

4. **Simulator**: Run from any machine that can reach the backend URL:

   ```bash
   python simulator/log_simulator.py --api https://your-backend-url/api/v1
   ```

## API Summary

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/alerts` | List alerts (query: severity, alert_type, source_ip, limit, offset) |
| POST | `/api/v1/alerts` | Create alert (body: severity, source_ip, alert_type, description, optional timestamp) |
| GET | `/api/v1/metrics` | Dashboard metrics (last 24h) |
| WS | `/api/v1/alerts/ws` | Real-time alert stream (new alerts pushed as JSON) |
| GET | `/health` | Health check |

## License

MIT.
