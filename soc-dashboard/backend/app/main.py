"""FastAPI application entry point."""
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import get_settings
from .database import init_db
from .routers import alerts, metrics

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    app.state.loop = asyncio.get_running_loop()
    from .websocket_manager import broadcast_consumer
    task = asyncio.create_task(broadcast_consumer())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="SOC Security Dashboard API",
    description="Real-time security monitoring API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(alerts.router, prefix=settings.API_PREFIX)
app.include_router(metrics.router, prefix=settings.API_PREFIX)


@app.get("/health")
def health():
    return {"status": "ok"}
