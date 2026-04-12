"""Alerts REST API and WebSocket."""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import desc

from ..database import get_db
from ..models import Alert
from ..schemas import AlertCreate, AlertResponse
from ..websocket_manager import ws_connections, enqueue_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=List[AlertResponse])
def list_alerts(
    severity: Optional[str] = Query(None),
    alert_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """List alerts with optional filters."""
    q = db.query(Alert).order_by(desc(Alert.timestamp))
    if severity:
        q = q.filter(Alert.severity == severity)
    if alert_type:
        q = q.filter(Alert.alert_type == alert_type)
    if source_ip:
        q = q.filter(Alert.source_ip == source_ip)
    return q.offset(offset).limit(limit).all()


@router.post("", response_model=AlertResponse)
def create_alert(
    request: Request,
    alert: AlertCreate,
    db: Session = Depends(get_db),
):
    """Create a new alert (used by log simulator)."""
    ts = alert.timestamp or datetime.utcnow()
    db_alert = Alert(
        severity=alert.severity,
        timestamp=ts,
        source_ip=alert.source_ip,
        alert_type=alert.alert_type,
        description=alert.description,
    )
    db.add(db_alert)
    db.commit()
    db.refresh(db_alert)
    payload = {
        "id": db_alert.id,
        "severity": db_alert.severity,
        "timestamp": db_alert.timestamp.isoformat(),
        "source_ip": db_alert.source_ip,
        "alert_type": db_alert.alert_type,
        "description": db_alert.description,
    }
    loop = getattr(request.app.state, "loop", None)
    enqueue_alert(payload, loop)
    return db_alert


@router.websocket("/ws")
async def websocket_alerts(websocket: WebSocket):
    """Real-time alert stream via WebSocket."""
    await websocket.accept()
    ws_connections.append(websocket)
    try:
        while True:
            # Keep connection alive; client can also send ping
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in ws_connections:
            ws_connections.remove(websocket)
