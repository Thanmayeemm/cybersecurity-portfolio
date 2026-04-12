"""WebSocket connection manager and broadcast queue."""
import asyncio
from typing import List, Dict, Any
from fastapi import WebSocket

ws_connections: List[WebSocket] = []
alert_queue: asyncio.Queue = asyncio.Queue()


async def broadcast_consumer():
    """Background task: consume from queue and send to all WebSocket clients."""
    while True:
        try:
            alert = await alert_queue.get()
            dead = []
            for conn in ws_connections:
                try:
                    await conn.send_json(alert)
                except Exception:
                    dead.append(conn)
            for c in dead:
                if c in ws_connections:
                    ws_connections.remove(c)
        except asyncio.CancelledError:
            break
        except Exception:
            continue


def enqueue_alert(alert: Dict[str, Any], loop: asyncio.AbstractEventLoop = None):
    """Called from sync code (e.g. POST) to push alert to WebSocket clients."""
    if loop is not None:
        loop.call_soon_threadsafe(alert_queue.put_nowait, alert)
    else:
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(alert_queue.put_nowait, alert)
        except RuntimeError:
            alert_queue.put_nowait(alert)
