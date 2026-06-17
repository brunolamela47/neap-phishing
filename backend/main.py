from fastapi import FastAPI
from fastapi.middleware.cors import  CORSMiddleware
from fastapi.staticfiles import StaticFiles
from backend.ws_manager import manager
from fastapi import WebSocket, WebSocketDisconnect

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.auth import router as auth_router
from backend.emails import router as email_router
from backend.dashboard import router as dashboard_router
from database.database import create_tables

app = FastAPI(

	title = "NEAP - Network Email Anti-Phishing",
	description = "Academic phishing detection and analysis system",
	version = "1.0.0"
)


app.add_middleware(
	CORSMiddleware,
	allow_origins = ["*"],
	allow_credentials = True,
	allow_methods = ["*"],
	allow_headers = ["*"],
)

app.include_router(auth_router, prefix = "/auth", tags = ["Authentication"])
app.include_router(email_router, prefix = "/emails", tags = ["Emails"])
app.include_router(dashboard_router, prefix = "/dashboard", tags = ["Dashboard"])

@app.on_event("startup")
async def startup():
	create_tables()
	print("NEAP API started")
	print("NEAP Docs: http://localhost:8000/docs")

@app.get("/")
async def root():
	return {"status": "online", "app": "NEAP", "version": "1.0.0"}

# ─── WebSocket Manager ───
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"WebSocket connected — {len(self.active_connections)} active")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"WebSocket disconnected — {len(self.active_connections)} active")

    async def broadcast(self, message: dict):
        """Send message to all connected clients."""
        dead = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                dead.append(connection)
        for d in dead:
            self.active_connections.remove(d)

manager = ConnectionManager()

# ─── WebSocket endpoint ───
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
