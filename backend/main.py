from fastapi import FastAPI
from fastapi.middleware.cors import  CORSMiddleware
from fastapi.staticfiles import StaticFiles
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
app.include_router(email_router, prefix = "/admin", tags = ["Emails"])
app.include_router(dashboard_router, prefix = "/dashboard", tags = ["Dashboard"])

@app.on_event("startup")
async def startup():
	create_tables()
	print("NEAP API started")
	print("NEAP Docs: http://localhost:8000/docs")

@app.get("/")
async def root():
	return {"status": "online", "app": "NEAP", "version": "1.0.0"}
