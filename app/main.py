from fastapi import FastAPI
from app.routes import auth
from motor.motor_asyncio import AsyncIOMotorClient
import time, os
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

start_time = time.time()

MONGODB_DB = os.getenv("MONGODB_DB", "test")  
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")

mongo_client = AsyncIOMotorClient(MONGODB_URI)
db = mongo_client[MONGODB_DB]

@app.get("/health")
async def health_check():
    try:
        # Replace with your actual DB check
        await mongo_client.admin.command("ping")
        db_status = "connected"
    except Exception:
        db_status = "disconnected"

    uptime_seconds = time.time() - start_time
    return {
        "status": "ok",
        "uptime_seconds": int(uptime_seconds),
        "database": db_status,
        "message": "API is healthy"
    }

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI :)"}

app.include_router(auth.router)