from fastapi import FastAPI
from app.routes import auth

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI :)"}

app.include_router(auth.router)