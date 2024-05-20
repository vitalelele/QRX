from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

# TODO: Create endpoints for QRX tool using FastAPI
@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}

