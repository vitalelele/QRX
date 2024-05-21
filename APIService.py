from fastapi import FastAPI
from pydantic import BaseModel
from view.View import View

app = FastAPI()


# TODO: Create endpoints for QRX tool using FastAPI
@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}

@app.get("/about_project")
async def about_project():
    view = View()
    return {"message": view.get_message_about_project()}