from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel
from view.View import View
from model.QRScanner import QRScanner

app = FastAPI()
qr_scanner = QRScanner()

'''
    This is the API service that will be used to interact with the QRX tool.
    It will provide endpoints for scanning QR codes and generating QR codes.
    The API service will be built using FastAPI.
    Name of the serice is QRAPIX (QR API X)
    The API service will have the following endpoints:
    - /scan_qr: This endpoint will be used to scan a QR code.
    ... more endpoints to be added later.

    Developed by: Antonio Vitale
    GitHub Repository: github.com/vitalelele/qrx
'''

# TODO: Create endpoints for QRX tool using FastAPI
@app.get("/")
async def read_root():
    return {"message": "Hello, World!"}

@app.get("/about_project")
async def about_project():
    view = View()
    return {"message": view.get_message_about_project()}

@app.post("/scan_qr")
async def scan_qr(qr_code: UploadFile = File(...)):
    if not qr_code:
        return {"error": "No QR code file provided"}

    try:
        file_contents = await qr_code.read()
        file_path = f"static/qr_generated/temp_upload/{qr_code.filename}"
        with open(file_path, "wb") as f:
            f.write(file_contents)

        qr_scanner.scan_qr_code(file_path)
        qr_scanner.urlControl()
        result = qr_scanner.get_control_results()
        return {"result" : result}
    except Exception as e:
        return {"error": str(e)}