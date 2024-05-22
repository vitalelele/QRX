from fastapi import FastAPI, File, UploadFile
from pydantic import BaseModel
from view.View import View
from model.QRScanner import QRScanner

app = FastAPI()
qr_scanner = QRScanner()
qr_scanner.is_api_call = True


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
async def info_root():
    return {"message": "Hello, this is QRAPIX, follow the documentation to use the API service",
            "GitHub Repository": "github.com/vitalelele/qrx",
            "Author": "Antonio Vitale",
            "API Documentation": "link.to/documentation",
            "API Version": "1.0",
            "API Name": "QRAPIX",
            "API Description": "API service for QRX tool",
            "API Status": "Active",
            "API License": "MIT",
            "API Contact": "",
            "API Endpoints": "scan_qr, generate_qr, about_project",
            }
            

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
        file_path = f"static/qr_generated/{qr_code.filename}"
        with open(file_path, "wb") as f:
            f.write(file_contents)

        qr_scanner.scan_qr_code(file_path)
        qr_scanner.urlScan_APIservice()
        result = qr_scanner.get_control_results()
        return {"result" : result}
    
    except Exception as e:
        return {"error": str(e)}

# TODO: Add endpoint for generating QR codes
@app.post("/generate_qr")
async def generate_qr(data: str):
    # try:
    #     qr_scanner.generate_qr_code(data)
    #     return {"message": "QR code generated successfully"}
    # except Exception as e:
    #     return {"error": str(e)}
    pass