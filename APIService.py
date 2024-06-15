from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from view.View import View
from model.QRScanner import QRScanner
from model.QRGenerator import QRGenerator
from fastapi.responses import FileResponse
from pydantic import BaseModel, constr, ValidationError, Field
from fastapi.middleware.cors import CORSMiddleware
import shutil, os, logging

app = FastAPI(
    title="QRAPIX",
    description="API service for interacting with the QRX tool. It provides endpoints for scanning QR codes and generating QR codes.",
    version="1.0",
    terms_of_service="http://example.com/terms/",
    contact={
        "name": "Antonio Vitale",
        "url": "http://example.com/contact/",
        "email": "support@example.com",
    },
    license_info={
        "name": "MIT",
        "url": "http://example.com/license/",
    },
)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Allow all origins for CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

qr_scanner = QRScanner()
qr_generator = QRGenerator()
qr_scanner.is_api_call = True
qr_generator.is_api_call = True

class QRCodeRequest(BaseModel):
    data: str = Field(..., example="Your data here")
    qr_type: str = constr(regex="^(standard|microqr|frame)$") 

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

@app.get("/", tags=["Information"], summary="Root Information", description="Provides general information about the QRAPIX service.")
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
            "API Contact": "vitaleleinfo@gmail.com",
            "API Endpoints": "scan_qr, generate_qr, about_project",
            }           

@app.get("/about_project", tags=["Information"], summary="About the Project", description="Provides information about the QRAPIX project.")
async def about_project():
    view = View()
    return {"message": view.get_message_about_project()}

@app.post("/scan_qr", tags=["QR Code Operations"], summary="Scan QR Code", description="Endpoint for scanning a QR code. Upload a QR code image to get analysis result.")
async def scan_qr(qr_code: UploadFile = File(...)):
    if not qr_code:
        raise HTTPException(status_code=400, detail="No QR code file provided")

    try:
        file_contents = await qr_code.read()
        file_path = f"static/qr_generated/{qr_code.filename}"
        with open(file_path, "wb") as f:
            f.write(file_contents)

        qr_scanner.scan_qr_code(file_path)
        qr_scanner.urlScan_APIservice()
        result = qr_scanner.get_control_results()
        return {"result": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/generate_qr", tags=["QR Code Operations"], summary="Generate QR Code", description="Endpoint for generating a QR code.")
async def generate_qr(data: str = Form(...), qr_type: str = Form(...), logo: UploadFile = File(None)):
    qr_generator.delete_temporary_qr_codes()
    try:
        logo_path = None
        if qr_type == "frame" and logo:
            logo_path = f"static/qr_generated/{logo.filename}"
            with open(logo_path, "wb") as buffer:
                shutil.copyfileobj(logo.file, buffer)

        temp_file_path = qr_generator.generate_temporary_qr_api(data, qr_type, logo_path)
        if temp_file_path:
            response = FileResponse(temp_file_path, media_type="image/png", filename=os.path.basename(temp_file_path))
            return response
        else:
            raise HTTPException(status_code=500, detail="QR code generation failed: " + e)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
