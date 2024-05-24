# 🚀 QRX - QReXamination 🎨

## Overview
Welcome to QRX - QReXamination! This command-line tool is your ultimate companion in the world of QR codes. Whether you need to scan a QR code from an image file or generate one from scratch, we've got you covered!

**Important Note:** Before scanning the QR code below, make sure you trust its source. Stay safe and avoid scanning unknown QR codes to protect your privacy and security. Remember, safety first! 🔒

## QR Code Safety Warning
<p align="center">
  <img src="https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=Please%20be%20careful%20when%20scanning%20this%20QR%20code!%20%F0%9F%9A%A8" alt="Safety Warning QR Code">
</p>

## Features
- **Scan QR codes:** Easily scan QR codes from image files.
- **Generate QR codes:** Create custom QR codes with different types and optional logos.
- **API Service:** Use the QRAPIX API to integrate QR code functionalities into your applications.

## Installation
1. **Clone the repository:**
   ```sh
   git clone https://github.com/vitalelele/QRX.git
   ```

2. **Navigate to the project directory:**
   ```sh
   cd QRX
   ```

3. **Install the required dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

   Make sure you have Python installed on your system.
   Currently dependencies in use are:
    ```sh
    $ pip freeze 
    colorama==0.4.6
    pillow==10.3.0
    pyzbar==0.1.9
    qrcode==7.4.2
    requests
    ```

## Usage
1. **Run the tool:**
   ```sh
   python main.py
   ```

2. **Follow the on-screen instructions to choose an option:**
   - Scan a QR code
   - Generate a QR code

## QRAPIX
QRX - QReXamination also provides a RESTful API service called QRAPIX, which allows you to interact with the QRX tool programmatically. The API is built using FastAPI and provides the following endpoints:

| QRAPIX Status | ![#ff0000](https://via.placeholder.com/15/ff0000/ff0000.png) Offline | 
<!-- | QRAPIX Status | ![#00FF00](https://via.placeholder.com/15/00FF00/00FF00.png) Online | -->

|-----------------------------------------------------------------------------------------------|

### Endpoints

#### Scan QR Code
- **Endpoint:** `/scan_qr`
- **Method:** `POST`
- **Parameters:**
  - `qr_code`: The QR code image file to be scanned (as `multipart/form-data`).
- **Example in Python:**
  ```python
  import requests

  url = "http://localhost:8000/scan_qr"
  files = {"qr_code": open("path/to/qr_code_image.png", "rb")}

  response = requests.post(url, files=files)
  print(response.json())
  ```

#### Generate QR Code
- **Endpoint:** `/generate_qr`
- **Method:** `POST`
- **Parameters:**
  - `data`: The data to encode in the QR code (as `form-data`).
  - `qr_type`: The type of QR code to generate (`standard`, `microqr`, `frame`) (as `form-data`).
  - `logo`: (Optional) The logo image file to embed in the QR code (as `multipart/form-data`).
- **Example in Python:**
  ```python
  import requests

  url = "http://localhost:8000/generate_qr"
  data = {"data": "Hello, World!", "qr_type": "standard"}
  files = {"logo": open("path/to/logo_image.png", "rb")} if logo_path else {}

  response = requests.post(url, data=data, files=files)
  if response.status_code == 200:
      with open("generated_qr_code.png", "wb") as f:
          f.write(response.content)
  else:
      print(response.json())
  ```

#### About Project
- **Endpoint:** `/about_project`
- **Method:** `GET`
- **Description:** Returns information about the QRX project.
- **Example in Python:**
  ```python
  import requests

  url = "http://localhost:8000/about_project"
  response = requests.get(url)
  print(response.json())
  ```

## Customization
### Changing API Keys
To use certain features, such as URL analysis, you may need to update the API keys in the `config.json` file located in the `static` folder. Please replace the default values (`YOUR_API_KEY`) with your own API keys obtained from the respective service provider. You can obtain API keys from services like Google, Twitter, or other APIs that the tool may utilize.

## Environment Setup
For maximum security, we recommend setting up a virtual environment before installing the dependencies. Here's how you can do it:

1. **Create a virtual environment:**
   ```sh
   python -m venv venv
   ```

2. **Activate the virtual environment:**
   - Windows:
     ```sh
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```sh
     source venv/bin/activate
     ```

3. **Proceed with the installation as mentioned in the Installation section.**

## Author
This awesome tool was crafted with ❤️ by Antonio Vitale ([@vitalelele](https://github.com/vitalelele)). If you have any questions or suggestions, feel free to reach out!

## Contributing
We welcome contributions from the community! If you'd like to contribute to QRX - QReXamination, please check out the [CONTRIBUTING](CONTRIBUTING.md) guidelines.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
