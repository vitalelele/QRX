# 🚀 QRX - QReXamination 🔎🔬

<div align="center">
  <img src="https://github.com/vitalelele/QRX/assets/65810505/9076a6c0-9e0f-494c-9faa-8e2e9576a590" alt="Immagine QRX">
</div>
## Overview
Welcome to QRX - QReXamination, your trusty sidekick in the realm of QR codes! 🎉

Ever wondered what lurks behind those seemingly innocent QR codes? With QRX, you're equipped to unveil the mysteries hidden within. Whether it's scrutinizing URLs, deciphering intricate schemes, or unraveling mysterious text, this tool is your go-to magician's wand for QR code analysis.

In a world where every scan is a potential risk, we're here to empower you with insights. Think of us as your magical lens, offering a sneak peek into the secrets concealed within QR realms. Stay savvy, stay secure! 🔍🔒

<p><strong>This versatile tool represents the culmination of the experimental segment of my thesis within the realm of Computer Science and Technologies for Software Development at University of Bari Aldo Moro in 2024.</strong> It endeavors to encapsulate a comprehensive suite of functionalities, meticulously crafted to cater to a diverse audience ranging from end-users to seasoned developers and system integrators.</p>
<p>The <u>essence of our endeavor</u> lies in <em>simplifying the intricate landscape of QR code management</em>.</p>
<p>Picture a meticulously curated repository of controls and functionalities, <strong>seamlessly integrated into a single, powerful tool</strong>. Whether one seeks to <u>scan QR codes with the precision of a seasoned practitioner or generate new ones with effortless finesse</u>, this tool serves as an <em>indispensable asset</em>.</p>

At its core, our pursuit is not merely technological; it embodies a quest for simplicity, efficiency, and security. As we traverse through the realms of QR code exploration, armed with this innovative tool, we invite fellow adventurers to join us on this expedition towards enhanced QR code security and usability.

Continuously scanning for new horizons, just like QR codes in the digital landscape. ✨ <br>
Per aspera ad astra.

## Features

- **Scan QR Codes:** Embark on a thrilling QR code adventure with this feature! Not only does it kickstart scans on QR codes, but it also plays detective, sniffing out any sneaky schemes or shortened links lurking within. Think of it as your QR code guardian angel! Once detected, it unleashes a squadron of API services for a deep dive analysis, culminating in a beautifully crafted HTML report. And the best part? You can enjoy front-row seats to the scan results directly within the tool interface, making security checks as fun as a rollercoaster ride!

- **Generate QR Codes:** Unleash your inner QR code artist with this whimsical feature! From crafting Standard QR codes to Micro QR codes and even Frame QR codes, the possibilities are as endless as the cosmos. Choose your destination for these digital masterpieces - whether it's a specific path or the cozy confines of the default `static/qr_generated` folder. Each file is lovingly stamped with a unique timestamp, capturing the magic of its creation. It's like giving birth to your very own QR code universe! (`qr_code_YYYY-MM-DD_H_M_S.png`)

- **API Service:** Ahoy there, tech explorer! Prepare to embark on a thrilling journey through the enchanted realm of the QRAPIX API service! Dive into the treasure trove of API documentation, where hidden gems of endpoint functionalities await your discovery. Whether you're a seasoned coder seeking to seamlessly integrate QR code magic into your applications or just a curious soul eager to unravel the mysteries of QR code technology, the API service promises a voyage filled with excitement and enlightenment. Strap on your adventure boots and let's set sail! 🚀🔍

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
   ![Immagine 2024-05-26 201931](https://github.com/vitalelele/QRX/assets/65810505/c0d6a6fe-94bd-4be6-861a-34b1d4be2f49)


2. **Follow the on-screen instructions to choose an option**

## QRAPIX - ![#ff0000](https://via.placeholder.com/15/ff0000/ff0000.png) Offline
QRX - QReXamination also provides a RESTful API service called QRAPIX, which allows you to interact with the QRX tool programmatically. The API is built using FastAPI and provides the following endpoints:

<!-- | QRAPIX Status | ![#00FF00](https://via.placeholder.com/15/00FF00/00FF00.png) Online | -->

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
To use certain features, such as URL analysis, you may need to update the API keys in the `config.json` file located in the `static` folder. Please replace the default values (`YOUR_API_KEY`) with your own API keys obtained from the respective service provider. Below is a list of the APIs used and how to obtain an API key for each service:

**VirusTotal**
- **Documentation:** <a href="https://developers.virustotal.com/v3.0/reference" target="_blank">VirusTotal API Documentation</a>
- **Get API Key:** Sign up for a free account at <a href="https://www.virustotal.com/" target="_blank">VirusTotal</a> and obtain your API key from your account settings.

**IPQualityScore**
- **Documentation:** <a href="https://www.ipqualityscore.com/documentation/proxy-detection/overview" target="_blank">IPQualityScore API Documentation</a>
- **Get API Key:** Sign up for a free account at <a href="https://www.ipqualityscore.com/" target="_blank">IPQualityScore</a> and obtain your API key from your account settings.

**urlscan.io**
- **Documentation:** <a href="https://urlscan.io/docs/api/" target="_blank">urlscan.io API Documentation</a>
- **Get API Key:** Sign up for a free account at <a href="https://urlscan.io/" target="_blank">urlscan.io</a> and obtain your API key from your account settings.

**AbuseIPDB**
- **Documentation:** <a href="https://docs.abuseipdb.com/" target="_blank">AbuseIPDB API Documentation</a>
- **Get API Key:** Sign up for a free account at <a href="https://www.abuseipdb.com/" target="_blank">AbuseIPDB</a> and obtain your API key from your account settings.

**IP2Location**
- **Documentation:** <a href="https://www.ip2location.com/web-service/ip2location" target="_blank">IP2Location API Documentation</a>
- **Get API Key:** Sign up for a free account at <a href="https://www.ip2location.com/" target="_blank">IP2Location</a> and obtain your API key from your account settings.



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
