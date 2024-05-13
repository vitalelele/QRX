<p align="center">
  <img src="https://i.imgur.com/QRCodeToolLogo.png" alt="QRX - QReXamination Logo" width="200" height="200">
</p>

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
- **Generate QR codes:** Create QR codes from text or URLs.
- **URL analysis:** Check if a scanned URL is a short URL.

## Installation
1. **Clone the repository:**
   ```
   git clone https://github.com/vitalelele/QRX.git
   ```

2. **Navigate to the project directory:**
   ```
   cd QRX
   ```

3. **Install the required dependencies:**
   ```
   pip install -r requirements.txt
   ```

   Make sure you have Python installed on your system.

## Usage
1. **Run the tool:**
   ```
   python main.py
   ```

2. **Follow the on-screen instructions to choose an option:**
   - Scan a QR code
   - Generate a QR code
   - About the project
   - Exit

## Customization
### Changing API Keys
To use certain features, such as URL analysis, you may need to update the API keys in the `config.json` file located in the `static` folder. Please replace the default values (`YOUR_API_KEY`) with your own API keys obtained from the respective service provider. You can obtain API keys from services like Google, Twitter, or other APIs that the tool may utilize.

## Environment Setup
For maximum security, we recommend setting up a virtual environment before installing the dependencies. Here's how you can do it:

1. **Create a virtual environment:**
   ```
   python -m venv venv
   ```

2. **Activate the virtual environment:**
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - macOS/Linux:
     ```
     source venv/bin/activate
     ```

3. **Proceed with the installation as mentioned in the Installation section.**

## Author
This awesome tool was crafted with ❤️ by Antonio Vitale ([@vitalele](https://github.com/vitalelele)). If you have any questions or suggestions, feel free to reach out!

## Contributing
We welcome contributions from the community! If you'd like to contribute to QRX - QReXamination, please check out the [CONTRIBUTING](CONTRIBUTING.md) guidelines.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
