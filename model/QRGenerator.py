import qrcode

class QRGenerator:
    def generate_qr_code(self, data):
        try:
            qr = qrcode.make(data)
            qr.save("static/qr_generated/qr_code.png")
            print("QR code generated and saved!")
        except Exception as e:
            print("Error during generation:", e)
