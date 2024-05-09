import qrcode

class QRGenerator:
    def generate_qr_code(self, data):
        try:
            qr = qrcode.make(data)
            qr.save("qr_generated/qr_code.png")
            print("QR code generato e salvato!")
        except Exception as e:
            print("Errore durante la generazione:", e)
