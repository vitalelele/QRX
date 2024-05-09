# from pyzbar.pyzbar import decode
from PIL import Image

class QRScanner:
    def scan_qr_code(self, file_path):
        # TODO: implementare la scansione del QR code
        print("toimplement")
        # try:
        #     img = Image.open(file_path)
        #     decoded_objects = decode(img)
        #     if decoded_objects:
        #         for obj in decoded_objects:
        #             print("Dato del QR code:", obj.data.decode('utf-8'))
        #     else:
        #         print("Nessun QR code trovato nel file.")
        # except Exception as e:
        #     print("Errore durante la scansione:", e)
