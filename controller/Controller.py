import sys
from view.View import View
from model.QRScanner import QRScanner
from model.QRGenerator import QRGenerator


class Controller:
    def __init__(self):
        self.view = View()
        self.scanner = QRScanner()
        self.generator = QRGenerator()

    def run(self):
        self.view.print_banner()
        while True:
            self.view.show_menu()
            choice = input("Inserisci la tua scelta (1-3): ")
            if choice == "1":
                file_path = input("Inserisci il percorso del file del QR code: ")
                self.scanner.scan_qr_code(file_path)
            elif choice == "2":
                data = input("Inserisci il testo o l'URL per il QR code: ")
                # file_path = input("Inserisci il percorso di salvataggio per il QR code generato: ")
                # voglio salvarlo sempre nella folder qr_generated
                self.generator.generate_qr_code(data)
            elif choice == "3":
                print("Uscita dal tool. A presto!")
                sys.exit(0)
            else:
                print("Scelta non valida. Riprova.")
