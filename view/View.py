import time
import sys

class View:
    def print_banner(self):
        banner = """
  /$$$$$$  /$$$$$$$            /$$   /$$                         /$$                       /$$     /$$                    
 /$$__  $$| $$__  $$          | $$  / $$                        |__/                      | $$    |__/                    
| $$  \ $$| $$  \ $$  /$$$$$$ |  $$/ $$/  /$$$$$$  /$$$$$$/$$$$  /$$ /$$$$$$$   /$$$$$$  /$$$$$$   /$$  /$$$$$$  /$$$$$$$ 
| $$  | $$| $$$$$$$/ /$$__  $$ \  $$$$/  |____  $$| $$_  $$_  $$| $$| $$__  $$ |____  $$|_  $$_/  | $$ /$$__  $$| $$__  $$
| $$  | $$| $$__  $$| $$$$$$$$  >$$  $$   /$$$$$$$| $$ \ $$ \ $$| $$| $$  \ $$  /$$$$$$$  | $$    | $$| $$  \ $$| $$  \ $$
| $$/$$ $$| $$  \ $$| $$_____/ /$$/\  $$ /$$__  $$| $$ | $$ | $$| $$| $$  | $$ /$$__  $$  | $$ /$$| $$| $$  | $$| $$  | $$
|  $$$$$$/| $$  | $$|  $$$$$$$| $$  \ $$|  $$$$$$$| $$ | $$ | $$| $$| $$  | $$|  $$$$$$$  |  $$$$/| $$|  $$$$$$/| $$  | $$
 \____ $$$|__/  |__/ \_______/|__/  |__/ \_______/|__/ |__/ |__/|__/|__/  |__/ \_______/   \___/  |__/ \______/ |__/  |__/
      \__/                                                                               

                                Developed by @vitalele - 2024
        """
        # Stampa i caratteri del banner uno per volta
        for char in banner:
            # Stampa il carattere senza andare a capo
            sys.stdout.write(char)
            sys.stdout.flush()
            
            # Aggiungi un breve ritardo per l'effetto macchina da scrivere
            time.sleep(0.002)  # Puoi regolare la velocità del ritardo

    def show_menu(self):
        menu = """
        Seleziona un'opzione:
        1. Scansiona un QR code
        2. Genera un QR code
        3. Esci
        """
        print(menu)
