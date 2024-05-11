from pyzbar.pyzbar import decode
from PIL import Image
from colorama import init, Fore, Style
import sys, time


"""
A class that represents a QR code scanner.
Attributes:
    urlCode (str): The decoded URL from the QR code.
Methods:
    scan_qr_code(file_path): Scans a QR code from an image file.
    getUrlCode(): Returns the decoded URL from the QR code.
    checkShortUrl(): Checks if the decoded URL is a short URL.
Developed by @vitalele - 2024
"""
class QRScanner:

    def __init__(self):
        self.urlCode = None

    def scan_qr_code(self, file_path):
        """
        Scans a QR code from an image file.

        Args:
            file_path (str): The path to the image file containing the QR code.

        Returns:
            None
        """
        init(convert=True)
        try:
            img = Image.open(file_path)
            decoded_objects = decode(img)
            if decoded_objects:
                for obj in decoded_objects:
                    self.print_qr_code_info(obj)
                    self.urlCode = obj.data.decode()
                    return True
            else:
                print(f"{Style.BRIGHT}{Fore.RED}No QR code found in the file.\n{Style.RESET_ALL}")
                return False
        except Exception as e:
            print("Error during scanning:", e)

    def print_qr_code_info(self, obj):
        """
        Prints information about a decoded QR code.

        Args:
            obj: An object representing the decoded QR code.

        Returns:
            None

        Prints the following information about the decoded QR code:
        - Decoded URL
        - QR code type
        - QR code location
        - QR code polygon
        - QR code raw data

        Example usage:
        ```
        qr_code = decode_qr_code(image)
        print_qr_code_info(qr_code)
        ```
        """
        print(
            f"{Style.BRIGHT}{Fore.GREEN}QR code decoded successfully!\n"
            f"Decoded URL: {Fore.CYAN}{obj.data.decode()}\n"
            f"QR code type: {Fore.CYAN}{obj.type}\n"
            f"QR code location: {Fore.CYAN}{obj.rect}\n"
            f"QR code polygon: {Fore.CYAN}{obj.polygon}\n"
            f"QR code raw data: {Fore.CYAN}{obj.data}\n"
            f"{Style.BRIGHT}QR code analysis in progress...{Style.RESET_ALL}",
            end=""
        )
        sys.stdout.flush()  # Forza l'output immediato
        animation = "|/-\\"
        # in range(100) = 10 secondi
        # remember to set to 100 when finished !!!!!!! 
        for i in range(1):
            time.sleep(0.1)
            sys.stdout.write("\b" + animation[i % len(animation)])
            sys.stdout.flush()
        print(" Done" + Style.RESET_ALL)

    def urlControl(self):

        print(f"\n{Style.BRIGHT}{Fore.YELLOW}QR Code URL Analysis Result:{Style.RESET_ALL}")

        # Initialize colorama with convert=True
        init(convert=True)
        
        # Check if the URL is a short URL, using the method checkShortUrl()
        is_short_url = self.checkShortUrl()
        print(f"{Style.BRIGHT}  URL Short: {Fore.GREEN if is_short_url else Fore.RED}{'true' if is_short_url else 'false'}{Style.RESET_ALL}")


        return

    def getUrlCode(self):
        """
        Returns the decoded URL from the QR code.

        Returns:
            str: The decoded URL from the QR code.
        """
        return self.urlCode

    def checkShortUrl(self):
        """
        Checks if the decoded URL is a short URL.

        Returns:
            bool: True if the decoded URL is a short URL, False otherwise.
        """
        # urlShortList.txt contain the list of short urls
        with open("static/urlShortList.txt", "r") as f:
            short_urls = f.read().splitlines()

        return any(self.urlCode.startswith(shortened) for shortened in short_urls)


        # try:
        #     response = requests.head(self.urlCode)
        #     if response.status_code == 301 or response.status_code == 302:
        #         return True
        #     else:
        #         return False
        # except requests.exceptions.RequestException as e:
        #     print("Error while checking the URL:", e)
        #     return False
