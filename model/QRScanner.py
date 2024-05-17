from pyzbar.pyzbar import decode
from PIL import Image
from colorama import init, Fore, Style
import sys, time, requests, base64, os, urllib
from model.APIManager import APIManager

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
        self.log_file_path = "static/log/logError.txt"

        # Initialize the API manager with the configuration file
        # self.api_manager = APIManager("static/config.json")

        # for debugging I made another config file that contains my API the debuConfig.json added to the .gitignore
        self.api_manager = APIManager("static/debugConfig.json")

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
        for i in range(50):
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
        
        # Check if the URL is safe using the method checkVirusTotal()
        virustotalcheck, errorCode = self.checkVirusTotal()
        if errorCode:
            print(f"{Fore.RED}VirusTotal API: error, see the log file in static/log for further information{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT} VirusTotal API: {Fore.GREEN if virustotalcheck else Fore.RED}{'safe' if virustotalcheck else 'not safe'}{Style.RESET_ALL}")
        
        # Check if the URL is safe using the method checkIpQualityScore()
        ipQualityCheck, errorCode = self.checkIpQualityScore()
        if errorCode:
            print(f"{Fore.RED}IPQualityScore API: error, see the log file in static/log for further information{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT} IPQualityScore API: {Fore.GREEN if ipQualityCheck else Fore.RED}{'safe' if ipQualityCheck else 'not safe'}{Style.RESET_ALL}")


        # more control coming soon :)
        print(f"{Style.BRIGHT}\nMore control coming soon...{Style.RESET_ALL}")

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

    def checkVirusTotal(self):
        """
        Checks the URL against the VirusTotal API for malicious content.
        Refer to the VirusTotal API documentation for more information: https://docs.virustotal.com/reference/urls-votes-get
    
        Also see: https://docs.virustotal.com/reference/url#url-identifiers
        Basically Base64 encode the URL and use it as the URL ID.

        Returns:
            bool: True if the URL is safe, False if it is flagged as malicious.
            bool: True if there was an error while checking the URL with VirusTotal, False otherwise.
        """
        # Encode the URL using Base64, refer to the VirusTotal API documentation for more information
        url_id = base64.urlsafe_b64encode(self.urlCode.encode()).decode().strip("=")

        # Set the limit for the number of votes to retrieve
        vote_limit = 10 # You can adjust this value as needed, more votes may take longer to process but provide more information

        # Construct the URL for the VirusTotal API
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}/votes?limit={vote_limit}" 
        # Set the headers with the API key
        headers = {
            "accept":"application/json",
            "x-apikey": f"{self.api_manager.get_api_key('virustotal')}"
            ""
            }
        # This URL return a list of Vote objects that contain the verdict of the URL
        # Refer to: https://docs.virustotal.com/reference/vote-object
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            votes = response.json()["data"]
            for vote in votes:
                if vote["attributes"]["verdict"] != "harmless":
                    return False, False
            return True, False
        else:
            # print(f"{Fore.RED}Error checking the URL with VirusTotal: {response.text}{Style.RESET_ALL}")
            # This basically means an error occurred while checking the URL with VirusTotal, maybe is not an URL
            error_message = response.text
            self.save_error_to_log("VirusTotal", error_message)
            return False, True          

    # Save an error message to the log file
    def save_error_to_log(self, service_name, error_message):

        """
        Saves an error message to the log file for a specific service.

        Args:
            service_name (str): The name of the service where the error occurred.
            error_message (str): The error message to save in the log file.

        Returns:
            None
        """
        if not os.path.exists("static/log"):
            os.makedirs("static/log")  # Crea la cartella 'static' se non esiste

        with open(self.log_file_path, "a") as log_file:
            log_file.write(f"{service_name}: {error_message}\n")

        # print(f"Error logged in {self.log_file_path}: {error_message}")

        return

    # Reset the log file, I need to reset only one time when the tool is run so I'll call in the Controller.py run() method
    def reset_log_file(self):
        if os.path.exists(self.log_file_path):
            os.remove(self.log_file_path)
            # print(f"{Fore.YELLOW}Log file reset successfully.{Style.RESET_ALL}")

    def checkIpQualityScore(self):
        """
        Checks the URL against the IpQualityScore API for malicious content.
        Refer to the IpQualityScore API documentation for more information: https://www.ipqualityscore.com/documentation/malicious-url-scanner-api/overview
    
        Returns:
            bool: True if the URL is safe, False if it is flagged as malicious.
            bool: True if there was an error while checking the URL with IpQualityScore, False otherwise.
        """
        # Parse the urlCode to be used in the API request
        # e.g., https://www.ipqualityscore.com/api/json/url/your-api-key/https%3A%2F%2Fwww.google.com
        url = 'https://www.ipqualityscore.com/api/json/url/%s/%s' % (self.api_manager.get_api_key("ipqualityscore"), urllib.parse.quote_plus(self.urlCode))

        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print(data["unsafe"])
            if data["unsafe"] == False:
                # means that is safe
                return True, False
            else:
                return False, False
        else:
            # This basically means an error occurred while checking the URL with IpQualityScore, maybe is not an URL
            error_message = response.text
            self.save_error_to_log("IpQualityScore", error_message)
            return False, True
    
    # TODO: Implement the checkURLscanIO() method
    # https://urlscan.io/
    # Refer to the follow documentatio: https://urlscan.io/docs/api/
    def checkURLscanIO(self):
        pass
