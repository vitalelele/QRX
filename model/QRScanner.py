from pyzbar.pyzbar import decode
from PIL import Image
from colorama import init, Fore, Style
import sys, time, requests, base64, os, urllib, json, socket
from model.APIManager import APIManager

"""
A class that represents a QR code scanner.
Attributes:
    urlCode (str): The decoded URL from the QR code.
Methods:
    scan_qr_code(file_path): Scans a QR code from an image file.
    getUrlCode(): Returns the decoded URL from the QR code.
    checkShortUrl(): Checks if the decoded URL is a short URL.
Developed by @vitalelele - 2024
"""
class QRScanner:

    def __init__(self):
        self.urlCode = None
        self.urlIpAddr = None
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
                    self.__setUrlCode(obj.data.decode())
                    self.__setIpAddr()
                    self.print_qr_code_info(obj)
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
            f"IP address: {Fore.RED}{self.urlIpAddr}{Style.RESET_ALL}\n"
            f"{Style.BRIGHT}QR code analysis in progress...{Style.RESET_ALL}",
            end=""
        )
        sys.stdout.flush()  # Forza l'output immediato
        animation = "|/-\\"
        # in range(100) = 10 secondi
        # remember to set to 100 when finished !!!!!!!
        for i in range(5):
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
        print(f"{Style.BRIGHT} URL Short: {Fore.GREEN if is_short_url else Fore.RED}{'true' if is_short_url else 'false'}{Style.RESET_ALL}")
        
        # Check if the URL is safe using the method checkVirusTotal()
        virustotalcheck, error_code = self.checkVirusTotal()
        if error_code:
            print(f"{Fore.RED} VirusTotal API: error, see the log file in static/log for further information{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT} VirusTotal API: {Fore.GREEN if virustotalcheck else Fore.RED}{'safe' if virustotalcheck else 'not safe'}{Style.RESET_ALL}")
        
        # Check if the URL is safe using the method checkIpQualityScore()
        ipQualityCheck, error_code = self.checkIpQualityScore()
        if error_code:
            print(f"{Fore.RED} IPQualityScore API: error, see the log file in static/log for further information{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT} IPQualityScore API: {Fore.GREEN if ipQualityCheck else Fore.RED}{'safe' if ipQualityCheck else 'not safe'}{Style.RESET_ALL}")

        # Check if the URL is safe using the method checkURLscanIO()
        error_code, checkUrlScanIO = self.checkURLscanIO()
        if error_code:
            print(f"{Style.BRIGHT} URLscanIO API: {Fore.GREEN}request success{Style.RESET_ALL}")
            print(f"{Style.BRIGHT}      For further information visit: {checkUrlScanIO}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED} URLscanIO API: error, see the log file in static/log for further information{Style.RESET_ALL}")

        # Check if the IP address is found in the AbuseIPDB database using the method checkAbuseIPDB()
        error_code, checkAbuseIPDB_result = self.checkAbuseIPDB()
        if error_code:
            print(f"{Fore.RED} AbuseIPDB API: error, see the log file in static/log for further information{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT} AbuseIPDB API: {Fore.GREEN}request success{Style.RESET_ALL}")
            if checkAbuseIPDB_result:
                # print(f"     {Style.BRIGHT}AbuseIPDB result:{Style.RESET_ALL}")
                print(f"        _> Ip Address: {Fore.GREEN}{checkAbuseIPDB_result['ipAddress']}{Style.RESET_ALL}")
                print(f"        _> Is Whitelisted: {Fore.RED if checkAbuseIPDB_result['isWhitelisted'] is None else Fore.GREEN}{checkAbuseIPDB_result['isWhitelisted']}{Style.RESET_ALL}")
                print(f"        _> ISP: {Fore.RED if checkAbuseIPDB_result['isp'] is None else Fore.GREEN}{checkAbuseIPDB_result['isp']}{Style.RESET_ALL}")
                print(f"        _> Domain: {Fore.RED if checkAbuseIPDB_result['domain'] is None else ''}{checkAbuseIPDB_result['domain']}{Style.RESET_ALL}")
                print(f"        _> Is Tor: {Fore.RED if checkAbuseIPDB_result['isTor'] is False else ''}{checkAbuseIPDB_result['isTor']}{Style.RESET_ALL}")
                print(f"        _> Total Reports: {Fore.GREEN if checkAbuseIPDB_result['totalReports'] < 15 else ''}{checkAbuseIPDB_result['totalReports']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}{Style.BRIGHT}Nessun dato disponibile.{Style.RESET_ALL}")

        # Check if the 
        error_code, checkIp2Location_result = self.checkIp2Location()
        if error_code:
            print(f"{Fore.RED} Ip2Location API: error, see the log file in static/log for further information{Style.RESET_ALL}")
        else:
            print(f"{Style.BRIGHT} Ip2Location API: {Fore.GREEN}request success{Style.RESET_ALL}")
            # print(f"     {Style.BRIGHT}Ip2Location result:{Style.RESET_ALL}")
            print(f"        _> Country Code: {Fore.GREEN}{checkIp2Location_result['country_code']}{Style.RESET_ALL}")
            print(f"        _> Country Name: {Fore.GREEN}{checkIp2Location_result['country_name']}{Style.RESET_ALL}")
            print(f"        _> Region Name: {Fore.GREEN}{checkIp2Location_result['region_name']}{Style.RESET_ALL}")
            print(f"        _> City Name: {Fore.GREEN}{checkIp2Location_result['city_name']}{Style.RESET_ALL}")
            print(f"        _> Latitude: {Fore.GREEN}{checkIp2Location_result['latitude']}{Style.RESET_ALL}")
            print(f"        _> Longitude: {Fore.GREEN}{checkIp2Location_result['longitude']}{Style.RESET_ALL}")
            print(f"        _> Zip Code: {Fore.GREEN}{checkIp2Location_result['zip_code']}{Style.RESET_ALL}")
            print(f"        _> Is Proxy: {Fore.RED if checkIp2Location_result['is_proxy'] is False else ''}{checkIp2Location_result['is_proxy']}{Style.RESET_ALL}")


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
            # print(data["unsafe"])
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

    def checkURLscanIO(self):
        """
        Sends a POST request to the urlscan.io API to scan a given URL.
        Refer to the following documentation: https://urlscan.io/docs/api/

        Returns:
            bool: True if the request is successful, False otherwise.
            dict: The result of the scan if the request is successful.

        Raises:
            None.

        Example usage:
            result, success = checkURLscanIO()
        """
        headers = {'API-Key': self.api_manager.get_api_key("urlscanio"), 'Content-Type':'application/json'}
        data = {"url": self.urlCode, "visibility": "public"}
        response = requests.post('https://urlscan.io/api/v1/scan/',headers=headers, data=json.dumps(data))
        if response.status_code == 200:
            return True, response.json()["result"]
        else:
            error_message = response.text
            self.save_error_to_log("URLscanIO", error_message)
            return False

    def checkAbuseIPDB(self):
        """
            Checks the AbuseIPDB for information about the IP address.
            Refer to the AbuseIPDB API documentation for more information: https://docs.abuseipdb.com

            Returns:
                tuple: A tuple containing a boolean value indicating if the IP address is found in the AbuseIPDB database,
                       and a dictionary containing the relevant information about the IP address if it is found.
                       The dictionary contains the following keys:
                       - ipAddress: The IP address being checked
                       - isWhitelisted: Indicates if the IP address is whitelisted
                       - isp: The Internet Service Provider of the IP address
                       - domain: The domain associated with the IP address
                       - isTor: Indicates if the IP address is a Tor exit node
                       - totalReports: The total number of reports for the IP address
        """
        # Defining the api-endpoint
        url = 'https://api.abuseipdb.com/api/v2/check'

        querystring = {
            'ipAddress': {self.getIpAddr()},
            'maxAgeInDays': '90'
        }

        headers = {
            'Accept': 'application/json',
            'Key': self.api_manager.get_api_key("abuseipdb")
        }

        try:
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            response.raise_for_status()  # Raise an exception for 4xx/5xx errors

            response_data = response.json()
            # Retrieve important data from the response
            if 'data' in response_data:
                data = response_data['data']
                resultAbuseIPDB = {
                    "ipAddress": data.get("ipAddress"),
                    "isWhitelisted": data.get("isWhitelisted"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "isTor": data.get("isTor"),
                    "totalReports": data.get("totalReports")
                }
                return False, resultAbuseIPDB
            else:
                return False

        except requests.exceptions.RequestException as e:
            print(f"Errore nella richiesta: {e}")
            return False

    def checkIp2Location(self):
        # Definire il payload per la richiesta
        payload = {'key': self.api_manager.get_api_key("ip2location"), 'ip': self.getIpAddr(), 'format': 'json'}
        
        # Effettuare la richiesta HTTP
        response = requests.get('https://api.ip2location.io/', params=payload)
        
        # Controllare lo status della risposta
        if response.status_code == 200:
            # Se la richiesta va a buon fine, estrai le informazioni richieste
            data = response.json()
            result_return = {
                "country_code": data["country_code"],
                "country_name": data["country_name"],
                "region_name": data["region_name"],
                "city_name": data["city_name"],
                "latitude": data["latitude"],
                "longitude": data["longitude"],
                "zip_code": data["zip_code"],
                "is_proxy": data["is_proxy"]
            }
            return False, result_return
        else:
            # Se la richiesta non va a buon fine, ritorna False
            return True

    def getIpAddr(self):
        return self.urlIpAddr
    
    # Set the IP address extracted from the URL
    def __setIpAddr(self):
        # Analyze the URL to extract only the domain
        parsed_url = urllib.parse.urlparse(self.urlCode)

        try:
            # Get the IP address from the URL
            ip_address = socket.gethostbyname(parsed_url.hostname)
            self.urlIpAddr = ip_address
        except socket.gaierror as e:
            print(f"Error while getting the IP address: {Fore.RED}{e}{Style.RESET_ALL}")
            self.urlIpAddr = None
       
        return
    
    def __setUrlCode(self, url):
        self.urlCode = url
        return