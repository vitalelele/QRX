import sys, time, requests, base64, os, urllib, json, socket, datetime, re, mimetypes, tempfile
from pyzbar.pyzbar import decode
from PIL import Image
from colorama import init, Fore, Style
from model.APIManager import APIManager
from view.View import View
from urllib.parse import urlparse


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
        """
        Initializes the QRScanner object.

        Attributes:
            urlCode (str): The decoded URL from the QR code.
            urlIpAddr (str): The IP address associated with the URL.
            log_file_path (str): The path to the log file for error messages.
            report_file_path (str): The path to save the HTML report.
            report_data (list): A list to store the data for the report.
            control_results (dict): A dictionary to store the results of the control checks.
            is_api_call (bool): Indicates whether the API call is enabled.
            api_manager (APIManager): An instance of the APIManager class.

        Returns:
            None
        """
        self.urlCode = None
        self.urlIpAddr = None
        self.log_file_path = "static/log/logError.txt"
        self.report_file_path = None
        self.report_data = []
        self.control_results = {}
        self.is_api_call = False
        self.api_manager = APIManager("static/debugConfig.json")
        self.view = View()
        init(convert=True) # Initialize colorama for cross-platform colored text

    def scan_qr_code(self, file_path):
        """
        Scans a QR code from an image file.

        Args:
            file_path (str): The path to the image file containing the QR code.

        Returns:
            bool: True if a QR code is found and processed successfully, False otherwise.
        """
        init(convert=True)
        try:
            img = Image.open(file_path)
            decoded_objects = decode(img)
            if decoded_objects:
                for obj in decoded_objects:
                    self.__setUrlCode(obj.data.decode())
                    self.print_qr_code_info(obj)
                    try:
                        if not self.checkActionScheme():
                            self.__setIpAddr()
                    except Exception as e:
                        print(f"{Fore.RED}This is not a valid URL, cannot get the IP address.{Style.RESET_ALL}")
                        return False
                    
                    if self.is_api_call:
                        self.control_results["QR Code info"] = { "result" : self.print_qr_code_info(obj)}
                        return True
                    
                    return True
            else:
                print(f"{Style.BRIGHT}{Fore.RED}[!] No QR code found in the file.\n{Style.RESET_ALL}")
                return False
            
        except Exception as e:
            print(f"{Fore.RED}Error during scanning:{Style.RESET_ALL}", e)
            return False

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
        qr_info_message =   f"{Style.BRIGHT}{Fore.GREEN}QR code decoded successfully!\n"\
                            f"Decoded URL: {Fore.CYAN}{obj.data.decode()}\n"\
                            f"QR code type: {Fore.CYAN}{obj.type}\n"\
                            f"QR code location: {Fore.CYAN}{obj.rect}\n"\
                            f"QR code polygon: {Fore.CYAN}{obj.polygon}\n"\
                            f"QR code raw data: {Fore.CYAN}{obj.data}\n"\
                            f"IP address: {Fore.RED}{self.urlIpAddr}{Style.RESET_ALL}\n"\
                            f"{Style.BRIGHT}QR code analysis in progress...{Style.RESET_ALL}"
        
        # Check if the API call is enabled
        if self.is_api_call:
            qr_info_message_api_format = {
                            "decoded_successfully": True,
                            "decoded_url": obj.data.decode(),
                            "qr_code_type": obj.type,
                            "qr_code_location": obj.rect,
                            "qr_code_polygon": obj.polygon,
                            "qr_code_raw_data": obj.data,
                            "ip_address": self.urlIpAddr,
                            "analysis_in_progress": True
                            }
            return qr_info_message_api_format
    
        print(qr_info_message, end="")
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
        """
        Performs URL analysis for a QR code.

        This method checks various aspects of the URL obtained from the QR code, such as the action scheme, URL shortening, safety using VirusTotal,
        IP quality using IPQualityScore, URL scanning using URLscanIO, presence in the AbuseIPDB database, and IP location using IP2Location.

        Returns:
            None
        """
        print(f"\n{Style.BRIGHT}{Fore.YELLOW}QR Code URL Analysis Result:{Style.RESET_ALL}")

        download_info = self.checkDownload()
        if download_info['is_download']:
            download_warning = f"{Style.BRIGHT}{Fore.RED} [!] WARNING: This QR code initiates a download. Proceed with extreme caution!{Style.RESET_ALL}"
            print(download_warning)
            print(f"     Filename: {Fore.CYAN}{download_info['filename']}{Style.RESET_ALL}")
            print(f"     Site: {Fore.CYAN}{download_info['site']}{Style.RESET_ALL}")
            print(f"     Content Type: {Fore.CYAN}{download_info['content_type']}{Style.RESET_ALL}")
            print(f"     Content Length: {Fore.CYAN}{download_info['content_length']}{Style.RESET_ALL}")

            user_response = input(f"{Fore.YELLOW}Do you want to download and scan this file? (n is equal to start default URL analyisis) (y/n): {Style.RESET_ALL}")
            if user_response.lower() == 'y':
                # Scan the downloaded file
                scan_results = self.scan_file_virustotal(download_info['file_path'])
                print(f"\n{Style.BRIGHT}{Fore.YELLOW}VirusTotal File Scan Results:{Style.RESET_ALL}")

                analysis_stats = scan_results.get('attributes', {}).get('stats', {})
                file_info = scan_results.get('meta', {}).get('file_info', {})
                results = scan_results.get('attributes', {}).get('results', {})

                malicious_count = analysis_stats.get('malicious', 0)
                suspicious_count = analysis_stats.get('suspicious', 0)
                undetected_count = analysis_stats.get('undetected', 0)
                harmless_count = analysis_stats.get('harmless', 0)
                timeout_count = analysis_stats.get('timeout', 0)
                confirmed_timeout_count = analysis_stats.get('confirmed-timeout', 0)
                failure_count = analysis_stats.get('failure', 0)
                type_unsupported_count = analysis_stats.get('type-unsupported', 0)

                print(f"SHA-256: {Fore.CYAN}{file_info.get('sha256')}{Style.RESET_ALL}")
                print(f"MD5: {Fore.CYAN}{file_info.get('md5')}{Style.RESET_ALL}")
                print(f"SHA-1: {Fore.CYAN}{file_info.get('sha1')}{Style.RESET_ALL}")
                print(f"File Size: {Fore.CYAN}{file_info.get('size')} bytes{Style.RESET_ALL}")

                first_submission_date = scan_results.get('data', {}).get('attributes', {}).get('first_submission_date')
                last_analysis_date = scan_results.get('data', {}).get('attributes', {}).get('last_analysis_date')
                times_submitted = scan_results.get('data', {}).get('attributes', {}).get('times_submitted')
                total_votes = scan_results.get('data', {}).get('attributes', {}).get('total_votes', {})
                total_votes_harmless = total_votes.get('harmless', 0)
                total_votes_malicious = total_votes.get('malicious', 0)

                if first_submission_date:
                    print(f"First Submission Date: {Fore.CYAN}{datetime.datetime.fromtimestamp(first_submission_date)}{Style.RESET_ALL}")
                else:
                    print(f"First Submission Date: {Fore.CYAN}N/A{Style.RESET_ALL}")

                if last_analysis_date:
                    print(f"Last Analysis Date: {Fore.CYAN}{datetime.datetime.fromtimestamp(last_analysis_date)}{Style.RESET_ALL}")
                else:
                    print(f"Last Analysis Date: {Fore.CYAN}N/A{Style.RESET_ALL}")

                print(f"Times Submitted: {Fore.CYAN}{times_submitted}{Style.RESET_ALL}")
                print(f"Total Votes - Harmless: {Fore.GREEN}{total_votes_harmless}{Style.RESET_ALL}")
                print(f"Total Votes - Malicious: {Fore.RED}{total_votes_malicious}{Style.RESET_ALL}")

                print(f"\n{Style.BRIGHT}{Fore.YELLOW}Analysis Stats:{Style.RESET_ALL}")
                print(f"    Malicious: {Fore.RED if malicious_count > 0 else Fore.GREEN}{malicious_count}{Style.RESET_ALL}")
                print(f"    Suspicious: {Fore.RED if suspicious_count > 0 else Fore.GREEN}{suspicious_count}{Style.RESET_ALL}")
                print(f"    Undetected: {Fore.GREEN}{undetected_count}{Style.RESET_ALL}")
                print(f"    Harmless: {Fore.GREEN}{harmless_count}{Style.RESET_ALL}")
                print(f"    Timeout: {Fore.YELLOW if timeout_count > 0 else Fore.GREEN}{timeout_count}{Style.RESET_ALL}")
                print(f"    Confirmed Timeout: {Fore.YELLOW if confirmed_timeout_count > 0 else Fore.GREEN}{confirmed_timeout_count}{Style.RESET_ALL}")
                print(f"    Failure: {Fore.YELLOW if failure_count > 0 else Fore.GREEN}{failure_count}{Style.RESET_ALL}")
                print(f"    Type Unsupported: {Fore.YELLOW if type_unsupported_count > 0 else Fore.GREEN}{type_unsupported_count}{Style.RESET_ALL}")

                if malicious_count > 5:
                    print(f"{Style.BRIGHT}{Fore.YELLOW} [!] {Fore.RED}WARNING: This file is considered malicious by multiple engines! Proceed with extreme caution!{Style.RESET_ALL}\n")
                elif malicious_count == 0:
                    print(f"{Style.BRIGHT}{Fore.GREEN} This file is considered safe.{Style.RESET_ALL}\n")
                else:
                    print(f"{Fore.YELLOW} [!] If the 'malicious' score is not zero, it means that some engines consider the file unsafe.{Style.RESET.ALL}\n")

                self.generate_html_report("VirusTotal File Scan", True, f"""
                <b>File Scan Results:</b><br>
                SHA-256: {file_info.get('sha256')}<br>
                MD5: {file_info.get('md5')}<br>
                SHA-1: {file_info.get('sha1')}<br>
                File Size: {file_info.get('size')} bytes<br>
                First Submission Date: {datetime.datetime.fromtimestamp(first_submission_date) if first_submission_date else 'N/A'}<br>
                Last Analysis Date: {datetime.datetime.fromtimestamp(last_analysis_date) if last_analysis_date else 'N/A'}<br>
                Times Submitted: {times_submitted}<br>
                Total Votes - Harmless: {total_votes_harmless}<br>
                Total Votes - Malicious: {total_votes_malicious}<br>
                <b>Analysis Stats:</b><br>
                Malicious: {malicious_count}<br>
                Suspicious: {suspicious_count}<br>
                Undetected: {undetected_count}<br>
                Harmless: {harmless_count}<br>
                Timeout: {timeout_count}<br>
                Confirmed Timeout: {confirmed_timeout_count}<br>
                Failure: {failure_count}<br>
                Type Unsupported: {type_unsupported_count}<br>
                """)

                # Delete the temporary file
                if os.path.exists(download_info['file_path']):
                    os.remove(download_info['file_path'])
                
                self.save_report()
                print(f"{Style.BRIGHT}{Fore.BLUE}\n [*]{Fore.GREEN} Report saved to {self.report_file_path}{Style.RESET_ALL}")
                self.view.print_banner()
                return

        is_action_scheme = self.checkActionScheme()
        action_scheme_result = f"{Style.BRIGHT}{Fore.YELLOW} [!] {Style.RESET_ALL}Action Scheme: {Fore.GREEN if is_action_scheme else Fore.RED}{'true' if is_action_scheme else 'false'}{Style.RESET_ALL}"
        print(action_scheme_result)
        if is_action_scheme:
            print(f"{Fore.RED} [!] {Style.RESET_ALL}This QR code contains an action scheme.")
            print(f"{Fore.RED} [!] No further analysis is required.{Style.RESET_ALL}")
            print(f"{Fore.RED} [!] {Style.RESET_ALL}{Style.BRIGHT}{Fore.YELLOW}Be careful when opening a scheme, it could open some external services.{Style.RESET_ALL}")
            self.control_results["Action Scheme"] = True
            self.generate_html_report("Action Scheme", True, "This QR code contains an <b>action scheme</b>.")
            return

        is_short_url = self.checkShortUrl()
        short_url_result = f"{Style.BRIGHT} URL Short: {Fore.GREEN if is_short_url else Fore.RED}{'true' if is_short_url else 'false'}{Style.RESET_ALL}"
        print(short_url_result)
        self.control_results["URL Short"] = is_short_url
        self.generate_html_report("URL Short", not is_short_url, "The URL is a <b>short URL</b>" if is_short_url else "The URL is <b>not a short URL</b>")

        print(f"\n{Style.BRIGHT}{Fore.YELLOW}VirusTotal Analysis:{Style.RESET_ALL}")
        virustotalcheck, error_code, virusTotalData = self.checkVirusTotal()
        if error_code:
            virus_total_result = f"{Style.BRIGHT} VirusTotal API: {Fore.RED}request failed{Style.RESET_ALL}"
            print(virus_total_result)
            self.control_results["VirusTotal"] = "error"
            self.generate_html_report("VirusTotal", False, "Error while checking the URL with VirusTotal")
        else:
            virus_total_result = f"{Style.BRIGHT} VirusTotal API: {Fore.GREEN}request success{Style.RESET_ALL}\n"
            virus_total_result += f"     {Style.BRIGHT}VirusTotal result:{Style.RESET_ALL}\n"
            relevant_keys = ["last_analysis_stats", "total_votes", "categories", "reputation", "last_http_response_code", "last_final_url"]
            stats = virusTotalData["last_analysis_stats"]
            for key in relevant_keys:
                value = virusTotalData.get(key, "N/A")
                color = Fore.RED if key == "last_analysis_stats" and stats["malicious"] > 0 else Fore.GREEN
                virus_total_result += f"        _> {Style.BRIGHT}{key}:{Style.RESET_ALL} {color}{value}{Style.RESET_ALL}\n"
            
            if stats["malicious"] > 5:
                virus_total_result += f"{Style.BRIGHT}{Fore.YELLOW} [!] {Fore.RED}WARNING: This URL is malicious! Proceed with extreme caution!{Style.RESET_ALL}\n"
            elif stats["malicious"] == 0:
                virus_total_result += f"{Style.BRIGHT}{Fore.GREEN} This URL is considered safe.{Style.RESET_ALL}\n"
            else:
                virus_total_result += f"{Fore.YELLOW} [!] If the 'malicious' score is not zero, it means that a search engine considers the site unreliable.\n [*] Based on the number, evaluate other services to determine if the site is trustworthy.\n [*] If it is zero, then the site is considered safe. {Style.RESET_ALL}\n"
            
            print(virus_total_result)
            self.control_results["VirusTotal"] = virusTotalData
            report_message = f"<b><u>VirusTotal result:</b></u><br>"
            for key in relevant_keys:
                report_message += f"    - {key}: <i>{virusTotalData.get(key, 'N/A')}</i><br>"
            
            if stats["malicious"] > 5:
                report_message += "<b><font color='red'>WARNING: This URL is malicious! Proceed with extreme caution!</font></b><br>"
            elif stats["malicious"] == 0:
                report_message += "<b><font color='green'>This URL is considered safe.</font></b><br>"
            else:
                report_message += "<b><font> If the 'malicious' score is not zero, it means that a search engine considers the site unreliable. Based on the number, evaluate other services to determine if the site is trustworthy. If it is zero, then the site is considered safe.  </font></b><br>"
            
            self.generate_html_report("VirusTotal", virustotalcheck, report_message)

        print(f"\n{Style.BRIGHT}{Fore.YELLOW}IPQualityScore Analysis:{Style.RESET_ALL}")
        ipQualityCheck, error_code, ipQualityData = self.checkIpQualityScore()
        if error_code:
            ip_quality_score_result = f"{Style.BRIGHT} IPQualityScore API: {Fore.RED}request failed{Style.RESET_ALL}"
            print(ip_quality_score_result)
            self.control_results["IPQualityScore"] = "error"
            self.generate_html_report("IpQualityScore", False, "Error while checking the URL with IpQualityScore")
        else:
            ip_quality_score_result = f"{Style.BRIGHT} IPQualityScore API: {Fore.GREEN}request success{Style.RESET_ALL}\n"
            ip_quality_score_result += f"     {Style.BRIGHT}IPQualityScore result:{Style.RESET_ALL}\n"
            relevant_keys = ["message", "success", "unsafe", "domain", "root_domain", "content_type", "page_size", "domain_rank",
                            "dns_valid", "spamming", "malware", "phishing", "suspicious", "adult", "risk_score", "domain_trust", "page_title"]
            considerations = []
            for key in relevant_keys:
                value = ipQualityData.get(key, "N/A")
                if key in ["spamming", "malware", "phishing", "adult"] and value:
                    considerations.append(f"{key.replace('_', ' ')}")
                color = Fore.RED if value in [False, "false"] else Fore.GREEN
                ip_quality_score_result += f"        _> {Style.BRIGHT}{key}:{Style.RESET_ALL} {color}{value}{Style.RESET_ALL}\n"            
            print(ip_quality_score_result)
            self.control_results["IPQualityScore"] = ipQualityData
            report_message = f"<b><u>IPQualityScore result:</b></u><br>"
            for key in relevant_keys:
                report_message += f"    - {key}: <i>{ipQualityData.get(key, 'N/A')}</i><br>"
            if considerations:
                consideration_message = f"{Fore.YELLOW}[!]{Fore.RESET} This site contains {', '.join(considerations)}"
                print(f"{consideration_message}\n{Fore.YELLOW}[!] This site probably contains these types of cyber attacks or informations, be careful. {Style.RESET_ALL}")
                report_message += f"<b><font color='red'>WARNING </font>: this site probably contains <font color='red'>{', '.join(considerations)}</font></b><br>"
            self.generate_html_report("IPQualityScore", ipQualityCheck, report_message)

        print(f"\n{Style.BRIGHT}{Fore.YELLOW}URLscanIO Analysis:{Style.RESET_ALL}")
        error_code, checkUrlScanIO = self.checkURLscanIO()
        if error_code:
            check_urlscanio_result = f"{Fore.RED} URLscanIO API: error, see the log file in static/log for further information{Style.RESET_ALL}"
            print(check_urlscanio_result)
            self.control_results["URLscanIO"] = "error"
            self.generate_html_report("URLscanIO", False, "Error API, see the log file for further information.")
        else:
            check_urlscanio_result = f"{Style.BRIGHT} URLscanIO API: {Fore.GREEN}request success{Style.RESET_ALL}\n{Style.BRIGHT}      For further information visit: {checkUrlScanIO}{Style.RESET_ALL}"
            print(check_urlscanio_result)
            self.control_results["URLscanIO"] = checkUrlScanIO
            self.generate_html_report("URLscanIO", True, f"Visit the <b><a href='{checkUrlScanIO}' target='_blank'>URLscanIO</b></a> website for further information.")

        print(f"\n{Style.BRIGHT}{Fore.YELLOW}AbuseIPDB Analysis:{Style.RESET_ALL}")
        error_code, checkAbuseIPDB_result = self.checkAbuseIPDB()
        if error_code:
            print_checkAbuseIPDB = f"{Fore.RED} AbuseIPDB API: error, see the log file in static/log for further information{Style.RESET_ALL}"
            print(print_checkAbuseIPDB)
            self.control_results["AbuseIPDB"] = "error"
            self.generate_html_report("AbuseIPDB", False, "Error while checking the IP address with AbuseIPDB, see the log file for further information.")
        else:
            print(f"{Style.BRIGHT} AbuseIPDB API: {Fore.GREEN}request success{Style.RESET_ALL}")
            if checkAbuseIPDB_result:
                print_checkAbuseIPDB = f"     {Style.BRIGHT}AbuseIPDB result:{Style.RESET_ALL}\n" \
                                        f"        _> Ip Address: {Fore.GREEN}{checkAbuseIPDB_result['ipAddress']}{Style.RESET_ALL}\n" \
                                        f"        _> Is Whitelisted: {Fore.RED if checkAbuseIPDB_result['isWhitelisted'] is None else Fore.GREEN}{checkAbuseIPDB_result['isWhitelisted']}{Style.RESET_ALL}\n" \
                                        f"        _> ISP: {Fore.RED if checkAbuseIPDB_result['isp'] is None else Fore.GREEN}{checkAbuseIPDB_result['isp']}{Style.RESET_ALL}\n" \
                                        f"        _> Domain: {Fore.RED if checkAbuseIPDB_result['domain'] is None else ''}{checkAbuseIPDB_result['domain']}{Style.RESET_ALL}\n" \
                                        f"        _> Is Tor: {Fore.RED if checkAbuseIPDB_result['isTor'] is False else ''}{checkAbuseIPDB_result['isTor']}{Style.RESET_ALL}\n" \
                                        f"        _> Total Reports: {Fore.GREEN if checkAbuseIPDB_result['totalReports'] < 15 else ''}{checkAbuseIPDB_result['totalReports']}{Style.RESET_ALL}"
                print(print_checkAbuseIPDB)
                considerations = []
                if checkAbuseIPDB_result.get('isTor', False):
                    considerations.append(f"<font color='red'>utilizes the Tor network</font>")
                if checkAbuseIPDB_result.get('totalReports', 0) > 0:
                    considerations.append(f"<font color='red'>has received {checkAbuseIPDB_result['totalReports']} reports</font>")
                if considerations:
                    consideration_message = f"{Fore.YELLOW}[!]{Fore.RESET} This site {', '.join(considerations)}"
                    print(consideration_message)
                self.control_results["AbuseIPDB"] = checkAbuseIPDB_result
                report_message = f"<b><u>AbuseIPDB result:</b></u><br>"
                report_message += f"    - Ip Address: <i>{checkAbuseIPDB_result['ipAddress']}</i><br>"
                report_message += f"    - Is Whitelisted: <i>{checkAbuseIPDB_result['isWhitelisted']}</i><br>"
                report_message += f"    - ISP: <i>{checkAbuseIPDB_result['isp']}</i><br>"
                report_message += f"    - Domain: <i>{checkAbuseIPDB_result['domain']}</i><br>"
                report_message += f"    - Is Tor: <i>{checkAbuseIPDB_result['isTor']}</i><br>"
                report_message += f"    - Total Reports: <i>{checkAbuseIPDB_result['totalReports']}</i><br>"
                if considerations:
                    report_message += f"<b><font color='red'>WARNING: This site {', '.join(considerations)}</font></b><br>"
                self.generate_html_report("AbuseIPDB", True, report_message)
            else:
                print_checkAbuseIPDB = f"{Fore.RED}{Style.BRIGHT}No data available.{Style.RESET_ALL}"
                print(print_checkAbuseIPDB)
                self.control_results["AbuseIPDB"] = "No data available"
                self.generate_html_report("AbuseIPDB", False, "No data available for the IP address in the AbuseIPDB database.")

        print(f"\n{Style.BRIGHT}{Fore.YELLOW}IP2Location Analysis:{Style.RESET_ALL}")
        error_code, checkIp2Location_result = self.checkIp2Location()
        if error_code:
            print_checkIp2Location_result = f"{Fore.RED} IP2Location API: error, see the log file in static/log for further information{Style.RESET_ALL}"
            print(print_checkIp2Location_result)
            self.control_results["IP2Location"] = "error"
            self.generate_html_report("Ip2Location", False, "Error while checking the IP address with Ip2Location, see the log file for further information.")
        else:
            print_checkIp2Location_result = f"{Style.BRIGHT} IP2Location API: {Fore.GREEN}request success{Style.RESET_ALL}\n" \
                                        f"        _> Country Code: {Fore.GREEN}{checkIp2Location_result['country_code']}{Style.RESET_ALL}\n" \
                                        f"        _> Country Name: {Fore.GREEN}{checkIp2Location_result['country_name']}{Style.RESET_ALL}\n" \
                                        f"        _> Region Name: {Fore.GREEN}{checkIp2Location_result['region_name']}{Style.RESET_ALL}\n" \
                                        f"        _> City Name: {Fore.GREEN}{checkIp2Location_result['city_name']}{Style.RESET_ALL}\n" \
                                        f"        _> Latitude: {Fore.GREEN}{checkIp2Location_result['latitude']}{Style.RESET_ALL}\n" \
                                        f"        _> Longitude: {Fore.GREEN}{checkIp2Location_result['longitude']}{Style.RESET_ALL}\n" \
                                        f"        _> Zip Code: {Fore.GREEN}{checkIp2Location_result['zip_code']}{Style.RESET_ALL}\n" \
                                        f"        _> Is Proxy: {Fore.RED if checkIp2Location_result['is_proxy'] is False else Fore.GREEN}{checkIp2Location_result['is_proxy']}{Style.RESET_ALL}"
            print(print_checkIp2Location_result)
            self.control_results["IP2Location"] = checkIp2Location_result
            self.generate_html_report("Ip2Location", True, f"<b><u>IP2Location result:</b></u><br>"
                                                            f"    - Country Code: <i>{checkIp2Location_result['country_code']}</i><br>"
                                                            f"    - Country Name: <i>{checkIp2Location_result['country_name']}</i><br>"
                                                            f"    - Region Name: <i>{checkIp2Location_result['region_name']}</i><br>"
                                                            f"    - City Name: <i>{checkIp2Location_result['city_name']}</i><br>"
                                                            f"    - Latitude: <i>{checkIp2Location_result['latitude']}</i><br>"
                                                            f"    - Longitude: <i>{checkIp2Location_result['longitude']}</i><br>"
                                                            f"    - Zip Code: <i>{checkIp2Location_result['zip_code']}</i><br>"
                                                            f"    - Is Proxy: <i>{checkIp2Location_result['is_proxy']}</i>")

        self.save_report()
        print(f"{Style.BRIGHT}{Fore.BLUE}\n [*]{Fore.GREEN} Report saved to {self.report_file_path}{Style.RESET_ALL}")
        self.view.print_banner()
        return
    
    def getUrlCode(self):
        """
        Returns the decoded URL from the QR code.

        Returns:
            str: The decoded URL from the QR code.
        """
        return self.urlCode

    def checkActionScheme(self):
        """
        Checks if the provided URL code contains an action scheme.

        Returns:
            bool: True if an action scheme is present, False otherwise.
        """
        pattern = re.compile(
            r'^(mailto:|tel:|sms:|geo:|maps:|whatsapp:|facetime:|skype:|viber:|weixin:|line:|tg:|zoom:|sips:|sip:|ftp:|file:|callto:|git:|magnet:)', re.IGNORECASE)

        match = pattern.match(self.urlCode)

        if match:
            return True
        else:
            return False

    def checkShortUrl(self):
            """
            Checks if the decoded URL is a short URL.

            Returns:
                bool: True if the decoded URL is a short URL, False otherwise.
            """
            # urlShortList.txt contain the list of short urls
            with open("static/urlShortList.txt", "r") as f:
                short_urls = f.read().splitlines()

            # Check if the URL starts with any of the short URLs
            return any(self.urlCode.startswith(shortened) for shortened in short_urls)

    def checkDownload(self):
        """
        Checks if the URL points to a downloadable file and returns additional information.

        This method makes a HEAD request to the URL and inspects the 'Content-Type' header to determine
        if the URL points to a downloadable file. It also retrieves the filename, site initiating the download,
        and other relevant information.

        Returns:
            dict: A dictionary containing the following keys:
                - is_download (bool): True if the URL points to a downloadable file, False otherwise.
                - filename (str): The name of the downloadable file.
                - site (str): The site initiating the download.
                - content_type (str): The content type of the file.
                - content_length (str): The size of the file in bytes.
                - file_path (str): The path to the downloaded file.
        """
        download_info = {
            "is_download": False,
            "filename": None,
            "site": None,
            "content_type": None,
            "content_length": None,
            "file_path": None
        }

        try:
            response = requests.head(self.urlCode, allow_redirects=True)
            content_type = response.headers.get('Content-Type', '')
            content_length = response.headers.get('Content-Length', 'Unknown size')
            parsed_url = urlparse(self.urlCode)
            site = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if content_type:
                main_type = content_type.split('/')[0]
                if main_type in ['application', 'audio', 'video', 'image']:
                    filename = None
                    if 'Content-Disposition' in response.headers:
                        content_disposition = response.headers['Content-Disposition']
                        filename = re.findall('filename="?([^"]+)"?', content_disposition)
                        if filename:
                            filename = filename[0]
                    if not filename:
                        filename = os.path.basename(parsed_url.path)
                    
                    # Create a temporary file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
                        tmp_file.write(requests.get(self.urlCode).content)
                        tmp_file_path = tmp_file.name
                    
                    download_info.update({
                        "is_download": True,
                        "filename": filename,
                        "site": site,
                        "content_type": content_type,
                        "content_length": content_length,
                        "file_path": tmp_file_path
                    })
                    
                    return download_info
        except requests.RequestException as e:
            download_info.update({"error": str(e)})
        
        return download_info

    def checkVirusTotal(self):
        # Encode the URL using Base64, refer to the VirusTotal API documentation for more information
        url_id = base64.urlsafe_b64encode(self.urlCode.encode()).decode().strip("=")

        # Construct the URL for the VirusTotal API
        url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        # Set the headers with the API key
        headers = {
            "accept": "application/json",
            "x-apikey": self.api_manager.get_api_key('virustotal')
        }

        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()["data"]["attributes"]
            # Filter relevant keys
            relevant_keys = ["last_analysis_stats", "total_votes", "categories", "reputation", "last_http_response_code", "last_final_url"]
            filtered_data = {key: data.get(key, "N/A") for key in relevant_keys}

            # Check the analysis results
            stats = data["last_analysis_stats"]
            # Check if the URL is malicious
            # 5 is the threshold for the number of engines that flagged the URL as malicious
            is_malicious = stats["malicious"] > 0
            return not is_malicious, False, filtered_data
        else:
            error_message = response.text
            self.save_error_to_log("VirusTotal", error_message)
            return False, True, None
        
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
            if data["unsafe"] == False:
                return True, False, data
            else:
                return False, False, data
        else:
            error_message = response.text
            self.save_error_to_log("IpQualityScore", error_message)
            return False, True, None

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
        response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))

        if response.status_code == 200:
            return False, response.json()["result"]
        else:
            error_message = response.text
            self.save_error_to_log("URLscanIO", error_message)
            return True

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
        """
        Checks the IP location using the ip2location API.
        Refer to the ip2location API documentation for more information: https://ip2location.io/documentation
        
        Returns:
            tuple: A tuple containing a boolean value indicating the success of the request and a dictionary
            containing the extracted information if the request is successful. If the request fails, only the boolean value is returned.
        """
        payload = {'key': self.api_manager.get_api_key("ip2location"), 'ip': self.getIpAddr(), 'format': 'json'}
        
        response = requests.get('https://api.ip2location.io/', params=payload)
        
        if response.status_code == 200:
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
            return True

    def scan_file_virustotal(self, file_path):
        """
        Uploads the file to VirusTotal for scanning and retrieves the scan results.

        Args:
            file_path (str): The path to the file to be scanned.

        Returns:
            dict: The scan results from VirusTotal.
        """
        url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": self.api_manager.get_api_key('virustotal')
        }

        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(url, headers=headers, files=files)
            if response.status_code == 200:
                data = response.json()
                analysis_id = data["data"]["id"]
                return self.get_file_scan_report(analysis_id)
            else:
                self.save_error_to_log("VirusTotal", response.text)
                return None

    def get_file_scan_report(self, analysis_id):
        """
        Retrieves the file scan report from VirusTotal.

        Args:
            analysis_id (str): The analysis ID of the file scan.

        Returns:
            dict: The scan report from VirusTotal.
        """
        url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        headers = {
            "x-apikey": self.api_manager.get_api_key('virustotal')
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            self.save_error_to_log("VirusTotal", response.text)
            return None

    def urlScan_APIservice(self):
        """
        This method is used for making API calls.

        It performs various checks and stores the results in the `self.control_results` dictionary.

        Returns:
            None
        """

        # Check if the URL leads to a download
        download_info = self.checkDownload()
        if download_info['is_download']:
            download_warning = {
                "warning": "This QR code initiates a download. Proceed with extreme caution!",
                "filename": download_info['filename'],
                "site": download_info['site'],
                "content_type": download_info['content_type'],
                "content_length": download_info['content_length'],
                "message": "Be careful! This file could be malicious. It is recommended to scan it with QRX (https://github.com/vitalelele/QRX) or other tools before opening it on your machine."
            }
            self.control_results["download_info"] = download_warning
            self.cleanup_uploaded_qr_files()
            return self.control_results

        # if it's an action scheme we don't need to continue with the control
        action_scheme_result = self.checkActionScheme()
        if action_scheme_result:
            message = ("This QR code contains an action scheme."
                       "No further analysis is required. Be careful when opening a scheme, it could open some external services")
            self.control_results["action_scheme"] = {"result": action_scheme_result,
                                                     "message": message}
            return
        else:
            self.control_results["action_scheme"] = {"result": action_scheme_result,
                                                     "message": "This QR code contains an action scheme." if action_scheme_result else "This QR code does not contain an action scheme."}

        self.control_results["short_url"] = self.checkShortUrl()

        vt_result, vt_error = self.checkVirusTotal()
        self.control_results["virus_total"] = {"result": vt_result, "error": vt_error}

        ipqs_result, ipqs_error = self.checkIpQualityScore()
        self.control_results["ip_quality_score"] = {"result": ipqs_result, "error": ipqs_error}

        urlscanio_error, urlscanio_result = self.checkURLscanIO()
        self.control_results["url_scan_io"] = {"result": urlscanio_result, "error": urlscanio_error}

        abuseipdb_error, abuseipdb_result = self.checkAbuseIPDB()
        self.control_results["abuse_ip_db"] = {"result": abuseipdb_result, "error": abuseipdb_error}

        ip2location_error, ip2location_result = self.checkIp2Location()
        self.control_results["ip2_location"] = {"result": ip2location_result, "error": ip2location_error}

        return
    
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

    def reset_log_file(self):
        """
        Resets the log file by removing it if it exists.

        If the log file exists, it will be deleted. This method does not create a new log file.

        Parameters:
        None

        Returns:
        None
        """
        if os.path.exists(self.log_file_path):
            os.remove(self.log_file_path)
            # print(f"{Fore.YELLOW}Log file reset successfully.{Style.RESET_ALL}")
    
    def generate_html_report(self, service_name, status, message):
        """
        Generates a report entry for a specific service check.

        Args:
            service_name (str): The name of the service.
            status (bool): The status of the check.
            message (str): The result message of the check.

        Returns:
            None
        """
        status_str = "Success" if status else "Failure"
        status_color = "green" if status else "red"
        self.report_data.append(
            f"<tr><td>{service_name}</td><td style='color:{status_color};'>{status_str}</td><td>{message}</td></tr>"
        )
        
        # print(f"Report saved to {self.report_folder}")
        return
    
    def save_report(self):
            """
            Saves the report data to an HTML file.

            Returns:
                None
            """
            if not os.path.exists("static/report"):
                os.makedirs("static/report")

            current_time = datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S")            
            report_file_path = f"static/report/report_{current_time}.html"

            with open(report_file_path, "w") as report_file:
                report_file.write("""
                <html>
                    <head>
                        <title>QR Code Scan Report</title>
                        <style>
                            body {
                                font-family: Arial, sans-serif;
                                margin: 20px;
                            }
                            h1 {
                                color: #333;
                            }
                            table {
                                width: 100%;
                                border-collapse: collapse;
                                margin-top: 20px;
                            }
                            th, td {
                                padding: 12px;
                                text-align: left;
                                border-bottom: 1px solid #ddd;
                            }
                            th {
                                background-color: #4CAF50;
                                color: white;
                            }
                            tr:nth-child(even) {
                                background-color: #f2f2f2;
                            }
                            tr:hover {
                                background-color: #ddd;
                            }
                        </style>
                    </head>
                    <body>
                        <h1>QR Code Scan Report</h1>
                        <table>
                            <tr>
                                <th>Service</th>
                                <th>Status</th>
                                <th>Message</th>
                            </tr>
                """)

                report_file.write("".join(self.report_data))

                report_file.write("""
                        </table>
                    </body>
                </html>
                """)

            self.__set_report_file_path(report_file_path)
            # print(f"Report saved to {report_file_path}")

    def __set_report_file_path(self, report_file_path):
        """
        Set the file path for the report file.

        Parameters:
        report_file_path (str): The file path for the report file.

        Returns:
        None
        """
        self.report_file_path = report_file_path
        return
    
    def delete_all_reports(self):
        """
        Deletes all the reports saved in the 'report' folder.

        Returns:
            None
        """
        if os.path.exists("static/report"):
            confirm = input(f"{Fore.YELLOW} [!] Are you sure you want to delete all reports? (y/n): {Style.RESET_ALL}")
            if confirm.lower() == "y":
                for file in os.listdir("static/report"):
                    file_path = os.path.join("static/report", file)
                    os.remove(file_path)
                print(f"{Fore.YELLOW} [!] All reports deleted successfully.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED} [!] Deletion cancelled.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED} [!] No reports found in the 'report' folder.{Style.RESET_ALL}")

    def get_control_results(self):
        """
        Returns the results of the control checks.

        Returns:
            list: A list containing the results of the control checks.
        """
        if self.control_results is not []:
            return self.control_results
        else:
            return False
    
    def getIpAddr(self):
            """
            Returns the IP address associated with the QRScanner object.

            Returns:
                str: The IP address.
            """
            return self.urlIpAddr
    
    def __setIpAddr(self):
        """
        Sets the IP address based on the URL provided.

        This method analyzes the URL to extract the domain and then retrieves the IP address
        associated with that domain. If an error occurs while getting the IP address, the
        error message is printed and the IP address is set to None.

        Returns:
            None
        """
        parsed_url = urllib.parse.urlparse(self.urlCode)

        try:
            ip_address = socket.gethostbyname(parsed_url.hostname)
            self.urlIpAddr = ip_address
        except socket.gaierror as e:
            print(f"Error while getting the IP address: {Fore.RED}{e}{Style.RESET_ALL}")
            self.urlIpAddr = None

        return
    
    def __setUrlCode(self, url):
        """
        Sets the URL code for the QRScanner object.

        Parameters:
        url (str): The URL code to be set.

        Returns:
        None
        """
        self.urlCode = url
        return  

    def cleanup_uploaded_qr_files(self):
        """
        Deletes all the QR code files generated during the process.

        Returns:
            None
        """
        qr_generated_folder = "static/qr_generated" 
        if os.path.exists(qr_generated_folder):
            for file in os.listdir(qr_generated_folder):
                file_path = os.path.join(qr_generated_folder, file)
                os.remove(file_path)
