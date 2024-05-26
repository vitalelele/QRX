import sys
from view.View import View
from model.QRScanner import QRScanner
from model.QRGenerator import QRGenerator
from model.APIManager import APIManager
from colorama import init, Fore, Style

class Controller:
    def __init__(self):
        # Initialize colorama for cross-platform colored text
        init(convert=True)
        self.view = View()
        # Initialize the QR scanner and generator
        self.scanner = QRScanner()
        self.generator = QRGenerator()

        # Initialize the API manager with the configuration file
        # self.api_manager = APIManager("static/config.json")

        # for debugging I made another config file that contains my API the debuConfig.json added to the .gitignore
        self.api_manager = APIManager("static/debugConfig.json")

    def run(self):
        self.api_manager.load_api_keys()
        # Print the banner
        self.view.print_banner()
        # Reset the log file the first time the tool is run
        self.scanner.reset_log_file()
        while True:
            self.view.show_menu()
            choice = input(f"{Style.BRIGHT}{Fore.BLUE} [*]{Style.RESET_ALL} Enter your choice: ")
            # ----------------- Scan a QR code -----------------
            if choice == "1":
                file_path = input(f"{Style.BRIGHT}{Fore.BLUE} [*]{Style.RESET_ALL} Enter the {Style.BRIGHT}{Fore.LIGHTYELLOW_EX}file path{Style.RESET_ALL} of the QR code: {Style.RESET_ALL}")
                if self.scanner.scan_qr_code(file_path):
                    self.scanner.urlControl()
                else:
                    self.view.print_banner()
                    print(f"{Style.BRIGHT}{Fore.YELLOW}[!] {Style.RESET_ALL}{Fore.RED}Error scanning the QR code.\n{Style.RESET_ALL}")
            # ----------------- Generate a QR code -----------------
            elif choice == "2":
                data = input(f"{Style.BRIGHT}{Fore.BLUE} [*]{Style.RESET_ALL} Enter the text or URL for the QR code: ")
                # file_path = input("Enter the save path for the generated QR code: ")
                # I want to always save it in the qr_generated folder
                self.generator.generate_qr_code(data)
            # ----------------- About the project -----------------
            elif choice == "3":
                # is a feature for printing something about the project
                self.view.print_banner()
                self.view.about_project()
            # ----------------- Options -----------------
            elif choice == "4":
                self.view.print_banner()
                self.view.print_options()
                option_choice = input(f"{Style.BRIGHT}{Fore.BLUE} [*]{Style.RESET_ALL} Enter your option: ")
                if option_choice == "1":
                    self.view.print_banner()
                    self.generator.delete_generated_qr_codes()
                elif option_choice == "2":
                    self.view.print_banner()
                    self.scanner.delete_all_reports()  
                elif option_choice == "3":
                    self.view.print_banner()
                    # I added this feature for fun
                    print(f"{Style.BRIGHT}{Fore.CYAN};) Do you like more?{Style.RESET_ALL}")
                elif option_choice == "4":
                    self.run()
                    break
                else:
                    print(f"{Style.BRIGHT}{Fore.RED} [!] {Style.RESET_ALL} {Fore.RED}Invalid option. Please try again.{Style.RESET_ALL}")
                pass
            # ----------------- Exit -----------------
            elif choice == "5":
                self.view.print_banner()
                print(f"{Style.BRIGHT}{Fore.RED} [!] {Style.RESET_ALL}Exiting the tool. Goodbye!")
                sys.exit(0)
            else:
                self.view.print_banner()
                print(f"{Style.BRIGHT}{Fore.RED} [!] {Style.RESET_ALL}Invalid choice. Please try again.")

