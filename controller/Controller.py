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
        self.scanner = QRScanner()
        self.generator = QRGenerator()

        # Initialize the API manager with the configuration file
        # self.api_manager = APIManager("static/config.json")

        # for debugging I made another config file that contains my API the debuConfig.json added to the .gitignore
        self.api_manager = APIManager("static/debugConfig.json")


    def run(self):
        # TODO: Add a check for the API keys, if the user hasn't changed them from the default values
        self.api_manager.load_api_keys()
        # Print the banner
        self.view.print_banner()
        while True:
            self.view.show_menu()
            choice = input("Enter your choice (1-3): ")
            if choice == "1":
                file_path = input(f"Enter the {Style.BRIGHT}{Fore.LIGHTYELLOW_EX}file path{Style.RESET_ALL} of the QR code: {Style.RESET_ALL}")
                if self.scanner.scan_qr_code(file_path):
                    self.scanner.urlControl()
                else:
                    self.view.print_banner()
                    print(f"{Style.BRIGHT}{Fore.RED}Error scanning the QR code.\n{Style.RESET_ALL}")
            elif choice == "2":
                data = input("Enter the text or URL for the QR code: ")
                # file_path = input("Enter the save path for the generated QR code: ")
                # I want to always save it in the qr_generated folder
                self.generator.generate_qr_code(data)
            elif choice == "3":
                # is a feature for printing something about the project
                self.view.about_project()
            # Add the options menu
            elif choice == "4":
                self.view.print_banner()
                self.view.print_options()
                option_choice = input("Enter your option: ")
                if option_choice == "1":
                    self.view.print_banner()
                    self.generator.delete_generated_qr_codes()
                elif option_choice == "2":
                    self.run()
                    break
                else:
                    print(f"{Fore.RED}Invalid option. Please try again.{Style.RESET_ALL}")
                pass
            elif choice == "5":
                self.view.print_banner()
                print("Exiting the tool. Goodbye!")
                sys.exit(0)
            else:
                self.view.print_banner()
                print("Invalid choice. Please try again.")

