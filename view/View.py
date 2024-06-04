import sys, random, shutil, re
from colorama import init, Fore, Style

class View:
    """
    The View class represents the user interface of the QRX project.
    It provides methods for printing banners, menus, and messages to the console.
    """

    def __init__(self):
        # Initialize colorama for cross-platform colored text
        init(convert=True)
        self.message_about_project = (
            f"{Fore.BLUE}This project is a QR code scanner and generator tool developed by @vitalelele.\n{Style.RESET_ALL} "
            f"It was created as part of my thesis in Computer Science and Software Production Technologies.\n"
            f"{Fore.GREEN}This tool is the result of an in-depth study on the vulnerabilities of QR codes,{Style.RESET_ALL} "
            f"aiming to provide a useful \nresource for quickly verifying the security of QR codes. \n"
            f"Whether you are a user, a developer, or anyone else interested in QR code security, this tool is designed to help you.\n"
            f"The study highlights the various risks associated with QR codes and offers this tool as a solution to mitigate these risks.\n"
            f"By using this tool, you can scan QR codes from image files and generate QR codes from text or URLs, ensuring they are safe and secure.\n"
            f"For more detailed information, please visit the GitHub repository: https://github.com/vitalelele/QRX\n"
            f"{Fore.YELLOW}I am always looking for new horizons. Ad astra per aspera.\n{Style.RESET_ALL}"
        )


    def print_banner(self):
        """
        Prints a random banner from the 'banners.txt' file.
        """
        try:
            # Read the entire content of banners.txt as a single string
            with open("static/banners.txt", "r") as file:
                banners_content = file.read()
                # If there is content in the file
                if banners_content:
                    # Split the content into banners based on a separator (e.g., '---')
                    banners = banners_content.split('---')
                    # Select a random banner
                    random_banner = random.choice(banners)
                    print("\n")
                    # Split the banner into lines
                    banner_lines = random_banner.split('\n')
                    for line in banner_lines:
                        # Print each line centered
                        self.print_centered(line)
                    # Print an empty line after the banner
                    print()
                    # Print the developer info centered
                    self.print_centered(f"{Style.BRIGHT}Developed by @vitalelele - 2024")
                else:
                    self.print_centered(f"{Fore.RED}No banners found in the file.{Style.RESET_ALL}")
        except FileNotFoundError:
            self.print_centered(f"{Fore.RED}File banners.txt not found.{Style.RESET_ALL}")

    def show_menu(self):
        """
        Prints the main menu options.
        """
        menu = f"""
        {Fore.MAGENTA}{Style.BRIGHT}--- Select an option ---{Style.RESET_ALL}
        [1] Scan a QR code
        [2] Generate a QR code
        [3] About the project
        [4] Options
        [5] Exit
        """
        print(menu)

    def about_project(self):
        """
        Prints information about the QRX project.
        """
        # Split the message into lines
        lines = self.get_message_about_project().split('\n')
        # Print each line centered
        for line in lines:
            self.print_centered(line)


    def print_options(self):
        """
        Prints the options menu.
        """
        options = f"""
        Options:
        [1] Empty the {Style.BRIGHT}'qr_generated'{Style.RESET_ALL} folder {Fore.RED}{Style.BRIGHT}(delete all generated QR codes){Style.RESET_ALL}
        [2] Empty the {Style.BRIGHT}'report'{Style.RESET_ALL} folder {Fore.RED}{Style.BRIGHT}(delete all reports){Style.RESET_ALL}
        [3] Change banner randomly :)
        [4] Return to the main menu 
        """
        print(options)

    def print_centered(self, text):
        """
        Prints a text centered in the console.
        """
        # Remove ANSI colors before calculating the length of the text
        text_without_ansi = re.sub(r'\x1b\[[0-9;]*m', '', text)
        terminal_width = shutil.get_terminal_size().columns
        padding = (terminal_width - len(text_without_ansi)) // 2
        print(f" " * padding + text)

    def get_message_about_project(self):
        """
        Returns the message about the project.
        """
        return self.message_about_project