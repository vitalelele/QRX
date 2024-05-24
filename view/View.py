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
            f"{Fore.BLUE}This project is a QR code scanner and generator tool developed by @vitalelele. "
            f"The tool allows you to scan QR codes from image files and generate QR codes from text or URLs. "
            f"Visit the GitHub repository for more information "
            f"https://github.com/vitalelele/QRX{Style.RESET_ALL}"
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
        1. Scan a QR code
        2. Generate a QR code
        3. About the project
        4. Options
        5. Exit
        """
        print(menu)

    def about_project(self):
        """
        Prints information about the QRX project.
        """
        self.print_centered(f"{Fore.BLUE}This project is a QR code scanner and generator tool developed by @vitalelele.")
        self.print_centered(f"The tool allows you to scan QR codes from image files and generate QR codes from text or URLs.")
        self.print_centered(f"Visit the GitHub repository for more information")
        self.print_centered(f"https://github.com/vitalelele/QRX{Style.RESET_ALL}")

    def print_options(self):
        """
        Prints the options menu.
        """
        options = """
        Options:
        1. Empty the 'qr_generated' folder (delete all generated QR codes)
        2. Empty the 'report' folder (delete all reports)
        3. Change banner randomly :)
        4. Return to the main menu 
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