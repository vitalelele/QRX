import sys, random, shutil, re
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(convert=True)

class View:

    # Print the banner
    def print_banner(self):
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
        menu = f"""
        {Fore.MAGENTA}{Style.BRIGHT}--- Select an option ---{Style.RESET_ALL}
        1. Scan a QR code
        2. Generate a QR code
        3. About the project
        4. Options
        5. Exit
        """
        print(menu)

    # TODO: change about the project text
    def about_project(self):
        self.print_centered(f"{Fore.BLUE}This project is a QR code scanner and generator tool developed by @vitalelele.")
        self.print_centered(f"The tool allows you to scan QR codes from image files and generate QR codes from text or URLs.")
        self.print_centered(f"Visit the GitHub repository for more information")
        self.print_centered(f"https://github.com/vitalelele/QRX{Style.RESET_ALL}")

    def print_options(self):
        options = """
        Options:
        1. Empty the 'qr_generated' folder (delete all generated QR codes)
        2. Empty the 'report' folder (delete all reports)
        3. Change banner randomly :)
        4. Return to the main menu 
        """
        print(options)

    # Print a centered text
    def print_centered(self, text):
        # Rimuovi i colori ANSI prima di calcolare la lunghezza del testo
        text_without_ansi = re.sub(r'\x1b\[[0-9;]*m', '', text)
        terminal_width = shutil.get_terminal_size().columns
        padding = (terminal_width - len(text_without_ansi)) // 2
        print(f" " * padding + text)