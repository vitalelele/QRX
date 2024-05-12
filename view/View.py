import sys, random
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(convert=True)

class View:
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
                    # Print the characters of the banner one by one
                    print(f"[{Fore.RED}{random_banner}{Style.RESET_ALL}")
                    print(f"{Fore.LIGHTWHITE_EX}                                             Developed by {Style.BRIGHT}@vitalelele - 2024{Style.RESET_ALL}")
                    # for char in random_banner:
                    #     # Print the character without going to a new line
                    #     sys.stdout.write(char)
                    #     sys.stdout.flush()      
                    #     # Add a short delay for the typewriter effect
                    #     # time.sleep(0.002)  # You can adjust the delay speed
                else:
                    print(f"{Fore.RED}No banners found in the file.{Style.RESET_ALL}")
        except FileNotFoundError:
                print(f"{Fore.RED}File banners.txt not found.{Style.RESET_ALL}")

    

    #     # The banner text
    #     f"""{Fore.RED}
    #   /$$$$$$  /$$$$$$$            /$$   /$$                         /$$                       /$$     /$$                    
    #  /$$__  $$| $$__  $$          | $$  / $$                        |__/                      | $$    |__/                    
    # | $$  \ $$| $$  \ $$  /$$$$$$ |  $$/ $$/  /$$$$$$  /$$$$$$/$$$$  /$$ /$$$$$$$   /$$$$$$  /$$$$$$   /$$  /$$$$$$  /$$$$$$$ 
    # | $$  | $$| $$$$$$$/ /$$__  $$ \  $$$$/  |____ s $$| $$_  $$_  $$| $$| $$__  $$ |____  $$|_  $$_/  | $$ /$$__  $$| $$__  $$
    # | $$  | $$| $$__  $$| $$$$$$$$  >$$  $$   /$$$$$$$| $$ \ $$ \ $$| $$| $$  \ $$  /$$$$$$$  | $$    | $$| $$  \ $$| $$  \ $$
    # | $$/$$ $$| $$  \ $$| $$_____/ /$$/\  $$ /$$__  $$| $$ | $$ | $$| $$| $$  | $$ /$$__  $$  | $$ /$$| $$| $$  | $$| $$  | $$
    # |  $$$$$$/| $$  | $$|  $$$$$$$| $$  \ $$|  $$$$$$$| $$ | $$ | $$| $$| $$  | $$|  $$$$$$$  |  $$$$/| $$|  $$$$$$/| $$  | $$
    #  \____ $$$|__/  |__/ \_______/|__/  |__/ \_______/|__/ |__/ |__/|__/|__/  |__/ \_______/   \___/  |__/ \______/ |__/  |__/
    #       \__/                                                                               

    #                 {Style.BRIGHT}{Fore.BLUE}Developed by @vitalele - 2024{Style.RESET_ALL}
    #     """
    



    def show_menu(self):
        menu = f"""
        --- Select an option ---
        1. Scan a QR code
        2. Generate a QR code
        3. About the project
        4. Exit
        """
        print(menu)

    # TODO: change about the project text
    def about_project(self):
        print(f"{Fore.BLUE}This project is a QR code scanner and generator tool developed by @vitalele.")
        print(f"The tool allows you to scan QR codes from image files and generate QR codes from text or URLs.")
        print(f"Visit the GitHub repository for more information:{Style.RESET_ALL}")