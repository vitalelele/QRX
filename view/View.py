import sys
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(convert=True)

class View:
    def print_banner(self):

        # The banner text
        banner = f"""{Fore.RED}
  /$$$$$$  /$$$$$$$            /$$   /$$                         /$$                       /$$     /$$                    
 /$$__  $$| $$__  $$          | $$  / $$                        |__/                      | $$    |__/                    
| $$  \ $$| $$  \ $$  /$$$$$$ |  $$/ $$/  /$$$$$$  /$$$$$$/$$$$  /$$ /$$$$$$$   /$$$$$$  /$$$$$$   /$$  /$$$$$$  /$$$$$$$ 
| $$  | $$| $$$$$$$/ /$$__  $$ \  $$$$/  |____  $$| $$_  $$_  $$| $$| $$__  $$ |____  $$|_  $$_/  | $$ /$$__  $$| $$__  $$
| $$  | $$| $$__  $$| $$$$$$$$  >$$  $$   /$$$$$$$| $$ \ $$ \ $$| $$| $$  \ $$  /$$$$$$$  | $$    | $$| $$  \ $$| $$  \ $$
| $$/$$ $$| $$  \ $$| $$_____/ /$$/\  $$ /$$__  $$| $$ | $$ | $$| $$| $$  | $$ /$$__  $$  | $$ /$$| $$| $$  | $$| $$  | $$
|  $$$$$$/| $$  | $$|  $$$$$$$| $$  \ $$|  $$$$$$$| $$ | $$ | $$| $$| $$  | $$|  $$$$$$$  |  $$$$/| $$|  $$$$$$/| $$  | $$
 \____ $$$|__/  |__/ \_______/|__/  |__/ \_______/|__/ |__/ |__/|__/|__/  |__/ \_______/   \___/  |__/ \______/ |__/  |__/
      \__/                                                                               

                                {Style.BRIGHT}{Fore.BLUE}Developed by @vitalele - 2024{Style.RESET_ALL}
        """
        # Print the characters of the banner one by one
        for char in banner:
            # Print the character without going to a new line
            sys.stdout.write(char)
            sys.stdout.flush()
            
            # Add a short delay for the typewriter effect
            # time.sleep(0.002)  # You can adjust the delay speed

    def show_menu(self):
        menu = f"""
        --- Select an option ---
        1. Scan a QR code
        2. Generate a QR code
        3. Exit
        """
        print(menu)
