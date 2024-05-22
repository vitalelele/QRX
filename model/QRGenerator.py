import qrcode, os, datetime
from colorama import init, Fore, Style
from PIL import Image

# Initialize colorama for cross-platform colored text
init(convert=True)

class QRGenerator:
    def __init__(self):
        self.default_folder = "static\qr_generated"

    def generate_qr_code(self, data):
        try:
            # Display menu for choosing QR code type
            print(f"\nChoose the type of {Style.BRIGHT}QR code{Style.RESET_ALL} to generate:")
            print(f"{Fore.YELLOW} [1]{Style.RESET_ALL} Standard QR code (max capacity: 2953 alphanumeric characters)")
            print(f"{Fore.YELLOW} [2]{Style.RESET_ALL} FrameQR (max capacity: 2716 alphanumeric characters)")
            print(f"{Fore.YELLOW} [3]{Style.RESET_ALL} MicroQR code (max capacity: 35 alphanumeric characters)")
            print(f"{Fore.YELLOW} [4]{Style.RESET_ALL} Custom QR code (max capacity: depends on settings)")
            choice = input(f"{Style.BRIGHT}{Fore.YELLOW} _>{Style.RESET_ALL} Enter your choice: ")

            if choice == "1":
                self.generate_standard_qr_code(data)
            elif choice == "2":
                self.generate_frameqr(data)
            elif choice == "3":
                self.generate_microqr(data)
            elif choice == "4":
                # Implement custom QR code generation here
                print("Custom QR code generation is not yet implemented.")
            else:
                print("Invalid choice.")

        except Exception as e:
            # Print an error message
            print(f"{Fore.RED}Error during generation: {e}{Style.RESET_ALL}")

    def generate_standard_qr_code(self, data):
        try:
            # Generate the QR code
            qr = qrcode.make(data)
            # Save the QR code to the specified path
            qr.save(self.get_file_path())

            # Print a success message
            print(f"{Fore.GREEN}Standard QR code generated and saved in {self.default_folder} {Style.RESET_ALL}")

        except Exception as e:
            # Print an error message
            print(f"{Fore.RED}Error during generation: {e}{Style.RESET_ALL}")


    # TODO: need to fix the FrameQR code generation
    # FrameQR code generation is not working properly
    # whyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy >.<
    def generate_frameqr(self, data):
        try:
            # Load the logo image
            logo_path = input("Enter the path to the logo image: ")
            if not os.path.exists(logo_path):
                print(f"{Fore.RED}Logo image not found.{Style.RESET_ALL}")
                return

            # Generate the FrameQR code
            qr = qrcode.QRCode(version=6, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(data)
            qr.make(fit=True)

            # Load the logo image and add it to the QR code
            logo_img = Image.open(logo_path)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_width, qr_height = qr_img.size
            logo_width, logo_height = logo_img.size
            # Calculate position to place logo in the center of the QR code
            position = ((qr_width - logo_width) // 2, (qr_height - logo_height) // 2)
            # Paste logo on QR code image
            qr_img.paste(logo_img, position)

            # Save the FrameQR code to the specified path
            qr_img.save(self.get_file_path())

            # Print a success message
            print(f"{Fore.GREEN}FrameQR code with logo generated and saved in {self.default_folder}.{Style.RESET_ALL}")

        except Exception as e:
            # Print an error message
            print(f"{Fore.RED}Error during FrameQR code generation: {e}{Style.RESET_ALL}")

    def generate_microqr(self, data):
        try:
            # Generate the QR code
            qr = qrcode.make(data, version=1)
            # Save the QR code to the specified path
            qr.save(self.get_file_path())

            # Print a success message
            print(f"{Fore.GREEN}MicroQR code generated and saved in {self.default_folder}{Style.RESET_ALL}")

        except Exception as e:
            # Print an error message
            print(f"{Fore.RED}Error during generation: {e}{Style.RESET_ALL}")

    def get_file_path(self):
        # Ask the user if they want to use a custom path
        use_custom_path = input("Do you want to enter a custom path for saving the generated QR code? (y/n): ").strip().upper()

        if use_custom_path == "Y":
            # Ask the user to enter the desired path
            file_path = input(f"{Style.BRIGHT}{Fore.YELLOW} _>{Style.RESET_ALL} Enter the save path for the generated QR code: ").strip()
            # Check if the specified path is a folder
            if not (self.is_safe_path(file_path) and os.path.isdir(file_path)):
                print(f"{Fore.RED}\nThe specified path is not a valid folder.{Style.RESET_ALL}")
                return None
            else:
                return os.path.join(file_path, self.generate_file_name(file_path))
        else:
            # Create the folder if it doesn't exist
            if not os.path.exists(self.default_folder):
                os.makedirs(self.default_folder)
            return os.path.join(self.default_folder, self.generate_file_name(self.default_folder))


    def generate_file_name(self, folder_path):
        # Generate a unique file name based on the current timestamp
        # e.g., qr_code_01_01_2024_12_30.png
        # if the file already exists, append a counter to the file name
        # e.g., qr_code_01_01_2024_12_30_1.png, qr_code_01_01_2024_12_30_2.png, etc.
        now = datetime.datetime.now()
        timestamp = now.strftime("%Y-%m-%d_%H_%M_%S")
        # Base file name format 
        base_name = "qr_code_" + timestamp + ".png"
        file_name = base_name
        counter = 1
        # Check if the file already exists in the specified folder
        while os.path.exists(os.path.join(folder_path, file_name)):
            # If the file exists, append a counter to the file name
            file_name = base_name[:-4] + str(counter) + base_name[-4:]
            counter += 1
        return file_name

    def delete_generated_qr_codes(self):
        try:
            # List all files in the default folder
            file_list = os.listdir(self.default_folder)

            # Check if the folder is already empty
            if not file_list:
                print(f"{Fore.YELLOW}The folder {self.default_folder} is already empty.{Style.RESET_ALL}")
                return

            # Print the names of all files in the folder
            print(f"{Fore.YELLOW}QR codes found in {self.default_folder}:{Style.RESET_ALL}")
            for file_name in file_list:
                print(file_name)
            
            # Ask for confirmation before deleting
            confirmation = input(f"{Fore.YELLOW}Do you want to delete all the QR codes in {self.default_folder}? (Y/N): {Style.RESET_ALL}").strip().upper()

            if confirmation == "Y":
                # Delete all files in the folder
                for file_name in file_list:
                    file_path = os.path.join(self.default_folder, file_name)
                    os.remove(file_path)
                print(f"{Fore.GREEN}All QR codes in {self.default_folder} have been deleted.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Operation cancelled.{Style.RESET_ALL}")

        except Exception as e:
            # Print an error message
            print(f"{Fore.RED}Error during deletion: {e}{Style.RESET_ALL}")
    def is_safe_path(self, path):
        """
        Checks if the specified path is safe and exists.

        Args:
            path (str): The path to check.

        Returns:
            bool: True if the path is safe and exists, False otherwise.
        """
        # Check if the path exists
        if os.path.exists(path):
            # Check if the path is absolute and does not point to sensitive directories
            if os.path.isabs(path) and not ('..' in path or path.startswith('~')):
                return True
        return False
