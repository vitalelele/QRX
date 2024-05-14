import qrcode, os, datetime
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(convert=True)

class QRGenerator:
    def __init__(self):
        self.default_folder = "static\qr_generated"

    def generate_qr_code(self, data):
        try:
            # Ask the user if they want to use a custom path
            use_custom_path = input("Do you want to enter a custom path for saving the generated QR code? (Y/N): ").strip().upper()

            if use_custom_path == "Y":
                # Ask the user to enter the desired path
                file_path = input("Enter the save path for the generated QR code: ").strip()
                # Check if the specified path is a folder
                if not (self.is_safe_path(file_path) and os.path.isdir(file_path)):
                    print(f"{Fore.RED}\nThe specified path is not a valid folder.{Style.RESET_ALL}")
                    return
            else:
                # Create the folder if it doesn't exist
                if not os.path.exists(self.default_folder):
                    os.makedirs(self.default_folder)
                
                # File name (you can customize it as desired)
                file_name = self.generate_file_name(self.default_folder)
                # Full file path
                file_path = os.path.join(self.default_folder, file_name)

            # Generate the QR code
            qr = qrcode.make(data)
            # Save the QR code to the specified path
            qr.save(file_path)


            # Print a success message
            print(f"{Fore.GREEN}QR code generated and saved at: {file_path}{Style.RESET_ALL}")

        except Exception as e:
            # Print an error message
            print(f"{Fore.RED}Error during generation: {e}{Style.RESET_ALL}")

    def generate_file_name(self, folder_path):
        # Generate a unique file name based on the current timestamp
        # e.g., qr_code_01_01_2024_12_30.png
        # if the file already exists, append a counter to the file name
        # e.g., qr_code_01_01_2024_12_30_1.png, qr_code_01_01_2024_12_30_2.png, etc.
        now = datetime.datetime.now()
        timestamp = now.strftime("%d_%m_%Y_%H_%M")
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
