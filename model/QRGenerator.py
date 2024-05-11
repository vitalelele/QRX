import datetime
import os
import qrcode
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored text
init(convert=True)

class QRGenerator:
    def generate_qr_code(self, data):
        try:
            # Ask the user if they want to use a custom path
            use_custom_path = input("Do you want to enter a custom path for saving the generated QR code? (Y/N): ").strip().upper()

            if use_custom_path == "Y":
                # Ask the user to enter the desired path
                file_path = input("Enter the save path for the generated QR code: ").strip()
            else:
                # Default folder for generated QR codes
                default_folder = "static/qr_generated"
                # Create the folder if it doesn't exist
                if not os.path.exists(default_folder):
                    os.makedirs(default_folder)
                
                # File name (you can customize it as desired)
                file_name = self.generate_file_name(default_folder)
                # Full file path
                file_path = os.path.join(default_folder, file_name)

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
        now = datetime.now()
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