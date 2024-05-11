import json, os, sys
from colorama import init, Fore, Style

class APIManager:
    """
    The APIManager class is responsible for managing API keys and providing access to them.

    Args:
        config_file (str): The path to the configuration file.

    Attributes:
        config_file (str): The path to the configuration file.
        api_keys (dict): A dictionary containing the API keys loaded from the configuration file.

    Methods:
        __init__(self, config_file): Initializes the APIManager object.
        load_api_keys(self): Loads the API keys from the configuration file.
        are_api_keys_valid(self, api_keys): Checks if the API keys are valid.
        request_missing_api_keys(self): Requests the user to update the API keys.
        get_api_key(self, service): Retrieves the API key for a given service.
    """

    def __init__(self, config_file):
        self.config_file = config_file
        self.api_keys = self.load_api_keys()
        # Initialize colorama for cross-platform colored text
        init(convert=True)

    def load_api_keys(self):
        """
        Loads the API keys from the configuration file.

        Returns:
            dict: A dictionary containing the API keys.
        """
        try:
            with open(self.config_file, "r") as file:
                config_data = json.load(file)
                api_keys = config_data.get("api_keys", {})
                if not self.are_api_keys_valid(api_keys):
                    self.request_missing_api_keys()
                return api_keys
        except FileNotFoundError:
            print("Config file not found. Creating a new one.")
            self.request_missing_api_keys({})
            return {}

    def are_api_keys_valid(self, api_keys):
        """
        Checks if the API keys are valid.

        Args:
            api_keys (dict): A dictionary containing the API keys.

        Returns:
            bool: True if the API keys are valid, False otherwise.
        """
        default_key = "YOUR_API_KEY"
        for key in api_keys.values():
            if default_key in key or key.startswith(default_key) or len(key) == 0:
                return False
        return True

    def request_missing_api_keys(self):
        """
        Requests the user to update the API keys.
        """
        # Print warning messages
        print(f"{Fore.YELLOW}API keys not found or set to default values in the configuration file.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Please update the 'config.json' file with the required API keys before using the tool.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Exiting the program.{Style.RESET_ALL}")

        print(f"{Fore.RED}Please update{Style.RESET_ALL} the {Style.BRIGHT}{Fore.YELLOW}API keys{Style.RESET_ALL} and come back! ")
        sys.exit(1)
       
    def get_api_key(self, service):
        """
        Retrieves the API key for a given service.

        Args:
            service (str): The name of the service.

        Returns:
            str: The API key for the given service, or None if not found.
        """
        return self.api_keys.get(service, None)
