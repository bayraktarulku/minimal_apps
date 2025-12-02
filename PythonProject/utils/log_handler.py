import logging
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)


class LogHandler:
    def __init__(self, log_dir='logs'):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = os.path.join(log_dir, f'websec_{timestamp}.log')

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def info(self, message):
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
        self.logger.info(message)

    def success(self, message):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
        self.logger.info(message)

    def warning(self, message):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
        self.logger.warning(message)

    def error(self, message):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
        self.logger.error(message)

    def vulnerability(self, message):
        print(f"{Fore.RED}[VULNERABILITY]{Style.RESET_ALL} {message}")
        self.logger.warning(f"VULNERABILITY: {message}")

