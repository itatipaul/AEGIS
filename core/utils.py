import json
import os
import logging
from logging.handlers import RotatingFileHandler

def load_config(config_path="aegis/config/settings.json"):
    """Loads configuration from JSON file."""
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return json.load(f)
        return {}
    except Exception as e:
        print(f"[!] Config Load Error: {e}")
        return {}

def setup_logging(log_file="aegis.log", verbose=False):
    """
    Configures system-wide logging.
    CRITICAL FIX: Only adds FileHandler. Console output is managed by Rich (DisplayManager).
    """
    # Create the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO if not verbose else logging.DEBUG)
    
    # Remove existing handlers to prevent duplication
    if logger.hasHandlers():
        logger.handlers.clear()

    # 1. FILE HANDLER (Writes to aegis.log)
    # We keep this so you have a record on disk
    file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.INFO if not verbose else logging.DEBUG)
    
    logger.addHandler(file_handler)
    
    # 2. CONSOLE HANDLER -> REMOVED
    # The DisplayManager (Rich) in aegis/core/display.py now handles the console.
    # We do NOT add a StreamHandler here, avoiding the double-print glitch.
    
    return logger

def save_json(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        print(f"[!] JSON Save Error: {e}")
        return False
