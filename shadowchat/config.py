import os
import json
import logging

# Initialize logging
logger = logging.getLogger("ShadowChat")

# Default configuration values
DEFAULT_CONFIG = {
    "app_name": "ShadowChat",
    "version": "1.0.0",
    "logging_level": "INFO",
    "key_storage_path": "~/.shadowchat/keys/",
    "data_storage_path": "~/.shadowchat/data/",
    "theme": "dark"
}

CONFIG_FILE_PATH = os.path.expanduser("~/.shadowchat/config.json")

def ensure_config_directory():
    """Ensures the configuration and data directories exist."""
    try:
        config_dir = os.path.dirname(CONFIG_FILE_PATH)
        if not os.path.exists(config_dir):
            os.makedirs(config_dir)
            logger.info(f"Created config directory at {config_dir}")
    except Exception as e:
        logger.error(f"Error creating config directory: {e}")
        raise

def load_config():
    """Loads the configuration from the file, or creates a default config if none exists."""
    ensure_config_directory()

    if not os.path.exists(CONFIG_FILE_PATH):
        logger.info("No configuration file found. Creating default configuration.")
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG

    try:
        with open(CONFIG_FILE_PATH, "r") as config_file:
            config = json.load(config_file)
            logger.info("Configuration loaded successfully.")
            return config
    except Exception as e:
        logger.error(f"Failed to load configuration: {e}")
        raise

def save_config(config):
    """Saves the given configuration dictionary to the config file."""
    ensure_config_directory()

    try:
        with open(CONFIG_FILE_PATH, "w") as config_file:
            json.dump(config, config_file, indent=4)
            logger.info("Configuration saved successfully.")
    except Exception as e:
        logger.error(f"Failed to save configuration: {e}")
        raise

def get_config_value(key, default=None):
    """Gets a specific configuration value, returning a default if the key is not found."""
    config = load_config()
    return config.get(key, default)

if __name__ == "__main__":
    # Example usage
    config = load_config()
    print("Current Configuration:", config)

    # Update a value and save
    config["theme"] = "light"
    save_config(config)
    print("Updated Configuration:", load_config())
