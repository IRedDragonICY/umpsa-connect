import configparser
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)


class Config:
    CONFIG_FILE = Path.cwd() / 'config.ini'

    def __init__(self):
        logger.debug("Initializing Config class.")
        self.config = self.load_config()
        self.form_data = self.load_form_data()
        self.settings = self.load_settings()
        logger.debug("Config initialized with settings: %s", self.settings)

    def load_config(self):
        logger.debug("Loading configuration from %s", self.CONFIG_FILE)
        config = configparser.ConfigParser()
        config.read(self.CONFIG_FILE)
        return config

    def load_form_data(self) -> Dict[str, str]:
        logger.debug("Loading form data from configuration.")
        form_section = self.config['form_data']
        return {
            f"guestUser.fieldValues.{key}": form_section[key]
            for key in form_section
        }

    def load_settings(self) -> Dict[str, any]:
        logger.debug("Loading settings from configuration.")
        settings = self.config['settings']
        return {
            "headless": settings.getboolean('headless'),
            "auto_login_interval": settings.getint('auto_login_interval') * 60,
            "total_accounts": settings.getint('total_accounts'),
            "max_workers": settings.getint('max_workers')
        }

    def save(self):
        logger.debug("Saving configuration to %s", self.CONFIG_FILE)
        with self.CONFIG_FILE.open('w') as configfile:
            self.config.write(configfile)
        logger.info("Configuration saved successfully.")