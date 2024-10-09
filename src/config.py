import configparser
import logging
from pathlib import Path
from typing import Dict

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

class Config:
    CONFIG_FILE = Path.cwd() / 'config.ini'
    DEFAULT_FORM_DATA = {
        "ui_first_name": "",
        "ui_last_name": "",
        "ui_email_address": "",
        "ui_phone_number": "",
        "ui_company": "",
        "ui_reason_visit": "",
        "ui_ump_staff_name_text": ""
    }
    DEFAULT_SETTINGS = {
        "headless": "True",
        "auto_login_interval": "60",
        "total_accounts": "100",
        "max_workers": "10"
    }

    def __init__(self):
        logger.debug("Initializing Config class.")
        if not self.CONFIG_FILE.exists():
            logger.info("Config file not found. Creating default config.ini.")
            self.create_default_config()

        self.config = self.load_config()
        self.form_data = self.load_form_data()
        self.settings = self.load_settings()
        logger.debug("Config initialized with settings: %s", self.settings)

    def create_default_config(self):
        logger.debug("Creating default configuration.")
        config = configparser.ConfigParser()

        config['form_data'] = self.DEFAULT_FORM_DATA.copy()

        config['settings'] = self.DEFAULT_SETTINGS.copy()

        with self.CONFIG_FILE.open('w') as configfile:
            config.write(configfile)
        logger.info(f"Default config.ini created at {self.CONFIG_FILE}")

    def load_config(self):
        logger.debug("Loading configuration from %s", self.CONFIG_FILE)
        config = configparser.ConfigParser()
        config.read(self.CONFIG_FILE)
        return config

    def load_form_data(self) -> Dict[str, str]:
        logger.debug("Loading form data from configuration.")
        if 'form_data' not in self.config:
            logger.warning("'form_data' section missing in config.ini. Creating with default empty values.")
            self.config['form_data'] = self.DEFAULT_FORM_DATA.copy()
            self.save()
        form_section = self.config['form_data']
        return {
            f"guestUser.fieldValues.{key}": form_section.get(key, "")
            for key in self.DEFAULT_FORM_DATA
        }

    def load_settings(self) -> Dict[str, any]:
        logger.debug("Loading settings from configuration.")
        if 'settings' not in self.config:
            logger.warning("'settings' section missing in config.ini. Creating with default values.")
            self.config['settings'] = self.DEFAULT_SETTINGS.copy()
            self.save()
        settings = self.config['settings']
        return {
            "headless": settings.getboolean('headless', fallback=True),
            "auto_login_interval": settings.getint('auto_login_interval', fallback=60) * 60,
            "total_accounts": settings.getint('total_accounts', fallback=100),
            "max_workers": settings.getint('max_workers', fallback=10)
        }

    def save(self):
        logger.debug("Saving configuration to %s", self.CONFIG_FILE)
        with self.CONFIG_FILE.open('w') as configfile:
            self.config.write(configfile)
        logger.info("Configuration saved successfully.")
