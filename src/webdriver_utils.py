# webdriver_utils.py
import logging
import subprocess
import sys
from pathlib import Path

from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service

logger = logging.getLogger(__name__)

BASE_PATH = Path(getattr(sys, '_MEIPASS', Path.cwd()))


def get_webdriver(headless: bool) -> webdriver.Edge:
    logger.debug("Initializing WebDriver with headless=%s.", headless)
    opts = Options()
    opts.use_chromium = True
    opts.page_load_strategy = 'eager'
    if headless:
        opts.add_argument('--headless=new')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--window-size=1920,1080')
    opts.add_argument('--disable-extensions')
    opts.add_argument('--disable-cache')
    driver_path = BASE_PATH / 'driver' / 'msedgedriver.exe'
    service = Service(executable_path=str(driver_path))
    driver = webdriver.Edge(service=service, options=opts)
    driver.set_page_load_timeout(60)
    logger.info("WebDriver initialized.")
    return driver


def ensure_connected_to_umspa_id():
    ssid_target = "UMPSA-iD"
    profile_filename = "Wi-Fi-UMPSA-iD.xml"
    profile_path = BASE_PATH / profile_filename

    logger.info("Ensuring connection to SSID '%s'.", ssid_target)
    cmd = ['netsh', 'wlan', 'show', 'interfaces']
    try:
        output = subprocess.check_output(cmd, encoding='utf-8')
        ssid_line = next((line for line in output.split('\n')
                          if 'SSID' in line and 'BSSID' not in line), None)
        if ssid_line:
            current_ssid = ssid_line.split(':', 1)[1].strip()
            if current_ssid == ssid_target:
                logger.info("Already connected to SSID '%s'.", ssid_target)
                return
    except Exception as e:
        logger.error("Error checking current SSID: %s", e)

    logger.info("Attempting to connect to SSID '%s'.", ssid_target)
    if not profile_path.exists():
        logger.error("Profile file '%s' not found in '%s'.", profile_filename, BASE_PATH)
        return
    try:
        cmd_add_profile = ['netsh', 'wlan', 'add', 'profile', f'filename="{profile_path}"']
        subprocess.check_call(cmd_add_profile)
        cmd_connect = ['netsh', 'wlan', 'connect', f'name="{ssid_target}"']
        subprocess.check_call(cmd_connect, timeout=30)
        logger.info("Successfully connected to SSID '%s'.", ssid_target)
    except Exception as e:
        logger.error("Error connecting to SSID '%s': %s", ssid_target, e)