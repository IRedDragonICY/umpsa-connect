import base64
import binascii
import csv
import logging
import os
import re
import sys
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Dict, List, Any

from PIL import Image, ImageTk, UnidentifiedImageError
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from selenium import webdriver
from selenium.common.exceptions import (
    NoSuchElementException,
    TimeoutException,
    WebDriverException
)
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait


def resource_path(relative_path: str) -> str:
    """
    Returns the absolute path to the resource, supporting bundling with PyInstaller.

    Args:
        relative_path (str): Relative path to the resource.

    Returns:
        str: Absolute path to the resource.
    """
    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, relative_path)


# Type annotations for global variables
SCOPES: List[str] = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_FILE: str = resource_path('token.json')
CREDENTIALS_FILE: str = resource_path('client_secret.json')
CSV_FILE: str = resource_path('credentials.csv')
BACKUP_CSV_FILE: str = resource_path('credentials_backup.csv')
TOTAL_ACCOUNTS: int = 5000
MAX_WORKERS: int = 50
REGISTRATION_URL: str = "https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN"
REGISTRATION_SESSION: str = "https://ise01.umpsa.edu.my:8443/portal/PortalSetup.action?portal=2fe2f2b6-84d8-4a26-bc65-9f3e7b86446b"
LOGIN_URL: str = "http://2.2.2.2/login.html"
DRIVER_PATH: str = resource_path(os.path.join('driver', 'msedgedriver.exe'))
AUTO_LOGIN_INTERVAL: int = 60 * 60  # 1 hour

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(resource_path("app.log")),
        logging.StreamHandler(sys.stdout)
    ]
)


class Counter:
    def __init__(self, total: int):
        self.total: int = total
        self.completed: int = 0
        self.lock: threading.Lock = threading.Lock()

    def increment(self) -> int:
        with self.lock:
            self.completed += 1
            return self.completed

    def get_percentage(self) -> float:
        with self.lock:
            return (self.completed / self.total) * 100 if self.total else 0.0


class GmailService:
    def __init__(self):
        self.service = self.authenticate()

    @staticmethod
    def authenticate() -> Any:
        """
        Authenticates with the Gmail API using OAuth 2.0.

        Returns:
            Resource: Gmail API service resource.
        """
        creds: Optional[Credentials] = None
        if os.path.exists(TOKEN_FILE):
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
            logging.info("Loaded credentials from token file.")
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                logging.info("Refreshed expired credentials.")
            else:
                try:
                    flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                    creds = flow.run_local_server(port=0)
                    logging.info("Obtained new credentials via OAuth flow.")
                except FileNotFoundError:
                    logging.error(f"Credentials file {CREDENTIALS_FILE} not found.")
                    raise
                except Exception as e:
                    logging.error(f"Failed to obtain credentials: {e}")
                    raise
            try:
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
                    logging.info("Saved new credentials to token file.")
            except IOError as e:
                logging.error(f"Failed to save token file: {e}")
                raise
        try:
            return build('gmail', 'v1', credentials=creds)
        except HttpError as e:
            logging.error(f"Failed to build Gmail service: {e}")
            raise

    def search_emails(self, query: str, user_id: str = 'me') -> List[Dict[str, str]]:
        """
        Searches for emails based on the provided query.

        Args:
            query (str): The email search query.
            user_id (str, optional): Gmail user ID. Defaults to 'me'.

        Returns:
            List[Dict[str, str]]: List of email messages matching the query.
        """
        try:
            messages: List[Dict[str, str]] = []
            response = self.service.users().messages().list(userId=user_id, q=query).execute()
            messages.extend(response.get('messages', []))
            while 'nextPageToken' in response:
                response = self.service.users().messages().list(
                    userId=user_id, q=query, pageToken=response['nextPageToken']).execute()
                messages.extend(response.get('messages', []))
            logging.info(f"Found {len(messages)} messages matching query.")
            return messages
        except HttpError as e:
            logging.error(f'HTTP error searching emails: {e}')
            return []
        except Exception as e:
            logging.error(f'Unexpected error searching emails: {e}')
            return []

    def get_email_content(self, msg_id: str, user_id: str = 'me') -> str:
        """
        Retrieves the content of an email by its message ID.

        Args:
            msg_id (str): The email message ID.
            user_id (str, optional): Gmail user ID. Defaults to 'me'.

        Returns:
            str: The email content in text format.
        """
        try:
            message = self.service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
            body = self.extract_body(message.get('payload', {}))
            logging.debug(f"Extracted body from message ID {msg_id}.")
            return body
        except HttpError as e:
            logging.error(f'HTTP error retrieving email with ID {msg_id}: {e}')
            return ''
        except Exception as e:
            logging.error(f'Unexpected error retrieving email with ID {msg_id}: {e}')
            return ''

    @staticmethod
    def extract_body(payload: Dict) -> str:
        """
        Extracts the body of an email from its payload.

        Args:
            payload (Dict): The email payload.

        Returns:
            str: The email body.
        """
        if 'parts' in payload:
            for part in payload['parts']:
                text = GmailService.extract_body(part)
                if text:
                    return text
        else:
            data = payload.get('body', {}).get('data')
            if data:
                try:
                    return base64.urlsafe_b64decode(data).decode('utf-8')
                except (binascii.Error, UnicodeDecodeError):
                    logging.warning("Failed to decode email body.")
                    return ''
        return ''


def extract_credentials(content: str) -> Optional[Dict[str, str]]:
    """
    Extracts credentials (Username and Password) from email content.

    Args:
        content (str): The email content in text format.

    Returns:
        Optional[Dict[str, str]]: Credentials if found, else None.
    """
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    username_match = re.search(r'Username:\s*(\S+)', text)
    password_match = re.search(r'Password:\s*(\S+)', text)
    if username_match and password_match:
        creds = {
            'Username': username_match.group(1).strip(),
            'Password': password_match.group(1).strip()
        }
        logging.info(f"Extracted credentials: {creds}")
        return creds
    logging.warning("Failed to extract credentials from email content.")
    return None


def get_webdriver(headless: bool = True) -> webdriver.Edge:
    """
    Initializes the Selenium WebDriver for Microsoft Edge with optimizations
    to enhance execution speed by disabling CSS, images, and other unnecessary resources.

    Args:
        headless (bool, optional): Run browser in headless mode. Defaults to True.

    Returns:
        webdriver.Edge: An optimized instance of Edge WebDriver.

    Raises:
        WebDriverException: If the WebDriver fails to initialize.
    """
    options = Options()
    options.use_chromium = True

    if headless:
        # options.add_argument('--headless=new')  # Updated headless mode
        options.add_argument('--disable-gpu')  # Disable GPU acceleration

    options.add_argument('--disable-extensions')
    options.add_argument('--disable-popup-blocking')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-software-rasterizer')

    prefs = {
        "profile.managed_default_content_settings.images": 2,
        "profile.default_content_setting_values.stylesheets": 2,
        "profile.managed_default_content_settings.stylesheets": 2,
        "profile.default_content_setting_values.javascript": 1,
    }
    options.add_experimental_option("prefs", prefs)

    options.page_load_strategy = 'eager'

    options.add_argument('--log-level=3')

    options.add_argument('--ignore-certificate-errors')
    options.add_argument('--allow-insecure-localhost')
    options.accept_insecure_certs = True

    service = Service(executable_path=DRIVER_PATH)
    try:
        driver = webdriver.Edge(service=service, options=options)
        logging.info("Initialized optimized Selenium WebDriver in headless mode.")

        try:
            driver.execute_cdp_cmd(
                'Network.setBlockedURLs',
                {"urls": ["*.css"]}
            )
            logging.info("Blocked CSS resources via DevTools Protocol.")
        except Exception as e:
            logging.warning(f"Failed to block CSS via CDP: {e}")

        return driver
    except WebDriverException as e:
        logging.error(f"WebDriverException during initialization: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error initializing WebDriver: {e}")
        raise


class UMPSAConnectApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("UMPSA Connect")
        self.style = self.set_dark_mode()
        self.auto_login_timer: Optional[threading.Timer] = None
        self.credentials_lock = threading.Lock()

        self.frame = tk.Frame(self.root, bg=self.style['bg'])
        self.frame.pack(padx=20, pady=20)

        tk.Label(
            self.frame,
            text="UMPSA Connect",
            bg=self.style['bg'],
            fg=self.style['fg'],
            font=('Arial', 16)
        ).pack(pady=(0, 20))

        self.load_logo()

        self.output_label = tk.Label(self.frame, text="", bg=self.style['bg'], fg=self.style['fg'])
        self.output_label.pack(pady=(0, 20))

        self.counter = Counter(TOTAL_ACCOUNTS)

        buttons = [
            ("Login", self.initiate_login),
            ("Register", self.start_registration),
            ("Fetch Email", self.fetch_emails)
        ]

        for text, cmd in buttons:
            tk.Button(
                self.frame,
                text=text,
                bg="#4a4a4a",
                fg=self.style['fg'],
                width=20,
                command=cmd
            ).pack(pady=5)

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_dark_mode(self) -> Dict[str, str]:
        """
        Applies dark mode styling to the application.

        Returns:
            Dict[str, str]: Background and foreground colors.
        """
        bg_color = "#2e2e2e"
        fg_color = "#ffffff"
        self.root.configure(bg=bg_color)
        logging.info("Applied dark mode styling.")
        return {'bg': bg_color, 'fg': fg_color}

    def load_logo(self):
        """
        Loads and displays the application logo.
        """
        img_path = resource_path(os.path.join("assets", "logo.png"))  # Ensure img_path is defined before try
        try:
            with Image.open(img_path) as img:
                img = img.resize((img.width // 6, img.height // 6), Image.Resampling.LANCZOS)
                logo: tk.PhotoImage = ImageTk.PhotoImage(img)
                tk.Label(self.frame, image=logo, bg=self.style['bg']).pack(pady=(0, 20))
                self.frame.image = logo
                logging.info("Loaded and displayed logo.")
        except FileNotFoundError:
            logging.error(f"Logo file not found at path: {img_path}")
        except UnidentifiedImageError:
            logging.error("Failed to identify image file for logo.")
        except Exception as e:
            logging.error(f"Unexpected error loading logo: {e}")

    def initiate_login(self):
        """
        Initiates the login process and schedules auto-login.
        """
        self.login()
        self.schedule_auto_login()

    def register_user(self, index: int):
        """
        Automatically registers a user.

        Args:
            index (int): Index of the user being registered.
        """
        try:
            with get_webdriver(headless=True) as driver:
                driver.get(REGISTRATION_SESSION)
                driver.get(REGISTRATION_URL)
                form_data = {
                    "guestUser.fieldValues.ui_first_name": "IRedDragonICY",
                    "guestUser.fieldValues.ui_last_name": "IRedDragonICY",
                    "guestUser.fieldValues.ui_email_address": "2200018401@webmail.uad.ac.id",
                    "guestUser.fieldValues.ui_phone_number": "+628000000000",
                    "guestUser.fieldValues.ui_company": "*",
                    "guestUser.fieldValues.ui_reason_visit": "Student Exchange",
                    "guestUser.fieldValues.ui_ump_staff_name_text": "Mr."
                }
                for field, value in form_data.items():
                    try:
                        driver.execute_script(f"document.getElementsByName('{field}')[0].value = '{value}';")
                    except NoSuchElementException:
                        logging.warning(f"Field '{field}' not found on the registration page.")
                try:
                    submit_button = driver.find_element(By.ID, "ui_self_reg_submit_button")
                    submit_button.click()
                    logging.info(f"User {index} registration submitted.")
                except NoSuchElementException:
                    logging.error(f"Submit button not found for user {index} registration.")

            completed = self.counter.increment()
            percentage = self.counter.get_percentage()
            self.output_label.config(
                text=f"Progress: {completed}/{self.counter.total} ({percentage:.2f}%) registrations completed.")
        except WebDriverException as e:
            logging.error(f"Selenium WebDriver error during registration {index}: {e}")
            self.output_label.config(text=f"Selenium error during registration {index}: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during registration {index}: {e}")
            self.output_label.config(text=f"Unexpected error during registration {index}: {e}")

    def start_registration(self):
        """
        Starts the registration process in parallel.
        """
        self.output_label.config(text="Registration started...")
        threading.Thread(target=self.run_registration, daemon=True).start()

    def run_registration(self):
        """
        Executes the registration process using ThreadPoolExecutor.
        """
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(self.register_user, range(1, self.counter.total + 1))
        self.output_label.config(text="Registration completed.")
        logging.info("All registrations completed.")

    def fetch_emails(self):
        """
        Initiates the email fetching process.
        """
        self.output_label.config(text="Fetching emails...")
        threading.Thread(target=self.run_fetch_emails, daemon=True).start()

    def run_fetch_emails(self):
        """
        Executes the email fetching and extraction process.
        """
        gmail_service = GmailService()
        query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
        messages = gmail_service.search_emails(query=query)
        if not messages:
            self.output_label.config(text='No emails found.')
            return

        credentials_list: List[Dict[str, str]] = []
        for msg in messages:
            content = gmail_service.get_email_content(msg['id'])
            creds = extract_credentials(content)
            if creds:
                credentials_list.append(creds)

        if credentials_list:
            try:
                with self.credentials_lock:
                    if os.path.exists(CSV_FILE):
                        try:
                            os.replace(CSV_FILE, BACKUP_CSV_FILE)
                            logging.info("Backed up existing credentials.csv to credentials_backup.csv.")
                        except OSError as e:
                            logging.error(f"Failed to backup credentials.csv: {e}")
                            self.output_label.config(text=f"Failed to backup credentials: {e}")
                            return

                    try:
                        with open(CSV_FILE, 'w', newline='', encoding='utf-8') as csvfile:
                            writer = csv.DictWriter(csvfile, fieldnames=['Username', 'Password'])
                            writer.writeheader()
                            writer.writerows(credentials_list)
                        self.output_label.config(text=f'Credentials saved to {CSV_FILE}')
                        logging.info(f"Saved {len(credentials_list)} credentials to CSV.")
                    except IOError as e:
                        logging.error(f"IOError while writing to CSV: {e}")
                        self.output_label.config(text=f"Failed to save credentials: {e}")
            except Exception as e:
                logging.error(f"Unexpected error during email fetching: {e}")
                self.output_label.config(text=f"Unexpected error: {e}")
        else:
            self.output_label.config(text='No credentials extracted.')
            logging.info("No credentials were extracted from the fetched emails.")

    def schedule_auto_login(self, interval: int = AUTO_LOGIN_INTERVAL):
        """
        Schedules auto-login at specified intervals.

        Args:
            interval (int, optional): Interval in seconds. Defaults to AUTO_LOGIN_INTERVAL.
        """
        self.auto_login_timer = threading.Timer(interval, self.auto_login)
        self.auto_login_timer.daemon = True
        self.auto_login_timer.start()
        logging.info(f"Scheduled auto-login every {interval} seconds.")

    def auto_login(self):
        """
        Performs auto-login and reschedules the next login.
        """
        self.login()
        self.schedule_auto_login()

    def login(self):
        """
        Initiates the login process.
        """
        self.output_label.config(text="Logging in...")
        threading.Thread(target=self.run_login, daemon=True).start()

    def run_login(self):
        """
        Executes the login process using credentials from the CSV file.
        Continuously attempts to log in until a successful login occurs or all credentials are exhausted.
        """
        try:
            driver = get_webdriver(headless=True)
        except WebDriverException as e:
            logging.error(f"Failed to initialize WebDriver: {e}")
            self.output_label.config(text=f"Failed to initialize WebDriver: {e}")
            return
        except Exception as e:
            logging.error(f"Unexpected error initializing WebDriver: {e}")
            self.output_label.config(text=f"Unexpected WebDriver error: {e}")
            return

        try:
            while True:
                current_cred = self.get_first_credential()
                if not current_cred:
                    self.output_label.config(text="No credentials available to attempt login.")
                    logging.warning("No credentials available to attempt login.")
                    break

                logging.info(f"Attempting login with credentials: {current_cred}")
                self.output_label.config(text=f"Attempting login with Username: {current_cred['Username']}")

                try:
                    driver.get(LOGIN_URL)
                    wait = WebDriverWait(driver, 10)
                    username_field = wait.until(EC.presence_of_element_located((By.ID, "user.username")))
                    username_field.clear()
                    username_field.send_keys(current_cred['Username'])

                    password_field = driver.find_element(By.ID, "user.password")
                    password_field.clear()
                    password_field.send_keys(current_cred['Password'])

                    login_button = driver.find_element(By.ID, "ui_login_signon_button")
                    login_button.click()
                    logging.info("Submitted login form.")

                    try:
                        error_element = WebDriverWait(driver, 5).until(
                            EC.presence_of_element_located((By.ID, "ui_login_failed_error"))
                        )
                        if "Authentication failed" in error_element.text:
                            logging.warning("Authentication failed with current credentials.")
                            self.output_label.config(text="Authentication failed. Trying next credentials...")
                            self.remove_first_credential()
                            continue  #
                    except TimeoutException:
                        pass

                    try:
                        aup_text = driver.find_element(By.CLASS_NAME, "cisco-ise-aup-text")
                        driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text)
                        accept_button = driver.find_element(By.ID, "ui_aup_accept_button")
                        accept_button.click()
                        logging.info("Accepted AUP.")
                    except NoSuchElementException:
                        logging.info("AUP not present or already accepted.")

                    try:
                        continue_button = driver.find_element(By.ID, "ui_max_devices_continue_button")
                        continue_button.click()
                        logging.info("Clicked Continue button for Maximum Devices Reached.")

                    except NoSuchElementException:
                        logging.info("Maximum Devices Reached not present or already handled.")

                    if self.is_login_successful(driver):
                        self.output_label.config(text="Login successful.")
                        logging.info("Login successful.")
                        self.remove_first_credential()
                        break
                    else:
                        logging.warning("Login might not be successful. Retrying with next credentials.")
                        self.output_label.config(text="Login may not be successful. Trying next credentials...")
                        self.remove_first_credential()
                        continue

                except WebDriverException as e:
                    logging.error(f"Selenium WebDriver error during login with {current_cred['Username']}: {e}")
                    self.output_label.config(text=f"Selenium error: {e}. Trying next credentials...")
                    self.remove_first_credential()
                    continue
                except Exception as e:
                    logging.error(f"Unexpected error during login with {current_cred['Username']}: {e}")
                    self.output_label.config(text=f"Unexpected error: {e}. Trying next credentials...")
                    self.remove_first_credential()
                    continue
        finally:
            driver.quit()
            logging.info("WebDriver closed.")

    @staticmethod
    def is_login_successful(driver: webdriver.Edge) -> bool:
        """
        Determines if the login was successful based on page elements or title.

        Args:
            driver (webdriver.Edge): The Selenium WebDriver instance.

        Returns:
            bool: True if login is successful, False otherwise.
        """
        try:
            success_element = driver.find_element(By.ID, "success_element_id")
            if success_element:
                return True
        except NoSuchElementException:
            pass
        except Exception as e:
            logging.error(f"Unexpected error while checking login success: {e}")

        # Alternatively, check the page title or URL
        try:
            if "dashboard" in driver.current_url.lower():
                return True
        except Exception as e:
            logging.error(f"Unexpected error while checking URL for login success: {e}")
        return False

    def get_first_credential(self) -> Optional[Dict[str, str]]:
        """
        Retrieves the first credential from the CSV file.

        Returns:
            Optional[Dict[str, str]]: The first credential if available, else None.
        """
        with self.credentials_lock:
            try:
                with open(CSV_FILE, 'r', newline='', encoding='utf-8') as infile:
                    reader = csv.DictReader(infile)
                    credentials = list(reader)
                    if credentials:
                        return credentials[0]
                    else:
                        return None
            except FileNotFoundError:
                logging.error(f"Credentials file {CSV_FILE} not found.")
                return None
            except IOError as e:
                logging.error(f"IOError while reading credentials: {e}")
                return None
            except Exception as e:
                logging.error(f"Unexpected error while reading credentials: {e}")
                return None

    def remove_first_credential(self):
        """
        Removes the first credential from the CSV file.
        """
        with self.credentials_lock:
            try:
                with open(CSV_FILE, 'r', newline='', encoding='utf-8') as infile:
                    reader = csv.reader(infile)
                    rows = list(reader)
                    if len(rows) <= 1:
                        self.output_label.config(text="No more credentials available.")
                        logging.warning("No more credentials to try.")
                        try:
                            os.remove(CSV_FILE)
                            logging.info(f"Removed empty credentials file: {CSV_FILE}")
                        except OSError as e:
                            logging.error(f"Failed to remove credentials file: {e}")
                        return
                    updated_rows = [rows[0]] + rows[2:]
                with open(CSV_FILE, 'w', newline='', encoding='utf-8') as outfile:
                    writer = csv.writer(outfile)
                    writer.writerows(updated_rows)
                logging.info("Removed the first credential from CSV.")
            except FileNotFoundError:
                logging.error(f"Credentials file {CSV_FILE} not found during removal.")
            except IOError as e:
                logging.error(f"IOError while removing credential: {e}")
                self.output_label.config(text=f"Failed to update credentials: {e}")
            except Exception as e:
                logging.error(f"Unexpected error while removing credential: {e}")
                self.output_label.config(text=f"Unexpected error: {e}")

    def on_closing(self):
        """
        Handles the application closure.
        """
        if self.auto_login_timer:
            self.auto_login_timer.cancel()
            logging.info("Canceled auto-login timer.")
        self.root.destroy()
        logging.info("Application closed.")


def main():
    root = tk.Tk()
    _app = UMPSAConnectApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
