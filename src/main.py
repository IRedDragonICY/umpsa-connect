import base64
import binascii
import csv
import os
import re
import threading
import tkinter as tk
import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Optional, Dict, List, cast

from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from PIL import Image, ImageTk

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
TOTAL_ACCOUNTS: int = 5000
MAX_WORKERS: int = 50
REGISTRATION_URL: str = "https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN"
LOGIN_URL: str = "http://2.2.2.2/login.html"
DRIVER_PATH: str = resource_path(os.path.join('driver', 'msedgedriver.exe'))
AUTO_LOGIN_INTERVAL: int = 60 * 60  - 3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(resource_path("app.log")),
        logging.StreamHandler()
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
    def authenticate() -> any:
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
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
                logging.info("Obtained new credentials via OAuth flow.")
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
                logging.info("Saved new credentials to token file.")
        return build('gmail', 'v1', credentials=creds)

    def search_emails(self, query: str, user_id: str = 'me') -> List[Dict]:
        """
        Searches for emails based on the provided query.

        Args:
            query (str): The email search query.
            user_id (str, optional): Gmail user ID. Defaults to 'me'.

        Returns:
            List[Dict]: List of email messages matching the query.
        """
        try:
            messages: List[Dict] = []
            response = self.service.users().messages().list(userId=user_id, q=query).execute()
            messages.extend(response.get('messages', []))
            while 'nextPageToken' in response:
                response = self.service.users().messages().list(
                    userId=user_id, q=query, pageToken=response['nextPageToken']).execute()
                messages.extend(response.get('messages', []))
            logging.info(f"Found {len(messages)} messages matching query.")
            return messages
        except Exception as e:
            logging.error(f'Error searching emails: {e}')
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
        except Exception as e:
            logging.error(f'Failed to retrieve email with ID {msg_id}: {e}')
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

def get_webdriver(headless: bool = True, in_private: bool = False) -> webdriver.Edge:
    """
    Initializes the Selenium WebDriver for Microsoft Edge.

    Args:
        headless (bool, optional): Run browser in headless mode. Defaults to True.
        in_private (bool, optional): Run browser in private mode. Defaults to True.

    Returns:
        webdriver.Edge: An instance of Edge WebDriver.

    Raises:
        Exception: If the WebDriver fails to initialize.
    """
    options = Options()
    options.use_chromium = True
    if headless:
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
    if in_private:
        options.add_argument('--inprivate')
    service = Service(executable_path=DRIVER_PATH)
    try:
        driver = webdriver.Edge(service=service, options=options)
        logging.info("Initialized Selenium WebDriver.")
        return driver
    except Exception as e:
        logging.error(f"Failed to initialize WebDriver: {e}")
        raise

class UMPSAConnectApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("UMPSA Connect")
        self.style = self.set_dark_mode()
        self.auto_login_timer: Optional[threading.Timer] = None

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
            ("Register", partial(self.start_registration)),
            ("Fetch Email", partial(self.fetch_emails))
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
        try:
            img_path = resource_path(os.path.join("assets", "logo.png"))
            with Image.open(img_path) as img:
                img = img.resize((img.width // 6, img.height // 6), Image.Resampling.LANCZOS)
                # Use cast to inform the type checker that logo is a PhotoImage
                logo: tk.PhotoImage = cast(tk.PhotoImage, ImageTk.PhotoImage(img))
                tk.Label(self.frame, image=logo, bg=self.style['bg']).pack(pady=(0, 20))
                self.frame.image = logo
                logging.info("Loaded and displayed logo.")
        except Exception as e:
            logging.error(f"Error loading logo: {e}")

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
            with get_webdriver() as driver:
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
                    driver.execute_script(f"document.getElementsByName('{field}')[0].value = '{value}';")
                submit_button = driver.find_element(By.ID, "ui_self_reg_submit_button")
                submit_button.click()
                logging.info(f"User {index} registration submitted.")

            completed = self.counter.increment()
            percentage = self.counter.get_percentage()
            self.output_label.config(text=f"Progress: {completed}/{self.counter.total} ({percentage:.2f}%) registrations completed.")
        except Exception as e:
            logging.error(f"Error during registration {index}: {e}")
            self.output_label.config(text=f"Error during registration {index}: {e}")

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
                with open(CSV_FILE, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=['Username', 'Password'])
                    writer.writeheader()
                    writer.writerows(credentials_list)
                self.output_label.config(text=f'Credentials saved to {CSV_FILE}')
                logging.info(f"Saved {len(credentials_list)} credentials to CSV.")
            except Exception as e:
                self.output_label.config(text=f"Failed to save credentials: {e}")
                logging.error(f"Failed to save credentials: {e}")
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
        """
        try:
            with open(CSV_FILE, 'r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                credentials = list(reader)
                if not credentials:
                    self.output_label.config(text="No credentials available in CSV.")
                    logging.warning("Credentials CSV is empty.")
                    return
                first_cred = credentials.pop(0)
                logging.info(f"Attempting login with credentials: {first_cred}")
        except FileNotFoundError:
            self.output_label.config(text=f"Credentials file {CSV_FILE} not found.")
            logging.error(f"Credentials file {CSV_FILE} not found.")
            return
        except Exception as e:
            self.output_label.config(text=f"Error reading credentials: {e}")
            logging.error(f"Error reading credentials: {e}")
            return

        try:
            with get_webdriver() as driver:
                driver.get(LOGIN_URL)
                wait = WebDriverWait(driver, 10)
                wait.until(EC.presence_of_element_located((By.ID, "user.username"))).send_keys(first_cred['Username'])
                driver.find_element(By.ID, "user.password").send_keys(first_cred['Password'])
                driver.find_element(By.ID, "ui_login_signon_button").click()
                logging.info("Submitted login form.")

                try:
                    aup_text = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cisco-ise-aup-text")))
                    driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text)
                    accept_button = wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button")))
                    accept_button.click()
                    logging.info("Accepted AUP.")
                except Exception:
                    logging.info("AUP not present or already accepted.")

                wait.until(EC.title_is('Success'))
                self.output_label.config(text="Login successful.")
                logging.info("Login successful.")
        except Exception as e:
            self.output_label.config(text=f"Login error: {e}")
            logging.error(f"Login error: {e}")
            return

        try:
            if credentials:
                with open(CSV_FILE, 'w', newline='', encoding='utf-8') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=['Username', 'Password'])
                    writer.writeheader()
                    writer.writerows(credentials)
                logging.info("Updated credentials CSV after login.")
            else:
                os.remove(CSV_FILE)
                self.output_label.config(text="All credentials have been used and removed.")
                logging.info("All credentials used. Removed CSV file.")
        except Exception as e:
            self.output_label.config(text=f"Failed to update credentials file: {e}")
            logging.error(f"Failed to update credentials file: {e}")

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
