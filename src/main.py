import base64
import binascii
import csv
import logging
import os
import re
import sys
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Lock, Timer
from tkinter import messagebox, ttk
from typing import Dict, List, Optional

from PIL import Image, ImageTk
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

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BASE_PATH = Path(getattr(sys, '_MEIPASS', Path.cwd()))
TOKEN_FILE = BASE_PATH / 'token.json'
CREDENTIALS_FILE = BASE_PATH / 'client_secret.json'
CSV_FILE = BASE_PATH / 'credentials.csv'
TOTAL_ACCOUNTS = 5000
MAX_WORKERS = 50
REGISTRATION_URL = "https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN"
LOGIN_URL = "http://2.2.2.2/login.html"
DRIVER_PATH = BASE_PATH / 'driver' / 'msedgedriver.exe'
AUTO_LOGIN_INTERVAL = 60 * 60

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(BASE_PATH / "app.log")),
        logging.StreamHandler()
    ]
)

def resource_path(relative_path: str) -> Path:
    return BASE_PATH / relative_path

class Counter:
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.lock = Lock()

    def increment(self) -> int:
        with self.lock:
            self.completed += 1
            return self.completed

    def get_percentage(self) -> float:
        with self.lock:
            return (self.completed / self.total) * 100 if self.total else 0.0


def authenticate():
    creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES) if TOKEN_FILE.exists() else None
    if creds and creds.valid:
        logging.info("Loaded credentials from token file.")
    elif creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        logging.info("Refreshed expired credentials.")
    else:
        flow = InstalledAppFlow.from_client_secrets_file(str(CREDENTIALS_FILE), SCOPES)
        creds = flow.run_local_server(port=0)
        logging.info("Obtained new credentials via OAuth flow.")
        with TOKEN_FILE.open('w') as token:
            token.write(creds.to_json())
            logging.info("Saved new credentials to token file.")
    return build('gmail', 'v1', credentials=creds)


class GmailService:
    def __init__(self):
        self.service = authenticate()

    def search_emails(self, query: str, user_id: str = 'me') -> List[Dict]:
        messages = []
        try:
            response = self.service.users().messages().list(userId=user_id, q=query).execute()
            messages.extend(response.get('messages', []))
            while 'nextPageToken' in response:
                response = self.service.users().messages().list(userId=user_id, q=query,
                                                                pageToken=response['nextPageToken']).execute()
                messages.extend(response.get('messages', []))
            logging.info(f"Found {len(messages)} messages matching query.")
        except Exception as e:
            logging.error(f'Error searching emails: {e}')
        return messages

    def get_email_content(self, msg_id: str, user_id: str = 'me') -> str:
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

def extract_credentials(content: str) -> Optional[Dict[str, str]]:
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    matches = re.findall(r'(Username|Password):\s*(\S+)', text)
    creds = {k: v.strip() for k, v in matches}
    if 'Username' in creds and 'Password' in creds:
        logging.info(f"Extracted credentials: {creds}")
        return creds
    logging.warning("Failed to extract credentials from email content.")
    return None


def get_webdriver(headless=True, in_private=False) -> webdriver.Edge:
    opts = Options()
    opts.use_chromium = True

    opts.page_load_strategy = 'eager'

    if headless:
        opts.add_argument('--headless=new')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--window-size=1920,1080')
    if in_private:
        opts.add_argument('--inprivate')
    opts.add_argument('--disable-extensions')
    opts.add_argument('--disable-cache')

    try:
        driver = webdriver.Edge(service=Service(executable_path=str(DRIVER_PATH)), options=opts)
        driver.execute_cdp_cmd("Network.enable", {})
        driver.execute_cdp_cmd("Network.setBlockedURLs", {
            "urls": [
                "*.css", "*.png", "*.jpg", "*.jpeg",
                "*.gif", "*.svg", "*.ico", "*.woff",
                "*.woff2", "*.ttf"
            ]
        })


        logging.info("WebDriver initialized")
        return driver
    except Exception as e:
        logging.error(f"WebDriver initialization failed: {e}")
        raise


class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, style):
        super().__init__(parent)
        self.title("Settings")
        self.configure(bg=style['bg'])
        self.geometry("320x300")
        self.resizable(False, False)

        ttk.Label(self, text="Settings", font=('Arial', 14, 'bold')).pack(pady=10)

        frame = ttk.Frame(self)
        frame.pack(pady=10, padx=20, fill='x')

        ttk.Label(frame, text="Auto-login Interval (minutes):").pack(anchor='w', pady=5)
        self.auto_login_var = tk.IntVar(value=AUTO_LOGIN_INTERVAL // 60)
        ttk.Entry(frame, textvariable=self.auto_login_var).pack(fill='x')

        ttk.Button(self, text="Save", command=self.save_settings).pack(pady=20)

    def save_settings(self):
        global AUTO_LOGIN_INTERVAL
        try:
            AUTO_LOGIN_INTERVAL = self.auto_login_var.get() * 60
            messagebox.showinfo("Settings", "Settings saved successfully.")
            logging.info(f"Auto-login interval set to {AUTO_LOGIN_INTERVAL} seconds.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            logging.error(f"Failed to save settings: {e}")

class UMPSAConnectApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("UMPSA Connect")
        self.style = self.set_dark_mode()
        self.auto_login_timer: Optional[Timer] = None

        self.root.geometry("320x580")
        self.root.resizable(False, False)

        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="UMPSA Connect",
                  background=self.style['bg'],
                  foreground=self.style['fg'],
                  font=('Arial', 16, 'bold')).pack(pady=(10, 10))

        self.load_logo(frame)

        self.output_label = ttk.Label(frame, text="", background=self.style['bg'],
                                      foreground=self.style['fg'])
        self.output_label.pack(pady=(10, 10))

        self.counter = Counter(TOTAL_ACCOUNTS)

        buttons = [
            ("Login", self.initiate_login),
            ("Register", self.start_registration),
            ("Fetch Email", self.fetch_emails),
            ("Settings", self.open_settings)
        ]

        for text, cmd in buttons:
            ttk.Button(frame, text=text, command=cmd).pack(pady=5, fill='x')

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_dark_mode(self) -> Dict[str, str]:
        bg_color, fg_color = "#2e2e2e", "#ffffff"
        self.root.configure(bg=bg_color)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=bg_color, foreground=fg_color, font=('Arial', 10))
        style.configure('TButton', padding=6, relief="flat")
        style.map('TButton', background=[('active', '#4a4a4a')], foreground=[('active', 'white')])
        logging.info("Applied dark mode styling.")
        return {'bg': bg_color, 'fg': fg_color}

    def load_logo(self, parent):
        try:
            img_path = resource_path("assets/logo.png")
            with Image.open(img_path) as img:
                resized_img = img.resize(
                    (192, int(192 * img.height / img.width)),
                    Image.Resampling.LANCZOS
                )
                logo = ImageTk.PhotoImage(resized_img)
            logo_label = ttk.Label(parent, image=logo, background=self.style['bg'])
            logo_label.image = logo
            logo_label.pack(pady=(0, 10))
            logging.info("Loaded and displayed logo.")
        except Exception as e:
            logging.error(f"Error loading logo: {e}")

    def open_settings(self):
        SettingsWindow(self.root, self.style)

    def initiate_login(self):
        self.login()
        self.schedule_auto_login()

    def register_user(self, index: int):
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
                driver.find_element(By.ID, "ui_self_reg_submit_button").click()
                logging.info(f"User {index} registration submitted.")

            completed = self.counter.increment()
            percentage = self.counter.get_percentage()
            self.output_label.config(text=f"Progress: {completed}/{self.counter.total} ({percentage:.2f}%) registrations completed.")
        except Exception as e:
            logging.error(f"Error during registration {index}: {e}")
            self.output_label.config(text=f"Error during registration {index}: {e}")

    def start_registration(self):
        self.output_label.config(text="Registration started...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_registration)

    def run_registration(self):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            executor.map(self.register_user, range(1, self.counter.total + 1))
        self.output_label.config(text="Registration completed.")
        logging.info("All registrations completed.")

    def fetch_emails(self):
        self.output_label.config(text="Fetching emails...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_fetch_emails)

    def run_fetch_emails(self):
        gmail_service = GmailService()
        query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
        messages = gmail_service.search_emails(query=query)
        if not messages:
            self.output_label.config(text='No emails found.')
            return

        credentials_list = [
            creds for msg in messages
            if (creds := extract_credentials(gmail_service.get_email_content(msg['id'])))
        ]

        if credentials_list:
            try:
                with CSV_FILE.open('w', newline='', encoding='utf-8') as csvfile:
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
        self.auto_login_timer = Timer(interval, self.auto_login)
        self.auto_login_timer.daemon = True
        self.auto_login_timer.start()
        logging.info(f"Scheduled auto-login every {interval} seconds.")

    def auto_login(self):
        self.login()
        self.schedule_auto_login()

    def login(self):
        self.output_label.config(text="Logging in...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_login)

    def run_login(self):
        try:
            # Membaca kredensial dari file CSV
            with CSV_FILE.open('r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                credentials = list(reader)
                if not credentials:
                    self.output_label.config(text="No credentials available in CSV.")
                    logging.warning("Credentials CSV is empty.")
                    return
                first_cred = credentials.pop(0)  # Mengambil kredensial pertama
                logging.info(f"Attempting login with credentials: {first_cred}")
        except FileNotFoundError:
            self.output_label.config(text=f"Credentials file {CSV_FILE} not found.")
            logging.error(f"Credentials file {CSV_FILE} not found.")
            return
        except Exception as e:
            self.output_label.config(text=f"Error reading credentials: {e}")
            logging.error(f"Error reading credentials: {e}")
            return

        # Bagian proses login
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
                    wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button"))).click()
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
                with CSV_FILE.open('w', newline='', encoding='utf-8') as outfile:
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
        if self.auto_login_timer:
            self.auto_login_timer.cancel()
            logging.info("Canceled auto-login timer.")
        self.root.destroy()
        logging.info("Application closed.")

def main():
    root = tk.Tk()
    UMPSAConnectApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
