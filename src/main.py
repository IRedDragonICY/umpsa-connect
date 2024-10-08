import base64
import binascii
import csv
import logging
import re
import subprocess
import sys
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from threading import Lock, Timer
from tkinter import ttk, messagebox
from typing import Dict, List, Optional

from PIL import Image, ImageTk
from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

BASE_PATH = Path(getattr(sys, '_MEIPASS', Path.cwd()))
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
LOG_FILE = BASE_PATH / "app.log"
logging.basicConfig(level=logging.INFO,
                    format='[%(asctime)s] %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler(str(LOG_FILE))])

class Config:
    CONFIG_FILE = BASE_PATH / 'config.ini'
    def __init__(self):
        self.config = self.load_config()
        self.form_data = self.load_form_data()
        self.settings = self.load_settings()

    def load_config(self):
        import configparser
        config = configparser.ConfigParser()
        config.read(self.CONFIG_FILE)
        return config

    def load_form_data(self) -> Dict[str, str]:
        form_section = self.config['form_data']
        return {
            f"guestUser.fieldValues.{key}": form_section[key]
            for key in form_section
        }

    def load_settings(self) -> Dict[str, any]:
        settings = self.config['settings']
        return {
            "headless": settings.getboolean('headless'),
            "auto_login_interval": settings.getint('auto_login_interval') * 60,
            "total_accounts": settings.getint('total_accounts'),
            "max_workers": settings.getint('max_workers')
        }

    def save(self):
        with self.CONFIG_FILE.open('w') as configfile:
            self.config.write(configfile)

class Counter:
    def __init__(self, total: int):
        self.total = total
        self.completed = 0
        self.lock = Lock()

    def increment(self) -> None:
        with self.lock:
            self.completed += 1

    def get_progress(self) -> str:
        with self.lock:
            percentage = (self.completed / self.total) * 100 if self.total else 0.0
            return f"{self.completed}/{self.total} ({percentage:.2f}%)"

def authenticate(token_file: Path, credentials_file: Path) -> Credentials:
    creds = Credentials.from_authorized_user_file(str(token_file), SCOPES) if token_file.exists() else None
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    else:
        from google_auth_oauthlib.flow import InstalledAppFlow
        flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
        creds = flow.run_local_server(port=0)
    with token_file.open('w') as token:
        token.write(creds.to_json())
    return creds

class GmailService:
    def __init__(self, token_file: Path, credentials_file: Path):
        creds = authenticate(token_file, credentials_file)
        self.service = build('gmail', 'v1', credentials=creds)

    def search_emails(self, query: str) -> List[Dict]:
        messages = []
        response = self.service.users().messages().list(userId='me', q=query).execute()
        messages.extend(response.get('messages', []))
        while 'nextPageToken' in response:
            response = self.service.users().messages().list(
                userId='me', q=query, pageToken=response['nextPageToken']).execute()
            messages.extend(response.get('messages', []))
        return messages

    def get_email_content(self, msg_id: str) -> str:
        message = self.service.users().messages().get(
            userId='me', id=msg_id, format='full').execute()
        return self.extract_body(message.get('payload', {}))

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
                    pass
        return ''

def extract_credentials(content: str) -> Optional[Dict[str, str]]:
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    matches = re.findall(r'(Username|Password):\s*(\S+)', text)
    creds = {k: v for k, v in matches}
    if 'Username' in creds and 'Password' in creds:
        return creds
    return None

def get_webdriver(headless: bool) -> webdriver.Edge:
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
    return driver

def ensure_connected_to_umspa_id():
    ssid_target = "UMPSA-iD"
    profile_filename = "Wi-Fi-UMPSA-iD.xml"
    profile_path = BASE_PATH / profile_filename
    cmd = ['netsh', 'wlan', 'show', 'interfaces']
    try:
        output = subprocess.check_output(cmd, encoding='utf-8')
        ssid_line = next((line for line in output.split('\n') if 'SSID' in line and 'BSSID' not in line), None)
        if ssid_line:
            current_ssid = ssid_line.split(':', 1)[1].strip()
            if current_ssid == ssid_target:
                logging.info(f"Already connected to SSID '{ssid_target}'")
                return
    except Exception as e:
        logging.error(f"Error checking current SSID: {e}")
    logging.info(f"Attempting to connect to SSID '{ssid_target}'")
    if not profile_path.exists():
        logging.error(f"Profile file '{profile_filename}' not found in '{BASE_PATH}'")
        return
    try:
        cmd_add_profile = ['netsh', 'wlan', 'add', 'profile', f'filename="{profile_path}"']
        subprocess.check_call(cmd_add_profile)
        cmd_connect = ['netsh', 'wlan', 'connect', f'name="{ssid_target}"']
        subprocess.check_call(cmd_connect, timeout=30)
        logging.info(f"Successfully connected to SSID '{ssid_target}'")
    except Exception as e:
        logging.error(f"Error connecting to SSID '{ssid_target}': {e}")

class UMPSAConnectApp:
    TOKEN_FILE = BASE_PATH / 'token.json'
    CREDENTIALS_FILE = BASE_PATH / 'client_secret.json'
    CREDENTIALS_CSV = BASE_PATH / 'credentials.csv'
    CONFIG = Config()
    REGISTRATION_URL = "https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN"
    LOGIN_URL = "http://2.2.2.2/login.html"
    def __init__(self):
        self.output_label = None
        self.root = tk.Tk()
        self.root.title("UMPSA Connect")
        self.style = self.set_dark_mode()
        self.root.geometry("320x580")
        self.root.resizable(False, False)
        self.counter = Counter(self.CONFIG.settings['total_accounts'])
        self.auto_login_timer: Optional[Timer] = None
        self.settings_window = None
        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def set_dark_mode(self) -> Dict[str, str]:
        bg_color, fg_color = "#2e2e2e", "#ffffff"
        self.root.configure(bg=bg_color)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=bg_color, foreground=fg_color, font=('Arial', 10))
        style.configure('TButton', padding=6, relief="flat")
        style.configure('TEntry', foreground='black', fieldbackground='white')
        style.map('TButton', background=[('active', '#4a4a4a')], foreground=[('active', 'white')])
        return {'bg': bg_color, 'fg': fg_color}

    def setup_ui(self):
        frame = ttk.Frame(self.root, padding=10)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text="UMPSA Connect", background=self.style['bg'],
                  foreground=self.style['fg'], font=('Arial', 16, 'bold')).pack(pady=(10, 10))
        self.load_logo(frame)
        self.output_label = ttk.Label(frame, text="", background=self.style['bg'],
                                      foreground=self.style['fg'], wraplength=280, anchor='center')
        self.output_label.pack(pady=(10, 10))
        buttons = [
            ("Login", self.initiate_login),
            ("Register", self.start_registration),
            ("Fetch Email", self.fetch_emails),
            ("Settings", self.open_settings)
        ]
        for text, cmd in buttons:
            ttk.Button(frame, text=text, command=cmd).pack(pady=5, fill='x')

    def load_logo(self, parent):
        img_path = BASE_PATH / "assets" / "logo.png"
        with Image.open(img_path) as img:
            resized_img = img.resize((192, int(192 * img.height / img.width)), Image.Resampling.LANCZOS)
            logo = ImageTk.PhotoImage(resized_img)
        logo_label = ttk.Label(parent, image=logo, background=self.style['bg'])
        logo_label.image = logo
        logo_label.pack(pady=(0, 10))
        logo_label.bind("<Button-1>", self.show_version_info)

    @staticmethod
    def show_version_info(_event=None):
        version_info = "Version 1.0\nCreated by IRedDragonICY"
        messagebox.showinfo("About", version_info)

    def open_settings(self):
        if self.settings_window is None or not self.settings_window.winfo_exists():
            self.settings_window = SettingsWindow(self.root, self.style, self.on_settings_window_closed, self.reload_config, self.CONFIG)

    def on_settings_window_closed(self):
        self.settings_window = None

    def reload_config(self):
        self.CONFIG = Config()
        self.counter = Counter(self.CONFIG.settings['total_accounts'])

    def initiate_login(self):
        ensure_connected_to_umspa_id()
        self.login()
        self.schedule_auto_login()

    def register_user(self, index: int):
        try:
            with get_webdriver(self.CONFIG.settings['headless']) as driver:
                driver.get(self.REGISTRATION_URL)
                for field, value in self.CONFIG.form_data.items():
                    script = f"document.getElementsByName('{field}')[0].value = '{value}';"
                    driver.execute_script(script)
                driver.find_element(By.ID, "ui_self_reg_submit_button").click()
            self.counter.increment()
            progress = self.counter.get_progress()
            self.output_label.config(text=f"Registration progress: {progress}")
        except Exception as e:
            logging.error(f"Error during registration {index}: {e}")

    def start_registration(self):
        self.output_label.config(text="Registration started...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_registration)

    def run_registration(self):
        total_accounts = self.CONFIG.settings['total_accounts']
        max_workers = self.CONFIG.settings['max_workers'] or None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.register_user, range(1, total_accounts + 1))
        self.output_label.config(text="Registration completed.")

    def fetch_emails(self):
        self.output_label.config(text="Fetching emails...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_fetch_emails)

    def run_fetch_emails(self):
        gmail_service = GmailService(self.TOKEN_FILE, self.CREDENTIALS_FILE)
        query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
        messages = gmail_service.search_emails(query)
        if not messages:
            self.output_label.config(text='No emails found.')
            return
        credentials_list = []
        for msg in messages:
            content = gmail_service.get_email_content(msg['id'])
            creds = extract_credentials(content)
            if creds:
                credentials_list.append(creds)
        if credentials_list:
            with self.CREDENTIALS_CSV.open('w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=['Username', 'Password'])
                writer.writeheader()
                writer.writerows(credentials_list)
            self.output_label.config(text=f'Credentials saved to {self.CREDENTIALS_CSV.name}.')
        else:
            self.output_label.config(text='No credentials extracted.')

    def schedule_auto_login(self):
        interval = self.CONFIG.settings['auto_login_interval']
        self.auto_login_timer = Timer(interval, self.auto_login)
        self.auto_login_timer.daemon = True
        self.auto_login_timer.start()

    def auto_login(self):
        ensure_connected_to_umspa_id()
        self.login()
        self.schedule_auto_login()

    def login(self):
        self.output_label.config(text="Logging in...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_login)

    def run_login(self):
        try:
            with self.CREDENTIALS_CSV.open('r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                credentials = list(reader)
                if not credentials:
                    self.output_label.config(text="No credentials available.")
                    return
                first_cred = credentials.pop(0)
        except FileNotFoundError:
            self.output_label.config(text="Credentials file not found.")
            return
        except Exception:
            self.output_label.config(text="Error reading credentials.")
            return
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with get_webdriver(self.CONFIG.settings['headless']) as driver:
                    driver.get(self.LOGIN_URL)
                    wait = WebDriverWait(driver, 20)
                    wait.until(EC.presence_of_element_located((By.ID, "user.username"))).send_keys(first_cred['Username'])
                    driver.find_element(By.ID, "user.password").send_keys(first_cred['Password'])
                    driver.find_element(By.ID, "ui_login_signon_button").click()
                    try:
                        aup_text = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cisco-ise-aup-text")))
                        driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text)
                        wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button"))).click()
                    except TimeoutException:
                        pass
                    wait.until(EC.title_is('Success'))
                    self.output_label.config(text="Login successful.")
                    break
            except Exception:
                if attempt == max_retries - 1:
                    self.output_label.config(text="Login failed.")
        if credentials:
            with self.CREDENTIALS_CSV.open('w', newline='', encoding='utf-8') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=['Username', 'Password'])
                writer.writeheader()
                writer.writerows(credentials)
        else:
            self.CREDENTIALS_CSV.unlink()

    def on_closing(self):
        if self.auto_login_timer:
            self.auto_login_timer.cancel()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

class SettingsWindow(tk.Toplevel):
    def __init__(self, parent, style, on_close_callback, reload_config_callback, config: Config):
        super().__init__(parent)
        self.title("Settings")
        self.configure(bg=style['bg'])
        self.geometry("400x550")
        self.resizable(False, False)
        self.reload_config_callback = reload_config_callback
        self.config = config
        self.style = style
        self.on_close_callback = on_close_callback
        self.form_vars = {}
        self.auto_login_var = tk.StringVar(value=str(self.config.settings['auto_login_interval'] // 60))
        self.headless_var = tk.BooleanVar(value=self.config.settings['headless'])
        self.total_accounts_var = tk.StringVar(value=str(self.config.settings['total_accounts']))
        self.max_workers_var = tk.StringVar(value=str(self.config.settings['max_workers']))
        self.setup_ui()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_ui(self):
        ttk.Label(self, text="Settings", font=('Arial', 14, 'bold')).pack(pady=10)
        settings_frame = ttk.Frame(self)
        settings_frame.pack(pady=10, padx=20, fill='x')
        ttk.Label(settings_frame, text="Auto-login Interval (minutes):").pack(anchor='w', pady=5)
        self.auto_login_var.trace('w', lambda *args: self.save_settings())
        ttk.Entry(settings_frame, textvariable=self.auto_login_var).pack(fill='x')
        self.headless_var.trace('w', lambda *args: self.save_settings())
        ttk.Checkbutton(settings_frame, text="Headless Mode", variable=self.headless_var).pack(anchor='w')
        ttk.Label(settings_frame, text="Total Accounts:").pack(anchor='w', pady=5)
        self.total_accounts_var.trace('w', lambda *args: self.save_settings())
        ttk.Entry(settings_frame, textvariable=self.total_accounts_var).pack(fill='x')
        ttk.Label(settings_frame, text="Max Workers:").pack(anchor='w', pady=5)
        self.max_workers_var.trace('w', lambda *args: self.save_settings())
        ttk.Entry(settings_frame, textvariable=self.max_workers_var).pack(fill='x')
        form_data_frame = ttk.LabelFrame(self, text="Form Data", padding=10)
        form_data_frame.pack(pady=10, padx=20, fill='both', expand=True)
        for key in self.config.config['form_data']:
            label = key.replace('ui_', '').replace('_', ' ').title()
            row = ttk.Frame(form_data_frame)
            row.pack(fill='x', pady=5)
            ttk.Label(row, text=label + ":").pack(side='left')
            var = tk.StringVar(value=self.config.config['form_data'][key])
            var.trace('w', partial(self.save_form_data, key, var))
            self.form_vars[key] = var
            ttk.Entry(row, textvariable=var).pack(side='right', fill='x', expand=True)

    def save_settings(self):
        auto_login_interval = self.auto_login_var.get()
        total_accounts = self.total_accounts_var.get()
        max_workers = self.max_workers_var.get()
        self.config.config.set('settings', 'headless', str(self.headless_var.get()))
        self.config.config.set('settings', 'auto_login_interval', auto_login_interval if auto_login_interval.isdigit() else '0')
        self.config.config.set('settings', 'total_accounts', total_accounts if total_accounts.isdigit() else '0')
        self.config.config.set('settings', 'max_workers', max_workers if max_workers.isdigit() else '0')
        self.config.save()
        self.reload_config_callback()

    def save_form_data(self, key, var, *_args):
        self.config.config.set('form_data', key, var.get())
        self.config.save()

    def on_close(self):
        self.destroy()
        if self.on_close_callback:
            self.on_close_callback()

if __name__ == "__main__":
    ensure_connected_to_umspa_id()
    app = UMPSAConnectApp()
    app.run()