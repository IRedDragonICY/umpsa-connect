import csv
import logging
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from threading import Timer
from tkinter import messagebox, ttk
from typing import Dict, Optional

from PIL import Image, ImageTk
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from config import Config
from counter import Counter
from gmail_service import (GmailService, extract_credentials)
from webdriver_utils import (BASE_PATH, ensure_connected_to_umspa_id,
                             get_webdriver)

logger = logging.getLogger(__name__)


class UMPSAConnectApp:
    TOKEN_FILE = BASE_PATH / 'token.json'
    CREDENTIALS_FILE = BASE_PATH / 'client_secret.json'
    CREDENTIALS_CSV = BASE_PATH / 'credentials.csv'
    CONFIG = Config()
    REGISTRATION_URL = "https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN"
    LOGIN_URL = "http://2.2.2.2/login.html"

    def __init__(self):
        logger.debug("Initializing UMPSAConnectApp.")
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
        logger.info("UMPSAConnectApp initialized.")

    def set_dark_mode(self) -> Dict[str, str]:
        bg_color, fg_color = "#2e2e2e", "#ffffff"
        self.root.configure(bg=bg_color)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background=bg_color, foreground=fg_color, font=('Arial', 10))
        style.configure('TButton', padding=6, relief="flat")
        style.configure('TEntry', foreground='black', fieldbackground='white')
        style.map('TButton', background=[('active', '#4a4a4a')], foreground=[('active', 'white')])
        logger.debug("Dark mode set with background color %s and foreground color %s.", bg_color, fg_color)
        return {'bg': bg_color, 'fg': fg_color}

    def setup_ui(self):
        logger.debug("Setting up UI components.")
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
        logger.debug("UI components setup complete.")

    def load_logo(self, parent):
        logger.debug("Loading application logo.")
        img_path = BASE_PATH / "assets" / "logo.png"
        try:
            with Image.open(img_path) as img:
                resized_img = img.resize((192, int(192 * img.height / img.width)), Image.Resampling.LANCZOS)
                logo = ImageTk.PhotoImage(resized_img)
            logo_label = ttk.Label(parent, image=logo, background=self.style['bg'])
            logo_label.image = logo
            logo_label.pack(pady=(0, 10))
            logo_label.bind("<Button-1>", self.show_version_info)
            logger.debug("Logo loaded and displayed.")
        except Exception as e:
            logger.error("Error loading logo image: %s", e)

    @staticmethod
    def show_version_info(_event=None):
        version_info = "Version 1.0\nCreated by IRedDragonICY"
        messagebox.showinfo("About", version_info)
        logger.info("Version info displayed.")

    def open_settings(self):
        logger.debug("Opening settings window.")
        if self.settings_window is None or not self.settings_window.winfo_exists():
            self.settings_window = SettingsWindow(self.root, self.style, self.on_settings_window_closed,
                                                  self.reload_config, self.CONFIG)
            logger.info("Settings window opened.")

    def on_settings_window_closed(self):
        self.settings_window = None
        logger.debug("Settings window closed.")

    def reload_config(self):
        logger.debug("Reloading configuration.")
        self.CONFIG = Config()
        self.counter = Counter(self.CONFIG.settings['total_accounts'])
        logger.info("Configuration reloaded.")

    def initiate_login(self):
        ensure_connected_to_umspa_id()
        self.login()
        self.schedule_auto_login()

    def register_user(self, index: int):
        logger.info("Starting registration for user %d.", index)
        try:
            with get_webdriver(self.CONFIG.settings['headless']) as driver:
                driver.get(self.REGISTRATION_URL)
                logger.debug("Registration page loaded.")
                for field, value in self.CONFIG.form_data.items():
                    script = f"document.getElementsByName('{field}')[0].value = '{value}';"
                    driver.execute_script(script)
                    logger.debug("Set form field '%s' to '%s'.", field, value)
                driver.find_element(By.ID, "ui_self_reg_submit_button").click()
                logger.info("Registration form submitted for user %d.", index)
            self.counter.increment()
            progress = self.counter.get_progress()
            self.output_label.config(text=f"Registration progress: {progress}")
        except Exception as e:
            logger.error("Error during registration %d: %s", index, e)

    def start_registration(self):
        logger.info("Registration process started.")
        self.output_label.config(text="Registration started...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_registration)

    def run_registration(self):
        logger.debug("Running registration in thread pool.")
        total_accounts = self.CONFIG.settings['total_accounts']
        max_workers = self.CONFIG.settings['max_workers'] or None
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            executor.map(self.register_user, range(1, total_accounts + 1))
        self.output_label.config(text="Registration completed.")
        logger.info("Registration process completed.")

    def fetch_emails(self):
        logger.info("Fetching emails.")
        self.output_label.config(text="Fetching emails...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_fetch_emails)

    def run_fetch_emails(self):
        logger.debug("Running fetch emails in thread pool.")
        gmail_service = GmailService(self.TOKEN_FILE, self.CREDENTIALS_FILE)
        query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
        messages = gmail_service.search_emails(query)
        if not messages:
            self.output_label.config(text='No emails found.')
            logger.warning("No emails found matching the query.")
            return
        credentials_list = []
        for msg in messages:
            content = gmail_service.get_email_content(msg['id'])
            creds = extract_credentials(content)
            if creds:
                credentials_list.append(creds)
            else:
                logger.warning("No credentials extracted from message ID %s.", msg['id'])
        if credentials_list:
            with self.CREDENTIALS_CSV.open('w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=['Username', 'Password'])
                writer.writeheader()
                writer.writerows(credentials_list)
            self.output_label.config(text=f'Credentials saved to {self.CREDENTIALS_CSV.name}.')
            logger.info("Credentials saved to %s.", self.CREDENTIALS_CSV)
        else:
            self.output_label.config(text='No credentials extracted.')
            logger.warning("No credentials extracted from any emails.")

    def schedule_auto_login(self):
        interval = self.CONFIG.settings['auto_login_interval']
        logger.info("Scheduling auto-login every %d seconds.", interval)
        self.auto_login_timer = threading.Timer(interval, self.auto_login)
        self.auto_login_timer.daemon = True
        self.auto_login_timer.start()

    def auto_login(self):
        logger.info("Performing auto-login.")
        ensure_connected_to_umspa_id()
        self.login()
        self.schedule_auto_login()

    def login(self):
        logger.info("Starting login process.")
        self.output_label.config(text="Logging in...")
        ThreadPoolExecutor(max_workers=1).submit(self.run_login)

    def run_login(self):
        logger.debug("Running login in thread pool.")
        try:
            with self.CREDENTIALS_CSV.open('r', newline='', encoding='utf-8') as infile:
                reader = csv.DictReader(infile)
                credentials = list(reader)
                if not credentials:
                    self.output_label.config(text="No credentials available.")
                    logger.warning("No credentials available for login.")
                    return
                first_cred = credentials.pop(0)
        except FileNotFoundError:
            self.output_label.config(text="Credentials file not found.")
            logger.error("Credentials file %s not found.", self.CREDENTIALS_CSV)
            return
        except Exception as e:
            self.output_label.config(text="Error reading credentials.")
            logger.error("Error reading credentials: %s", e)
            return
        max_retries = 3
        for attempt in range(max_retries):
            logger.info("Login attempt %d.", attempt + 1)
            try:
                with get_webdriver(self.CONFIG.settings['headless']) as driver:
                    driver.get(self.LOGIN_URL)
                    wait = WebDriverWait(driver, 20)
                    wait.until(EC.presence_of_element_located((By.ID, "user.username"))).send_keys(first_cred['Username'])
                    driver.find_element(By.ID, "user.password").send_keys(first_cred['Password'])
                    driver.find_element(By.ID, "ui_login_signon_button").click()
                    logger.debug("Login form submitted.")
                    try:
                        aup_text = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cisco-ise-aup-text")))
                        driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text)
                        wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button"))).click()
                        logger.debug("Accepted AUP.")
                    except TimeoutException:
                        logger.debug("AUP not presented.")
                    wait.until(EC.title_is('Success'))
                    self.output_label.config(text="Login successful.")
                    logger.info("Login successful.")
                    break
            except Exception as e:
                logger.error("Login attempt %d failed: %s", attempt + 1, e)
                if attempt == max_retries - 1:
                    self.output_label.config(text="Login failed.")
                    logger.error("All login attempts failed.")
        if credentials:
            with self.CREDENTIALS_CSV.open('w', newline='', encoding='utf-8') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=['Username', 'Password'])
                writer.writeheader()
                writer.writerows(credentials)
            logger.debug("Updated credentials file after login.")
        else:
            self.CREDENTIALS_CSV.unlink()
            logger.info("All credentials used. Credentials file deleted.")

    def on_closing(self):
        logger.info("Application is closing.")
        if self.auto_login_timer:
            self.auto_login_timer.cancel()
            logger.debug("Auto-login timer cancelled.")
        self.root.destroy()
        logger.debug("Main window destroyed.")

    def run(self):
        logger.info("Starting the application.")
        self.root.mainloop()
        logger.info("Application closed.")


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
        logger.info("Settings window initialized.")

    def setup_ui(self):
        logger.debug("Setting up UI components for settings window.")
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
        logger.debug("Settings UI components setup complete.")

    def save_settings(self):
        auto_login_interval = self.auto_login_var.get()
        total_accounts = self.total_accounts_var.get()
        max_workers = self.max_workers_var.get()
        logger.debug("Saving settings: auto_login_interval=%s, total_accounts=%s, max_workers=%s",
                     auto_login_interval, total_accounts, max_workers)
        self.config.config.set('settings', 'headless', str(self.headless_var.get()))
        self.config.config.set('settings', 'auto_login_interval',
                               auto_login_interval if auto_login_interval.isdigit() else '0')
        self.config.config.set('settings', 'total_accounts', total_accounts if total_accounts.isdigit() else '0')
        self.config.config.set('settings', 'max_workers', max_workers if max_workers.isdigit() else '0')
        self.config.save()
        self.reload_config_callback()
        logger.info("Settings saved.")

    def save_form_data(self, key, var, *_args):
        logger.debug("Saving form data: %s=%s", key, var.get())
        self.config.config.set('form_data', key, var.get())
        self.config.save()
        logger.info("Form data saved.")

    def on_close(self):
        logger.debug("Closing settings window.")
        self.destroy()
        if self.on_close_callback:
            self.on_close_callback()
        logger.info("Settings window closed.")