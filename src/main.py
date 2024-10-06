import base64
import csv
import os
import re
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from functools import partial
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

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'client_secret.json'
CSV_FILE = 'credentials.csv'
TOTAL_ACCOUNTS = 5000
MAX_WORKERS = 50
REGISTRATION_URL = "https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN"
LOGIN_URL = "http://2.2.2.2/login.html"
DRIVER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'driver/msedgedriver.exe')

class Counter:
    def __init__(self, total):
        self.total = total
        self.completed = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.completed += 1
            return self.completed

    def get_percentage(self):
        with self.lock:
            return (self.completed / self.total) * 100

class GmailService:
    def __init__(self, token_file=TOKEN_FILE, credentials_file=CREDENTIALS_FILE, scopes=SCOPES):
        self.service = self.authenticate(token_file, credentials_file, scopes)

    @staticmethod
    def authenticate(token_file, credentials_file, scopes):
        creds = None
        if os.path.exists(token_file):
            creds = Credentials.from_authorized_user_file(token_file, scopes)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(credentials_file, scopes)
                creds = flow.run_local_server(port=0)
            with open(token_file, 'w') as token:
                token.write(creds.to_json())
        return build('gmail', 'v1', credentials=creds)

    def search_emails(self, query, user_id='me'):
        try:
            messages = []
            response = self.service.users().messages().list(userId=user_id, q=query).execute()
            messages.extend(response.get('messages', []))
            while 'nextPageToken' in response:
                response = self.service.users().messages().list(
                    userId=user_id, q=query, pageToken=response['nextPageToken']).execute()
                messages.extend(response.get('messages', []))
            return messages
        except Exception as e:
            print(f'Error saat mencari email: {e}')
            return []

    def get_email_content(self, msg_id, user_id='me'):
        try:
            message = self.service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
            return self.extract_body(message['payload'])
        except Exception as e:
            print(f'Gagal mengambil isi email dengan ID {msg_id}: {e}')
            return ''

    @staticmethod
    def extract_body(payload):
        if 'parts' in payload:
            for part in payload['parts']:
                text = GmailService.extract_body(part)
                if text:
                    return text
        else:
            data = payload.get('body', {}).get('data')
            if data:
                return base64.urlsafe_b64decode(data).decode('utf-8')
        return ''

def extract_credentials(content):
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    username = re.search(r'Username:\s*(\S+)', text)
    password = re.search(r'Password:\s*(\S+)', text)
    return {
        'Username': username.group(1).strip() if username else None,
        'Password': password.group(1).strip() if password else None
    }

def get_webdriver(headless=True, in_private=True):
    options = Options()
    options.use_chromium = True
    if headless:
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')

    service = Service(executable_path=DRIVER_PATH)
    return webdriver.Edge(service=service, options=options)

def register_user(index, output_label, counter):
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

        completed = counter.increment()
        percentage = counter.get_percentage()
        output_label.config(text=f"Progress: {completed}/{counter.total} ({percentage:.2f}%) registrasi selesai.")
    except Exception as e:
        output_label.config(text=f"Error selama registrasi {index}: {e}")

def start_registration(output_label, counter):
    output_label.config(text="Registrasi dimulai...")

    def run():
        try:
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
                executor.map(lambda i: register_user(i, output_label, counter), range(1, counter.total + 1))
            output_label.config(text="Registrasi selesai.")
        except Exception as e:
            output_label.config(text=f"Kesalahan saat memulai registrasi: {e}")

    threading.Thread(target=run, daemon=True).start()

def fetch_emails(output_label):
    output_label.config(text="Mengambil email...")

    def run():
        gmail_service = GmailService()
        query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
        messages = gmail_service.search_emails(query=query)
        if not messages:
            output_label.config(text='Tidak ada email yang ditemukan.')
            return

        credentials_list = []
        for msg in messages:
            content = gmail_service.get_email_content(msg['id'])
            creds = extract_credentials(content)
            if creds['Username'] and creds['Password']:
                credentials_list.append(creds)

        if credentials_list:
            try:
                with open(CSV_FILE, 'w', newline='') as csvfile:
                    writer = csv.DictWriter(csvfile, fieldnames=['Username', 'Password'])
                    writer.writeheader()
                    writer.writerows(credentials_list)
                output_label.config(text=f'Kredensial telah disimpan ke {CSV_FILE}')
            except Exception as e:
                output_label.config(text=f"Gagal menyimpan kredensial: {e}")
        else:
            output_label.config(text='Tidak ada kredensial yang diekstrak.')

    threading.Thread(target=run, daemon=True).start()

def login(output_label):
    output_label.config(text="Proses login...")

    def run():
        try:
            with open(CSV_FILE, 'r', newline='') as infile:
                reader = csv.DictReader(infile)
                credentials = list(reader)
                if not credentials:
                    output_label.config(text="Tidak ada kredensial yang tersedia di file CSV.")
                    return
                first_cred = credentials.pop(0)
        except FileNotFoundError:
            output_label.config(text=f"File kredensial {CSV_FILE} tidak ditemukan.")
            return
        except Exception as e:
            output_label.config(text=f"Terjadi kesalahan saat membaca kredensial: {e}")
            return

        try:
            with get_webdriver() as driver:
                driver.get(LOGIN_URL)
                wait = WebDriverWait(driver, 10)
                wait.until(EC.presence_of_element_located((By.ID, "user.username"))).send_keys(first_cred['Username'])
                driver.find_element(By.ID, "user.password").send_keys(first_cred['Password'])
                driver.find_element(By.ID, "ui_login_signon_button").click()
                aup_text = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cisco-ise-aup-text")))
                driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text)
                wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button"))).click()
                wait.until(EC.title_is('Success'))
                output_label.config(text="Login berhasil")
        except Exception as e:
            output_label.config(text=f"Terjadi kesalahan selama login: {e}")
            return

        try:
            if credentials:
                with open(CSV_FILE, 'w', newline='') as outfile:
                    writer = csv.DictWriter(outfile, fieldnames=['Username', 'Password'])
                    writer.writeheader()
                    writer.writerows(credentials)
            else:
                os.remove(CSV_FILE)
        except Exception as e:
            output_label.config(text=f"Gagal memperbarui file kredensial: {e}")

    threading.Thread(target=run, daemon=True).start()

def set_dark_mode(root):
    bg_color = "#2e2e2e"
    fg_color = "#ffffff"
    root.configure(bg=bg_color)
    return {'bg': bg_color, 'fg': fg_color}

def main():
    root = tk.Tk()
    root.title("UMPSA Connect")
    style = set_dark_mode(root)

    frame = tk.Frame(root, bg=style['bg'])
    frame.pack(padx=20, pady=20)

    tk.Label(frame, text="UMPSA Connect", bg=style['bg'], fg=style['fg'], font=('Arial', 16)).pack(pady=(0, 20))

    try:
        img = Image.open("assets/logo.png")
        img = img.resize((img.width // 6, img.height // 6), Image.Resampling.LANCZOS)
        logo = ImageTk.PhotoImage(img)
        tk.Label(frame, image=logo, bg=style['bg']).pack(pady=(0, 20))
        frame.image = logo
    except Exception as e:
        print(f"Error loading logo: {e}")

    output_label = tk.Label(frame, text="", bg=style['bg'], fg=style['fg'])
    output_label.pack(pady=(0, 20))

    counter = Counter(TOTAL_ACCOUNTS)

    buttons = [
        ("Login", lambda: login(output_label)),
        ("Register", partial(start_registration, output_label, counter)),
        ("Fetch Email", lambda: fetch_emails(output_label))
    ]

    for text, cmd in buttons:
        tk.Button(frame, text=text, bg="#4a4a4a", fg=style['fg'], width=20, command=cmd).pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
