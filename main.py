import base64
import csv
import os
import re
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor

from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.edge.options import Options
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.wait import WebDriverWait

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'client_secret.json'
CSV_FILE = 'credentials.csv'

total_accounts = 5000
completed_registrations = 0
lock = threading.Lock()

def set_dark_mode(root):
    bg_color = "#2e2e2e"
    fg_color = "#ffffff"
    root.configure(bg=bg_color)
    style = {'bg': bg_color, 'fg': fg_color}
    return style

def register_user(index, output_label):
    global completed_registrations
    options = Options()
    options.add_argument('--headless')
    driver = webdriver.Edge(options=options, keep_alive=False)

    try:
        driver.get("https://ise01.umpsa.edu.my:8443/portal/PortalSetup.action?portal=2fe2f2b6-84d8-4a26-bc65-9f3e7b86446b")
        driver.get("https://ise01.umpsa.edu.my:8443/portal/SelfRegistration.action?from=LOGIN")

        prefix = "guestUser.fieldValues.ui_"
        form_data = {
            f"{prefix}first_name": "IRedDragonICY",
            f"{prefix}last_name": "IRedDragonICY",
            f"{prefix}email_address": "2200018401@webmail.uad.ac.id",
            f"{prefix}phone_number": "+628000000000",
            f"{prefix}company": "*",
            f"{prefix}reason_visit": "Student Exchange",
            f"{prefix}ump_staff_name_text": "Mr."
        }

        for field_name, value in form_data.items():
            script = f"document.getElementsByName('{field_name}')[0].value = '{value}';"
            driver.execute_script(script)

        driver.find_element(By.ID, "ui_self_reg_submit_button").click()

        with lock:
            completed_registrations += 1
            percentage = (completed_registrations / total_accounts) * 100
            output_label.config(text=f"Progress: {completed_registrations}/{total_accounts} ({percentage:.2f}%) registrasi selesai.")

    except Exception as e:
        with lock:
            output_label.config(text=f"Error selama registrasi {index}: {e}")

    finally:
        driver.quit()

def start_registration(output_label):
    output_label.config(text="Registrasi dimulai...")
    def run():
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(lambda i: register_user(i, output_label), range(1, total_accounts + 1))
        output_label.config(text="Registrasi selesai.")

    threading.Thread(target=run).start()

def fetch_emails(output_label):
    output_label.config(text="Mengambil email...")
    def run():
        creds = authenticate_gmail()
        if not creds:
            output_label.config(text="Autentikasi gagal.")
            return
        service = build('gmail', 'v1', credentials=creds)

        query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
        messages = search_emails(service, query=query)
        if not messages:
            output_label.config(text='Tidak ada email yang ditemukan.')
            return

        credentials_list = []

        for msg in messages:
            content = get_email_content(service, msg['id'])
            if content:
                username, password = extract_credentials(content)
                if username and password:
                    credentials_list.append({'Username': username, 'Password': password})

        if credentials_list:
            with open(CSV_FILE, 'w', newline='') as csvfile:
                fieldnames = ['Username', 'Password']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(credentials_list)
            output_label.config(text=f'Kredensial telah disimpan ke {CSV_FILE}')
        else:
            output_label.config(text='Tidak ada kredensial yang diekstrak.')

    threading.Thread(target=run).start()

# Fungsi untuk login
def login(output_label):
    output_label.config(text="Proses login...")
    def run():
        url = "http://2.2.2.2/login.html"
        options = Options()
        options.add_argument('--headless')
        options.page_load_strategy = 'eager'

        credential_file = 'credentials.csv'

        try:
            with open(credential_file, 'r', newline='') as infile:
                reader = csv.DictReader(infile)
                fieldnames = reader.fieldnames
                first_row = next(reader, None)
                if not first_row:
                    output_label.config(text="Tidak ada kredensial yang tersedia di file CSV.")
                    return
                username = first_row['Username']
                password = first_row['Password']
                remaining_credentials = list(reader)
        except FileNotFoundError:
            output_label.config(text=f"File kredensial {credential_file} tidak ditemukan.")
            return
        except Exception as e:
            output_label.config(text=f"Terjadi kesalahan saat membaca kredensial: {e}")
            return

        with webdriver.Edge(options=options) as driver:
            driver.get(url)
            wait = WebDriverWait(driver, 5)

            try:
                username_field = wait.until(EC.presence_of_element_located((By.ID, "user.username")))
                password_field = driver.find_element(By.ID, "user.password")
                login_button = driver.find_element(By.ID, "ui_login_signon_button")

                username_field.send_keys(username)
                password_field.send_keys(password)
                login_button.click()

                aup_text_element = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "cisco-ise-aup-text")))
                driver.execute_script("arguments[0].scrollTop = arguments[0].scrollHeight;", aup_text_element)

                wait.until(EC.element_to_be_clickable((By.ID, "ui_aup_accept_button"))).click()

                wait.until(EC.title_is('Success'))
                output_label.config(text="Login berhasil")

            except Exception as e:
                output_label.config(text=f"Terjadi kesalahan selama login: {e}")
                return

        if remaining_credentials:
            with open(credential_file, 'w', newline='') as outfile:
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(remaining_credentials)
        else:
            os.remove(credential_file)

    threading.Thread(target=run).start()

def authenticate_gmail():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            try:
                flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
                creds = flow.run_local_server(port=0)
            except Exception as e:
                print(f"Autentikasi gagal: {e}")
                return None
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    return creds

def search_emails(service, user_id='me', query=''):
    try:
        messages = []
        response = service.users().messages().list(userId=user_id, q=query).execute()
        messages.extend(response.get('messages', []))
        while 'nextPageToken' in response:
            response = service.users().messages().list(
                userId=user_id, q=query, pageToken=response['nextPageToken']).execute()
            messages.extend(response.get('messages', []))
        return messages
    except Exception as e:
        print(f'Error saat mencari email: {e}')
        return []

def get_email_content(service, msg_id, user_id='me'):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id, format='full').execute()
        return get_message_body(message['payload'])
    except Exception as e:
        print(f'Gagal mengambil isi email dengan ID {msg_id}: {e}')
        return ''

def get_message_body(payload):
    if 'parts' in payload:
        for part in payload['parts']:
            text = get_message_body(part)
            if text:
                return text
    else:
        data = payload.get('body', {}).get('data')
        if data:
            decoded_data = base64.urlsafe_b64decode(data).decode('utf-8')
            return decoded_data
    return ''

def extract_credentials(content):
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()

    username = re.search(r'Username:\s*(\S+)', text)
    password = re.search(r'Password:\s*(\S+)', text)

    return (
        username.group(1).strip() if username else None,
        password.group(1).strip() if password else None
    )

def main():
    root = tk.Tk()
    root.title("UMPSA Connect")
    style = set_dark_mode(root)

    frame = tk.Frame(root, bg=style['bg'])
    frame.pack(padx=20, pady=20)

    title_label = tk.Label(frame, text="UMPSA Connect", bg=style['bg'], fg=style['fg'], font=('Arial', 16))
    title_label.pack(pady=(0, 20))

    output_label = tk.Label(frame, text="", bg=style['bg'], fg=style['fg'])
    output_label.pack(pady=(0, 20))

    register_button = tk.Button(frame, text="Register", bg="#4a4a4a", fg=style['fg'], width=20, command=lambda: start_registration(output_label))
    register_button.pack(pady=5)

    fetch_button = tk.Button(frame, text="Fetch Email", bg="#4a4a4a", fg=style['fg'], width=20, command=lambda: fetch_emails(output_label))
    fetch_button.pack(pady=5)

    login_button = tk.Button(frame, text="Login", bg="#4a4a4a", fg=style['fg'], width=20, command=lambda: login(output_label))
    login_button.pack(pady=5)

    root.mainloop()

if __name__ == "__main__":
    main()
