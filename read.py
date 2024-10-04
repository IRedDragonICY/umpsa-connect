import os
import base64
import re
import csv

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from bs4 import BeautifulSoup

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
TOKEN_FILE = 'token.json'
CREDENTIALS_FILE = 'client_secret.json'
CSV_FILE = 'credentials.csv'

def authenticate_gmail():
    creds = None
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
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
    creds = authenticate_gmail()
    service = build('gmail', 'v1', credentials=creds)

    query = 'from:Donotreply@ump.edu.my subject:"Your Guest Account Credentials!"'
    messages = search_emails(service, query=query)
    if not messages:
        print('Tidak ada email yang ditemukan.')
        return

    print(f'Ditemukan {len(messages)} email.')
    credentials_list = []

    for msg in messages:
        content = get_email_content(service, msg['id'])
        if content:
            username, password = extract_credentials(content)
            if username and password:
                credentials_list.append({'Username': username, 'Password': password})
        else:
            print(f'Isi email dengan ID {msg["id"]} tidak dapat diambil.')

    if credentials_list:
        with open(CSV_FILE, 'w', newline='') as csvfile:
            fieldnames = ['Username', 'Password']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(credentials_list)
        print(f'Kredensial telah disimpan ke {CSV_FILE}')
    else:
        print('Tidak ada kredensial yang diekstrak.')

if __name__ == '__main__':
    main()
