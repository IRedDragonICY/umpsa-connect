import base64
import binascii
import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from bs4 import BeautifulSoup
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def authenticate(token_file: Path, credentials_file: Path) -> Credentials:
    logger.info("Authenticating with Google API.")
    creds = Credentials.from_authorized_user_file(str(token_file), SCOPES) if token_file.exists() else None
    if creds and creds.valid:
        logger.debug("Valid credentials found.")
        return creds
    if creds and creds.expired and creds.refresh_token:
        logger.info("Refreshing expired credentials.")
        creds.refresh(Request())
    else:
        from google_auth_oauthlib.flow import InstalledAppFlow
        logger.info("No valid credentials found. Initiating new OAuth flow.")
        flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), SCOPES)
        creds = flow.run_local_server(port=0)
    with token_file.open('w') as token:
        token.write(creds.to_json())
        logger.debug("Credentials saved to token file.")
    return creds


class GmailService:
    def __init__(self, token_file: Path, credentials_file: Path):
        logger.debug("Initializing GmailService.")
        creds = authenticate(token_file, credentials_file)
        self.service = build('gmail', 'v1', credentials=creds)
        logger.info("GmailService initialized successfully.")

    def search_emails(self, query: str) -> List[Dict]:
        logger.info("Searching emails with query: %s", query)
        messages = []
        try:
            response = self.service.users().messages().list(userId='me', q=query).execute()
            messages.extend(response.get('messages', []))
            while 'nextPageToken' in response:
                logger.debug("Fetching next page of messages.")
                response = self.service.users().messages().list(
                    userId='me', q=query, pageToken=response['nextPageToken']).execute()
                messages.extend(response.get('messages', []))
            logger.info("Total messages found: %d", len(messages))
        except Exception as e:
            logger.error("Error searching emails: %s", e)
        return messages

    def get_email_content(self, msg_id: str) -> str:
        logger.debug("Getting email content for message ID: %s", msg_id)
        try:
            message = self.service.users().messages().get(
                userId='me', id=msg_id, format='full').execute()
            body = self.extract_body(message.get('payload', {}))
            logger.debug("Email content extracted.")
            return body
        except Exception as e:
            logger.error("Error getting email content: %s", e)
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
                    text = base64.urlsafe_b64decode(data).decode('utf-8')
                    return text
                except (binascii.Error, UnicodeDecodeError) as e:
                    logger.error("Error decoding email body: %s", e)
        return ''


def extract_credentials(content: str) -> Optional[Dict[str, str]]:
    logger.debug("Extracting credentials from email content.")
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()
    matches = re.findall(r'(Username|Password):\s*(\S+)', text)
    creds = {k: v for k, v in matches}
    if 'Username' in creds and 'Password' in creds:
        logger.info("Credentials extracted successfully.")
        return creds
    logger.warning("Credentials not found in the email content.")
    return None