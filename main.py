import os
import base64
import time
import logging
from email.mime.text import MIMEText
from datetime import datetime, timedelta

import anthropic
import schedule
import keyring
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("email_analyzer.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Gmail API scopes
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']

# Keyring service names
GOOGLE_CREDS_SERVICE = 'email_analyzer_google'
ANTHROPIC_API_KEY_SERVICE = 'email_analyzer_anthropic'
USER_ACCOUNT = 'default'

# Custom label for processed spam
PROCESSED_SPAM_LABEL = 'ProcessedBySpamFilter'

# Add a global variable to track spam emails
spam_emails = []

def get_credentials():
    """Get and refresh Google OAuth credentials."""
    creds = None
    token_json = keyring.get_password(GOOGLE_CREDS_SERVICE, USER_ACCOUNT)
    
    if token_json:
        import json
        creds = Credentials.from_authorized_user_info(json.loads(token_json), SCOPES)
    
    # If credentials don't exist or are invalid, let the user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Load client secrets from keyring
            client_secrets = keyring.get_password(f"{GOOGLE_CREDS_SERVICE}_secrets", USER_ACCOUNT)
            if not client_secrets:
                raise ValueError("Google client secrets not found in keyring")
            
            import json
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                temp.write(client_secrets)
                temp_path = temp.name
            
            try:
                flow = InstalledAppFlow.from_client_secrets_file(temp_path, SCOPES)
                creds = flow.run_local_server(port=0)
            finally:
                os.unlink(temp_path)
        
        # Save the credentials to keyring
        keyring.set_password(
            GOOGLE_CREDS_SERVICE, 
            USER_ACCOUNT, 
            creds.to_json()
        )
    
    return creds

def get_anthropic_client():
    """Get Anthropic client with API key from keyring."""
    api_key = keyring.get_password(ANTHROPIC_API_KEY_SERVICE, USER_ACCOUNT)
    if not api_key:
        raise ValueError("Anthropic API key not found in keyring")
    
    return anthropic.Anthropic(api_key=api_key)

def get_gmail_service():
    """Get authenticated Gmail service."""
    creds = get_credentials()
    return build('gmail', 'v1', credentials=creds)

def get_unread_emails(service, max_results=10):
    """Get unread emails from the inbox."""
    try:
        # Get messages that are unread and in the inbox
        # Using q parameter to be more explicit about what we want
        results = service.users().messages().list(
            userId='me',
            q='in:inbox is:unread -in:spam -in:trash -category:promotions -category:forums -category:updates -category:social',
            maxResults=max_results
        ).execute()
        
        messages = results.get('messages', [])
        return messages
    except HttpError as error:
        logger.error(f"Error retrieving emails: {error}")
        return []

def get_email_content(service, msg_id):
    """Get the content of an email."""
    try:
        message = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
        headers = message['payload']['headers']
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'No Subject')
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), 'Unknown Sender')
        
        # Get email body
        parts = [message['payload']]
        body = ""
        
        while parts:
            part = parts.pop(0)
            if 'parts' in part:
                parts.extend(part['parts'])
            elif 'body' in part and 'data' in part['body']:
                body_data = part['body']['data']
                body += base64.urlsafe_b64decode(body_data).decode('utf-8')
        
        return {
            'id': msg_id,
            'subject': subject,
            'sender': sender,
            'body': body
        }
    except HttpError as error:
        logger.error(f"Error getting email content: {error}")
        return None

def is_sales_outreach(client, email_content):
    """Use Anthropic's Claude to determine if an email is a sales outreach."""
    prompt = f"""
    Please analyze this email content carefully, looking for the following indicators that suggest it might be a sales outreach.
    After analysis, respond with ONLY 'YES' or 'NO' without any explanation.

    1. Use of generic greetings (e.g., "Hi there", "Hello", "Dear Sir/Madam")
    2. Mentions of products, services, or solutions without prior context
    3. Requests for a meeting, call, or demo
    4. Claims of improving business metrics (e.g., increasing revenue, reducing costs)
    5. References to the recipient's company or role without specific details
    6. Use of sales jargon or buzzwords
    7. Inclusion of links to product pages or scheduling tools
    8. Mentioning mutual connections or claiming to have researched the recipient
    9. Multiple follow-up prompts or attempts to create urgency
    
    Subject: {email_content['subject']}    
    Email Body:
    {email_content['body']}
    
    """
    
    try:
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=150,
            temperature=0,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        
        result = response.content[0].text
        is_sales = result.strip().upper().startswith("YES")
        
        logger.info(f"Email analysis result: {result}")
        return is_sales, result
    except Exception as e:
        logger.error(f"Error analyzing email with Claude: {e}")
        return False, "Error analyzing email"

def create_custom_label(service):
    """Create a custom label if it doesn't exist."""
    try:
        # Check if label already exists
        results = service.users().labels().list(userId='me').execute()
        labels = results.get('labels', [])
        
        for label in labels:
            if label['name'] == PROCESSED_SPAM_LABEL:
                return label['id']
        
        # Create new label if it doesn't exist
        label_object = {
            'name': PROCESSED_SPAM_LABEL,
            'labelListVisibility': 'labelShow',
            'messageListVisibility': 'show'
        }
        
        created_label = service.users().labels().create(userId='me', body=label_object).execute()
        logger.info(f"Created custom label: {PROCESSED_SPAM_LABEL}")
        return created_label['id']
    except HttpError as error:
        logger.error(f"Error creating custom label: {error}")
        return None

def move_to_spam_and_block(service, email_data):
    """Move email to spam and block the sender."""
    try:
        # Create custom label if it doesn't exist
        label_id = create_custom_label(service)
        
        # Move to spam by adding SPAM label and removing INBOX label
        service.users().messages().modify(
            userId='me',
            id=email_data['id'],
            body={
                'removeLabelIds': ['INBOX'],
                'addLabelIds': ['SPAM', label_id] if label_id else ['SPAM']
            }
        ).execute()
        
        # Create a filter to block future emails from this sender
        sender_email = extract_email_address(email_data['sender'])
        if sender_email:
            service.users().settings().filters().create(
                userId='me',
                body={
                    'criteria': {
                        'from': sender_email
                    },
                    'action': {
                        'addLabelIds': ['SPAM', label_id] if label_id else ['SPAM'],
                        'removeLabelIds': ['INBOX']
                    }
                }
            ).execute()
            
            logger.info(f"Created filter to block emails from {sender_email}")
        
        logger.info(f"Moved email '{email_data['subject']}' to spam")
        return True
    except HttpError as error:
        logger.error(f"Error moving email to spam: {error}")
        return False

def extract_email_address(sender_string):
    """Extract email address from a sender string like 'Name <email@example.com>'."""
    import re
    match = re.search(r'<([^>]+)>', sender_string)
    if match:
        return match.group(1)
    elif '@' in sender_string:
        return sender_string.strip()
    return None

def send_summary_email(service):
    """Send a summary email with information about identified spam emails."""
    global spam_emails
    
    if not spam_emails:
        logger.info("No spam emails to report in summary")
        return
    
    # Create the email content
    email_body = "Here's a summary of emails identified as spam in the last 24 hours:\n\n"
    
    for email in spam_emails:
        # Get a preview of the email body (first 100 characters)
        preview = email['body'][:100] + "..." if len(email['body']) > 100 else email['body']
        
        email_body += f"Subject: {email['subject']}\n"
        email_body += f"From: {email['sender']}\n"
        email_body += f"Preview: {preview}\n\n"
        email_body += "-" * 50 + "\n\n"
    
    # Create the message
    message = MIMEText(email_body)
    message['to'] = 'me'  # Send to yourself
    message['subject'] = f'Spam Email Summary - {datetime.now().strftime("%Y-%m-%d")}'
    
    # Encode the message
    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
    
    try:
        # Send the email
        service.users().messages().send(
            userId='me',
            body={'raw': raw_message}
        ).execute()
        
        logger.info(f"Summary email sent with {len(spam_emails)} spam emails")
        
        # Clear the spam emails list after sending
        spam_emails = []
    except HttpError as error:
        logger.error(f"Error sending summary email: {error}")

def process_emails():
    """Main function to process emails."""
    global spam_emails
    
    try:
        logger.info("Starting email processing")
        
        # Get services
        gmail_service = get_gmail_service()
        anthropic_client = get_anthropic_client()
        
        # Get unread emails
        unread_emails = get_unread_emails(gmail_service)
        logger.info(f"Found {len(unread_emails)} unread emails")
        
        for email in unread_emails:
            email_content = get_email_content(gmail_service, email['id'])
            if not email_content:
                continue
                
            logger.info(f"Processing email: {email_content['subject']}")
            
            # Check if it's a sales outreach
            is_sales, analysis = is_sales_outreach(anthropic_client, email_content)
            
            if is_sales:
                # First add to spam_emails list before moving to spam
                spam_emails.append(email_content)
                
                # Move to spam folder
                gmail_service.users().messages().modify(
                    userId='me',
                    id=email['id'],
                    body={'addLabelIds': ['SPAM']}
                ).execute()
                logger.info(f"Email moved to spam: {email_content['subject']}")
                
                # Mark as read
                gmail_service.users().messages().modify(
                    userId='me',
                    id=email['id'],
                    body={'removeLabelIds': ['UNREAD']}
                ).execute()
                logger.info(f"Sales outreach email marked as read: {email_content['subject']}")
            else:
                # Do nothing - leave unread for review
                logger.info(f"Non-sales email left unread: {email_content['subject']}")
                
        logger.info("Email processing completed")
    except Exception as e:
        logger.error(f"Error in process_emails: {e}")

def send_daily_summary():
    """Function to send daily summary of spam emails."""
    try:
        logger.info("Sending daily summary email")
        gmail_service = get_gmail_service()
        send_summary_email(gmail_service)
    except Exception as e:
        logger.error(f"Error sending daily summary: {e}")

def send_manual_summary():
    """Function to manually send a summary of spam emails collected so far."""
    try:
        logger.info("Manually sending summary email")
        gmail_service = get_gmail_service()
        send_summary_email(gmail_service)
    except Exception as e:
        logger.error(f"Error sending manual summary: {e}")

def setup_keyring():
    """Initial setup to store credentials in keyring."""
    # Google OAuth client secrets
    if not keyring.get_password(f"{GOOGLE_CREDS_SERVICE}_secrets", USER_ACCOUNT):
        client_secrets_path = input("Enter path to Google OAuth client secrets JSON file: ")
        with open(client_secrets_path, 'r') as f:
            client_secrets = f.read()
        keyring.set_password(f"{GOOGLE_CREDS_SERVICE}_secrets", USER_ACCOUNT, client_secrets)
    
    # Anthropic API key
    if not keyring.get_password(ANTHROPIC_API_KEY_SERVICE, USER_ACCOUNT):
        api_key = input("Enter your Anthropic API key: ")
        keyring.set_password(ANTHROPIC_API_KEY_SERVICE, USER_ACCOUNT, api_key)

def main():
    """Main entry point for the application."""
    try:
        # Check if credentials are set up
        if (not keyring.get_password(f"{GOOGLE_CREDS_SERVICE}_secrets", USER_ACCOUNT) or
            not keyring.get_password(ANTHROPIC_API_KEY_SERVICE, USER_ACCOUNT)):
            setup_keyring()
            
        # Check for command line arguments
        import sys
        if len(sys.argv) > 1 and sys.argv[1] == "--send-summary":
            send_manual_summary()
            return
        
        # Process emails immediately
        process_emails()
        
        # Schedule to run every hour
        schedule.every(60).minutes.do(process_emails)
        
        # Schedule daily summary email at 8:00 AM
        schedule.every().day.at("08:00").do(send_daily_summary)
        
        logger.info("Email analyzer service started")
        
        # Keep the script running
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Email analyzer service stopped")
    except Exception as e:
        logger.error(f"Error in main function: {e}")

if __name__ == "__main__":
    main()
