# Email Analyzer

An automated email management system that uses AI to identify and filter out sales outreach emails from your Gmail inbox. The system uses Claude AI (Anthropic) to analyze emails and automatically moves identified sales outreach to spam.

## Features

- Automatically analyzes unread emails in your Gmail inbox
- Uses Claude AI to identify sales outreach emails
- Moves identified sales emails to spam
- Creates filters to block future emails from identified senders
- Sends daily summary emails of identified spam
- Runs continuously in the background
- Securely stores credentials using system keyring

## Prerequisites

- Python 3.7+
- Gmail account
- Anthropic API key
- Google OAuth 2.0 credentials

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/email-analyzer.git
cd email-analyzer
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

3. Set up your credentials:
   - Get your Anthropic API key from [Anthropic's website](https://console.anthropic.com/)
   - Set up Google OAuth 2.0 credentials from [Google Cloud Console](https://console.cloud.google.com/)
     - Enable Gmail API
     - Create OAuth 2.0 credentials
     - Download the client secrets JSON file

4. Run the initial setup:
```bash
python main.py
```
The script will prompt you to enter:
- Path to your Google OAuth client secrets JSON file
- Your Anthropic API key

## Usage

Run the email analyzer:
```bash
python main.py
```

To manually trigger a summary email of identified spam:
```bash
python main.py --send-summary
```

The script will:
- Run continuously in the background
- Check for new emails every hour
- Send a daily summary at 8:00 AM
- Move identified sales outreach to spam
- Create filters to block future emails from identified senders

## Security

- All credentials are stored securely using your system's keyring
- No credentials are stored in plain text
- OAuth 2.0 is used for Gmail authentication

## License

MIT License
