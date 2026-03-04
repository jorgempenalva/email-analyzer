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

## Deployment on Digital Ocean

**Server Details:**
- IP: `<your-server-ip>`
- User: `<your-user>`
- Location: ~/email-analyzer

**SSH Connection:**
```bash
ssh <your-user>@<your-server-ip>
```

**Managing the Script:**

The script runs in a screen session with venv activated. To check status:
```bash
screen -ls
```

To attach to the running session:
```bash
screen -r email_analyzer
```

To detach from screen: `Ctrl+A` then `D`

## Troubleshooting: Re-authenticating with Gmail

If you see errors like `invalid_grant: Token has been expired or revoked`, you need to re-authenticate:

**Step 1: Kill the old screen session**
```bash
screen -S email_analyzer -X quit
```

**Step 2: Exit to local machine and reconnect with SSH port forwarding**

Note: Google OAuth uses a random port. Start with a placeholder:

```bash
ssh -L 8080:localhost:8080 <your-user>@<your-server-ip>
```

**Step 3: Start the script in screen**
```bash
cd ~/email-analyzer
screen -S email_analyzer
source venv/bin/activate
python3 main.py
```

**Step 4: Check the OAuth URL for the actual port**

The script will show:
```
Please visit this URL to authorize: http://localhost:XXXXX/...
```

Look for the port number in the redirect_uri (e.g., `localhost:46963`).

**Step 5: Reconnect with the correct port**

- Stop script: `Ctrl+C`
- Detach: `Ctrl+A` then `D`
- Exit to local: `exit`
- Reconnect with correct port: `ssh -L 46963:localhost:46963 <your-user>@<your-server-ip>`
- Resume: `cd ~/email-analyzer && screen -r email_analyzer`
- Activate venv: `source venv/bin/activate`
- Run: `python3 main.py`

**Step 6: Open the OAuth URL in your local browser**

Copy the full URL and paste it in your browser. The SSH tunnel forwards the callback to the server.

**Step 7: After authentication**

The script continues running. Detach with `Ctrl+A` then `D` to leave it in the background.

## License

MIT License
