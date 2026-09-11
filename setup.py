import os.path

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


# ======================================================================
# CONFIGURATION.
# ======================================================================

SCOPES = [
    "https://mail.google.com/"
]

TOKEN_FILE = "token.json"
CREDENTIALS_FILE = "credentials.json"

PROJECT_ID = "pristine-atom-497215-c2"

TOPIC_NAME = (
    f"projects/{PROJECT_ID}/topics/gmail-notifications"
)


# ======================================================================
# GMAIL AUTHENTICATION
# ======================================================================

def get_credentials():
    creds = None

    # --------------------------------------------------------------
    # Load existing OAuth credentials.
    # --------------------------------------------------------------

    if os.path.exists(TOKEN_FILE):
        print(f"[*] Loading credentials from {TOKEN_FILE}...")

        creds = Credentials.from_authorized_user_file(
            TOKEN_FILE,
            SCOPES,
        )

    # --------------------------------------------------------------
    # Refresh or create credentials.
    # --------------------------------------------------------------

    if creds and creds.expired and creds.refresh_token:
        print("[*] Access token expired. Refreshing...")

        creds.refresh(Request())

    elif not creds or not creds.valid:
        print("[*] No valid credentials found.")
        print("[*] Starting OAuth flow...")

        flow = InstalledAppFlow.from_client_secrets_file(
            CREDENTIALS_FILE,
            SCOPES,
        )

        print(
            "[!] Log in with your Gmail test account "
            "when the browser opens."
        )

        creds = flow.run_local_server(
            port=0
        )

    # --------------------------------------------------------------
    # Verify credentials.
    # --------------------------------------------------------------

    if not creds.valid:
        raise RuntimeError(
            "Gmail OAuth credentials are invalid."
        )

    # --------------------------------------------------------------
    # Print the scopes actually associated with the credentials.
    #
    # This is useful for diagnosing the exact 403 we were seeing.
    # --------------------------------------------------------------

    print("[AUTH] Credentials are valid.")
    print(f"[AUTH] Granted scopes: {creds.scopes}")

    required_scope = "https://mail.google.com/"

    if not creds.scopes or required_scope not in creds.scopes:
        raise RuntimeError(
            "\n"
            "Gmail credentials do not contain the required scope.\n"
            f"Required: {required_scope}\n"
            f"Actual:   {creds.scopes}\n"
            "\n"
            "Delete token.json and run setup.py again to "
            "perform a fresh OAuth authorization."
        )

    # --------------------------------------------------------------
    # Save credentials.
    # --------------------------------------------------------------

    with open(TOKEN_FILE, "w") as token:
        token.write(creds.to_json())

    print(f"[*] Credentials saved to {TOKEN_FILE}")

    return creds


# ======================================================================
# GMAIL WATCH
# ======================================================================

def setup_watch():
    creds = get_credentials()

    # --------------------------------------------------------------
    # Explicitly pass our OAuth credentials.
    # --------------------------------------------------------------

    gmail_service = build(
        "gmail",
        "v1",
        credentials=creds,
    )

    print(
        "[*] Gmail API client initialized."
    )

    # --------------------------------------------------------------
    # Create Gmail watch.
    # --------------------------------------------------------------

    request = {
        "labelIds": [
            "INBOX"
        ],
        "topicName": TOPIC_NAME,
    }

    print(
        f"[*] Creating Gmail watch..."
    )

    print(
        f"[*] Topic: {TOPIC_NAME}"
    )

    response = (
        gmail_service
        .users()
        .watch(
            userId="me",
            body=request,
        )
        .execute()
    )

    # --------------------------------------------------------------
    # Print the initial history ID.
    #
    # This is important for email_handler.py.
    # You can use this as INITIAL_HISTORY_ID if you want the daemon
    # to start from exactly this point.
    # --------------------------------------------------------------

    print(
        "\n[+] Watch initialized successfully!"
    )

    print(
        f"[+] historyId: {response.get('historyId')}"
    )

    print(
        f"[+] expiration: {response.get('expiration')}"
    )

    print(
        "\n[*] Save the historyId above."
    )

    print(
        "[*] It can be used as INITIAL_HISTORY_ID "
        "in email_handler.py."
    )


# ======================================================================
# ENTRY POINT
# ======================================================================

if __name__ == "__main__":
    setup_watch()