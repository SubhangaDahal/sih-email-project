from googleapiclient.discovery import build

# IMPORTANT: These must be the OAuth credentials for the TEST ACCOUNT
# Do not use the main account's Application Default Credentials here.
gmail_service = build('gmail', 'v1', credentials=test_account_oauth_creds)

request = {
    'labelIds': ['INBOX'],
    # Make sure this is the TOPIC path, not the subscription path
    'topicName': 'projects/YOUR_MAIN_PROJECT_ID/topics/YOUR_TOPIC_NAME'
}

response = gmail_service.users().watch(userId='me', body=request).execute()
print("Watch initialized successfully:", response)