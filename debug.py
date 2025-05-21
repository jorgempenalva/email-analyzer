from main import get_credentials, build

creds = get_credentials()
people_service = build('people', 'v1', credentials=creds)

page_token = None
found = False
target_email = "jkochman@apib.com"

while True:
    results = people_service.otherContacts().list(
        pageSize=1000,
        readMask='emailAddresses,names',
        pageToken=page_token
    ).execute()

    for person in results.get('otherContacts', []):
        for email in person.get('emailAddresses', []):
            if email.get('value', '').lower() == target_email:
                name = person.get('names', [{}])[0].get('displayName', 'No Name')
                print(f"Found: Name: {name} | Email: {email.get('value')}")
                found = True

    page_token = results.get('nextPageToken')
    if not page_token or found:
        break

if not found:
    print(f"{target_email} not found in Other Contacts.")