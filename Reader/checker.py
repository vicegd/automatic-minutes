#automaticminutes@gmail.com
#automaticminutes2018id

from __future__ import print_function
from apiclient.discovery import build
from googleapiclient.errors import HttpError
from httplib2 import Http
from oauth2client import file, client, tools
import json
import functions

# Setup the Gmail API
SCOPES = 'https://www.googleapis.com/auth/gmail.readonly'
store = file.Storage('credentials.json')
creds = store.get()
if not creds or creds.invalid:
    flow = client.flow_from_clientsecrets('client_secret.json', SCOPES)
    creds = tools.run_flow(flow, store)
service = build('gmail', 'v1', http=creds.authorize(Http()))

# Call the Gmail API
results = service.users().labels().list(userId='me').execute()
labels = results.get('labels', [])
if not labels:
    print('No labels found.')
else:
    print('Labels:')
    for label in labels:
        print(label['name'])

emails = results.get('')

#messages = functions.ListMessagesMatchingQuery(service, 'me')
#for message_info in messages:
#    print(message_info)
#    message = functions.GetMessage(service, 'me', message_info['id'])
#    print(message)
   # print(message_info['snippet'])

threads_info = functions.ListThreadsMatchingQuery(service, 'me')
for thread_info in threads_info:
    thread = functions.GetThread(service, 'me', thread_info['id'])
    print("This is the thread with ID = {}".format(thread['id']))
    for message_info in thread['messages']:
        print("\t Email with ID = {}".format(message_info['id']))
        print("\t\t Date = {}".format(message_info["internalDate"]))
        print("\t\t Subject = {}".format(message_info["payload"]["headers"][5]["value"]))
        #print("\t\t Subject = {}".format(message_info['subject']))
        #print("\t\t {}".format(message_info))
        jsonb = json.dumps(message_info, sort_keys=True, indent=4)
        print(jsonb)
        #jsonToPython = json.loads(jsonb)
        #print(jsonToPython)