import base64
import email
from apiclient import errors
from googleapiclient.errors import HttpError

def GetMessage(service, user_id, msg_id):
    try:
        message = service.users().messages().get(userId=user_id, id=msg_id).execute()

        print('Message snippet: %s' % message['snippet'])

        return message
    except HttpError:
        print('An error occurred')

def ListMessagesMatchingQuery(service, user_id, query=''):
    """List all Messages of the user's mailbox matching the query.

    Args:
      service: Authorized Gmail API service instance.
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      query: String used to filter messages returned.
      Eg.- 'from:user@some_domain.com' for Messages from a particular sender.

    Returns:
      List of Messages that match the criteria of the query. Note that the
      returned list contains Message IDs, you must use get with the
      appropriate ID to get the details of a Message.
    """
    try:
        response = service.users().messages().list(userId=user_id,
                                                   q=query).execute()
        messages = []
        if 'messages' in response:
            messages.extend(response['messages'])

        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().messages().list(userId=user_id, q=query,
                                                       pageToken=page_token).execute()
            messages.extend(response['messages'])

        return messages
    except(HttpError):
        print('An error occurred')

def ListThreadsMatchingQuery(service, user_id, query=''):
    """List all Threads of the user's mailbox matching the query.

    Args:
      service: Authorized Gmail API service instance.
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      query: String used to filter messages returned.
             Eg.- 'label:UNREAD' for unread messages only.

    Returns:
      List of threads that match the criteria of the query. Note that the returned
      list contains Thread IDs, you must use get with the appropriate
      ID to get the details for a Thread.
    """
    try:
        response = service.users().threads().list(userId=user_id, q=query).execute()
        threads = []
        if 'threads' in response:
            threads.extend(response['threads'])

        while 'nextPageToken' in response:
            page_token = response['nextPageToken']
            response = service.users().threads().list(userId=user_id, q=query,
                                                      pageToken=page_token).execute()
            threads.extend(response['threads'])

        return threads
    except HttpError:
        print('An error occurred')

def GetThread(service, user_id, thread_id):
    """Get a Thread.

    Args:
      service: Authorized Gmail API service instance.
      user_id: User's email address. The special value "me"
      can be used to indicate the authenticated user.
      thread_id: The ID of the Thread required.

    Returns:
      Thread with matching ID.
    """
    try:
        thread = service.users().threads().get(userId=user_id, id=thread_id).execute()
        #messages = thread['messages']
        #print(messages)
        #print(thread)
        #print('thread id: {} - number of messages in this thread: {}'.format(thread['id'], len(messages)))
        return thread
    except HttpError:
        print('An error occurred')