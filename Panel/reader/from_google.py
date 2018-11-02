import email
import imaplib
import sys
import re
from datetime import datetime
from email.header import Header, decode_header
from pprint import pprint as pp

DEFAULT_MAIL_SERVER = 'imap.gmail.com'

# No user parameters below this line
ADDR_PATTERN = re.compile('<(.*?)>')  # Finds email as <nospam@nospam.com>


def connect(user, pwd, server=DEFAULT_MAIL_SERVER):
    conn = imaplib.IMAP4_SSL(server)
    try:
        conn.login(user, pwd)
    except imaplib.IMAP4.error:
        print("Failed to login")
        sys.exit(1)
    return conn

def get_folder(conn, folder_name):
    if conn.state == "SELECTED":
        conn.close()

    rv, data = conn.select(folder_name)
    if rv != 'OK':
        print ("Could not open specified folder. Known labels:")
        print_folders(conn)
    return conn

def print_folders(conn):
    for f in conn.list():
        print("\t", f)

def get_email_ids(conn, query='ALL'):
    if conn.state != "SELECTED":
        raise imaplib.IMAP4.error("Cannot search without selecting a folder")

    rv, data = conn.uid('search', None, query)
    if rv != 'OK':
        print ("Could not fetch email ids")
        return []
    return data[0].split()

def get_headers(conn, uid):
    typ, data = conn.fetch(uid, '(RFC822)')

    if typ != 'OK':
        print("Could not feach message")
        raise imaplib.IMAP4.error("Could not featch email")

    email_content = data[0][1]
    msg = email.message_from_bytes(email_content)
    return msg


def get_recipients(msg_parsed):
    """Given a parsed message, extract and return recipient list"""
    recipients = []
    addr_fields = ['From', 'To', 'Cc', 'Bcc']

    for f in addr_fields:
        rfield = msg_parsed.get(f, "") # Empty string if field not present
        rlist = re.findall(ADDR_PATTERN, rfield)
        recipients.extend(rlist)

    return recipients

def get_field(msg, field):
    try:
        value = ''
        header = decode_header(msg[field])
        for s, encoding in header:
            value += s if type(s) is str else s.decode(encoding or 'utf-8')
        return value
    except:
        return ''

def get_text(msg):
    if msg.is_multipart():
        return get_text(msg.get_payload(1))
    else:
        return msg.get_payload(None, True)

def get_data(conn, uids):
    data = []

    for uid in uids:
        msg = get_headers(conn, uid)
        newlist = list()
        for i in msg.keys():
            newlist.append(i)

        email_message_id = get_field(msg, 'Message-ID').split(' ')[-1]
        email_in_reply_to = get_field(msg, 'In-Reply-To').split(' ')[-1]
        email_datetime =  get_field(msg, 'Date')
        email_subject = get_field(msg, 'Subject')
        email_from = get_field(msg, 'From')
        email_to = get_field(msg, 'To')
        email_cc = get_field(msg, 'Cc')
        email_body = get_text(msg)
        #print(msg)
        #print(newlist)
        #print(get_field(msg, 'X-Received'))
        #print(get_text(msg))
        ''' 
        print(newlist)
        print('MESSAGE_ID:', email_message_id)
        print('IN_REPLY_TO:', email_in_reply_to)
        print('DATE:', email_date)
        print('SUBJECT:', email_subject)
        print('FROM:', email_from)
        print('TO:', email_to)
        print('CC:', email_cc)
        '''
        try:
            email_datetime = datetime.strptime(email_datetime, '%a, %d %b %Y %H:%M:%S %z')
        except ValueError:
            email_datetime = datetime.strptime(email_datetime, '%a, %d %b %Y %H:%M:%S %z (%Z)')

        item = {}
        item['Id'] = email_message_id
        item['Reply_to'] = email_in_reply_to
        item['Date'] = email_datetime
        item['Subject'] = email_subject
        item['From'] = email_from
        item['To'] = email_to
        item['Cc'] = email_cc
        item['Body'] = email_body
        data.append(item)

    return data

def close(conn):
    try:
        conn.close()
    finally:
        conn.logout()
'''
if __name__ == "__main__":
    conn = connect(USER_NAME, PASSWORD)

    conn = get_folder(conn, SEARCH_FOLDER)

    uids = get_email_ids(conn)

    print(uids)

    data = []

    all_recipients = []
    for uid in uids:
        msg = fetch_message(conn, uid)
        newlist = list()
        for i in msg.keys():
            newlist.append(i)

        email_message_id = get_field('Message-ID').split(' ')[-1]
        email_in_reply_to = get_field('In-Reply-To').split(' ')[-1]
        email_date =  get_field('Date')
        email_subject = get_field('Subject')
        email_from = get_field('From')
        email_to = get_field('To')
        email_cc = get_field('Cc')

        #print(msg)
        print(newlist)
        print('MESSAGE_ID:', email_message_id)
        print('IN_REPLY_TO:', email_in_reply_to)
        print('DATE:', email_date)
        print('SUBJECT:', email_subject)
        print('FROM:', email_from)
        print('TO:', email_to)
        print('CC:', email_cc)

        item = {}
        item['Message_Id'] = email_message_id
        item['In_Reply_to'] = email_in_reply_to
        item['Date'] = email_date
        item['Subject'] = email_subject
        item['From'] = email_from
        item['To'] = email_to
        item['Cc'] = email_cc
        data.append(item)

        print(data)

        print("-----------------------------------------------------")

        recip_list = get_recipients(msg)
        all_recipients.extend(recip_list)

        # Very unsophisticated way of showing the recipient list
        #print ("List of all recipients:")
        #print ("------------")
        #pp(all_recipients)

        #print ("\n\n List of all UNIQUE recipients:")
        #print ("-------------------------------")
        #pp(set(all_recipients))

    try:
        conn.close()
    finally:
        conn.logout()
'''