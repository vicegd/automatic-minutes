import reader.from_google as reader
from pprint import pprint as pp

USER_NAME_DCM = 'piloto.dcm@gmail.com'
USER_NAME_MSWADM = 'piloto.mswadm@gmail.com'
PASSWORD = 'Innova2018.'
SEARCH_FOLDER = 'INBOX'

#Diseño y contrucción de MDA
print("Diseño y contrucción de MDA")
conn = reader.connect(USER_NAME_DCM, PASSWORD)
conn = reader.get_folder(conn, SEARCH_FOLDER)
uids = reader.get_email_ids(conn)
data = reader.get_data(conn, uids)
pp(data)
reader.close(conn)

#Modelado de software Web adaptable dirigido por modelos
'''
print("-------------------------------------------------------")
print("Modelado de software Web adaptable dirigido por modelos")
conn = reader.connect(USER_NAME_MSWADM, PASSWORD)
conn = reader.get_folder(conn, SEARCH_FOLDER)
uids = reader.get_email_ids(conn)
data = reader.get_data(conn, uids)
print(data)
reader.close(conn)
'''