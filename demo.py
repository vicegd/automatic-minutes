from pprint import pprint
from DBManager.db_manager import DB_Manager
from Reports.pdf_generator import PDF_Generator

course = "Diseño y Construcción de MDA"
year = "2018-2019"

db = DB_Manager()
pdf = PDF_Generator(course)
pdf.set_author('Automatic Minutes')
pdf.set_title(course)
pdf.front_page()

email = {
    'email_id' : 1,
    'thread_id' : 1,
    'subject' : 'Example of subject',
    'data' : 'Data',
    'time_stamp' : 1541579988,
    'author' : 'Vicente García',
    'author_email' : 'garciavicente@uniovi.es',
    'cc' : ['Edward Rolando', 'Cristian González'],
    'cc_emails' : ['rolandoedward@uniovi.es', 'gonzalezcristian@uniovi.es'],
    'year' : '2018-2019',
    'course' : 'Diseño y Construcción de MDA'
}
#db.insert_data(email)
email2 = {
    'email_id' : 2,
    'thread_id' : 1,
    'subject' : 'Example of subject2',
    'data' : 'Data2',
    'time_stamp' : 1541579100,
    'author' : 'Vicente García2',
    'author_email' : 'garciavicente@uniovi.es',
    'cc' : ['Edward Rolando2', 'Cristian González2'],
    'cc_emails' : ['rolandoedward@uniovi.es', 'gonzalezcristian@uniovi.es'],
    'year' : '2018-2019',
    'course' : 'Diseño y Construcción de MDA'
}

#db.insert_data(email2)

#for email in db.get_data():
#    pdf.insert_email(email)

#for email in db.get_one_query_data({''}):
#    print(email)

thread_numbers = db.get_thread_numbers(course, year)

for thread_number in thread_numbers:
    thread = db.get_query_data({'thread_id' : thread_number})
    thread_start = db.get_min_time(thread_number)
    thread_end = db.get_max_time(thread_number)
    thread_title = "Reunión online que comienza en {} y termina en {}".format(thread_start, thread_end)
    pdf.thread_separator(thread_title)

    for email in thread:
        pdf.insert_email(email)

#pdf.thread_separator("Summary")
pdf.output('report.pdf', 'F')


#pprint(db.get_one_query_data({'email_id' : 1}))

#for email in db.get_query_data({'email_id' : 1}):
#    pprint(email)

#pdf.close_pdf('report.pdf')