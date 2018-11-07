from pprint import pprint
from DBManager.db_manager import DB_Manager
from Reports.pdf_generator import PDF_Generator


db = DB_Manager()
pdf = PDF_Generator()

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

pdf = PDF_Generator()
pdf.set_title('tituloooo')
pdf.set_author('Jules Verne')
pdf.front_page()
pdf.thread_separator("HILO 1")

for email in db.get_data():
    pdf.insert_email(email)

#pdf.print_chapter(1, 'A RUNAWAY REEF', '20k_c1.txt')
#pdf.print_chapter(2, 'THE PROS AND CONS', '20k_c2.txt')
pdf.output('tuto3.pdf', 'F')


#pprint(db.get_one_query_data({'email_id' : 1}))

#for email in db.get_query_data({'email_id' : 1}):
#    pprint(email)

#pdf.close_pdf('report.pdf')