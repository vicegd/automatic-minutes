import os
from DBManager.db_manager import DB_Manager
from Reports.pdf_generator import PDF_Generator
from Reader.checker import Checker

#course = "Diseño y Construcción de MDA"
course = "Modelado de Software Web Adaptable Dirigido por Modelos"
year = "2018-2019"

file_path = "Minutes/" + course + "/" + "Report.pdf"
file_path_emails = "Minutes/" + course + "/Emails/"

directory = os.path.dirname(file_path)
try:
    os.stat(directory)
except:
    os.mkdir(directory)

directory_emails = os.path.dirname(file_path_emails)
try:
    os.stat(directory_emails)
except:
    os.mkdir(directory_emails)


db = DB_Manager()
checker = Checker(course, year)
pdf = PDF_Generator(course)

pdf.set_author('Automatic Minutes')
pdf.set_title(course)
pdf.front_page()

emails = checker.get_info()
for email in emails:
    db.insert_data(email)

thread_numbers = db.get_thread_numbers(course, year)

for thread_number in thread_numbers:
    thread = db.get_query_data({'thread_id' : thread_number})
    thread_start = db.get_min_time(thread_number)
    thread_end = db.get_max_time(thread_number)
    thread_title = "Reunión online que comienza en {} y termina en {}".format(thread_start, thread_end)
    pdf.thread_separator(thread_title)

    for email in thread:
        pdf.insert_email(email, directory_emails)

#pdf.thread_separator("Summary")
pdf.output(file_path, 'F')

