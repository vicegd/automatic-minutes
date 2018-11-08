from fpdf import FPDF
from datetime import datetime
from time import time

class PDF_Generator(FPDF):
    title = ""

    def __init__(self, title):
        self.title = title
        super().__init__()

    def header(self):
        self.set_font('Arial', 'B', 12)
        self.set_draw_color(0, 0, 255)
        self.cell(3, 9, self.title, 0, 1, 'L')
        self.line(10, 18, 200, 18)
        # Line break
        self.ln(10)

    def footer(self):
        # Position at 1.5 cm from bottom
        self.set_y(-15)
        # Arial italic 8
        self.set_font('Arial', 'I', 8)
        # Text color in gray
        self.set_text_color(128)
        # Page number
        self.cell(0, 10, 'Page ' + str(self.page_no()), 0, 0, 'C')

    def front_page(self):
        self.add_page()
        self.image('Reports/Resources/logo_uniovi.png', 70, 120, 70)
        self.set_font('Arial', 'B', 20)
        self.ln(30)
        w = self.get_string_width(self.title) + 6
        self.set_x((210 - w) / 2)
        self.cell(w, 9, self.title, 0, 1, 'C')
        self.ln(6)
        self.set_font('Arial', 'B', 16)
        s = "Actas autogeneradas"
        w = self.get_string_width(s) + 6
        self.set_x((210 - w) / 2)
        self.cell(w, 9, s, 0, 1, 'C')
        self.ln(170)
        self.cell(140)
        self.set_font('Arial', 'B', 12)
        self.cell(10, 10, 'Fecha de generación: ' + datetime.fromtimestamp(time()).strftime('%Y-%m-%d %H:%M'), 0, 1, 'C')

    def thread_separator(self, thread):
        self.add_page()
        self.set_font('Arial', '', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, '%s' % (thread), 0, 1, 'L', 1)
        self.ln(4)

    def insert_email(self, email):
        self.ln()
        self.set_font('Arial', 'B', 14)
        self.cell(0, 5, email['subject'], 0, 1)
        self.ln()
        self.set_font('Times', '', 12)
        self.cell(0, 5, "Enviado el: " + datetime.utcfromtimestamp(float(email['time_stamp'])).strftime('%Y-%m-%d %H:%M:%S'), 0, 1)
        self.insert_author("Enviado por:", email['author'], email['author_email'])
        i = 0
        recipents = "Recibido por: "
        for cc_email in email['cc_emails']:
            if (email['cc'][i] != ""):
                recipents += email['cc'][i] + " (" + cc_email + "); "
            else:
                recipents += "(" + cc_email + "); "
            i += 1
        self.cell(0, 5, recipents, 0, 1)
        self.cell(0, 5, "Contenido:", 0, 1)
        self.ln()
        self.set_font('Courier', '', 12)
        self.cell(0, 5, email['data'], 1, 1)
        self.ln()


    def insert_author(self, text, name, address):
        self.multi_cell(0, 5, text + " " + name + " (" + address + ")", 0, 1)

# email2 = {
#     'email_id' : 2,
#     'thread_id' : 1,
#     'subject' : 'Example of subject2',
#     'data' : 'Data2',
#     'time_stamp' : 1541579100,
#     'author' : 'Vicente García2',
#     'author_email' : 'garciavicente@uniovi.es',
#     'cc' : ['Edward Rolando2', 'Cristian González2'],
#     'cc_emails' : ['rolandoedward@uniovi.es', 'gonzalezcristian@uniovi.es'],
#     'year' : '2018-2019',
#     'course' : 'Diseño y Construcción de MDA'
# }



