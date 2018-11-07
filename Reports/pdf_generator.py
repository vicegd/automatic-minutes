from fpdf import FPDF
from datetime import datetime

title = '20000 Leagues Under the Seas'

class PDF_Generator(FPDF):
    def header(self):
        # Arial bold 15
        self.set_font('Arial', 'B', 15)
        # Calculate width of title and position
        w = self.get_string_width(title) + 6
        self.set_x((210 - w) / 2)
        # Colors of frame, background and text
        self.set_draw_color(0, 80, 180)
        self.set_fill_color(230, 230, 0)
        self.set_text_color(220, 50, 50)
        # Thickness of frame (1 mm)
        self.set_line_width(1)
        # Title
        self.cell(w, 9, title, 1, 1, 'C', 1)
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



