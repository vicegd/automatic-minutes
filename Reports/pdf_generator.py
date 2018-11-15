from fpdf import FPDF, HTMLMixin
from datetime import datetime
from time import time

class PDF_Generator(FPDF, HTMLMixin):
    title = ""

    def __init__(self, title):
        self.title = title
        super().__init__()

    def header(self):
        self.set_font('Arial', 'B', 12)
        self.set_draw_color(0, 0, 255)
        self.cell(3, 9, self.title, 0, 1, 'L')
        self.set_text_color(0, 0, 0)
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

    def insert_email(self, email, path):
        self.ln()
        self.set_font('Arial', 'B', 14)
        self.set_text_color(100, 100, 255)
        self.cell(0, 5, email['subject'], 0, 1)
        self.ln()
        self.set_font('Times', '', 12)
        self.set_text_color(0, 0, 0)
        self.write_html("<b>Enviado el: </b>")
        self.write(5, datetime.utcfromtimestamp(float(float(email['time_stamp']))/1000).strftime('%Y-%m-%d %H:%M:%S')+ "\n\n")
        self.write_html("<b>Enviado por: </b>")
        self.write(5, email['author'] + "\n\n")
        self.write_html("<b>Recibido por (TO): </b>")
        self.write(5, email['to'] + "\n\n")
        if (email['cc'] != None):
            self.write_html("<b>Recibido por (CC): </b>")
            self.write(5, email['cc'] + "\n\n")
        self.write_html("<b>Resumen del mensaje recibido: </b>")
        self.set_font('Courier', '', 12)
        snippet = email['snippet'].decode("latin-1", 'ignore')
        snippet = snippet.replace("&lt;", "<")
        snippet = snippet.replace("&gt;", ">")
        self.write(5, snippet + "\n\n")
        self.write_html("<b>Contenido completo del mensaje: </b>")
        self.write(5, "\n")
        f = open(path + "/" + email['email_id'] + '.html', 'w+', encoding=email['data_charset'])
        f.write(email['data'])
        f.close()
        self.write_html('La información, en formato HTML, contenida en este correo electrónico, puede verse en el siguiente <a href=emails/' + email['email_id'] + '.html>enlace</a>')
        self.write(5, "\n\n\n")

