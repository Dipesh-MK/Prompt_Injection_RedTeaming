import os
from fpdf import FPDF, XPos, YPos

class DocPDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 16)
        self.set_text_color(230, 57, 70)
        self.cell(0, 10, 'RedTeamForge: Architectural Deep Dive & Documentation', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f'Page {self.page_no()}', new_x=XPos.RIGHT, new_y=YPos.TOP, align='C')

def generate_documentation_pdf(md_path, pdf_path):
    pdf = DocPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    with open(md_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    for line in lines:
        line = line.strip('\n')
        
        # Heading 1
        if line.startswith('# '):
            pdf.ln(5)
            pdf.set_font('Helvetica', 'B', 14)
            pdf.set_text_color(13, 17, 23)
            # Remove md
            text = line[2:].replace('**', '')
            text = text.encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(0, 8, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
            pdf.ln(2)
        
        # Heading 2 / 3
        elif line.startswith('## ') or line.startswith('### '):
            pdf.ln(3)
            pdf.set_font('Helvetica', 'B', 12)
            pdf.set_text_color(37, 99, 235) # Blue theme for subheaders
            text = line.lstrip('#').strip().replace('**', '')
            text = text.encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(0, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
            pdf.ln(1)
            
        elif line == '---':
            pdf.set_draw_color(200, 200, 200)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(3)
            
        else:
            if not line.strip():
                pdf.ln(2)
                continue
                
            pdf.set_font('Helvetica', '', 10)
            pdf.set_text_color(40, 40, 40)
            text = line.replace('**', '').replace('__', '').replace('`', '')
            # Clean up the text to avoid FPDF width crash
            text = " ".join(text.split())
            text = text.encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
    pdf.output(pdf_path)
    print(f"Success! Generated {pdf_path}")

if __name__ == '__main__':
    generate_documentation_pdf('RedTeamForge_Documentation.md', 'RedTeamForge_Documentation.pdf')
