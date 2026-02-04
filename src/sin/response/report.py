from fpdf import FPDF
from datetime import datetime
import os

class SecurityReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'SIN: Network Security Audit', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf_report(devices):
    pdf = SecurityReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Title Info
    pdf.cell(200, 10, txt=f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True, align='C')
    pdf.ln(10)
    
    # Summary
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Total Active Assets: {len(devices)}", ln=True)
    pdf.ln(5)
    
    # Device Table
    pdf.set_font("Arial", size=10)
    for device in devices:
        # Check for vulns
        vuln_count = len(device.get('vulnerabilities', []))
        status_color = "SAFE" if vuln_count == 0 else "CRITICAL"
        
        pdf.set_font("Arial", 'B', 11)
        pdf.cell(0, 8, f"Device: {device.get('ip_address')} ({status_color})", ln=True)
        
        pdf.set_font("Arial", size=10)
        pdf.cell(0, 5, f" - Hostname: {device.get('hostname')}", ln=True)
        pdf.cell(0, 5, f" - OS: {device.get('os_family')}", ln=True)
        pdf.cell(0, 5, f" - Open Ports: {device.get('open_ports')}", ln=True)
        
        if vuln_count > 0:
            pdf.set_text_color(255, 0, 0)
            pdf.cell(0, 5, f" - Vulnerabilities: {vuln_count} Detected!", ln=True)
            pdf.set_text_color(0, 0, 0)
            
        pdf.ln(5)
        
    # Save
    report_path = "data/latest_report.pdf"
    os.makedirs("data", exist_ok=True)
    pdf.output(report_path)
    return report_path
