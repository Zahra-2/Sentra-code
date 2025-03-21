import csv
from io import StringIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,Image
import json



FILENAME = "vulnerability_report.pdf"


def generate_vulnerability_report(nmap_results, scan_results, dns_results, output_file, device_name,device_type,target,logo_path="logo.png"):

    doc = SimpleDocTemplate(output_file, pagesize=A4, leftMargin=0.75 * inch, rightMargin=0.75 * inch, topMargin=1 * inch, bottomMargin=1 * inch)
    elements = []
    
    # Custom Styles
    title_style = ParagraphStyle('TitleStyle', fontName='Helvetica-Bold', fontSize=22, spaceAfter=20, alignment=1)
    heading_style = ParagraphStyle('HeadingStyle', fontName='Helvetica-Bold', fontSize=18, spaceAfter=14)
    subheading_style = ParagraphStyle('SubheadingStyle', fontName='Helvetica-Bold', fontSize=14, spaceAfter=8)
    body_style = ParagraphStyle('BodyStyle', fontName='Helvetica', fontSize=12, spaceAfter=6)
    # Logo
    if logo_path:
        logo = Image(logo_path, width=4*inch, height=3*inch) 
        elements.append(logo)
        # elements.append(Spacer(1, 2))
    
    # Title
    elements.append(Paragraph("Network Vulnerability Scanner Report", title_style))
    elements.append(Spacer(1, 4))

    elements.append(Paragraph(f"Device Name: {device_name}", heading_style))
    elements.append(Paragraph(f"Device Type: {device_type}", heading_style))
    elements.append(Paragraph(f"URL/IP: {target}", heading_style))
    elements.append(Spacer(1, 2))

    elements.append(Paragraph("Summary", heading_style))
    summary_data = [
        ["Overall Risk Level:", scan_results.get('risk_level', 'Unknown')],
        ["Critical:", scan_results.get('critical', 0)],
        ["High:", scan_results.get('high', 0)],
        ["Medium:", scan_results.get('medium', 0)],
        ["Low:", scan_results.get('low', 0)],
        ["Info:", scan_results.get('info', 0)],
        ["Scan Duration:", scan_results.get('duration', 'Unknown')]
    ]
    
    summary_table = Table(summary_data, colWidths=[200, 200])
    summary_table.setStyle(TableStyle([
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))
    
    #NMAP 
    for finding in nmap_results:
   
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(finding['title'], subheading_style))
        elements.append(Paragraph(f"<b>Risk Description:</b> {finding['risk_description']}", body_style))
        elements.append(Paragraph(f"<b>Recommendation:</b> {finding['recommendation']}", body_style))
        elements.append(Spacer(1, 20))
    # Vulnerabilites

    elements.append(Paragraph("Findings", heading_style))
    for finding in scan_results.get('findings', []):
   
        elements.append(Spacer(1, 10))
        elements.append(Paragraph(finding['title'], subheading_style))
        elements.append(Paragraph(f"<b>Risk Description:</b> {finding['risk_description']}", body_style))
        elements.append(Paragraph(f"<b>Recommendation:</b> {finding['recommendation']}", body_style))
        elements.append(Spacer(1, 20))
        
    # DNS 
    elements.append(Paragraph("DNS Records", heading_style))
    dns_data = [[record_type, ', '.join(records) if isinstance(records, list) else records] for record_type, records in dns_results.items()]
    dns_table = Table(dns_data, colWidths=[200, 250])
    dns_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(dns_table)

    # Page Break
    elements.append(PageBreak())
    
    
    # Create the PDF
    doc.build(elements)
    print(f"Report saved to {output_file}")


def get_wstg_risk_level(wstg_code):
    # Define risk levels based on WSTG category
    risk_mapping = {
        "INPV": "Critical",  # Input Validation
        "ATHN": "Critical",  # Authentication
        "ATHZ": "Critical",  # Authorization
        "SESS": "High",      # Session Management
        "CLNT": "Medium",    # Client-Side Testing
        "SRVV": "High",      # Server-Side Testing
        "CONF": "Medium",    # Configuration & Deployment
        "BUSL": "High",      # Business Logic
        "DVCS": "Medium",    # Version Control
        "INFO": "Low"        # Information Gathering
    }
    
    # Extract the category from the WSTG code
    parts = wstg_code.split("-")
    if len(parts) < 3:
        return "Unknown"  # Invalid WSTG code format
    
    category = parts[1]  # Get the category part
    
    # Return the corresponding risk level
    return risk_mapping.get(category, "Unknown")

# Example usage with scan results
def main(results:dict, device_name, device_type, target):
 

    risk_levels = {
        "critical":0,
        "high":0,
        "medium":0,
        "low":0,
        "info":0
        }
 
    nmap_results = []
 
    # csv_file = StringIO(results["Nmap"])

    # # Read the CSV data
    # csv_reader = csv.DictReader(csv_file, delimiter=';')

    # Convert to a list of dictionaries

    for record in results["Nmap"]:
        findings = {
                    "title": f"Service: {record['name']}\nProtocol: {record['protocol']}\nPort:{record['port']}",
                    'risk_description': "Info",
                    'recommendation': "Update to the latest stable version with security patches available"
                }
        nmap_results.append(findings)
        
    
    with open("reuslts.json","r") as file:
        data = json.load(file)

    vulnerblity_scan_results = []  
    
    if "WebScan" not in results.keys():


        for vulnerblity in data["vulnerabilities"]:
            if data["vulnerabilities"][vulnerblity] == []:
                pass
            else:
                findings = {
                    "title": vulnerblity,
                    'risk_description': get_wstg_risk_level(data["classifications"][vulnerblity]['wstg'][0]),
                    'recommendation':data["classifications"][vulnerblity]["sol"]
                }
                try:
                
                    risk_level = findings["risk_description"].lower()
                    index = risk_levels.get(risk_level)
                    if index != None:
                        risk_levels[risk_level] +=1
                    
                except:
                    print("Not found")
                vulnerblity_scan_results.append(findings)

    scan_results = {
        "risk_level": "Info",
        "critical": risk_levels["critical"],
        "high": risk_levels["high"],
        "medium": risk_levels["medium"],
        "low": risk_levels["low"],
        "info": risk_levels["info"],
        "findings": vulnerblity_scan_results
    }
        # print(sample_scan_results)
    # Sample DNS Records

    
    generate_vulnerability_report(nmap_results, scan_results, results["DNS"], FILENAME,device_name,device_type,target)
    
