#!/usr/bin/env python3
"""
WeasyPrint PDF Generator
Called by PHP: python3 generate_pdf.py <input_html_file> <output_pdf_file>
Uses HTML(string=...) with FontConfiguration - same approach that works.
"""
import sys
from weasyprint import HTML
from weasyprint.text.fonts import FontConfiguration

def generate_pdf(input_html_path, output_pdf_path):
    # Read HTML content from file as string
    with open(input_html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Setup font configuration for Google Fonts download
    font_config = FontConfiguration()
    
    # Convert HTML string to PDF (using string= NOT filename=)
    HTML(string=html_content).write_pdf(
        output_pdf_path,
        font_config=font_config
    )
    print("OK")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 generate_pdf.py <input.html> <output.pdf>", file=sys.stderr)
        sys.exit(1)
    
    try:
        generate_pdf(sys.argv[1], sys.argv[2])
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
