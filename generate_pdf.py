#!/usr/bin/env python3
"""
WeasyPrint PDF Generator
Called by PHP: python3 generate_pdf.py <input_html_file> <output_pdf_file> [base_url]
Uses HTML(string=...) with FontConfiguration - same approach that works.
"""
import sys
import os
from weasyprint import HTML
from weasyprint.text.fonts import FontConfiguration

def generate_pdf(input_html_path, output_pdf_path, base_url=None):
    # Read HTML content from file as string
    with open(input_html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()
    
    # Setup font configuration for Google Fonts download
    font_config = FontConfiguration()
    
    # Determine base_url: use provided arg, or derive from input file directory
    if not base_url:
        base_url = 'file://' + os.path.dirname(os.path.abspath(input_html_path)) + '/'
    
    # Convert HTML string to PDF (using string= with base_url for relative asset resolution)
    HTML(string=html_content, base_url=base_url).write_pdf(
        output_pdf_path,
        font_config=font_config
    )
    print("OK")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 generate_pdf.py <input.html> <output.pdf> [base_url]", file=sys.stderr)
        sys.exit(1)
    
    try:
        base_url = sys.argv[3] if len(sys.argv) >= 4 else None
        generate_pdf(sys.argv[1], sys.argv[2], base_url)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
