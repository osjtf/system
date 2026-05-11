#!/usr/bin/env python3
"""
WeasyPrint PDF Generator
Called by PHP: python3 generate_pdf.py <input_html_file> <output_pdf_file>

Font strategy:
- The HTML already contains @font-face rules with direct gstatic.com URLs.
- WeasyPrint fetches these URLs directly (no JS needed, unlike Google Fonts CSS API).
- Fonts are cached locally in /tmp/weasyprint_fonts/ for subsequent calls.
"""
import sys
import os
import re
import urllib.request

from weasyprint import HTML
from weasyprint.text.fonts import FontConfiguration

FONT_CACHE_DIR = '/tmp/weasyprint_fonts'

# Map of font URL patterns to local cache filenames
FONT_URLS = {
    # Noto Sans Arabic v33 - arabic subset
    'NotoSansArabic.woff2': 'https://fonts.gstatic.com/s/notosansarabic/v33/nwpCtLGrOAZMl5nJ_wfgRg3DrWFZWsnVBJ_sS6tlqHHFlj4wv4r4xA.woff2',
    # Inter Regular
    'Inter-Regular.woff2': 'https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuLyfAZ9hiJ-Ek-_EeA.woff2',
    # Inter Bold
    'Inter-Bold.woff2': 'https://fonts.gstatic.com/s/inter/v13/UcCO3FwrK3iLTeHuS_fvQtMwCp50KnMw2boKoduKmMEVuDyfAZ9hiJ-Ek-_EeA.woff2',
}


def cache_fonts():
    """Download and cache fonts locally. Returns dict of {url: local_path}."""
    os.makedirs(FONT_CACHE_DIR, exist_ok=True)
    url_to_local = {}
    for filename, url in FONT_URLS.items():
        local_path = os.path.join(FONT_CACHE_DIR, filename)
        if not os.path.exists(local_path) or os.path.getsize(local_path) == 0:
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    data = resp.read()
                with open(local_path, 'wb') as f:
                    f.write(data)
            except Exception as e:
                print(f"Warning: Could not cache font {filename}: {e}", file=sys.stderr)
                local_path = None
        if local_path and os.path.exists(local_path):
            url_to_local[url] = 'file://' + local_path
    return url_to_local


def rewrite_font_urls(html_content, url_to_local):
    """Replace remote font URLs in @font-face with local file:// paths."""
    for remote_url, local_url in url_to_local.items():
        html_content = html_content.replace(remote_url, local_url)
    # Also rewrite any Google Fonts CSS API links to nothing (they can't be used by WeasyPrint)
    import re
    html_content = re.sub(
        r'<link[^>]+fonts\.googleapis\.com[^>]*>',
        '',
        html_content,
        flags=re.IGNORECASE
    )
    return html_content


def generate_pdf(input_html_path, output_pdf_path):
    with open(input_html_path, 'r', encoding='utf-8') as f:
        html_content = f.read()

    font_config = FontConfiguration()

    # Try to use locally cached fonts for faster, more reliable rendering
    try:
        url_to_local = cache_fonts()
        if url_to_local:
            html_content = rewrite_font_urls(html_content, url_to_local)
    except Exception as e:
        print(f"Warning: Font caching failed, using remote URLs: {e}", file=sys.stderr)

    HTML(string=html_content).write_pdf(
        output_pdf_path,
        font_config=font_config,
        presentational_hints=True,
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
