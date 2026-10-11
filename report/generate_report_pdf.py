"""
Converts REPORT.md into an academic, beautifully styled HTML document and PDF
calibrated to produce a clean, publication-quality 4-page academic report.
"""

import re
import subprocess
from pathlib import Path

def markdown_to_html(md_text: str) -> str:
    # Normalize line endings
    text = md_text.replace('\r\n', '\n')

    # Code blocks replacement
    code_blocks = []
    def save_code(match):
        idx = len(code_blocks)
        lang = match.group(1) or ''
        code = match.group(2).strip()
        code_escaped = (code.replace('&', '&amp;')
                            .replace('<', '&lt;')
                            .replace('>', '&gt;'))
        code_blocks.append(f'<pre class="code-block {lang}"><code>{code_escaped}</code></pre>')
        return f'@@CODEBLOCK_{idx}@@'

    text = re.sub(r'```(\w+)?\n([\s\S]*?)```', save_code, text)

    # Tables replacement
    tables = []
    def save_table(match):
        idx = len(tables)
        lines = match.group(0).strip().split('\n')
        headers = [c.strip() for c in lines[0].split('|')[1:-1]]
        t_html = '<table class="academic-table">\n<thead><tr>'
        for h in headers:
            t_html += f'<th>{h}</th>'
        t_html += '</tr></thead>\n<tbody>'
        for line in lines[2:]:
            cells = [c.strip() for c in line.split('|')[1:-1]]
            t_html += '<tr>'
            for c in cells:
                t_html += f'<td>{c}</td>'
            t_html += '</tr>'
        t_html += '</tbody></table>'
        tables.append(t_html)
        return f'@@TABLE_{idx}@@'

    text = re.sub(r'(\|[^\n]+\|\n\|[-: |]+\|\n(\|[^\n]+\|\n?)+)', save_table, text)

    # Math display replacement
    math_blocks = []
    def save_math(match):
        idx = len(math_blocks)
        eq = match.group(1).strip()
        math_blocks.append(f'<div class="math-display"><em>{eq}</em></div>')
        return f'@@MATH_{idx}@@'

    text = re.sub(r'\$\$([\s\S]*?)\$\$', save_math, text)

    # Headers
    text = re.sub(r'^# (.+)$', r'<h1>\1</h1>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.+)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
    text = re.sub(r'^### (.+)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)

    # Bold and Italic
    text = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.+?)\*', r'<em>\1</em>', text)

    # Inline code and inline math
    text = re.sub(r'`([^`]+)`', r'<code>\1</code>', text)
    text = re.sub(r'\$([^\$]+)\$', r'<em>\1</em>', text)

    # Horizontal rules
    text = re.sub(r'^---$', r'<hr class="divider">', text, flags=re.MULTILINE)

    # Process paragraphs and lists by splitting on double newlines
    blocks = text.split('\n\n')
    processed_blocks = []

    for block in blocks:
        block_s = block.strip()
        if not block_s:
            continue

        if block_s.startswith('@@CODEBLOCK_') or block_s.startswith('@@TABLE_') or block_s.startswith('@@MATH_'):
            processed_blocks.append(block_s)
        elif block_s.startswith('<h') or block_s.startswith('<hr'):
            processed_blocks.append(block_s)
        elif block_s.startswith('- '):
            # Unordered list
            items = block_s.split('\n')
            list_html = '<ul class="academic-list">'
            for it in items:
                it_s = it.strip()
                if it_s.startswith('- '):
                    list_html += f'<li>{it_s[2:]}</li>'
            list_html += '</ul>'
            processed_blocks.append(list_html)
        elif re.match(r'^\d+\.\s', block_s):
            # Ordered list
            items = block_s.split('\n')
            list_html = '<ol class="academic-list">'
            for it in items:
                it_s = it.strip()
                it_cleaned = re.sub(r'^\d+\.\s*', '', it_s)
                list_html += f'<li>{it_cleaned}</li>'
            list_html += '</ol>'
            processed_blocks.append(list_html)
        else:
            # Standard paragraph (preserve single-line breaks inside if any)
            p_content = block_s.replace('\n', ' ')
            processed_blocks.append(f'<p>{p_content}</p>')

    output_html = '\n'.join(processed_blocks)

    # Restore placeholders
    for idx, cb in enumerate(code_blocks):
        output_html = output_html.replace(f'@@CODEBLOCK_{idx}@@', cb)
    for idx, tb in enumerate(tables):
        output_html = output_html.replace(f'@@TABLE_{idx}@@', tb)
    for idx, mb in enumerate(math_blocks):
        output_html = output_html.replace(f'@@MATH_{idx}@@', mb)

    return output_html

def build_academic_document():
    report_dir = Path(__file__).resolve().parent
    md_file = report_dir / 'REPORT.md'
    out_html = report_dir / 'SecurePass_Academic_Report.html'
    out_pdf = report_dir / 'SecurePass_Academic_Report.pdf'

    if not md_file.exists():
        print(f"Error: {md_file} not found.")
        return

    content_md = md_file.read_text(encoding='utf-8')
    body_html = markdown_to_html(content_md)

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecurePass Academic Report - Hochschule Offenburg</title>
<style>
    @page {{
        size: A4;
        margin: 14mm 15mm 14mm 15mm;
        @bottom-right {{
            content: "Page " counter(page) " of " counter(pages);
            font-size: 8pt;
            color: #666;
        }}
    }}
    body {{
        font-family: 'Times New Roman', Times, serif;
        font-size: 9.8pt;
        line-height: 1.36;
        color: #111;
        background: #fff;
        max-width: 820px;
        margin: 0 auto;
        padding: 10px;
    }}
    h1 {{
        font-family: 'Arial', 'Helvetica', sans-serif;
        font-size: 14.5pt;
        font-weight: bold;
        text-align: center;
        margin-bottom: 6px;
        line-height: 1.22;
        color: #0b2545;
    }}
    .author-meta {{
        text-align: center;
        font-size: 8.5pt;
        color: #444;
        margin-bottom: 12px;
    }}
    h2 {{
        font-family: 'Arial', 'Helvetica', sans-serif;
        font-size: 10.8pt;
        font-weight: bold;
        color: #134074;
        border-bottom: 1px solid #134074;
        padding-bottom: 2px;
        margin-top: 12px;
        margin-bottom: 5px;
        page-break-after: avoid;
    }}
    h3 {{
        font-family: 'Arial', 'Helvetica', sans-serif;
        font-size: 9.6pt;
        font-weight: bold;
        color: #1d2d44;
        margin-top: 8px;
        margin-bottom: 3px;
        page-break-after: avoid;
    }}
    p {{
        margin-bottom: 6px;
        text-align: justify;
    }}
    .academic-list {{
        margin: 4px 0 6px 20px;
        padding: 0;
    }}
    .academic-list li {{
        margin-bottom: 3px;
        text-align: justify;
    }}
    code {{
        font-family: 'Courier New', Courier, monospace;
        font-size: 8.8pt;
        background-color: #f1f3f5;
        padding: 1px 3px;
        border-radius: 2px;
    }}
    pre.code-block {{
        background-color: #f8f9fa;
        border: 1px solid #dcdcdc;
        border-radius: 3px;
        padding: 6px 10px;
        font-family: 'Courier New', Courier, monospace;
        font-size: 8pt;
        line-height: 1.28;
        overflow-x: auto;
        margin: 6px 0 8px 0;
        page-break-inside: avoid;
    }}
    .math-display {{
        text-align: center;
        margin: 5px 0;
        font-style: italic;
        background: #fbfbfb;
        padding: 3px;
        border-radius: 3px;
        font-size: 9.2pt;
    }}
    .divider {{
        border: none;
        border-top: 1px solid #ddd;
        margin: 10px 0;
    }}
    .academic-table {{
        width: 100%;
        border-collapse: collapse;
        font-size: 8pt;
        margin: 6px 0 8px 0;
        page-break-inside: avoid;
    }}
    .academic-table th {{
        background-color: #edf2f7;
        border: 1px solid #cbd5e0;
        padding: 4px 6px;
        font-weight: bold;
        text-align: left;
    }}
    .academic-table td {{
        border: 1px solid #e2e8f0;
        padding: 4px 6px;
    }}
    .academic-table tr:nth-child(even) {{
        background-color: #f7fafc;
    }}
    .print-bar {{
        background: #134074;
        color: white;
        padding: 8px 14px;
        margin-bottom: 14px;
        border-radius: 5px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-family: sans-serif;
        font-size: 9pt;
    }}
    .print-btn {{
        background: #eef2f6;
        color: #134074;
        border: none;
        padding: 5px 12px;
        border-radius: 4px;
        font-weight: bold;
        cursor: pointer;
    }}
    @media print {{
        .print-bar {{
            display: none;
        }}
        body {{
            padding: 0;
            max-width: 100%;
        }}
    }}
</style>
</head>
<body>
<div class="print-bar">
    <span><strong>Hochschule Offenburg Academic Report</strong> - Ready for Moodle Submission</span>
    <button class="print-btn" onclick="window.print()">Print / Save as PDF</button>
</div>
{body_html}
</body>
</html>
"""

    out_html.write_text(document, encoding='utf-8')
    print(f"[SUCCESS] Compiled HTML: {out_html}")

    # Generate PDF via Headless Edge
    edge_path = Path(r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe")
    if edge_path.exists():
        cmd = [
            str(edge_path),
            "--headless=new",
            "--disable-gpu",
            f"--print-to-pdf={out_pdf}",
            f"file:///{out_html.as_posix()}"
        ]
        subprocess.run(cmd, capture_output=True)
        if out_pdf.exists():
            from pypdf import PdfReader
            reader = PdfReader(str(out_pdf))
            print(f"[SUCCESS] Generated PDF: {out_pdf} (Total pages: {len(reader.pages)})")

if __name__ == '__main__':
    build_academic_document()
