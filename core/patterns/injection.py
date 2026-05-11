import re

SQL_CONCAT_PATTERNS = [
    r'(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER).{0,60}(\+|%s|\.format\(|f["\'])',
    r'(?i)execute\s*\(\s*["\'].*(SELECT|INSERT|UPDATE|DELETE)',
    r'(?i)cursor\.execute\s*\(\s*f["\']',
    r'(?i)query\s*=\s*["\'].*(SELECT|INSERT).{0,40}["\'\+]',
]

EVAL_PATTERNS = [
    r'\beval\s*\(',
    r'\bexec\s*\(',
    r'__import__\s*\(',
    r'subprocess\.(call|run|Popen)\s*\(.{0,60}(request|input|param|query|body)',
    r'os\.system\s*\(.{0,60}(request|input|param|query|body)',
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern in SQL_CONCAT_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'injection_sql',
                    'severity': 'critical',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': 'Possible SQL injection — string concatenation in query',
                    'description': 'A SQL query appears to be built using string formatting or concatenation with user-controlled data.',
                    'fix': None
                })

        for pattern in EVAL_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'injection_eval',
                    'severity': 'critical',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': 'Dangerous code execution — eval() or exec() detected',
                    'description': 'Use of eval() or exec() with potentially user-controlled input can lead to remote code execution.',
                    'fix': None
                })

    return findings
