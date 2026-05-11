import re

REDOS_PATTERNS = [
    (r'(\([^)]*\+[^)]*\))\+', 'Nested quantifiers in regex — possible ReDoS vulnerability', 'high', 'redos_nested'),
    (r'\(\.\*\)\+|\(\.\+\)\*|\(\.\*\)\*', 'Catastrophic backtracking pattern detected in regex', 'critical', 'redos_catastrophic'),
    (r'(?i)re\.(match|search|findall)\s*\([^,]{40,}', 'Complex regex applied to user input — verify for ReDoS', 'medium', 'redos_complex'),
    (r'(?i)new\s+RegExp\s*\(\s*(req\.|request\.|params\.|query\.)', 'Regex constructed from user input — ReDoS risk', 'critical', 'redos_user_input'),
    (r'(?i)re\.compile\s*\(\s*(request|req|user_input|params)', 'Regex compiled from user-controlled data', 'critical', 'redos_compile_user'),
]

UNSAFE_REGEX_PATTERNS = [
    r'\(\w+\+\)\+',
    r'\(\w+\*\)\+',
    r'\(\w+\|\w+\)\+\w+',
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern, title, severity, pattern_id in REDOS_PATTERNS:
            try:
                if re.search(pattern, line):
                    findings.append({
                        'pattern_id': pattern_id,
                        'severity': severity,
                        'file': file_path,
                        'line': line_num,
                        'snippet': line.strip()[:120],
                        'title': title,
                        'description': 'Regular expression may be vulnerable to ReDoS — crafted input can cause exponential backtracking.',
                        'fix': None
                    })
            except re.error:
                continue

        for unsafe in UNSAFE_REGEX_PATTERNS:
            try:
                if re.search(unsafe, line):
                    findings.append({
                        'pattern_id': 'redos_pattern',
                        'severity': 'high',
                        'file': file_path,
                        'line': line_num,
                        'snippet': line.strip()[:120],
                        'title': 'Potentially catastrophic regex pattern',
                        'description': 'This regex contains nested quantifiers that can cause exponential backtracking.',
                        'fix': None
                    })
            except re.error:
                continue

    return findings
