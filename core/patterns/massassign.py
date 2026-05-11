import re

MASS_ASSIGN_PATTERNS = [
    (r'(?i)Model\s*\(\s*\*\*request\.(json|data|form|body)\(\)', 'Mass assignment — model created directly from request body', 'critical', 'mass_direct'),
    (r'(?i)\.update\s*\(\s*request\.(json|data|form)\(\)', 'Mass assignment — model updated directly from request body', 'critical', 'mass_update'),
    (r'(?i)for\s+key\s*,\s*value\s+in\s+request\.(json|data|form)', 'Iterating raw request data into model — possible mass assignment', 'high', 'mass_iterate'),
    (r'(?i)Object\.assign\s*\(\s*\w+\s*,\s*req\.body\s*\)', 'Mass assignment via Object.assign with req.body', 'critical', 'mass_js_assign'),
    (r'(?i)\.\s*set\s*\(\s*req\.body\s*\)', 'Mongoose model set from raw req.body', 'critical', 'mass_mongoose'),
    (r'(?i)user\[key\]\s*=\s*value|user\.__dict__\.update', 'Dynamic attribute assignment from user input', 'critical', 'mass_dynamic'),
    (r'(?i)attrs\s*=\s*params\.permit!', 'Rails strong parameters bypassed with permit!', 'critical', 'mass_rails_permit'),
    (r'(?i)role\s*:\s*params\[:role\]|is_admin\s*:\s*params\[:is_admin\]', 'Privilege field taken directly from params', 'critical', 'mass_privilege'),
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern, title, severity, pattern_id in MASS_ASSIGN_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': pattern_id,
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': title,
                    'description': 'Mass assignment vulnerability — attackers can set protected fields like role or is_admin.',
                    'fix': None
                })

    return findings
