import re

CLIENT_AUTH_PATTERNS = [
    r'(?i)(isAdmin|isAuthenticated|role\s*===?\s*["\']admin["\']|user\.role).{0,30}(localStorage|sessionStorage|cookie)',
    r'(?i)localStorage\.getItem\s*\(.{0,30}(token|auth|role|admin|user)',
    r'(?i)if\s*\(.{0,30}(isAdmin|isLoggedIn|authenticated).{0,30}\)\s*\{',
    r'(?i)jwt\.decode\s*\(.{0,60}(verify\s*:\s*false|algorithms\s*=\s*\[\s*["\']none)',
    r'(?i)verify\s*=\s*False',
    r'(?i)SECRET_KEY\s*=\s*["\']["\']',
    r'(?i)SECRET_KEY\s*=\s*["\']changeme',
    r'(?i)SECRET_KEY\s*=\s*["\']default',
    r'(?i)SECRET_KEY\s*=\s*["\']secret',
]

MISSING_AUTH_PATTERNS = [
    r'(?i)@app\.(get|post|put|delete|patch)\s*\(["\'][^"\']+["\'][^\)]*\)',
]

PASSWORD_PATTERNS = [
    r'(?i)password\s*==\s*["\']',
    r'(?i)if\s+password\s*==',
    r'(?i)md5\s*\(.{0,30}password',
    r'(?i)hashlib\.md5\s*\(',
    r'(?i)password\s*=\s*["\'][a-zA-Z0-9]{4,}["\']',
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern in CLIENT_AUTH_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'auth_client_side',
                    'severity': 'critical',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': 'Client-side authentication logic detected',
                    'description': 'Authentication or role checks appear to rely on client-side storage which can be tampered with.',
                    'fix': None
                })

        for pattern in PASSWORD_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'auth_plaintext_password',
                    'severity': 'critical',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': 'Plain-text password comparison or weak hashing',
                    'description': 'Passwords are being compared in plain text or hashed with a weak algorithm like MD5.',
                    'fix': None
                })

    return findings
