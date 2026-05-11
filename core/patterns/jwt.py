import re

JWT_PATTERNS = [
    (r'(?i)algorithm\s*=\s*["\']none["\']', 'JWT algorithm set to none — authentication bypass', 'critical', 'jwt_none_algo'),
    (r'(?i)verify_signature\s*=\s*False', 'JWT signature verification disabled', 'critical', 'jwt_no_verify'),
    (r'(?i)options\s*=\s*\{[^}]*verify_exp\s*:\s*False', 'JWT expiry verification disabled', 'critical', 'jwt_no_exp'),
    (r'(?i)jwt\.decode\s*\([^)]*verify\s*=\s*False', 'JWT decoded without verification', 'critical', 'jwt_decode_no_verify'),
    (r'(?i)SECRET\s*=\s*["\']secret["\']|JWT_SECRET\s*=\s*["\']secret["\']', 'JWT secret is literally the word secret', 'critical', 'jwt_weak_secret'),
    (r'(?i)JWT_SECRET\s*=\s*["\'][a-z]{1,10}["\']', 'JWT secret appears too short or weak', 'high', 'jwt_short_secret'),
    (r'(?i)jwt\.sign\s*\([^)]*expiresIn\s*:\s*["\'](\d{3,}[dmy]|never|0)["\']', 'JWT token never expires or has very long expiry', 'high', 'jwt_no_expiry'),
    (r'(?i)HS256|HS384|HS512', 'HMAC JWT — ensure secret is at least 256 bits', 'medium', 'jwt_hmac_check'),
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern, title, severity, pattern_id in JWT_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': pattern_id,
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': title,
                    'description': 'JWT misconfiguration detected — authentication may be bypassable.',
                    'fix': None
                })

    return findings
