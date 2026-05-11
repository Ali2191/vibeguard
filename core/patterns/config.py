import re

CORS_PATTERNS = [
    r'(?i)allow_origins\s*=\s*\[\s*["\']\*["\']',
    r'(?i)Access-Control-Allow-Origin["\s:]+\*',
    r'(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*["\']\*["\']',
    r'(?i)CORS_ORIGIN_ALLOW_ALL\s*=\s*True',
]

RATE_LIMIT_MISSING = [
    r'(?i)@app\.(post|put|delete)\s*\(["\'][^"\']*login[^"\']*["\']',
    r'(?i)@app\.(post|put|delete)\s*\(["\'][^"\']*register[^"\']*["\']',
    r'(?i)@app\.(post|put|delete)\s*\(["\'][^"\']*signup[^"\']*["\']',
    r'(?i)@router\.(post|put|delete)\s*\(["\'][^"\']*login[^"\']*["\']',
]

FILE_UPLOAD_PATTERNS = [
    r'(?i)file\.save\s*\(',
    r'(?i)uploadedFile\s*\.',
    r'(?i)request\.files',
    r'(?i)multipart/form-data',
    r'(?i)shutil\.copyfileobj',
]

DEBUG_PATTERNS = [
    r'(?i)DEBUG\s*=\s*True',
    r'(?i)app\.run\s*\(.{0,30}debug\s*=\s*True',
    r'(?i)FLASK_DEBUG\s*=\s*1',
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']
    content = parsed_file['content']

    for line_num, line in enumerate(lines, start=1):
        for pattern in CORS_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'config_cors',
                    'severity': 'high',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': 'CORS wildcard origin detected',
                    'description': 'CORS is configured to allow all origins (*) which exposes the API to cross-origin attacks.',
                    'fix': None
                })

        for pattern in RATE_LIMIT_MISSING:
            if re.search(pattern, line):
                has_rate_limit = bool(re.search(r'(?i)(rate.?limit|limiter|throttle|slowapi)', content))
                if not has_rate_limit:
                    findings.append({
                        'pattern_id': 'config_ratelimit',
                        'severity': 'high',
                        'file': file_path,
                        'line': line_num,
                        'snippet': line.strip()[:120],
                        'title': 'Login/register endpoint missing rate limiting',
                        'description': 'Authentication endpoints have no visible rate limiting — vulnerable to brute force attacks.',
                        'fix': None
                    })

        for pattern in FILE_UPLOAD_PATTERNS:
            if re.search(pattern, line):
                has_validation = bool(re.search(r'(?i)(allowed_extensions|mimetype|content.type|magic|filetype)', content))
                if not has_validation:
                    findings.append({
                        'pattern_id': 'config_upload',
                        'severity': 'high',
                        'file': file_path,
                        'line': line_num,
                        'snippet': line.strip()[:120],
                        'title': 'Unvalidated file upload detected',
                        'description': 'File upload handler found with no visible file type or extension validation.',
                        'fix': None
                    })

        for pattern in DEBUG_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'config_debug',
                    'severity': 'medium',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': 'Debug mode enabled in production code',
                    'description': 'Debug mode exposes stack traces and internal information to users.',
                    'fix': None
                })

    return findings
