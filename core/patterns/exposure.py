import re

EXPOSURE_PATTERNS = [
    # console log leaks
    (r'(?i)console\.(log|warn|error|debug)\s*\(.{0,80}(password|secret|token|key|auth|credential)', 'exposure_console', 'medium', 'Sensitive data logged to console'),
    (r'(?i)print\s*\(.{0,80}(password|secret|token|key|auth|credential)', 'exposure_console', 'medium', 'Sensitive data printed to stdout'),
    # SSL disable
    (r'(?i)verify\s*=\s*False', 'exposure_ssl', 'high', 'SSL certificate verification disabled'),
    (r'(?i)ssl_verify\s*=\s*False', 'exposure_ssl', 'high', 'SSL certificate verification disabled'),
    (r'(?i)CERT_NONE|CERT_OPTIONAL', 'exposure_ssl', 'high', 'Weak SSL certificate mode used'),
    (r'(?i)rejectUnauthorized\s*:\s*false', 'exposure_ssl', 'high', 'SSL certificate verification disabled'),
    # pickle deserialization
    (r'(?i)pickle\.(loads?|dump)', 'exposure_pickle', 'critical', 'Unsafe pickle deserialization detected'),
    (r'(?i)yaml\.load\s*\(', 'exposure_yaml', 'critical', 'Unsafe YAML load without safe loader'),
    (r'(?i)yaml\.unsafe_load', 'exposure_yaml', 'critical', 'Unsafe YAML load detected'),
    # path traversal
    (r'(?i)open\s*\(\s*[^)]*\+\s*(request|input|param|query|body|user)', 'exposure_traversal', 'high', 'Potential path traversal via user input'),
    (r'(?i)send_file\s*\(\s*[^)]*(request|input|param|query|body)', 'exposure_traversal', 'high', 'Potential path traversal via send_file'),
    (r'(?i)\.\./', 'exposure_traversal', 'medium', 'Path traversal pattern detected'),
    (r'(?i)path\.join\s*\(\s*[^)]*(request|input|param|query|body)', 'exposure_traversal', 'high', 'Path traversal via dynamic path construction'),
    # HTTP URLs
    (r'(?i)http://[^\s"\'<>]+', 'exposure_http', 'low', 'HTTP URL detected — consider HTTPS'),
    # stack trace exposure
    (r'(?i)traceback\.print_exc|traceback\.format_exc', 'exposure_stacktrace', 'medium', 'Stack trace may be exposed to users'),
    (r'(?i)app\.use\s*\(\s*errorhandler|errorHandler', 'exposure_stacktrace', 'medium', 'Custom error handler may leak stack traces'),
    # .env in commits
    (r'(?i)\.env["\'\s]', 'exposure_envfile', 'medium', '.env file reference in source code'),
    # inline secrets in URLs
    (r'(?i)(ftp|http|https|mongodb|redis|amqp)://[^:]+:[^@]+@', 'exposure_urlsecret', 'critical', 'Credentials embedded in URL'),
    # hardcoded IPs
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', 'exposure_hardcoded_ip', 'low', 'Hardcoded IP address detected'),
    # sensitive comments
    (r'(?i)#\s*(TODO|FIXME|HACK|BUG|XXX).{0,40}(password|secret|token|key|credential)', 'exposure_comment', 'low', 'Sensitive reference in code comment'),
    (r'(?i)/\*\s*(TODO|FIXME|HACK|BUG|XXX).{0,40}(password|secret|token|key|credential)', 'exposure_comment', 'low', 'Sensitive reference in code comment'),
    # subprocess shell=True
    (r'(?i)subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True', 'exposure_shell', 'critical', 'Subprocess with shell=True allows command injection'),
    # dynamic imports
    (r'(?i)__import__\s*\([^)]*(request|input|param|query|body|user)', 'exposure_dynamic_import', 'critical', 'Dynamic import with user-controlled input'),
    (r'(?i)importlib\.import_module\s*\([^)]*(request|input|param|query|body|user)', 'exposure_dynamic_import', 'critical', 'Dynamic import with user-controlled input'),
    # XML XXE
    (r'(?i)xml\.etree\.ElementTree\.parse|lxml\.etree\.parse', 'exposure_xml', 'high', 'XML parsing without XXE protection'),
    (r'(?i)xml\.dom\.minidom\.parseString', 'exposure_xml', 'high', 'XML parsing without XXE protection'),
    # CSRF missing
    (r'(?i)@app\.(post|put|delete|patch)\s*\([^)]*\)', 'exposure_csrf', 'medium', 'State-changing endpoint may lack CSRF protection'),
    # JWT none algorithm
    (r'(?i)algorithms\s*=\s*\[\s*["\']none["\']\s*\]', 'exposure_jwt_none', 'critical', 'JWT configured to accept "none" algorithm'),
    (r'(?i)verify\s*=\s*False.*jwt|jwt.*verify\s*=\s*False', 'exposure_jwt_none', 'high', 'JWT verification disabled'),
    # temp file issues
    (r'(?i)mktemp\s*\(', 'exposure_tempfile', 'medium', 'Insecure temporary file creation (mktemp)'),
    (r'(?i)tempfile\.mktemp', 'exposure_tempfile', 'medium', 'Insecure temporary file creation'),
    # regex DoS
    (r'(?i)re\.(search|match|findall|compile)\s*\([^)]*\([^)]*\+[^)]*\)', 'exposure_regex_dos', 'medium', 'Nested quantifiers may cause ReDoS'),
    (r'(?i)\(\?\.\*\)\+|\(a\+\)\+|\(\[a-z\]\+\)\+', 'exposure_regex_dos', 'medium', 'Nested quantifier pattern may cause ReDoS'),
    # weak random
    (r'(?i)random\.randint|random\.random\s*\(|random\.choice\s*\(', 'exposure_weak_random', 'medium', 'Weak random generator used for security purpose'),
    (r'(?i)math\.random\s*\(\)', 'exposure_weak_random', 'medium', 'Weak random generator used for security purpose'),
    # verbose error
    (r'(?i)raise\s+\w+Error\s*\(\s*f["\']', 'exposure_verbose_error', 'low', 'Formatted error message may leak internal details'),
    (r'(?i)res\.status\(\d+\)\.send\s*\(\s*(err|error|e)\s*\)', 'exposure_verbose_error', 'medium', 'Raw error object sent to client'),
]


def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file.get('file', '')
    lines = parsed_file.get('lines', [])

    for line_num, line in enumerate(lines, start=1):
        for pattern, pattern_id, severity, title in EXPOSURE_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': pattern_id,
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': title,
                    'description': f'{title} in {file_path}.',
                    'fix': None
                })

    return findings
