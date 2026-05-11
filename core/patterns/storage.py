import re

STORAGE_PATTERNS = [
    (r'(?i)s3\.amazonaws\.com/[a-z0-9\-]+', 'Public S3 bucket reference', 'high'),
    (r'(?i)storage\.googleapis\.com/[a-z0-9\-]+', 'Public GCS bucket reference', 'high'),
    (r'(?i)\.blob\.core\.windows\.net/', 'Public Azure Blob reference', 'high'),
    (r'(?i)(ACL|acl)\s*=\s*["\']public-read["\']', 'S3 bucket set to public-read', 'critical'),
    (r'(?i)BlockPublicAcls\s*=\s*False', 'S3 public access not blocked', 'critical'),
    (r'(?i)(mongo|postgresql|mysql|redis|amqp)://[^\s"\'<>]+', 'Exposed connection string', 'critical'),
    (r'(?i)SQLALCHEMY_DATABASE_URL\s*=\s*["\'][^"\']+["\']', 'Hardcoded database URL', 'high'),
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern, title, severity in STORAGE_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'storage_001',
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': title,
                    'description': 'A storage resource or database connection appears to be publicly exposed or hardcoded.',
                    'fix': None
                })

    return findings
