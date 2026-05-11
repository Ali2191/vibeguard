import re
import math
from collections import Counter

SECRET_PATTERNS = [
    ('OpenAI API key',        r'sk-[a-zA-Z0-9]{32,}'),
    ('Anthropic API key',     r'sk-ant-[a-zA-Z0-9\-]{32,}'),
    ('AWS Access Key',        r'AKIA[0-9A-Z]{16}'),
    ('AWS Secret Key',        r'(?i)aws.{0,20}secret.{0,20}["\']([a-zA-Z0-9/+=]{40})["\']'),
    ('Stripe Secret Key',     r'sk_live_[a-zA-Z0-9]{24,}'),
    ('Stripe Test Key',       r'sk_test_[a-zA-Z0-9]{24,}'),
    ('GitHub Token',          r'gh[pousr]_[a-zA-Z0-9]{36,}'),
    ('Google API Key',        r'AIza[0-9A-Za-z\-_]{35}'),
    ('Slack Token',           r'xox[baprs]-[a-zA-Z0-9\-]{10,}'),
    ('Generic Secret',        r'(?i)(secret|password|passwd|pwd|api_key|apikey|token)\s*=\s*["\'][a-zA-Z0-9\-_\.]{8,}["\']'),
    ('Private Key Block',     r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    ('Database URL',          r'(?i)(postgres|mysql|mongodb|redis):\/\/[^\s"\']+:[^\s"\']+@[^\s"\']+'),
]

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def check_high_entropy_strings(line: str, line_num: int, file_path: str) -> list[dict]:
    findings = []
    matches = re.finditer(r'["\']([a-zA-Z0-9+/=\-_]{20,})["\']', line)
    for match in matches:
        candidate = match.group(1)
        entropy = shannon_entropy(candidate)
        if entropy > 4.5:
            findings.append({
                'pattern_id': 'secrets_entropy',
                'severity': 'high',
                'file': file_path,
                'line': line_num,
                'snippet': line.strip()[:120],
                'title': 'High-entropy string — possible secret',
                'description': f'String with entropy {entropy:.2f} detected — may be a hardcoded secret or token.',
                'fix': None
            })
    return findings

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for label, pattern in SECRET_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': 'secrets_001',
                    'severity': 'critical',
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': f'Hardcoded secret detected — {label}',
                    'description': f'A {label} appears to be hardcoded directly in source code.',
                    'fix': None
                })
        findings.extend(check_high_entropy_strings(line, line_num, file_path))

    return findings
