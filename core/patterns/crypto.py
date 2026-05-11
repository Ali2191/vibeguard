import re

CRYPTO_PATTERNS = [
    (r'(?i)random\.random\(\)|random\.randint\(|random\.choice\(', 'Insecure random — use secrets module for security', 'high', 'crypto_weak_random'),
    (r'(?i)Math\.random\(\)', 'Math.random() is not cryptographically secure', 'high', 'crypto_math_random'),
    (r'(?i)hashlib\.md5\s*\(|hashlib\.sha1\s*\(', 'Weak hash algorithm — MD5/SHA1 are broken', 'high', 'crypto_weak_hash'),
    (r'(?i)DES\s*\(|3DES\s*\(|RC4\s*\(|Blowfish\s*\(', 'Deprecated encryption algorithm detected', 'critical', 'crypto_weak_cipher'),
    (r'(?i)AES\s*\.\s*new\s*\([^)]*MODE_ECB', 'AES ECB mode is insecure — use GCM or CBC', 'critical', 'crypto_aes_ecb'),
    (r'(?i)key\s*=\s*b["\'][0]{8,}["\']|key\s*=\s*b["\']\\x00', 'Null or zero encryption key detected', 'critical', 'crypto_null_key'),
    (r'(?i)iv\s*=\s*b["\'][0]{8,}["\']|nonce\s*=\s*b["\'][0]{8,}["\']', 'Static/zero IV or nonce — breaks encryption security', 'critical', 'crypto_static_iv'),
    (r'(?i)padding\s*=\s*["\']PKCS1v15["\']|PKCS1_v1_5', 'PKCS1v15 padding is vulnerable to Bleichenbacher attack', 'high', 'crypto_weak_padding'),
    (r'(?i)token_hex\s*\(\s*[1-7]\s*\)|token_bytes\s*\(\s*[1-7]\s*\)', 'Cryptographic token too short — use at least 16 bytes', 'high', 'crypto_short_token'),
]

def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file['file']
    lines = parsed_file['lines']

    for line_num, line in enumerate(lines, start=1):
        for pattern, title, severity, pattern_id in CRYPTO_PATTERNS:
            if re.search(pattern, line):
                findings.append({
                    'pattern_id': pattern_id,
                    'severity': severity,
                    'file': file_path,
                    'line': line_num,
                    'snippet': line.strip()[:120],
                    'title': title,
                    'description': 'Cryptographic weakness detected — data may not be securely protected.',
                    'fix': None
                })

    return findings
