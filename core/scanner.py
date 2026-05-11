from core.parser import parse_directory
from core.patterns import secrets, injection, auth, storage, config
from core.patterns import packages, exposure, jwt, crypto, massassign, redos

SCANNERS = [
    secrets, injection, auth, storage, config,
    packages, exposure, jwt, crypto, massassign, redos
]
SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

def deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for f in findings:
        key = (f['file'], f['line'], f['snippet'][:40])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique

def scan_path(path: str) -> dict:
    parsed_files = parse_directory(path)
    all_findings = []

    for parsed_file in parsed_files:
        for scanner in SCANNERS:
            try:
                findings = scanner.scan(parsed_file)
                all_findings.extend(findings)
            except Exception:
                continue

    all_findings = deduplicate(all_findings)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

    summary = {
        'total': len(all_findings),
        'critical': sum(1 for f in all_findings if f['severity'] == 'critical'),
        'high':     sum(1 for f in all_findings if f['severity'] == 'high'),
        'medium':   sum(1 for f in all_findings if f['severity'] == 'medium'),
        'low':      sum(1 for f in all_findings if f['severity'] == 'low'),
    }

    return {
        'path': path,
        'files_scanned': len(parsed_files),
        'summary': summary,
        'findings': all_findings
    }
