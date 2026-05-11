import re
import requests

FAKE_PACKAGES = {
    'python': [
        'urllib3-test', 'requests2', 'python-requests', 'django-secure',
        'flask-login2', 'numpy-official', 'pandas-gpt', 'openai-unofficial',
        'pytorch-cuda', 'tensorflow-ai', 'crypto-utils', 'hashlib2',
        'os2', 'sys2', 'json2', 'base64-encoder',
        'socket-client', 'threading2', 'multiprocessing2',
        'gpt4-package', 'chatgpt-helper', 'ai-code-writer',
        'official-requests', 'verified-urllib3', 'trusted-flask',
        'pypi-validator', 'setup-tools2', 'pip-installer',
        'python-ssl', 'https-verifier', 'secure-requests2',
    ],
    'javascript': [
        'lodash2', 'react-dom2', 'axios-official', 'express-router2',
        'webpack-cli2', 'babel-core2', 'jquery-cdn', 'vue-router2',
        'nextjs-official', 'typescript-compiler2', 'npm-validator',
        'node-ssl', 'crypto-js2', 'jsonwebtoken2', 'mongoose2',
        'mongodb-client2', 'redis-client2', 'graphql-tools2',
        'tailwindcss-official', 'bootstrap-cdn2', 'chalk2',
        'eslint-plugin2', 'prettier-formatter2', 'jest-test2',
    ],
}

SUSPICIOUS_NAME_PATTERNS = [
    r'(?i)(unofficial|unverified|untrusted|fake|cloned|mirror)',
    r'(?i)(gpt4?|chatgpt|openai|gemini|claude|copilot|ai[-_])',
    r'(?i)(official|verified|trusted|secure[-_]?)',
    r'(?i)(test|beta|alpha|dev|debug|temp|tmp)[-_]\w+',
    r'(?i)\w+[-_](test|beta|alpha|dev|debug|temp|tmp)',
    r'(?i)(helper|util|utils|toolkit|lib|library)$',
    r'(?i)(requests|urllib|flask|django|react|vue|lodash)[-_]\d+',
    r'(?i)\d+[-_](requests|urllib|flask|django|react|vue|lodash)',
]


def _check_pypi(package: str) -> bool:
    try:
        resp = requests.get(
            f'https://pypi.org/pypi/{package}/json',
            timeout=3,
            headers={'Accept': 'application/json'}
        )
        return resp.status_code == 200
    except Exception:
        return False


def _check_npm(package: str) -> bool:
    try:
        resp = requests.get(
            f'https://registry.npmjs.org/{package}',
            timeout=3,
            headers={'Accept': 'application/json'}
        )
        return resp.status_code == 200
    except Exception:
        return False


PYTHON_STDLIB = {
    'abc', 'argparse', 'array', 'ast', 'asyncio', 'atexit', 'base64', 'bdb',
    'binascii', 'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk',
    'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections', 'colorsys',
    'compileall', 'concurrent', 'configparser', 'contextlib', 'contextvars',
    'copy', 'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes', 'curses', 'dataclasses',
    'datetime', 'dbm', 'decimal', 'difflib', 'dis', 'distutils', 'doctest',
    'email', 'encodings', 'enum', 'errno', 'faulthandler', 'fcntl', 'filecmp',
    'fileinput', 'fnmatch', 'fractions', 'ftplib', 'functools', 'gc', 'getopt',
    'getpass', 'gettext', 'glob', 'graphlib', 'grp', 'gzip', 'hashlib', 'heapq',
    'hmac', 'html', 'http', 'idlelib', 'imaplib', 'imghdr', 'imp', 'importlib',
    'inspect', 'io', 'ipaddress', 'itertools', 'json', 'keyword', 'lib2to3',
    'linecache', 'locale', 'logging', 'lzma', 'mailbox', 'mailcap', 'marshal',
    'math', 'mimetypes', 'mmap', 'modulefinder', 'multiprocessing', 'netrc',
    'nis', 'nntplib', 'numbers', 'operator', 'optparse', 'os', 'ossaudiodev',
    'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil', 'platform',
    'plistlib', 'poplib', 'posix', 'posixpath', 'pprint', 'profile', 'pstats',
    'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri', 'random',
    're', 'readline', 'reprlib', 'resource', 'rlcompleter', 'runpy', 'sched',
    'secrets', 'select', 'selectors', 'shelve', 'shlex', 'shutil', 'signal',
    'site', 'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver', 'spwd',
    'sqlite3', 'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct',
    'subprocess', 'sunau', 'symtable', 'sys', 'sysconfig', 'syslog', 'tabnanny',
    'tarfile', 'telnetlib', 'tempfile', 'termios', 'test', 'textwrap', 'threading',
    'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback',
    'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing', 'unicodedata',
    'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref',
    'webbrowser', 'winreg', 'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc',
    'zipapp', 'zipfile', 'zipimport', 'zlib',
}

NODE_BUILTINS = {
    'assert', 'buffer', 'child_process', 'cluster', 'console', 'constants',
    'crypto', 'dgram', 'dns', 'domain', 'events', 'fs', 'http', 'https',
    'module', 'net', 'os', 'path', 'punycode', 'querystring', 'readline',
    'repl', 'stream', 'string_decoder', 'sys', 'timers', 'tls', 'tty', 'url',
    'util', 'v8', 'vm', 'zlib',
}


def _extract_deps(parsed_file: dict) -> list[tuple[str, str]]:
    deps = []
    content = parsed_file.get('content', '')
    file_path = parsed_file.get('file', '')

    if file_path.endswith('requirements.txt'):
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            pkg = re.split(r'[=<>!~;]', line)[0].strip()
            if pkg and pkg.lower() not in PYTHON_STDLIB:
                deps.append((pkg, 'python'))

    elif file_path.endswith('package.json'):
        for match in re.finditer(r'"([@\w\-/]+)"\s*:\s*"', content):
            pkg = match.group(1)
            if pkg.split('/')[0].replace('@', '') not in NODE_BUILTINS:
                deps.append((pkg, 'javascript'))

    elif file_path.endswith('.py'):
        for match in re.finditer(r'(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)', content):
            pkg = match.group(1)
            if pkg.lower() not in PYTHON_STDLIB:
                deps.append((pkg, 'python'))

    elif file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
        for match in re.finditer(r"(?:import\s+.*?\s+from\s+['\"]|require\s*\(\s*['\"])([@\w\-/]+)", content):
            pkg = match.group(1)
            if pkg.split('/')[0].replace('@', '') not in NODE_BUILTINS:
                deps.append((pkg, 'javascript'))

    return deps


def scan(parsed_file: dict) -> list[dict]:
    findings = []
    file_path = parsed_file.get('file', '')
    deps = _extract_deps(parsed_file)

    for pkg, ecosystem in deps:
        pkg_lower = pkg.lower()

        if pkg_lower in [p.lower() for p in FAKE_PACKAGES.get(ecosystem, [])]:
            findings.append({
                'pattern_id': 'packages_hallucinated',
                'severity': 'high',
                'file': file_path,
                'line': 1,
                'snippet': f'{pkg}',
                'title': f'Known fake/hallucinated package — {pkg}',
                'description': f'This package name matches a known hallucinated or fake package list for {ecosystem}.',
                'fix': None
            })
            continue

        for pattern in SUSPICIOUS_NAME_PATTERNS:
            if re.search(pattern, pkg_lower):
                findings.append({
                    'pattern_id': 'packages_suspicious',
                    'severity': 'medium',
                    'file': file_path,
                    'line': 1,
                    'snippet': f'{pkg}',
                    'title': f'Suspicious package name — {pkg}',
                    'description': f'Package name contains suspicious keywords or naming patterns that may indicate a typosquat or hallucinated dependency.',
                    'fix': None
                })
                break

        if ecosystem == 'python' and not _check_pypi(pkg):
            findings.append({
                'pattern_id': 'packages_hallucinated',
                'severity': 'high',
                'file': file_path,
                'line': 1,
                'snippet': f'{pkg}',
                'title': f'Package not found on PyPI — {pkg}',
                'description': f'This package does not exist on PyPI according to a live registry check. It may be hallucinated by an AI.',
                'fix': None
            })
        elif ecosystem == 'javascript' and not _check_npm(pkg):
            findings.append({
                'pattern_id': 'packages_hallucinated',
                'severity': 'high',
                'file': file_path,
                'line': 1,
                'snippet': f'{pkg}',
                'title': f'Package not found on npm — {pkg}',
                'description': f'This package does not exist on the npm registry according to a live registry check. It may be hallucinated by an AI.',
                'fix': None
            })

    return findings
