import os
import json
import time
from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SYSTEM_PROMPT = """You are a senior security engineer reviewing AI-generated code for vulnerabilities.
You will be given a security finding from a code scanner.
Your job is to return a JSON object with exactly these fields:
{
  "fix": "one concrete sentence telling the developer exactly what to change",
  "example": "a short code snippet (2-5 lines max) showing the fixed version",
  "why": "one sentence explaining why this is dangerous"
}

Rules:
- Be specific and actionable, not generic
- The example must be real code, not pseudocode
- Never say consider or you might want to — be direct
- Return ONLY valid JSON, no markdown, no backticks, no explanation outside JSON
"""

STATIC_FIXES = {
    'secrets_001': {
        'fix': 'Remove the hardcoded secret and load it from an environment variable using os.getenv().',
        'example': 'import os\nAPI_KEY = os.getenv("API_KEY")\n# Store the real value in your .env file',
        'why': 'Hardcoded secrets committed to source code are permanently exposed in git history even after deletion.'
    },
    'secrets_entropy': {
        'fix': 'Move this high-entropy string to an environment variable — it resembles a secret or token.',
        'example': 'import os\nSECRET = os.getenv("MY_SECRET")',
        'why': 'High-entropy strings in source code are a common pattern for accidentally committed credentials.'
    },
    'injection_sql': {
        'fix': 'Use parameterized queries instead of string concatenation to prevent SQL injection.',
        'example': 'cursor.execute(\n  "SELECT * FROM users WHERE username = ?",\n  (username,)\n)',
        'why': 'String-concatenated SQL queries allow attackers to inject arbitrary SQL commands.'
    },
    'injection_eval': {
        'fix': 'Remove eval(), exec(), or os.system() with user input — use a safe alternative like ast.literal_eval() for data parsing.',
        'example': 'import ast\n# Instead of eval(user_input)\nresult = ast.literal_eval(user_input)',
        'why': 'Executing user-controlled input allows attackers to run arbitrary code on your server.'
    },
    'auth_client_side': {
        'fix': 'Move all authentication and role checks to server side — never trust localStorage or sessionStorage for security decisions.',
        'example': '// Server-side check (Node.js example)\napp.get("/admin", verifyJWT, (req, res) => {\n  if (req.user.role !== "admin") return res.status(403).end();\n});',
        'why': 'Client-side values can be freely manipulated by any user via browser DevTools.'
    },
    'auth_plaintext_password': {
        'fix': 'Replace MD5 with bcrypt, argon2, or scrypt for password hashing.',
        'example': 'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n# Verify: bcrypt.checkpw(password.encode(), hashed)',
        'why': 'MD5 is cryptographically broken and can be reversed via rainbow tables in seconds.'
    },
    'storage_001': {
        'fix': 'Move the connection string to an environment variable and ensure the resource is not publicly accessible.',
        'example': 'import os\nDB_URL = os.getenv("DATABASE_URL")\n# Add DATABASE_URL to your .env file',
        'why': 'Exposed connection strings give attackers direct access to your database or storage.'
    },
    'config_cors': {
        'fix': 'Replace the wildcard CORS origin with an explicit allowlist of trusted domains.',
        'example': 'app.use(cors({\n  origin: ["https://yourdomain.com", "https://app.yourdomain.com"]\n}));',
        'why': 'Wildcard CORS allows any website to make authenticated requests to your API on behalf of your users.'
    },
    'config_ratelimit': {
        'fix': 'Add rate limiting to this endpoint using slowapi (Python) or express-rate-limit (Node.js).',
        'example': 'from slowapi import Limiter\nlimiter = Limiter(key_func=get_remote_address)\n@app.post("/login")\n@limiter.limit("5/minute")\nasync def login(request: Request): ...',
        'why': 'Unprotected login endpoints allow unlimited brute-force password attempts.'
    },
    'config_upload': {
        'fix': 'Validate file type using magic bytes (not just extension) and restrict allowed MIME types before saving.',
        'example': 'ALLOWED = {"image/jpeg", "image/png", "application/pdf"}\nif file.content_type not in ALLOWED:\n    raise HTTPException(400, "File type not allowed")',
        'why': 'Unvalidated uploads allow attackers to upload executable files that can be run on your server.'
    },
    'config_debug': {
        'fix': 'Set DEBUG to False in production and load it from an environment variable.',
        'example': 'import os\nDEBUG = os.getenv("DEBUG", "false").lower() == "true"',
        'why': 'Debug mode exposes full stack traces, internal paths, and environment variables to anyone who triggers an error.',
    },
    'packages_hallucinated': {
        'fix': 'Verify the package exists on the official registry (PyPI or npm) and install the correct package name.',
        'example': '# Verify on pypi.org or npmjs.org before installing\npip install requests  # not requests2 or python-requests',
        'why': 'AI tools often hallucinate package names that do not exist, leading to broken builds or typosquat attacks.',
    },
    'packages_suspicious': {
        'fix': 'Audit the package on the official registry, check download counts, and verify the publisher before using it.',
        'example': '# Check package reputation\nnpm audit --audit-level moderate\n# Or use tools like socket.dev',
        'why': 'Suspicious naming patterns (e.g., unofficial, gpt4, trusted) are common indicators of typosquatting or malicious packages.',
    },
    'exposure_console': {
        'fix': 'Remove console.log/print statements that output sensitive data; use structured logging with redaction for production.',
        'example': 'import logging\nlogging.basicConfig(level=logging.INFO)\n# Use logging.info() instead of print()',
        'why': 'Console output can expose sensitive data like API keys, credentials, or personal identifiable information.'
    },
    'exposure_email': {
        'fix': 'Move email addresses to environment variables or a secrets manager — never hardcode real email addresses.',
        'example': 'import os\nEMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")',
        'why': 'Hardcoded email addresses can be used for spamming, phishing, or other malicious activities.'
    }
}