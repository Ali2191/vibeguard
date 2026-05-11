import os
import uuid
import shutil
import tempfile
import zipfile
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(title="VibeGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store — works for serverless cold starts
report_store: dict[str, str] = {}

LANDING_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VibeGuard — Security Scanner for AI-Generated Code</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0f0f0f; --bg2: #161616; --bg3: #1e1e1e;
    --border: #2a2a2a; --text: #e8e8e8; --muted: #888;
    --red: #ff4444; --yellow: #ffaa00; --green: #44cc88;
    --blue: #4488ff; --radius: 10px;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --mono: 'SF Mono', 'Fira Code', monospace;
  }
  body { background: var(--bg); color: var(--text); font-family: var(--font); min-height: 100vh; }
  header { padding: 24px 40px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
  .logo { font-size: 20px; font-weight: 700; }
  .logo span { color: var(--red); }
  .tagline-header { font-size: 12px; color: var(--muted); }
  .hero { text-align: center; padding: 80px 20px 60px; }
  .hero h1 { font-size: 48px; font-weight: 800; letter-spacing: -1px; line-height: 1.1; margin-bottom: 16px; }
  .hero h1 em { color: var(--red); font-style: normal; }
  .hero p { font-size: 18px; color: var(--muted); max-width: 520px; margin: 0 auto 40px; line-height: 1.6; }
  .upload-card { background: var(--bg2); border: 1px solid var(--border); border-radius: 16px; max-width: 560px; margin: 0 auto; padding: 36px; }
  .upload-card h2 { font-size: 16px; font-weight: 600; margin-bottom: 24px; }
  .drop-zone { border: 2px dashed var(--border); border-radius: var(--radius); padding: 40px 20px; text-align: center; cursor: pointer; transition: all 0.2s; margin-bottom: 20px; }
  .drop-zone:hover, .drop-zone.dragover { border-color: var(--red); background: #1a0a0a; }
  .drop-zone .icon { font-size: 32px; margin-bottom: 8px; }
  .drop-zone p { color: var(--muted); font-size: 13px; }
  .drop-zone strong { color: var(--text); }
  #file-input { display: none; }
  .file-name { font-size: 12px; color: var(--green); margin-top: 8px; font-family: var(--mono); }
  .options { display: flex; gap: 12px; margin-bottom: 20px; }
  .option { flex: 1; background: var(--bg3); border: 1px solid var(--border); border-radius: var(--radius); padding: 12px; cursor: pointer; transition: all 0.15s; }
  .option input { margin-right: 8px; accent-color: var(--red); }
  .option label { font-size: 13px; cursor: pointer; }
  .option small { display: block; color: var(--muted); font-size: 11px; margin-top: 2px; margin-left: 20px; }
  .scan-btn { width: 100%; background: var(--red); color: white; border: none; border-radius: var(--radius); padding: 14px; font-size: 15px; font-weight: 600; cursor: pointer; font-family: var(--font); transition: all 0.15s; }
  .scan-btn:hover { background: #cc3333; }
  .scan-btn:disabled { background: #333; color: var(--muted); cursor: not-allowed; }
  .progress-area { display: none; text-align: center; padding: 20px 0; }
  .spinner { width: 32px; height: 32px; border: 3px solid var(--border); border-top-color: var(--red); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 0 auto 12px; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .progress-text { color: var(--muted); font-size: 13px; }
  .features { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; max-width: 860px; margin: 60px auto; padding: 0 20px; }
  .feature { background: var(--bg2); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; }
  .feature .feat-icon { font-size: 24px; margin-bottom: 10px; }
  .feature h3 { font-size: 14px; font-weight: 600; margin-bottom: 6px; }
  .feature p { font-size: 12px; color: var(--muted); line-height: 1.6; }
  .checks { max-width: 560px; margin: 0 auto 60px; padding: 0 20px; }
  .checks h3 { font-size: 13px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 16px; text-align: center; }
  .check-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
  .check-item { background: var(--bg2); border: 1px solid var(--border); border-radius: 6px; padding: 8px 12px; font-size: 12px; display: flex; align-items: center; gap: 8px; }
  .check-item::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--red); flex-shrink: 0; }
  footer { border-top: 1px solid var(--border); padding: 24px 40px; text-align: center; color: var(--muted); font-size: 12px; }
  @media (max-width: 600px) {
    .hero h1 { font-size: 32px; }
    .features { grid-template-columns: 1fr; }
    .check-grid { grid-template-columns: 1fr; }
    header { padding: 16px 20px; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">Vibe<span>Guard</span></div>
  <div class="tagline-header">AI-generated code security scanner</div>
</header>

<div class="hero">
  <h1>Your AI wrote the code.<br><em>We check if it's safe.</em></h1>
  <p>VibeGuard scans vibe-coded repos for the most common security vulnerabilities AI tools introduce without telling you.</p>

  <div class="upload-card">
    <h2>Scan your project</h2>
    <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
      <div class="icon">&#128194;</div>
      <p><strong>Upload a ZIP file</strong> of your project</p>
      <p>or click to browse</p>
      <div class="file-name" id="file-name"></div>
    </div>
    <input type="file" id="file-input" accept=".zip">

    <div class="options">
      <div class="option">
        <input type="radio" name="mode" id="mode-fast" value="fast" checked>
        <label for="mode-fast">Fast scan</label>
        <small>Pattern matching only, instant results</small>
      </div>
      <div class="option">
        <input type="radio" name="mode" id="mode-ai" value="ai">
        <label for="mode-ai">AI fixes</label>
        <small>Adds Gemini fix suggestions</small>
      </div>
    </div>

    <button class="scan-btn" id="scan-btn" onclick="startScan()" disabled>
      Select a file to scan
    </button>

    <div class="progress-area" id="progress-area">
      <div class="spinner"></div>
      <div class="progress-text" id="progress-text">Uploading and scanning...</div>
    </div>
  </div>
</div>

<div class="features">
  <div class="feature">
    <div class="feat-icon">&#128273;</div>
    <h3>Secret detection</h3>
    <p>Finds hardcoded API keys, tokens, and passwords using regex + entropy scoring across 10 provider formats.</p>
  </div>
  <div class="feature">
    <div class="feat-icon">&#128137;</div>
    <h3>Injection vulnerabilities</h3>
    <p>Catches SQL injection, eval() abuse, pickle deserialization, and path traversal attacks.</p>
  </div>
  <div class="feature">
    <div class="feat-icon">&#128737;</div>
    <h3>Auth & config issues</h3>
    <p>Detects client-side auth, missing rate limiting, wildcard CORS, SSL disabled, and debug mode.</p>
  </div>
</div>

<div class="checks">
  <h3>22+ checks run on every scan</h3>
  <div class="check-grid">
    <div class="check-item">Hardcoded API keys</div>
    <div class="check-item">Client-side auth</div>
    <div class="check-item">SQL injection</div>
    <div class="check-item">eval() with user input</div>
    <div class="check-item">Exposed DB connections</div>
    <div class="check-item">Plain-text passwords</div>
    <div class="check-item">Wildcard CORS</div>
    <div class="check-item">Missing rate limits</div>
    <div class="check-item">Public S3 buckets</div>
    <div class="check-item">Unvalidated uploads</div>
    <div class="check-item">Debug mode in prod</div>
    <div class="check-item">High-entropy strings</div>
    <div class="check-item">Hallucinated packages</div>
    <div class="check-item">Sensitive data in logs</div>
    <div class="check-item">SSL verification off</div>
    <div class="check-item">Unsafe deserialization</div>
    <div class="check-item">Path traversal</div>
    <div class="check-item">Non-HTTPS URLs</div>
    <div class="check-item">Stack trace exposure</div>
    <div class="check-item">Unsafe YAML load</div>
  </div>
</div>

<footer>
  VibeGuard &mdash; built for the vibe-coding era &nbsp;&middot;&nbsp;  <a href="https://github.com/Ali2191/vibeguard" style="color:#888;">GitHub</a>
</footer>

<script>
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const scanBtn = document.getElementById('scan-btn');
const fileName = document.getElementById('file-name');
let selectedFile = null;

fileInput.addEventListener('change', e => {
  selectedFile = e.target.files[0];
  if (selectedFile) {
    fileName.textContent = selectedFile.name;
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan ' + selectedFile.name;
  }
});

dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files[0];
  if (file && file.name.endsWith('.zip')) {
    selectedFile = file;
    fileName.textContent = file.name;
    scanBtn.disabled = false;
    scanBtn.textContent = 'Scan ' + file.name;
  }
});

async function startScan() {
  if (!selectedFile) return;
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const formData = new FormData();
  formData.append('file', selectedFile);
  formData.append('use_ai', mode === 'ai' ? 'true' : 'false');

  scanBtn.style.display = 'none';
  document.getElementById('progress-area').style.display = 'block';

  const messages = [
    'Uploading your project...',
    'Parsing files...',
    'Running 22+ security checks...',
    mode === 'ai' ? 'Generating AI fix suggestions...' : 'Generating report...',
  ];
  let mi = 0;
  const ticker = setInterval(() => {
    if (mi < messages.length - 1) mi++;
    document.getElementById('progress-text').textContent = messages[mi];
  }, 2000);

  try {
    const res = await fetch('/scan', { method: 'POST', body: formData });
    clearInterval(ticker);
    if (!res.ok) {
      const err = await res.text();
      throw new Error(err);
    }
    const data = await res.json();
    window.location.href = '/report/' + data.report_id;
  } catch (err) {
    clearInterval(ticker);
    document.getElementById('progress-text').textContent = 'Error: ' + err.message;
    scanBtn.style.display = 'block';
    document.getElementById('progress-area').style.display = 'none';
  }
}
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def landing():
    return LANDING_HTML


@app.post("/scan")
async def scan_endpoint(
    file: UploadFile = File(...),
    use_ai: str = Form(default="false")
):
    if not file.filename.endswith('.zip'):
        raise HTTPException(400, "Only ZIP files are supported")

    report_id = str(uuid.uuid4())[:8]
    tmp_dir = tempfile.mkdtemp()

    try:
        zip_path = os.path.join(tmp_dir, 'upload.zip')
        with open(zip_path, 'wb') as f:
            content = await file.read()
            f.write(content)

        extract_dir = os.path.join(tmp_dir, 'project')
        os.makedirs(extract_dir)
        with zipfile.ZipFile(zip_path, 'r') as z:
            z.extractall(extract_dir)

        results = scan_path(extract_dir)
        results['original_filename'] = file.filename
        results['path'] = file.filename.replace('.zip', '')

        ai_mode = use_ai.lower() == 'true'
        if results['findings']:
            results['findings'] = explain_all(
                results['findings'],
                use_ai=ai_mode
            )

        html = generate_html_report(results)
        report_store[report_id] = html

        return JSONResponse({
            "report_id": report_id,
            "summary": results['summary'],
            "files_scanned": results['files_scanned']
        })

    except zipfile.BadZipFile:
        raise HTTPException(400, "Invalid ZIP file")
    except Exception as e:
        raise HTTPException(500, f"Scan failed: {str(e)}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@app.get("/report/{report_id}", response_class=HTMLResponse)
async def get_report(report_id: str):
    html = report_store.get(report_id)
    if not html:
        raise HTTPException(404, "Report not found or expired — please scan again")
    return html


@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0", "checks": 22}
