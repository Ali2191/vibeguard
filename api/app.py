import os
import sys
import uuid
import shutil
import tempfile
import zipfile
from datetime import datetime
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.append('..')
from core.scanner import scan_path
from output.report import generate_html_report
from models.gemini_explainer import explain_all

load_dotenv()

app = FastAPI(title="VibeGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_methods=["*"],
    allow_headers=["*"],
    # Replace '*' with specific allowed origins.
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
    <div class="drop-zone" id="drop-zone">
      <input type="file" id="file-input" />
      <div class="icon">📁</div>
      <p>Drag and drop or <strong>click here</strong> to upload your project.</p>
    </div>
    <div class="file-name" id="file-name"></div>
    <div class="options">
      <div class="option">
        <input type="checkbox" id="option-1" />
        <label for="option-1">Option 1</label>
        <small>Some description for option 1.</small>
      </div>
      <div class="option">
        <input type="checkbox" id="option-2" />
        <label for="option-2">Option 2</label>
        <small>Some description for option 2.</small>
      </div>
    </div>
    <button class="scan-btn" id="scan-btn" disabled>Scan</button>
    <div class="progress-area" id="progress-area">
      <div class="spinner"></div>
      <div class="progress-text">Scanning...</div>
    </div>
  </div>
</div>

<div class="features">
  <div class="feature">
    <div class="feat-icon">🔍</div>
    <h3>Feature 1</h3>
    <p>Some description for feature 1.</p>
  </div>
  <div class="feature">
    <div class="feat-icon">📊</div>
    <h3>Feature 2</h3>
    <p>Some description for feature 2.</p>
  </div>
  <div class="feature">
    <div class="feat-icon">🚀</div>
    <h3>Feature 3</h3>
    <p>Some description for feature 3.</p>
  </div>
</div>

<div class="checks">
  <h3>Checks</h3>
  <div class="check-grid">
    <div class="check-item">
      <div class="check-icon">🔒</div>
      <p>Check 1</p>
    </div>
    <div class="check-item">
      <div class="check-icon">🔒</div>
      <p>Check 2</p>
    </div>
  </div>
</div>

<footer>
  <p>&copy; 2023 VibeGuard</p>
</footer>

<script>
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const fileName = document.getElementById('file-name');
  const scanBtn = document.getElementById('scan-btn');
  const progressArea = document.getElementById('progress-area');

  dropZone.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    fileName.textContent = file.name;
    scanBtn.disabled = false;
  });

  scanBtn.addEventListener('click', () => {
    progressArea.style.display = 'block';
    // Call API to scan project
    fetch('/scan', {
      method: 'POST',
      body: new FormData(),
    })
      .then((response) => response.json())
      .then((data) => {
        console.log(data);
        progressArea.style.display = 'none';
      })
      .catch((error) => {
        console.error(error);
        progressArea.style.display = 'none';
      });
  });
</script>
"""

@app.get("/")
async def get_landing_page():
    return HTMLResponse(LANDING_HTML)

@app.post("/scan")
async def scan_project(file: UploadFile = File(...)):
    # Generate a unique ID for the report
    report_id = str(uuid.uuid4())

    # Save the uploaded file to a temporary directory
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    with open(file_path, 'wb') as f:
        f.write(file.file.read())

    # Scan the project
    report = scan_path(file_path)

    # Generate an HTML report
    html_report = generate_html_report(report)

    # Store the report in the in-memory store
    report_store[report_id] = html_report

    # Return the report ID
    return {"report_id": report_id}

@app.get("/report/{report_id}")
Review this code for security vulnerabilities and apply appropriate mitigations.
    # Check if the report ID is valid
    if report_id not in report_store:
        raise HTTPException(status_code=404, detail="Report not found")

    # Return the report
    return HTMLResponse(report_store[report_id])