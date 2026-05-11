const vscode = require('vscode');
const path = require('path');
const { execSync } = require('child_process');

let criticalDecoration;
let highDecoration;
let mediumDecoration;
let findingsProvider;
let diagnosticCollection;

function activate(context) {
  console.log('VibeGuard activated');

  criticalDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 68, 68, 0.15)',
    borderBottom: '2px solid rgba(255, 68, 68, 0.8)',
    overviewRulerColor: '#ff4444',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: '  ⚠ CRITICAL',
      color: '#ff4444',
      fontSize: '11px',
      fontWeight: 'bold',
    }
  });

  highDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 170, 0, 0.1)',
    borderBottom: '2px solid rgba(255, 170, 0, 0.7)',
    overviewRulerColor: '#ffaa00',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: '  ⚠ HIGH',
      color: '#ffaa00',
      fontSize: '11px',
    }
  });

  mediumDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(68, 136, 255, 0.08)',
    borderBottom: '1px solid rgba(68, 136, 255, 0.5)',
    overviewRulerColor: '#4488ff',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: '  ℹ MEDIUM',
      color: '#4488ff',
      fontSize: '11px',
    }
  });

  diagnosticCollection = vscode.languages.createDiagnosticCollection('vibeguard');
  context.subscriptions.push(diagnosticCollection);

  findingsProvider = new FindingsTreeProvider();
  vscode.window.registerTreeDataProvider('vibeguardFindings', findingsProvider);

  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.scan', () => scanWorkspace()),
    vscode.commands.registerCommand('vibeguard.scanFile', () => scanCurrentFile()),
    vscode.commands.registerCommand('vibeguard.clearFindings', clearFindings),
    vscode.commands.registerCommand('vibeguard.openFinding', (finding) => openFinding(finding)),
    vscode.commands.registerCommand('vibeguard.configure', () => configurePaths())
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      const config = vscode.workspace.getConfiguration('vibeguard');
      if (config.get('autoScanOnSave')) scanWorkspace();
    })
  );

  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) VibeGuard';
  statusBar.command = 'vibeguard.scan';
  statusBar.tooltip = 'Click to scan workspace for security issues';
  statusBar.show();
  context.subscriptions.push(statusBar);
}

function getConfig() {
  return vscode.workspace.getConfiguration('vibeguard');
}

function getPythonPath() {
  const config = getConfig();
  const configured = config.get('pythonPath');
  if (configured && configured !== 'auto') return configured;

  // Auto-detect
  const candidates = [
    '/opt/homebrew/bin/python3',
    '/usr/local/bin/python3',
    '/usr/bin/python3',
    '/usr/bin/python',
  ];

  for (const p of candidates) {
    try {
      execSync(`"${p}" --version`, { stdio: 'pipe', timeout: 3000 });
      return p;
    } catch {
      continue;
    }
  }
  return null;
}

function getVibeGuardPath() {
  const config = getConfig();
  const configured = config.get('vibeguardPath');
  if (configured) return configured;
  return null;
}

async function configurePaths() {
  // Auto-detect python
  const pythonPath = getPythonPath();

  const pythonInput = await vscode.window.showInputBox({
    title: 'VibeGuard: Python Path',
    prompt: 'Enter the full path to your Python 3 executable',
    value: pythonPath || '/opt/homebrew/bin/python3',
    placeHolder: '/opt/homebrew/bin/python3'
  });
  if (!pythonInput) return;

  const vibeguardInput = await vscode.window.showInputBox({
    title: 'VibeGuard: Project Path',
    prompt: 'Enter the full path to your vibeguard project folder',
    value: '/Users/tayyab/vibeguard',
    placeHolder: '/Users/tayyab/vibeguard'
  });
  if (!vibeguardInput) return;

  const config = getConfig();
  await config.update('pythonPath', pythonInput, vscode.ConfigurationTarget.Global);
  await config.update('vibeguardPath', vibeguardInput, vscode.ConfigurationTarget.Global);

  vscode.window.showInformationMessage(
    `VibeGuard configured! Python: ${pythonInput} | Project: ${vibeguardInput}`,
    'Scan Now'
  ).then(sel => { if (sel === 'Scan Now') scanWorkspace(); });
}

async function runScan(targetPath) {
  const pythonPath = getPythonPath();
  const vibeguardRoot = getVibeGuardPath();

  if (!pythonPath) {
    const action = await vscode.window.showErrorMessage(
      'VibeGuard: Python 3 not found. Please configure the path.',
      'Configure'
    );
    if (action === 'Configure') configurePaths();
    throw new Error('Python not found');
  }

  if (!vibeguardRoot) {
    const action = await vscode.window.showErrorMessage(
      'VibeGuard: vibeguard project path not configured.',
      'Configure'
    );
    if (action === 'Configure') configurePaths();
    throw new Error('vibeguard path not configured');
  }

  let output = '';
  try {
    output = execSync(
      `"${pythonPath}" -m cli.main scan "${targetPath}" --json-out`,
      {
        cwd: vibeguardRoot,
        timeout: 120000,
        maxBuffer: 20 * 1024 * 1024,
        encoding: 'utf8',
        env: { ...process.env, PYTHONPATH: vibeguardRoot }
      }
    );
  } catch (e) {
    // CLI exits with code 0 always — if it throws, check stdout anyway
    if (e.stdout && e.stdout.includes('"findings"')) {
      output = e.stdout;
    } else {
      throw new Error(`Scanner error: ${e.stderr || e.message}`);
    }
  }

  const jsonStart = output.indexOf('{"path"');
  if (jsonStart === -1) {
    const jsonStart2 = output.indexOf('{');
    if (jsonStart2 === -1) return [];
    const data = JSON.parse(output.substring(jsonStart2));
    return data.findings || [];
  }
  const data = JSON.parse(output.substring(jsonStart));
  return data.findings || [];
}

async function scanWorkspace() {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    vscode.window.showErrorMessage('VibeGuard: No workspace folder open');
    return;
  }
  const workspacePath = workspaceFolders[0].uri.fsPath;

  // First time — prompt to configure if not set
  if (!getVibeGuardPath()) {
    const action = await vscode.window.showWarningMessage(
      'VibeGuard needs to be configured before first use.',
      'Configure Now'
    );
    if (action === 'Configure Now') await configurePaths();
    return;
  }

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'VibeGuard: Scanning workspace...',
    cancellable: false
  }, async (progress) => {
    try {
      progress.report({ message: 'Running 35+ security checks...' });
      const findings = await runScan(workspacePath);
      displayFindings(findings, workspacePath);

      const s = getSummary(findings);
      if (s.total === 0) {
        vscode.window.showInformationMessage('VibeGuard: ✓ No security issues found!');
      } else {
        vscode.window.showWarningMessage(
          `VibeGuard: ${s.total} issues found — ${s.critical} critical, ${s.high} high, ${s.medium} medium`,
          'View Findings'
        ).then(sel => {
          if (sel === 'View Findings') {
            vscode.commands.executeCommand('workbench.view.extension.vibeguard');
          }
        });
      }
    } catch (err) {
      vscode.window.showErrorMessage(`VibeGuard scan failed: ${err.message}`, 'Configure').then(sel => {
        if (sel === 'Configure') configurePaths();
      });
    }
  });
}

async function scanCurrentFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('VibeGuard: No file open');
    return;
  }

  if (!getVibeGuardPath()) {
    const action = await vscode.window.showWarningMessage(
      'VibeGuard needs to be configured before first use.',
      'Configure Now'
    );
    if (action === 'Configure Now') await configurePaths();
    return;
  }

  const filePath = editor.document.uri.fsPath;
  const dirPath = path.dirname(filePath);

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'VibeGuard: Scanning current file...',
    cancellable: false
  }, async () => {
    try {
      const findings = await runScan(dirPath);
      const fileFindings = findings.filter(f =>
        f.file === filePath ||
        f.file.endsWith(path.basename(filePath))
      );
      displayFindings(fileFindings, dirPath);
      if (fileFindings.length === 0) {
        vscode.window.showInformationMessage('VibeGuard: ✓ No issues in this file');
      } else {
        vscode.window.showWarningMessage(`VibeGuard: ${fileFindings.length} issues in this file`);
      }
    } catch (err) {
      vscode.window.showErrorMessage(`VibeGuard: ${err.message}`);
    }
  });
}

function displayFindings(findings, workspacePath) {
  findingsProvider.refresh(findings, workspacePath);
  applyDecorations(findings);
  applyDiagnostics(findings);
}

function applyDecorations(findings) {
  const editorMap = new Map();
  for (const editor of vscode.window.visibleTextEditors) {
    editorMap.set(editor.document.uri.fsPath, editor);
  }

  const byFile = {};
  for (const f of findings) {
    if (!byFile[f.file]) byFile[f.file] = { critical: [], high: [], medium: [] };
    const sev = f.severity;
    if (sev === 'critical') byFile[f.file].critical.push(f);
    else if (sev === 'high') byFile[f.file].high.push(f);
    else if (sev === 'medium') byFile[f.file].medium.push(f);
  }

  for (const [filePath, editor] of editorMap) {
    const ff = byFile[filePath] || { critical: [], high: [], medium: [] };
    const toRange = (f) => {
      const line = Math.max(0, (f.line || 1) - 1);
      const docLine = editor.document.lineAt(Math.min(line, editor.document.lineCount - 1));
      return new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, docLine.text.length));
    };
    editor.setDecorations(criticalDecoration, ff.critical.map(toRange));
    editor.setDecorations(highDecoration, ff.high.map(toRange));
    editor.setDecorations(mediumDecoration, ff.medium.map(toRange));
  }
}

function applyDiagnostics(findings) {
  diagnosticCollection.clear();
  const diagMap = new Map();

  for (const f of findings) {
    if (!diagMap.has(f.file)) diagMap.set(f.file, []);
    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, 999));
    const severity = f.severity === 'critical' || f.severity === 'high'
      ? vscode.DiagnosticSeverity.Error
      : f.severity === 'medium'
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;

    const diag = new vscode.Diagnostic(range, `[VibeGuard] ${f.title}`, severity);
    diag.source = 'VibeGuard';
    diag.code = f.pattern_id;
    diagMap.get(f.file).push(diag);
  }

  for (const [filePath, diags] of diagMap) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
  }
}

function clearFindings() {
  findingsProvider.refresh([], '');
  diagnosticCollection.clear();
  for (const editor of vscode.window.visibleTextEditors) {
    editor.setDecorations(criticalDecoration, []);
    editor.setDecorations(highDecoration, []);
    editor.setDecorations(mediumDecoration, []);
  }
  vscode.window.showInformationMessage('VibeGuard: Findings cleared');
}

function openFinding(finding) {
  if (!finding?.file) return;
  const line = Math.max(0, (finding.line || 1) - 1);
  vscode.window.showTextDocument(vscode.Uri.file(finding.file), {
    selection: new vscode.Range(new vscode.Position(line, 0), new vscode.Position(line, 999))
  });
}

function getSummary(findings) {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
  };
}

class FindingsTreeProvider {
  constructor() {
    this._onDidChangeTreeData = new vscode.EventEmitter();
    this.onDidChangeTreeData = this._onDidChangeTreeData.event;
    this.findings = [];
    this.workspacePath = '';
  }

  refresh(findings, workspacePath) {
    this.findings = findings;
    this.workspacePath = workspacePath;
    this._onDidChangeTreeData.fire();
  }

  getTreeItem(element) { return element; }

  getChildren(element) {
    if (!element) {
      if (this.findings.length === 0) {
        const item = new vscode.TreeItem('No findings — workspace is clean ✓');
        return [item];
      }
      const groups = [];
      const icons = { critical: '🔴', high: '🟡', medium: '🔵', low: '⚪' };
      for (const sev of ['critical', 'high', 'medium', 'low']) {
        const sevFindings = this.findings.filter(f => f.severity === sev);
        if (sevFindings.length > 0) {
          const item = new vscode.TreeItem(
            `${icons[sev]} ${sev.toUpperCase()} (${sevFindings.length})`,
            vscode.TreeItemCollapsibleState.Expanded
          );
          item._findings = sevFindings;
          groups.push(item);
        }
      }
      return groups;
    }

    if (element._findings) {
      return element._findings.map(f => {
        const relativePath = f.file.replace(this.workspacePath, '').replace(/^\//, '');
        const item = new vscode.TreeItem(f.title, vscode.TreeItemCollapsibleState.None);
        item.description = `${relativePath}:${f.line}`;
        item.tooltip = f.snippet || f.description;
        item.command = {
          command: 'vibeguard.openFinding',
          title: 'Open Finding',
          arguments: [f]
        };
        return item;
      });
    }
    return [];
  }
}

function deactivate() {
  diagnosticCollection?.dispose();
}

module.exports = { activate, deactivate };
