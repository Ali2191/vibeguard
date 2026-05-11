const vscode = require('vscode');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

// Decoration types for inline highlights
let criticalDecoration;
let highDecoration;
let mediumDecoration;

// Findings tree data
let findingsProvider;
let currentFindings = [];
let diagnosticCollection;

function activate(context) {
  console.log('VibeGuard activated');

  // Init decorations
  criticalDecoration = vscode.window.createTextEditorDecorationType({
    backgroundColor: 'rgba(255, 68, 68, 0.15)',
    borderBottom: '2px solid rgba(255, 68, 68, 0.8)',
    overviewRulerColor: '#ff4444',
    overviewRulerLane: vscode.OverviewRulerLane.Right,
    after: {
      contentText: ' ⚠ CRITICAL',
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
      contentText: ' ⚠ HIGH',
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
      contentText: ' ℹ MEDIUM',
      color: '#4488ff',
      fontSize: '11px',
    }
  });

  // Diagnostic collection for Problems panel
  diagnosticCollection = vscode.languages.createDiagnosticCollection('vibeguard');
  context.subscriptions.push(diagnosticCollection);

  // Tree view
  findingsProvider = new FindingsTreeProvider();
  vscode.window.registerTreeDataProvider('vibeguardFindings', findingsProvider);

  // Register commands
  context.subscriptions.push(
    vscode.commands.registerCommand('vibeguard.scan', () => scanWorkspace(context)),
    vscode.commands.registerCommand('vibeguard.scanFile', () => scanCurrentFile(context)),
    vscode.commands.registerCommand('vibeguard.clearFindings', clearFindings),
    vscode.commands.registerCommand('vibeguard.openFinding', (finding) => openFinding(finding))
  );

  // Auto scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      const config = vscode.workspace.getConfiguration('vibeguard');
      if (config.get('autoScanOnSave')) {
        scanWorkspace(context);
      }
    })
  );

  // Status bar item
  const statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBar.text = '$(shield) VibeGuard';
  statusBar.command = 'vibeguard.scan';
  statusBar.tooltip = 'Click to scan workspace for security issues';
  statusBar.show();
  context.subscriptions.push(statusBar);
}

async function scanWorkspace(context) {
  const workspaceFolders = vscode.workspace.workspaceFolders;
  if (!workspaceFolders) {
    vscode.window.showErrorMessage('VibeGuard: No workspace folder open');
    return;
  }

  const workspacePath = workspaceFolders[0].uri.fsPath;

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'VibeGuard',
    cancellable: false
  }, async (progress) => {
    progress.report({ message: 'Scanning workspace for vulnerabilities...' });

    try {
      // Run the Python scanner directly if available
      const findings = await runLocalScan(workspacePath, progress);
      displayFindings(findings, workspacePath);

      const summary = getSummary(findings);
      if (summary.total === 0) {
        vscode.window.showInformationMessage('VibeGuard: ✓ No security issues found!');
      } else {
        vscode.window.showWarningMessage(
          `VibeGuard found ${summary.total} issues: ${summary.critical} critical, ${summary.high} high, ${summary.medium} medium`,
          'View Findings'
        ).then(selection => {
          if (selection === 'View Findings') {
            vscode.commands.executeCommand('workbench.view.extension.vibeguard');
          }
        });
      }
    } catch (err) {
      vscode.window.showErrorMessage(`VibeGuard scan failed: ${err.message}`);
    }
  });
}

async function runLocalScan(workspacePath, progress) {
  return new Promise((resolve, reject) => {
    progress.report({ message: 'Running security checks...' });

    // Try to find Python and run the scanner
    const scriptPath = path.join(__dirname, '..', '..', 'cli', 'main.py');
    const pythonCommands = ['python3', 'python'];

    let output = null;
    let lastError = null;

    for (const pythonCmd of pythonCommands) {
      try {
        output = execSync(
          `${pythonCmd} -m cli.main scan "${workspacePath}" --json-out`,
          {
            cwd: path.join(__dirname, '..', '..'),
            timeout: 60000,
            maxBuffer: 10 * 1024 * 1024,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe']
          }
        );
        break;
      } catch (e) {
        lastError = e;
        if (e.stdout) {
          output = e.stdout;
          break;
        }
        continue;
      }
    }

    if (!output) {
      reject(new Error(`Could not run scanner: ${lastError?.message || 'Python not found'}`));
      return;
    }

    try {
      // Extract JSON from output (skip any Rich terminal output before it)
      const jsonStart = output.indexOf('{');
      if (jsonStart === -1) {
        resolve([]);
        return;
      }
      const jsonStr = output.substring(jsonStart);
      const data = JSON.parse(jsonStr);
      resolve(data.findings || []);
    } catch (e) {
      reject(new Error(`Could not parse scan results: ${e.message}`));
    }
  });
}

async function scanCurrentFile(context) {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showErrorMessage('VibeGuard: No file open');
    return;
  }

  const filePath = editor.document.uri.fsPath;
  const workspacePath = path.dirname(filePath);

  await vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: 'VibeGuard: Scanning current file...',
    cancellable: false
  }, async (progress) => {
    try {
      const findings = await runLocalScan(workspacePath, progress);
      const fileFindings = findings.filter(f => f.file === filePath || f.file.endsWith(path.basename(filePath)));
      displayFindings(fileFindings, workspacePath);

      if (fileFindings.length === 0) {
        vscode.window.showInformationMessage('VibeGuard: ✓ No issues in this file');
      } else {
        vscode.window.showWarningMessage(`VibeGuard: ${fileFindings.length} issues found in this file`);
      }
    } catch (err) {
      vscode.window.showErrorMessage(`VibeGuard: ${err.message}`);
    }
  });
}

function displayFindings(findings, workspacePath) {
  currentFindings = findings;
  findingsProvider.refresh(findings, workspacePath);

  const config = vscode.workspace.getConfiguration('vibeguard');
  if (config.get('showInlineDecorations')) {
    applyDecorations(findings);
  }

  applyDiagnostics(findings);
}

function applyDecorations(findings) {
  const editorMap = new Map();

  for (const editor of vscode.window.visibleTextEditors) {
    editorMap.set(editor.document.uri.fsPath, editor);
  }

  // Group findings by file
  const byFile = {};
  for (const f of findings) {
    if (!byFile[f.file]) byFile[f.file] = { critical: [], high: [], medium: [] };
    const severity = f.severity;
    if (severity === 'critical') byFile[f.file].critical.push(f);
    else if (severity === 'high') byFile[f.file].high.push(f);
    else if (severity === 'medium') byFile[f.file].medium.push(f);
  }

  for (const [filePath, editor] of editorMap) {
    const fileFindings = byFile[filePath] || { critical: [], high: [], medium: [] };

    const toRange = (f) => {
      const line = Math.max(0, (f.line || 1) - 1);
      const docLine = editor.document.lineAt(Math.min(line, editor.document.lineCount - 1));
      return new vscode.Range(
        new vscode.Position(line, 0),
        new vscode.Position(line, docLine.text.length)
      );
    };

    editor.setDecorations(criticalDecoration, fileFindings.critical.map(toRange));
    editor.setDecorations(highDecoration, fileFindings.high.map(toRange));
    editor.setDecorations(mediumDecoration, fileFindings.medium.map(toRange));
  }
}

function applyDiagnostics(findings) {
  diagnosticCollection.clear();
  const diagMap = new Map();

  for (const f of findings) {
    const uri = vscode.Uri.file(f.file);
    if (!diagMap.has(f.file)) diagMap.set(f.file, []);

    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(
      new vscode.Position(line, 0),
      new vscode.Position(line, 999)
    );

    const severity = f.severity === 'critical' || f.severity === 'high'
      ? vscode.DiagnosticSeverity.Error
      : f.severity === 'medium'
        ? vscode.DiagnosticSeverity.Warning
        : vscode.DiagnosticSeverity.Information;

    const diag = new vscode.Diagnostic(
      range,
      `[VibeGuard] ${f.title}`,
      severity
    );
    diag.source = 'VibeGuard';
    diag.code = f.pattern_id;
    diagMap.get(f.file).push(diag);
  }

  for (const [filePath, diags] of diagMap) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
  }
}

function clearFindings() {
  currentFindings = [];
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
  if (!finding || !finding.file) return;
  const uri = vscode.Uri.file(finding.file);
  const line = Math.max(0, (finding.line || 1) - 1);

  vscode.window.showTextDocument(uri, {
    selection: new vscode.Range(
      new vscode.Position(line, 0),
      new vscode.Position(line, 999)
    )
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

// Tree view provider
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

  getTreeItem(element) {
    return element;
  }

  getChildren(element) {
    if (!element) {
      // Root — group by severity
      if (this.findings.length === 0) {
        return [new vscode.TreeItem('No findings — workspace is clean ✓')];
      }

      const groups = [];
      const severities = ['critical', 'high', 'medium', 'low'];

      for (const sev of severities) {
        const sevFindings = this.findings.filter(f => f.severity === sev);
        if (sevFindings.length > 0) {
          const icons = { critical: '🔴', high: '🟡', medium: '🔵', low: '⚪' };
          const item = new vscode.TreeItem(
            `${icons[sev]} ${sev.toUpperCase()} (${sevFindings.length})`,
            vscode.TreeItemCollapsibleState.Expanded
          );
          item.contextValue = 'severityGroup';
          item._findings = sevFindings;
          groups.push(item);
        }
      }
      return groups;
    }

    // Children of a severity group
    if (element._findings) {
      return element._findings.map(f => {
        const relativePath = f.file.replace(this.workspacePath, '').replace(/^\//, '');
        const item = new vscode.TreeItem(
          `${f.title}`,
          vscode.TreeItemCollapsibleState.None
        );
        item.description = `${relativePath}:${f.line}`;
        item.tooltip = f.snippet || f.description;
        item.command = {
          command: 'vibeguard.openFinding',
          title: 'Open Finding',
          arguments: [f]
        };
        item.contextValue = 'finding';
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
