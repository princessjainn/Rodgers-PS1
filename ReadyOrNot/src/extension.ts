import * as vscode from 'vscode';
import ignore from 'ignore';
import { runAudit } from './orchestrator/agentOrchestrator';
import { WorkspaceFile } from './types/vulnerability';

export function activate(context: vscode.ExtensionContext) {
	const diagnosticCollection = vscode.languages.createDiagnosticCollection('readyornot');
	context.subscriptions.push(diagnosticCollection);

	let ig = ignore();

	// Automatically load and parse actual patterns from .gitignore
	async function loadGitignore() {
		ig = ignore();
		// Always statically bypass base vscode outputs to stop infinite loops and memory leaks
		ig.add(['node_modules', '.git', 'out', 'dist', '.vscode', '.vscode-test', 'coverage', '*.vsix', '*.log']);

		try {
			const ignoreFiles = await vscode.workspace.findFiles('**/.gitignore', '**/{node_modules,.git,out,dist,.vscode,.vscode-test}/**');
			for (const gitignoreUri of ignoreFiles) {
				const doc = await vscode.workspace.openTextDocument(gitignoreUri);
				const lines = doc.getText().split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
				ig.add(lines);
			}
		} catch (e) {
			// Silently fail if .gitignore doesn't exist yet
		}
	}

	// Trigger initial load
	loadGitignore();

	// Scan a single document securely via Agent architecture
	async function scanDocument(document: vscode.TextDocument) {
		if (document.uri.scheme !== 'file') {
			return 0;
		}

		// Use standard ignore compliant check against relative paths
		let relativePath = vscode.workspace.asRelativePath(document.uri, false);
		const isAbsolute = relativePath === document.uri.fsPath || relativePath.startsWith('/') || /^[a-zA-Z]:/.test(relativePath);

		if (!isAbsolute) {
			try {
				if (ig.ignores(relativePath)) {
					diagnosticCollection.set(document.uri, []);
					return 0; // Completely skip files matched by .gitignore
				}
			} catch (e) {
				// Silently fallback if ignore throws on weird paths
			}
		}

		const workspaceFile: WorkspaceFile = {
			uri: document.uri.toString(),
			fsPath: document.uri.fsPath,
			content: document.getText()
		};

		const auditReport = await runAudit([workspaceFile]);
		const diagnostics: vscode.Diagnostic[] = [];

		for (const finding of auditReport.vulnerabilities) {
			const lineIndex = Math.max(0, finding.line - 1);
			if (lineIndex >= document.lineCount) continue;

			const lineText = document.lineAt(lineIndex).text;
			const range = new vscode.Range(lineIndex, 0, lineIndex, lineText.length || 1);

			let vsSeverity = vscode.DiagnosticSeverity.Information;
			if (finding.severity === 'ERROR') vsSeverity = vscode.DiagnosticSeverity.Warning;
			else if (finding.severity === 'WARNING') vsSeverity = vscode.DiagnosticSeverity.Warning;

			const msg = `[${finding.title}] ${finding.description}\nFix: ${finding.recommendation}`;
			const diagnostic = new vscode.Diagnostic(range, msg, vsSeverity);
			diagnostic.code = finding.id;
			diagnostic.source = `ReadyOrNot [${finding.agentSource}]`;
			diagnostics.push(diagnostic);
		}

		diagnosticCollection.set(document.uri, diagnostics);
		return auditReport.vulnerabilities.length;
	}

	// Command to manually scan workspace
	const disposable = vscode.commands.registerCommand('readyornot.scanVulnerabilities', async () => {

		// Immediately open the panel so the user sees it reacting!
		const panel = vscode.window.createWebviewPanel(
			'readyornotScanner',
			'ReadyOrNot Editor Panel',
			vscode.ViewColumn.One,
			{ enableScripts: true }
		);

		panel.webview.onDidReceiveMessage(async (message) => {
			if (message.command === 'openFile' && vscode.workspace.workspaceFolders) {
				const fileUri = vscode.Uri.joinPath(vscode.workspace.workspaceFolders[0].uri, message.file);
				try {
					const doc = await vscode.workspace.openTextDocument(fileUri);
					const editor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
					const line = Math.max(0, message.line - 1);
					const pos = new vscode.Position(line, 0);
					editor.selection = new vscode.Selection(pos, pos);
					editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
				} catch (e) {
					vscode.window.showErrorMessage(`Could not open file: ${message.file}`);
				}
			}
		});

		panel.webview.html = `<html><body style="padding: 40px; font-family: sans-serif; color: white;"><h2>🛡️ ReadyOrNot is scanning your workspace...</h2><p>Please wait...</p></body></html>`;

		vscode.window.withProgress({
			location: vscode.ProgressLocation.Notification,
			title: "ReadyOrNot: Scanning project for vulnerabilities...",
			cancellable: false
		}, async (progress) => {
			diagnosticCollection.clear();
			const allResults: { file: string, line: number, message: string, severity: string }[] = [];

			try {
				// Re-sync gitignore in case they literally just saved it
				await loadGitignore();

				// Find raw files in the workspace, explicitly blocking heavy metadata folders natively
				const rawFiles = await vscode.workspace.findFiles('**/*.*', '**/{node_modules,.git,out,dist,.vscode,.vscode-test,coverage}/**');

				// Filter thoroughly using the ignore plugin against workspace relative paths
				let files: vscode.Uri[] = [];
				files = rawFiles.filter(f => {
					try {
						let relPath = vscode.workspace.asRelativePath(f, false);
						const isAbs = relPath === f.fsPath || relPath.startsWith('/') || /^[a-zA-Z]:/.test(relPath);
						if (isAbs) return true; // Scan files outside workspace without filtering
						return !ig.ignores(relPath);
					} catch (e) {
						return true;
					}
				});

				if (files.length === 0) {
					vscode.window.showInformationMessage('No files found to scan. Make sure a Workspace folder is open!');
				} else {
					const totalFiles = files.length;
					let currentFile = 0;
					let totalVulnerabilities = 0;

					for (const uri of files) {
						try {
							const document = await vscode.workspace.openTextDocument(uri);

							const workspaceFile: WorkspaceFile = {
								uri: document.uri.toString(),
								fsPath: document.uri.fsPath,
								content: document.getText()
							};

							const fileReport = await runAudit([workspaceFile]);
							totalVulnerabilities += fileReport.vulnerabilities.length;

							const diags: vscode.Diagnostic[] = [];
							for (const finding of fileReport.vulnerabilities) {
								const lineIndex = Math.max(0, finding.line - 1);
								if (lineIndex >= document.lineCount) continue;

								const lineText = document.lineAt(lineIndex).text;
								const range = new vscode.Range(lineIndex, 0, lineIndex, lineText.length || 1);

								let vsSeverity = vscode.DiagnosticSeverity.Information;
								if (finding.severity === 'ERROR') vsSeverity = vscode.DiagnosticSeverity.Warning;
								else if (finding.severity === 'WARNING') vsSeverity = vscode.DiagnosticSeverity.Warning;

								const msg = `[${finding.title}] ${finding.description}\nFix: ${finding.recommendation}`;
								const diagnostic = new vscode.Diagnostic(range, msg, vsSeverity);
								diagnostic.code = finding.id;
								diagnostic.source = `ReadyOrNot [${finding.agentSource}]`;
								diags.push(diagnostic);

								allResults.push({
									file: vscode.workspace.asRelativePath(uri),
									line: finding.line,
									message: `[${finding.title}] ${finding.description}`,
									severity: finding.severity === 'ERROR' ? 'Error' : finding.severity === 'WARNING' ? 'Warning' : 'Info'
								});
							}

							diagnosticCollection.set(uri, diags);

						} catch (e) {
							console.error(`Error reading file ${uri.fsPath}:`, e);
						}

						currentFile++;
						progress.report({ increment: (1 / totalFiles) * 100, message: `Scanned ${currentFile}/${totalFiles} files` });
					}

					if (totalVulnerabilities > 0) {
						vscode.window.showWarningMessage(`ReadyOrNot complete. Found ${totalVulnerabilities} potential vulnerabilities.`);
					} else {
						vscode.window.showInformationMessage('ReadyOrNot complete. No obvious vulnerabilities found!');
					}
				}
			} catch (err: any) {
				vscode.window.showErrorMessage('Error during scan: ' + (err.message || err));
				allResults.push({ file: 'SYSTEM ERROR', line: 0, message: 'Scan crashed: ' + err, severity: 'Error' });
			}

			// Render the final results to the panel we created earlier
			panel.webview.html = getWebviewContent(allResults);
		});
	});

	context.subscriptions.push(disposable);

	// React to file changes in real-time
	vscode.workspace.onDidSaveTextDocument(document => {
		scanDocument(document);
	}, null, context.subscriptions);

	vscode.workspace.onDidOpenTextDocument(document => {
		scanDocument(document);
	}, null, context.subscriptions);

	vscode.workspace.textDocuments.forEach(document => {
		scanDocument(document);
	});
}

function getNonce() {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}

function getWebviewContent(results: { file: string, line: number, message: string, severity: string }[]) {
	// Sort results by severity (Error -> Warning -> Info)
	const severityWeight: Record<string, number> = { 'Error': 0, 'Warning': 1, 'Info': 2 };
	results.sort((a, b) => (severityWeight[a.severity] ?? 3) - (severityWeight[b.severity] ?? 3));

	const totalIssues = results.length;
	const errorCount = results.filter(r => r.severity === 'Error').length;
	const warningCount = results.filter(r => r.severity === 'Warning').length;
	const infoCount = results.filter(r => r.severity === 'Info').length;

	let rows = results.map(r => `
		<tr>
			<td style="width: 12%;">
				<span class="badge badge-${r.severity.toLowerCase()}">
					${r.severity}
				</span>
			</td>
			<td style="width: 30%;">
				<a class="location-link" onclick="openFile('${r.file.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}', ${r.line})">
					📄 ${r.file}:${r.line}
				</a>
			</td>
			<td style="width: 58%; color: var(--text-main);">
				${r.message}
			</td>
		</tr>
	`).join('');

	if (results.length === 0) {
		rows = `<tr><td colspan="3">
			<div class="empty-state">
				<div class="empty-icon">✅</div>
				<div class="empty-title">Zero Vulnerabilities Found</div>
				<div class="empty-desc">Your codebase is clean, secure, and production-ready.</div>
			</div>
		</td></tr>`;
	}

	const nonce = getNonce();

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<title>ReadyOrNot Results</title>
	<script nonce="${nonce}">
		const vscode = acquireVsCodeApi();
		function openFile(file, line) {
			vscode.postMessage({ command: 'openFile', file: file, line: line });
		}
	</script>
	<style>
		:root {
			--bg-dark: #09090b; /* Zinc 950 */
			--bg-card: rgba(24, 24, 27, 0.6); /* Zinc 900 */
			--bg-card-hover: rgba(39, 39, 42, 0.8); /* Zinc 800 */
			--text-main: #f4f4f5; /* Zinc 50 */
			--text-muted: #a1a1aa; /* Zinc 400 */
			--border: rgba(255, 255, 255, 0.08);
			--border-glow: rgba(255, 255, 255, 0.15);
			--accent-error: #ef4444; /* Red 500 */
			--accent-warning: #f59e0b; /* Amber 500 */
			--accent-info: #3b82f6; /* Blue 500 */
			--accent-success: #10b981; /* Emerald 500 */
		}
		* { box-sizing: border-box; }
		body {
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
			padding: 40px;
			color: var(--text-main);
			background-color: var(--bg-dark);
			background-image: 
				radial-gradient(circle at 10% 20%, rgba(239, 68, 68, 0.03), transparent 30%),
				radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.03), transparent 30%);
			background-attachment: fixed;
			margin: 0;
			-webkit-font-smoothing: antialiased;
			min-height: 100vh;
		}
		.container {
			max-width: 1400px;
			margin: 0 auto;
			animation: fadeIn 0.6s ease-out;
		}
		@keyframes fadeIn {
			from { opacity: 0; }
			to { opacity: 1; }
		}
		.header {
			display: flex;
			align-items: center;
			margin-bottom: 8px;
			gap: 16px;
		}
		.logo-icon {
			font-size: 42px;
			filter: drop-shadow(0 0 16px rgba(239, 68, 68, 0.4));
		}
		h1 {
			color: var(--text-main);
			font-size: 38px;
			font-weight: 700;
			margin: 0;
			letter-spacing: -0.5px;
			background: linear-gradient(135deg, #ffffff, #a1a1aa);
			-webkit-background-clip: text;
			-webkit-text-fill-color: transparent;
		}
		.subtitle {
			font-size: 16px;
			color: var(--text-muted);
			font-weight: 400;
			margin-bottom: 32px;
			letter-spacing: 0.2px;
		}
		.dashboard {
			display: grid;
			grid-template-columns: repeat(4, 1fr);
			gap: 20px;
			margin-bottom: 40px;
		}
		.dash-card {
			background: var(--bg-card);
			border: 1px solid var(--border);
			border-radius: 12px;
			padding: 24px;
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			display: flex;
			flex-direction: column;
			box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
			transition: transform 0.2s, border-color 0.2s, box-shadow 0.2s;
			position: relative;
			overflow: hidden;
		}
		.dash-card::before {
			content: '';
			position: absolute;
			top: 0; left: 0; width: 100%; height: 4px;
		}
		.dash-card.total::before { background: linear-gradient(90deg, #6366f1, #a855f7); }
		.dash-card.error::before { background: var(--accent-error); }
		.dash-card.warning::before { background: var(--accent-warning); }
		.dash-card.info::before { background: var(--accent-info); }
		.dash-card:hover {
			transform: translateY(-2px);
			border-color: var(--border-glow);
			box-shadow: 0 8px 30px rgba(0, 0, 0, 0.3);
		}
		.dash-title {
			font-size: 14px;
			font-weight: 600;
			color: var(--text-muted);
			text-transform: uppercase;
			letter-spacing: 1px;
			margin-bottom: 12px;
			display: flex;
			align-items: center;
			justify-content: space-between;
		}
		.dash-value {
			font-size: 42px;
			font-weight: 700;
			line-height: 1;
			color: var(--text-main);
		}
		.dash-card.total .dash-value { color: #e0e7ff; }
		.dash-card.error .dash-value { color: #fee2e2; }
		.dash-card.warning .dash-value { color: #fef3c7; }
		.dash-card.info .dash-value { color: #dbeafe; }

		.table-container {
			background: var(--bg-card);
			border-radius: 16px;
			border: 1px solid var(--border);
			box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
			backdrop-filter: blur(16px);
			-webkit-backdrop-filter: blur(16px);
			overflow: hidden;
			animation: slideUp 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
		}
		table {
			width: 100%;
			border-collapse: collapse;
			text-align: left;
		}
		th {
			background-color: rgba(255, 255, 255, 0.02);
			padding: 18px 24px;
			font-size: 13px;
			font-weight: 600;
			color: var(--text-muted);
			text-transform: uppercase;
			letter-spacing: 1px;
			border-bottom: 1px solid var(--border);
		}
		td {
			padding: 20px 24px;
			border-bottom: 1px solid rgba(255, 255, 255, 0.04);
			font-size: 15px;
			line-height: 1.6;
		}
		tr:hover td {
			background-color: var(--bg-card-hover);
		}
		tr:last-child td {
			border-bottom: none;
		}
		.badge {
			display: inline-flex;
			padding: 6px 12px;
			border-radius: 6px;
			font-size: 12px;
			font-weight: 700;
			letter-spacing: 0.5px;
			text-transform: uppercase;
		}
		.badge-error { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.3); }
		.badge-warning { background: rgba(245, 158, 11, 0.15); color: #fcd34d; border: 1px solid rgba(245, 158, 11, 0.3); }
		.badge-info { background: rgba(59, 130, 246, 0.15); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.3); }
		.location-link {
			color: #38bdf8;
			font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
			font-size: 13.5px;
			cursor: pointer;
			padding: 6px 10px;
			background: rgba(56, 189, 248, 0.08);
			border-radius: 6px;
			transition: all 0.2s;
			display: inline-block;
			border: 1px solid transparent;
		}
		.location-link:hover {
			background: rgba(56, 189, 248, 0.15);
			border-color: rgba(56, 189, 248, 0.3);
			transform: scale(1.02);
		}
		.empty-state { text-align: center; padding: 80px 40px; }
		.empty-icon { font-size: 64px; margin-bottom: 24px; animation: float 3s ease-in-out infinite; filter: drop-shadow(0 0 20px rgba(16, 185, 129, 0.4)); }
		.empty-title { font-size: 24px; font-weight: 600; color: var(--accent-success); margin-bottom: 12px; }
		.empty-desc { color: var(--text-muted); font-size: 16px; }
		@keyframes slideUp { from { opacity: 0; transform: translateY(30px); } to { opacity: 1; transform: translateY(0); } }
		@keyframes float { 0% { transform: translateY(0px); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0px); } }
		::-webkit-scrollbar { width: 10px; height: 10px; }
		::-webkit-scrollbar-track { background: var(--bg-dark); }
		::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 5px; }
		::-webkit-scrollbar-thumb:hover { background: #52525b; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">
			<span class="logo-icon">🛡️</span>
			<h1>ReadyOrNot</h1>
		</div>
		<p class="subtitle">Deep code analysis and security auditing tool.</p>

		<div class="dashboard">
			<div class="dash-card total">
				<div class="dash-title">Total Issues <span>📋</span></div>
				<div class="dash-value">${totalIssues}</div>
			</div>
			<div class="dash-card error">
				<div class="dash-title">Critical Errors <span>🚨</span></div>
				<div class="dash-value">${errorCount}</div>
			</div>
			<div class="dash-card warning">
				<div class="dash-title">Warnings <span>⚠️</span></div>
				<div class="dash-value">${warningCount}</div>
			</div>
			<div class="dash-card info">
				<div class="dash-title">Info & Tips <span>💡</span></div>
				<div class="dash-value">${infoCount}</div>
			</div>
		</div>

		<div class="table-container">
			<table>
				<thead>
					<tr>
						<th>Severity</th>
						<th>Location</th>
						<th>Vulnerability Description</th>
					</tr>
				</thead>
				<tbody>
					${rows}
				</tbody>
			</table>
		</div>
	</div>
</body>
</html>`;
}

export function deactivate() { }
