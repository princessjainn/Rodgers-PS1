import * as vscode from 'vscode';
import ignore from 'ignore';
import * as ts from 'typescript';

// Define our expansive vulnerability scanning rules based on the newly provided categories
const vulnerabilityRules = [
	// CATEGORY 5: PII Handling
	{
		id: 'pii-logging',
		regex: /console\.(log|info|warn|error)\s*\([^)]*(email|phone|aadhaar|ssn|password|location|dob|user)[^)]*\)/gi,
		message: 'GDPR / SOC2 Risk: Logging sensitive data (PII).',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	{
		id: 'pii-storage',
		regex: /(?:save|store|insert|update)\s*\([^)]*(password|ssn|aadhaar)[^)]*\)/gi,
		message: 'GDPR / SOC2 Risk: Unencrypted storage of sensitive data.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	// CATEGORY 6: AI Cost Explosion Risks
	{
		id: 'ai-loop',
		regex: /(?:for|while|foreach)\s*\([^)]*\)\s*\{[^}]*(?:callOpenAI|openai|anthropic|fetch|generateText)[^}]*\}/gi,
		message: 'Unbounded AI Cost Risk: LLM API call inside a loop without obvious limits or caching.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	// CATEGORY 7: Error Handling Failures
	{
		id: 'missing-error-handling',
		regex: /await\s+(?:fetch|axios\.(?:get|post|put|delete)|callOpenAI)/g,
		message: 'Reliability Risk: Ensure this await call is wrapped in a try/catch or has proper retry/fallback logic.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Warning'
	},
	// CATEGORY 8: Network & API Security
	{
		id: 'http-url',
		regex: /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s"'><]+/gi,
		message: 'Network Exposure Risk: Usage of insecure HTTP URL instead of HTTPS.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	{
		id: 'open-cors',
		regex: /Access-Control-Allow-Origin\s*:\s*(?:'|")?\*(?:'|")?/gi,
		message: 'Network Exposure Risk: Open CORS policy (*).',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	// CATEGORY 9: Database Risks
	{
		id: 'sql-injection',
		regex: /(?:'|")SELECT\s+.*\s+FROM\s+.*\s+WHERE\s+.*(?:'|")\s*\+/gi,
		message: 'Injection Vulnerability: Potential SQL injection. Avoid string concatenation for SQL queries.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	{
		id: 'sql-injection-template',
		regex: /SELECT.*FROM.*WHERE.*=.*\$\{.*\}/g,
		message: 'Injection Vulnerability: Potential SQL Injection: Unsanitized variable in SQL query.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	// CATEGORY 10: Observability Failure
	{
		id: 'observability-failure',
		regex: /console\.(error|warn)\s*\(/g,
		message: 'Operational Visibility Risk: Recommend using a dedicated monitoring/logging framework instead of raw console methods in production.',
		vscodeSeverity: vscode.DiagnosticSeverity.Information,
		displaySeverity: 'Info'
	},
	// CATEGORY 12: Environment Misconfiguration
	{
		id: 'env-isolation',
		regex: /[a-zA-Z0-9_]*(?:password|secret|api_?key|apikey|token|auth_?key)[a-zA-Z0-9_]*\s*[:=]\s*(?:["'`][^"'`\r\n]+["'`]|(?!(?:true|false|null|undefined|process)\b)[a-zA-Z0-9_\-]{5,})/gi,
		message: 'Environment Isolation Risk: Potential production keys or secrets hardcoded in source.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	{
		id: 'dev-config-prod',
		regex: /process\.env\.NODE_ENV\s*(?:===|==)\s*['"]development['"]/g,
		message: 'Environment Isolation Risk: Dev configurations potentially exposed in production paths.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Warning'
	},
	// CATEGORY 13: Exposed Debug Features
	{
		id: 'debug-exposure',
		regex: /(?:console\.log\s*\(\s*(?:token|password|secret|key)\s*\)|debug\s*=\s*true|\/test-route)/gi,
		message: 'Debug Exposure: Exposed debug features or sensitive logging.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	// CATEGORY 14: AI Data Leakage
	{
		id: 'ai-data-leakage',
		regex: /(?:prompt|messages).*?(?:schema|logs|user_data|PII)/gi,
		message: 'Sensitive Context Leakage: AI tools might accidentally expose context like database schema or PII.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	// EXTRAS From Before
	{
		id: 'eval-usage',
		regex: /eval\s*\(/g,
		message: 'Usage of eval() is a severe security risk.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Error'
	},
	{
		id: 'dangerously-set-inner-html',
		regex: /dangerouslySetInnerHTML/g,
		message: 'Usage of dangerouslySetInnerHTML can lead to XSS attacks.',
		vscodeSeverity: vscode.DiagnosticSeverity.Warning,
		displaySeverity: 'Warning'
	},
	{
		id: 'insecure-random',
		regex: /Math\.random\s*\(/g,
		message: 'Math.random() is not cryptographically secure.',
		vscodeSeverity: vscode.DiagnosticSeverity.Information,
		displaySeverity: 'Info'
	}
];

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

	// Scan a single document
	function scanDocument(document: vscode.TextDocument) {
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

		// Skip files that aren't likely code or env files
		const isCode = document.uri.fsPath.match(/\.(ts|js|jsx|tsx|json|html|css|py|java|c|cpp|go|rb|php)$/i);
		const isEnv = document.uri.fsPath.match(/\.env(\.[a-zA-Z0-9_-]+)?$/i);
		if (!isCode && !isEnv) {
			return 0;
		}

		const text = document.getText();
		const diagnostics: vscode.Diagnostic[] = [];
		let vulnerabilities = 0;

		// CATEGORY 11: Architecture Red Flags - massive single files
		if (document.lineCount > 1000) {
			const range = new vscode.Range(0, 0, 0, 1);
			const diagnostic = new vscode.Diagnostic(range, 'Architecture Fragility: Massive single file detected (>1000 lines). Break this down into smaller components.', vscode.DiagnosticSeverity.Warning);
			diagnostic.code = 'architecture-fragility';
			diagnostic.source = 'ReadyOrNot';
			diagnostics.push(diagnostic);
			vulnerabilities++;
		}

		// CATEGORY 11: Architecture Red Flags - business logic/DB in frontend
		if (document.uri.fsPath.match(/\.(jsx|tsx)$/i)) {
			if (/import\s+.*\s+from\s+['"](?:pg|mysql|sqlite3|typeorm|mongoose)['"]/gi.test(text)) {
				const range = new vscode.Range(0, 0, 0, 1);
				const diagnostic = new vscode.Diagnostic(range, 'Architecture Fragility: Direct database calls or imports detected from client/frontend components.', vscode.DiagnosticSeverity.Warning);
				diagnostic.code = 'architecture-fragility-db';
				diagnostic.source = 'ReadyOrNot';
				diagnostics.push(diagnostic);
				vulnerabilities++;
			}
		}

		// JS/TS AST Parsing for higher accuracy rules
		let astReportedIds = new Set<string>();
		if (document.uri.fsPath.match(/\.(ts|js|jsx|tsx)$/i)) {
			try {
				const sourceFile = ts.createSourceFile(
					document.uri.fsPath,
					text,
					ts.ScriptTarget.Latest,
					true
				);

				const visit = (node: ts.Node) => {
					// Detect usage of eval()
					if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
						const startPos = document.positionAt(node.getStart(sourceFile));
						const endPos = document.positionAt(node.getEnd());
						const range = new vscode.Range(startPos, endPos);

						const rule = vulnerabilityRules.find(r => r.id === 'eval-usage');
						if (rule) {
							const diagnostic = new vscode.Diagnostic(range, rule.message, rule.vscodeSeverity);
							diagnostic.code = rule.id;
							diagnostic.source = 'ReadyOrNot';
							diagnostics.push(diagnostic);
							vulnerabilities++;
							// To avoid duplicate from regex later:
							// We can track the ranges or just skip the regex for this ID
						}
					}

					// Detect unexpectedly dangerouslySetInnerHTML
					if (ts.isJsxAttribute(node) && node.name.getText(sourceFile) === 'dangerouslySetInnerHTML') {
						const startPos = document.positionAt(node.getStart(sourceFile));
						const endPos = document.positionAt(node.getEnd());
						const range = new vscode.Range(startPos, endPos);

						const rule = vulnerabilityRules.find(r => r.id === 'dangerously-set-inner-html');
						if (rule) {
							const diagnostic = new vscode.Diagnostic(range, rule.message, rule.vscodeSeverity);
							diagnostic.code = rule.id;
							diagnostic.source = 'ReadyOrNot';
							diagnostics.push(diagnostic);
							vulnerabilities++;
						}
					}
					ts.forEachChild(node, visit);
				};
				visit(sourceFile);

				// Mark these rules as already processed by AST
				astReportedIds.add('eval-usage');
				astReportedIds.add('dangerously-set-inner-html');
			} catch (err) {
				// Fallback to regex if parsing utterly fails
			}
		}

		for (const rule of vulnerabilityRules) {
			if (astReportedIds.has(rule.id)) continue;

			let match;
			// Important: reset regex state so it searches from beginning of file
			rule.regex.lastIndex = 0;
			while ((match = rule.regex.exec(text)) !== null) {
				const startPos = document.positionAt(match.index);
				const endPos = document.positionAt(match.index + match[0].length);
				const range = new vscode.Range(startPos, endPos);

				const diagnostic = new vscode.Diagnostic(range, rule.message, rule.vscodeSeverity);
				diagnostic.code = rule.id; // Also maps back to the webview
				diagnostic.source = 'ReadyOrNot';
				diagnostics.push(diagnostic);
				vulnerabilities++;
			}
		}

		diagnosticCollection.set(document.uri, diagnostics);
		return vulnerabilities;
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
							totalVulnerabilities += scanDocument(document);

							// Populate our results array to pass to the Webview
							const diags = diagnosticCollection.get(uri);
							if (diags) {
								for (const d of diags) {
									// Determine true underlying severity for UI label mapping
									let truesev = 'Info';
									if (typeof d.code === 'string') {
										const matchedRule = vulnerabilityRules.find(r => r.id === d.code);
										if (matchedRule) {
											truesev = matchedRule.displaySeverity;
										} else if (d.code === 'architecture-fragility' || d.code === 'architecture-fragility-db') {
											truesev = 'Warning';
										}
									}

									allResults.push({
										file: vscode.workspace.asRelativePath(uri),
										line: d.range.start.line + 1,
										message: d.message,
										severity: truesev
									});
								}
							}
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
