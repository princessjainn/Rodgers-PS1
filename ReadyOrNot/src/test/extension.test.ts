import * as assert from 'assert';
import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

suite('ReadyOrNot Extension Test Suite', () => {
	vscode.window.showInformationMessage('Start all tests.');

	test('Extension should activate successfully', async () => {
		const ext = vscode.extensions.getExtension('ready-or-not.ready-or-not');
		assert.ok(ext, 'Extension should be present in the host');
		if (!ext.isActive) {
			await ext.activate();
		}
		assert.ok(ext.isActive, 'Extension should be actively running');
	});

	test('Should detect eval vulnerability via AST and keys via Regex', async () => {
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!workspaceRoot) {
			assert.fail('Tests must run inside a valid workspace sandbox');
		}

		const testFilePath = path.join(workspaceRoot, 'vulnerable_code_test.ts');
		fs.writeFileSync(testFilePath, 'eval("console.log(1)");\nconst STRIPE_SECRET_KEY = "sk-test-12345";\nconst html = <div dangerouslySetInnerHTML={{ __html: "dirty" }} />;', 'utf8');

		const uri = vscode.Uri.file(testFilePath);
		const doc = await vscode.workspace.openTextDocument(uri);
		await vscode.window.showTextDocument(doc);

		// Yielding execution to allow real-time diagnostic watcher to run and parse AST
		await new Promise(resolve => setTimeout(resolve, 3000));

		const diags = vscode.languages.getDiagnostics(uri).filter(d => d.source === 'ReadyOrNot');

		const evalRule = diags.find(d => d.code === 'eval-usage');
		assert.ok(evalRule, 'AST Parser: failed to detect eval() usage');
		assert.strictEqual(evalRule?.severity, vscode.DiagnosticSeverity.Warning, 'Severity must be Warning (Yellow)');

		const dangerouslyRule = diags.find(d => d.code === 'dangerously-set-inner-html');
		assert.ok(dangerouslyRule, 'AST Parser: failed to detect dangerouslySetInnerHTML property');

		const keyRule = diags.find(d => d.code === 'env-isolation');
		assert.ok(keyRule, 'Regex Engine: failed to detect hardcoded API key (STRIPE_SECRET_KEY)');

		// Cleanup
		fs.unlinkSync(testFilePath);
	}).timeout(15000);

	test('Should actively respect and apply .gitignore exclusion rules', async () => {
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (!workspaceRoot) return;

		// Backup real gitignore
		const gitignorePath = path.join(workspaceRoot, '.gitignore');
		let originalGitignore = '';
		if (fs.existsSync(gitignorePath)) {
			originalGitignore = fs.readFileSync(gitignorePath, 'utf8');
		}

		try {
			fs.appendFileSync(gitignorePath, '\n*.ignoredtestfile\n');

			const testFilePath = path.join(workspaceRoot, 'secret_pass.ignoredtestfile');
			// This typically flags env-isolation
			fs.writeFileSync(testFilePath, 'const OPENAI_API_KEY = "sk-xyz123";', 'utf8');

			const uri = vscode.Uri.file(testFilePath);
			// We command an open which fires real-time watcher
			await vscode.workspace.openTextDocument(uri);

			// Also trigger bulk loop
			await vscode.commands.executeCommand('readyornot.scanVulnerabilities');

			await new Promise(resolve => setTimeout(resolve, 3000));

			const diags = vscode.languages.getDiagnostics(uri);
			const extDiags = diags.filter(d => d.source === 'ReadyOrNot');

			// Because of the 'ignore' library and gitignore update, it must skip parsing this file
			assert.strictEqual(extDiags.length, 0, 'Scanner failed to ignore a file strictly blocked by .gitignore');

			// Cleanup test asset
			fs.unlinkSync(testFilePath);
		} finally {
			// Restore original
			fs.writeFileSync(gitignorePath, originalGitignore, 'utf8');
		}
	}).timeout(20000);
});
