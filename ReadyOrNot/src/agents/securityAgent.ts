import * as ts from 'typescript';
import { Vulnerability, WorkspaceFile } from '../types/vulnerability';

/**
 * Security Agent:
 * Detects hardcoded secrets, eval() usage, dangerouslySetInnerHTML, and debug exposure.
 */
export async function runSecurityAgent(files: WorkspaceFile[]): Promise<Vulnerability[]> {
    const findings: Vulnerability[] = [];

    const secretRegex = /[a-zA-Z0-9_]*(?:password|secret|api_?key|apikey|token|auth_?key)[a-zA-Z0-9_]*\s*[:=]\s*(?:["'`][^"'`\r\n]+["'`]|(?!(?:true|false|null|undefined|process)\b)[a-zA-Z0-9_\-]{5,})/gi;
    const debugRegex = /(?:console\.log\s*\(\s*(?:token|password|secret|key)\s*\)|debug\s*=\s*true|\/test-route)/gi;

    for (const file of files) {
        // --- 1. AST Parsing for JS/TS/JSX/TSX ---
        let astParsedKeys = new Set<string>();
        if (file.fsPath.match(/\.(ts|js|jsx|tsx)$/i)) {
            try {
                const sourceFile = ts.createSourceFile(
                    file.fsPath,
                    file.content,
                    ts.ScriptTarget.Latest,
                    true
                );

                const visit = (node: ts.Node) => {
                    // Detect eval()
                    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'eval') {
                        const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                        findings.push({
                            id: 'eval-usage',
                            title: 'Unsafe eval() Execution',
                            severity: 'ERROR',
                            file: file.fsPath,
                            line: line + 1,
                            description: 'Usage of eval() detected, which makes your application susceptible to remote code execution (RCE).',
                            recommendation: 'Replace eval() with safe parsers like JSON.parse() or dedicated string formatters.',
                            agentSource: 'SecurityAgent'
                        });
                        astParsedKeys.add('eval-usage');
                    }

                    // Detect dangerouslySetInnerHTML
                    if (ts.isJsxAttribute(node) && node.name.getText(sourceFile) === 'dangerouslySetInnerHTML') {
                        const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
                        findings.push({
                            id: 'dangerously-set-inner-html',
                            title: 'XSS Vector: dangerouslySetInnerHTML',
                            severity: 'ERROR',
                            file: file.fsPath,
                            line: line + 1,
                            description: 'Found dangerouslySetInnerHTML property natively rendering unfiltered raw HTML to the DOM.',
                            recommendation: 'Refactor to standard React properties or securely sanitize input using DOMPurify before setting dangerously.',
                            agentSource: 'SecurityAgent'
                        });
                        astParsedKeys.add('dangerously-set-inner-html');
                    }
                    ts.forEachChild(node, visit);
                };
                visit(sourceFile);
            } catch (err) {
                // Silently skip AST failure and fallback to raw text if needed
            }
        }

        // --- 2. REGEX Analysis fallback / Secrets ---
        let match;
        // Search for secrets
        secretRegex.lastIndex = 0;
        while ((match = secretRegex.exec(file.content)) !== null) {
            const linesToMatch = file.content.substring(0, match.index).split('\n');
            const lineNumber = linesToMatch.length;
            findings.push({
                id: 'env-isolation',
                title: 'Hardcoded Secret Key',
                severity: 'ERROR',
                file: file.fsPath,
                line: lineNumber,
                description: 'Potential production key, API token, or secret hardcoded directly into source file.',
                recommendation: 'Move credentials into .env.local ignored files and access them dynamically via process.env.',
                agentSource: 'SecurityAgent'
            });
        }

        // Search for explicit Debug Exposure
        debugRegex.lastIndex = 0;
        while ((match = debugRegex.exec(file.content)) !== null) {
            const linesToMatch = file.content.substring(0, match.index).split('\n');
            const lineNumber = linesToMatch.length;
            findings.push({
                id: 'debug-exposure',
                title: 'Data Leak (Debug Mode)',
                severity: 'WARNING',
                file: file.fsPath,
                line: lineNumber,
                description: 'Identified explicitly exposed debug endpoints or unsafe logging of sensitive tokens.',
                recommendation: 'Wipe all development debug toggles and internal test routes before pushing to production branches.',
                agentSource: 'SecurityAgent'
            });
        }
    }

    return findings;
}
