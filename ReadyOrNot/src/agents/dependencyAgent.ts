import { Vulnerability, WorkspaceFile } from '../types/vulnerability';

/**
 * Dependency Agent:
 * Scans your node modules / package configs for outdated or blacklisted/unsafe dependencies.
 */
export async function runDependencyAgent(files: WorkspaceFile[]): Promise<Vulnerability[]> {
    const findings: Vulnerability[] = [];
    const blacklistedDeps = ['request', 'left-pad', 'crypto-js'];
    // Usually companies have their own internal known-bad lists or rely on npm audit wrappers

    for (const file of files) {
        if (!file.fsPath.endsWith('package.json')) continue;

        try {
            const pkg = JSON.parse(file.content);
            const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };

            for (const dep of Object.keys(deps)) {
                if (blacklistedDeps.includes(dep)) {
                    findings.push({
                        id: 'blacklisted-dependency',
                        title: 'Deprecated / Unsafe Dependency',
                        severity: 'WARNING',
                        file: file.fsPath,
                        line: 1, // Usually package.json errors are tied globally to the file
                        description: `The package '${dep}' is blacklisted due to known vulnerabilities, deprecation, or poor maintenance.`,
                        recommendation: `Remove '${dep}' and migrate to natively secure alternatives (e.g., Node's native 'fetch' or 'axios').`,
                        agentSource: 'DependencyAgent'
                    });
                }
            }

        } catch (e) {
            findings.push({
                id: 'malformed-package-json',
                title: 'Malformed Dependency Manifest',
                severity: 'INFO',
                file: file.fsPath,
                line: 1,
                description: 'The package.json file could not be parsed as valid JSON.',
                recommendation: 'Fix JSON formatting to allow NPM and scanners to install dependencies properly.',
                agentSource: 'DependencyAgent'
            });
        }
    }

    return findings;
}
