import { Vulnerability, WorkspaceFile } from '../types/vulnerability';

/**
 * Compliance Agent:
 * Targets Personally Identifiable Information (PII) leakage and unsafe logging protocols.
 */
export async function runComplianceAgent(files: WorkspaceFile[]): Promise<Vulnerability[]> {
    const findings: Vulnerability[] = [];

    // Basic PII or unsafe logging detectors
    const piiRegex = /(?:console\.log|Logger\.(?:info|error))\s*\(\s*(?:.*)(?:user|ssn|social_?security|credit_?card|passport)\b\s*\)/gi;
    const basicLoggingRule = /console\.(log|error|info)\s*\(/gi;

    for (const file of files) {
        if (!file.fsPath.match(/\.(ts|js|jsx|tsx|py)$/i)) continue;

        let match;

        // Find heavy PII leakage
        piiRegex.lastIndex = 0;
        while ((match = piiRegex.exec(file.content)) !== null) {
            const numLines = file.content.substring(0, match.index).split('\n').length;
            findings.push({
                id: 'pii-leakage',
                title: 'Compliance: PII Data Logging',
                severity: 'ERROR',
                file: file.fsPath,
                line: numLines,
                description: 'Logging explicit Personally Identifiable Information (PII) directly to console output violates GDPR and SOC2 compliance.',
                recommendation: 'Mask all sensitive data elements (e.g. hash passports and strings) prior to logging out.',
                agentSource: 'ComplianceAgent'
            });
        }

        // Broad monitoring failure
        basicLoggingRule.lastIndex = 0;
        while ((match = basicLoggingRule.exec(file.content)) !== null) {
            const numLines = file.content.substring(0, match.index).split('\n').length;
            findings.push({
                id: 'observability-failure',
                title: 'Operational Visibility Risk',
                severity: 'INFO',
                file: file.fsPath,
                line: numLines,
                description: `Raw usage of ${match[0]}... is not reliable for scalable tracing in production.`,
                recommendation: 'Recommend using a dedicated monitoring/logging framework (e.g., Winston, Sentry, Datadog) instead of native STDOUT buffers.',
                agentSource: 'ComplianceAgent'
            });
        }
    }

    return findings;
}
