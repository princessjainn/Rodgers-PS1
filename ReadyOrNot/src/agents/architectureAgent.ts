import { Vulnerability, WorkspaceFile } from '../types/vulnerability';

/**
 * Architecture Agent:
 * Checks code maintainability flags and anti-patterns like frontend DB connections.
 */
export async function runArchitectureAgent(files: WorkspaceFile[]): Promise<Vulnerability[]> {
    const findings: Vulnerability[] = [];

    const serverDbImports = /(?:import|require).*?['"](pg|mysql|mysql2|sequelize|typeorm|mongoose)['"]/gi;

    for (const file of files) {
        // Massive monolithic files
        const lines = file.content.split('\n');
        if (lines.length > 1000) {
            findings.push({
                id: 'architecture-fragility',
                title: 'Architecture Fragility: God Object',
                severity: 'WARNING',
                file: file.fsPath,
                line: 1, // Overall file issue
                description: 'Massive monolithic file detected (>1000 lines).',
                recommendation: 'Break this module down into smaller, composable elements for testing and maintainability.',
                agentSource: 'ArchitectureAgent'
            });
        }

        // Frontend importing DB directly
        if (file.fsPath.match(/\.(tsx|jsx)$/i)) { // Standard React/Next pattern
            let match;
            serverDbImports.lastIndex = 0;
            while ((match = serverDbImports.exec(file.content)) !== null) {
                const numLines = file.content.substring(0, match.index).split('\n').length;
                findings.push({
                    id: 'architecture-fragility-db',
                    title: 'Severe Anti-Pattern: Frontend DB Access',
                    severity: 'ERROR',
                    file: file.fsPath,
                    line: numLines,
                    description: `Client UI file directly imports server-side DB client '${match[1]}'.`,
                    recommendation: 'Refactor this logic into a dedicated backend API route or Server Component/Action layer.',
                    agentSource: 'ArchitectureAgent'
                });
            }
        }
    }

    return findings;
}
