import { WorkspaceFile, FinalAuditReport, Vulnerability } from '../types/vulnerability';

import { runSecurityAgent } from '../agents/securityAgent';
import { runDependencyAgent } from '../agents/dependencyAgent';
import { runComplianceAgent } from '../agents/complianceAgent';
import { runAiRiskAgent } from '../agents/aiRiskAgent';
import { runArchitectureAgent } from '../agents/architectureAgent';
import { runScoringAgent } from '../agents/scoringAgent';

/**
 * Agent Orchestrator:
 * Single entry point handling workspace batching and executing analysis agents sequentially
 * or concurrently, guaranteeing standardized structural outputs.
 */
export async function runAudit(files: WorkspaceFile[]): Promise<FinalAuditReport> {
    const allFindings: Vulnerability[] = [];

    // Run agents completely isolated from each other across all files
    // Wait for all specialized agents to finish their independent scans
    const [
        securityFindings,
        dependencyFindings,
        complianceFindings,
        aiRiskFindings,
        architectureFindings
    ] = await Promise.all([
        runSecurityAgent(files),
        runDependencyAgent(files),
        runComplianceAgent(files),
        runAiRiskAgent(files),
        runArchitectureAgent(files)
    ]);

    // Aggregate massive pool of intelligence results
    allFindings.push(
        ...securityFindings,
        ...dependencyFindings,
        ...complianceFindings,
        ...aiRiskFindings,
        ...architectureFindings
    );

    // Filter duplicates dynamically (e.g. if two agents catch the same line/id accidentally)
    const uniqueFindings = allFindings.filter((finding, index, self) =>
        index === self.findIndex(t => (
            t.id === finding.id && t.file === finding.file && t.line === finding.line
        ))
    );

    // Score the aggregate logic and yield the final GO/NO-GO platform report
    return runScoringAgent(uniqueFindings);
}
