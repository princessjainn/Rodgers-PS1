import { FinalAuditReport, Vulnerability } from '../types/vulnerability';

/**
 * Scoring Agent:
 * Takes aggregated findings from all intelligence modules to compute a holistic 
 * deployment security score and decision.
 */
export function runScoringAgent(vulnerabilities: Vulnerability[]): FinalAuditReport {
    let errorCount = 0;
    let warningCount = 0;
    let infoCount = 0;

    for (const v of vulnerabilities) {
        if (v.severity === 'ERROR') errorCount++;
        else if (v.severity === 'WARNING') warningCount++;
        else infoCount++;
    }

    // Default perfect score
    let score = 100;

    // Penalize heavily for direct errors, moderately for warnings, minimally for info
    score -= (errorCount * 25);
    score -= (warningCount * 10);
    score -= (infoCount * 2);

    // Floor score at 0
    score = Math.max(0, score);

    // Strictly forbid deployment on Errors or terrible scores
    const decision = (errorCount > 0 || score < 50) ? 'NO-GO' : 'GO';

    return {
        vulnerabilities,
        scoreDetails: {
            totalVulnerabilities: vulnerabilities.length,
            errorCount,
            warningCount,
            infoCount,
            finalScore: score,
            decision
        },
        timestamp: new Date().toISOString()
    };
}
