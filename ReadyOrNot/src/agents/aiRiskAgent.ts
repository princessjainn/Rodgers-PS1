import { Vulnerability, WorkspaceFile } from '../types/vulnerability';

/**
 * AI Risk Agent:
 * Evaluates possible LLM prompt injections or raw inputs sent to AI SDKs without guards.
 */
export async function runAiRiskAgent(files: WorkspaceFile[]): Promise<Vulnerability[]> {
    const findings: Vulnerability[] = [];

    // Simple heuristic catching OpenAI style prompt injection vectors: 
    // Example: `prompt: "Translate this text: " + userInput`
    const promptInjectionRegex = /(?:messages|prompt)[\s:={\[]+.*?[\$`]\{?(?:input|userInput|query|message)\}?.*?}/gi;

    for (const file of files) {
        if (!file.fsPath.match(/\.(ts|js|py)$/i)) continue;

        let match;
        promptInjectionRegex.lastIndex = 0;

        while ((match = promptInjectionRegex.exec(file.content)) !== null) {
            const numLines = file.content.substring(0, match.index).split('\n').length;
            findings.push({
                id: 'ai-prompt-injection',
                title: 'AI Code Risk: Prompt Injection Vulnerability',
                severity: 'WARNING',
                file: file.fsPath,
                line: numLines,
                description: 'Detected raw user input being directly appended or interpolated into an LLM prompt.',
                recommendation: 'Sanitize input thoroughly. Provide strict system boundaries or utilize explicit function calling rather than relying on unstructured text parsing from clients.',
                agentSource: 'AiRiskAgent'
            });
        }
    }

    return findings;
}
