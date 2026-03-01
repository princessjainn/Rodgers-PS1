#!/usr/bin/env node
const { execSync } = require('child_process');

console.log("🛡️ Booting ReadyOrNot Scanner inside VS Code...");
try {
    // This executes the URL handler which talks to the running VS Code instance
    execSync('code --open-url vscode://command/readyornot.scanVulnerabilities', { stdio: 'inherit' });
    console.log("✅ Scan dispatched to VS Code Editor Panel!");
} catch (e) {
    console.error("❌ Failed to contact VS Code.");
    console.error("Please make sure VS Code is currently open, and the 'code' command is available in your PATH.");
}
