# ReadyOrNot 🛡️

A next-generation VS Code extension that dynamically audits your codebase in real-time, checking for critical security vulnerabilities, architectural fragility, environment misconfigurations, and AI privacy leakage.

## Features ✨
- **Zero Configuration:** Simply install and it instantly begins analyzing your JS, TS, React, and Python files.
- **Deep Gitignore Integration:** Seamlessly respects your `.gitignore` configuration for lighting-fast scans.
- **AST-Enhanced Parsing:** Replaces noisy regex checks with exact Abstract Syntax Tree evaluation for complex rules.
- **Glassmorphism Analytics Dashboard:** Launch the report window for a sorted, interactive overview of the health of your project.

## Usage
- Open any workspace and start writing code. ReadyOrNot will silently audit your files.
- To open the detailed report dashboard:
  1. Click the **Shield Icon** (🛡️) located in the editor title bar.
  2. Or, open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and type `ReadyOrNot: Open Editor Panel`.
  3. Clicking on any issue location inside the dashboard instantly highlights the exact faulty line inside your editor.

## Limitations & False Positives 🚨
No automated tool is perfect. ReadyOrNot is designed to fail safe by bringing potential risks to your attention.
- **False Positives:** Broad rules like API key detection might flag harmless randomized strings or test hashes. Similarly, generic SQL query strings might trigger injection warnings. Use your judgment!
- **Mitigation:** If a rule is consistently noisy, simply add the file extension to `.gitignore` to mute it entirely for that project.
- **Scope:** Deeply nested dynamic variables inside massive loops or chained functions might go undetected. Always complement static analysis with code review.

## Support & Reporting
To report false positives or suggest improvements, please visit our repository issue tracker!

Enjoy coding securely.
