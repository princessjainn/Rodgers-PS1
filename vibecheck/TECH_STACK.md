# ReadyOrNot 🛡️ - Technology Stack

Here is the complete outline of the technologies, languages, and frameworks powering the **ReadyOrNot** VS Code extension.

## 🧱 Core Architecture & Language
- **TypeScript (`v5.9.3`)**: The entire extension is strictly typed for robust development, static error checking, and seamless interaction with the VS Code API.
- **Node.js (`v22.x` environment)**: Serves as the Javascript runtime foundation backing the extension.
- **VS Code Extension API (`^1.109.0`)**: The official Microsoft API used for natively interacting with the editor (Diagnostics, Webviews, File System parsing, and Editor Commands).

## ⚙️ Scanning & Parsing Engine
- **TypeScript Compiler API (AST)**: Powers the semantic understanding of the code. Instead of guessing with regex, the extension constructs an **Abstract Syntax Tree (AST)** to natively read JavaScript/TypeScript files and pinpoint explicit syntax like `eval()` usage and React's `dangerouslySetInnerHTML`.
- **RegEx Engine**: A finely tuned suite of Regular Expressions handling generic string parsing for other file types, like `.env` configurations and Python files, to scan for hardcoded keys and environment misconfigurations.

## 🗄️ File Processing & Ignore Logic
- **`ignore` (`v7.0.5`)**: A highly specialized NPM library replicating exactly how Git natively processes `.gitignore` rules. This allows the extension to read `.gitignore` patterns and drop non-essential files before they reach the scanning engine.
- **`vscode.workspace.findFiles()`**: Hardware-accelerated search natively provided by VS Code to aggressively block heavyweight folders like `node_modules` and `.vscode-test` directly in C++ memory for massive performance boosts.

## 💎 Frontend UI (Webview Dashboard)
- **Vanilla HTML/CSS/JS**: Designed entirely without heavy frameworks (like React or Vue) to ensure the analytical dashboard boots offline in single-digit milliseconds.
- **Glassmorphism CSS Design**: Custom-built styling utilizing modern visual techniques like `backdrop-filter: blur()`, CSS hover animations, semi-transparent backgrounds, and drop shadows to achieve a highly premium look.
- **Google Fonts (Outfit)**: A geometric sans-serif font injected to give the dashboard a clean, modernized aesthetic.
- **Strict Content-Security-Policy (CSP)**: Utilizes randomly-generated cryptographic `nonces` for inline scripting to lock down against injection vulnerabilities inside VS Code.

## 🧪 Testing & Quality Assurance
- **Mocha (`@types/mocha`)**: The core behavioral testing framework.
- **`@vscode/test-electron` (`v2.5.2`)**: The official test runner that spawns a headless, isolated simulated instance of VS Code to natively trigger real integration tests (like mimicking opening and scanning documents).
- **ESLint (`v9.39.2`) & `typescript-eslint`**: Used extensively to maintain strict code hygiene and catch logic bugs before packaging.

## 📦 Build & Packaging Tools
- **`tsc` (TypeScript Compiler)**: Actively watches and compiles your extension into runtime Javascript in the `/out/` directory.
- **`@vscode/vsce`**: The official Microsoft Visual Studio Code Extension Manager CLI used to bundle, compress, and natively package the source code into the final `.vsix` installer artifact.
