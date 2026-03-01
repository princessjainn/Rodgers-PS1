const regex = /[a-zA-Z0-9_]*(?:password|secret|api_?key|apikey|token|auth_?key)[a-zA-Z0-9_]*\s*[:=]\s*(?:["'`][^"'`\r\n]+["'`]|(?!(?:true|false|null|undefined|process)\b)[a-zA-Z0-9_\-]{5,})/gi;

console.log(regex.exec('const OPENAI_API_KEY = "sk-123"'));
regex.lastIndex = 0;
console.log(regex.exec('GEMINI_API_KEY=AIzaSy12345'));
regex.lastIndex = 0;
console.log(regex.exec('const apiKey = process.env.KEY')); // Should NOT match or should only match part? Wait, process dot has dots, so it fails the unquoted match which only allows [a-zA-Z0-9_\-]! So it returns null!
regex.lastIndex = 0;
console.log(regex.exec('apiKey = myTokenHash123')); // Matches; acceptable false pos since it looks like a hash
regex.lastIndex = 0;
