// src/utils/patterns.js

exports.patterns = {
  // Data exfiltration patterns
  dataExfiltration: [
    /process\.env/,
    /require\(['"]child_process['"]\)/,
    /\.exec\(|\.execSync\(/,
    /https?:\/\/[^/"]+(\/[^"]*)?/g,
    /new WebSocket\(/,
    /require\(['"]request['"]\)/,
    /require\(['"]axios['"]\)/,
    /require\(['"]http['"]\)/,
    /require\(['"]https['"]\)/,
    /fetch\(/,
    /XMLHttpRequest/,
    /socket\./,
    /\.send\(/,
    /\.upload\(/,
    /\.post\(/,
    /\.put\(/,
    /navigator\.sendBeacon/
  ],
  
  // Malicious code patterns
  maliciousCode: [
    /eval\(|new Function\(/,
    /base64/i,
    /\\x[0-9a-f]{2}/i,
    /fromCharCode/,
    /createElement\(['"]script['"]\)/,
    /document\.write/,
    /\[\s*\]\[['"]\w+['"]\]/,  // [][ ] notation
    /Function\(.*return.*\)/,
    /setTimeout\(.*eval/,
    /setInterval\(.*eval/,
    /with\s*\(/,
    /debugger/,
    /\bshell\b/,
    /\bcmd\b/,
    /\bpowersh/i,
    /document\.location\s*=/,
    /window\.location\s*=/,
    /window\.open\(/,
    /document\.cookie/
  ],
  
  // System access patterns
  systemAccess: [
    /require\(['"]fs['"]\)/,
    /require\(['"]path['"]\)/,
    /require\(['"]os['"]\)/,
    /process\.binding/,
    /require\(['"]child_process['"]\)/,
    /require\(['"]cluster['"]\)/,
    /require\(['"]worker_threads['"]\)/,
    /process\.kill/,
    /process\.exit/,
    /process\.env/,
    /process\.cwd/,
    /process\.chdir/,
    /global\./,
    /require\(['"]systeminformation['"]\)/,
    /require\(['"]sudo-prompt['"]\)/,
    /require\(['"]registry-js['"]\)/
  ],
  
  // Cryptocurrency mining patterns
  cryptoMining: [
    /CryptoNight/i,
    /stratum\+tcp/,
    /minerAddress/,
    /hashrate/i,
    /webpack\.min\.js/,
    /coinhive/i,
    /cryptonight/i,
    /minero/i,
    /miner\.start/i,
    /webassembly\.memory/i,
    /mining-pool/i,
    /pool\.supportxmr/i,
    /electroneum/i,
    /monero/i,
    /xmr\b/i
  ],
  
  // Obfuscation patterns
  obfuscation: [
    /^[a-zA-Z$_][a-zA-Z0-9$_]{0,2}$/, // Suspicious short variable names
    /\[['"]\w+['"]\]\[['"]\w+['"]\]/, // Nested bracket notation
    /\\u[0-9a-f]{4}/i, // Unicode escapes
    /\\x[0-9a-f]{2}/i, // Hex escapes
    /\w{50,}/, // Very long identifiers
    /[^\w\s{}\(\);\[\]]{10,}/, // Long sequences of special characters
    /\([^)]+\)\s*\([^)]+\)/, // Multiple parentheses
    /\+[\s\r\n]*\+[\s\r\n]*\+/, // String concatenation obfuscation
    /\\\\[0-7]{3}/, // Octal escapes
    /(?:\{|\[)\s*(?:\}|\])\s*\(/, // IIFE obfuscation
    /\b(atob|btoa)\b/, // Base64 encoding/decoding
    /String\.fromCharCode\((?:\d+\s*,\s*)*\d+\)/ // Character code arrays
  ],

  // Package manipulation patterns
  packageManipulation: [
    /package\.json/,
    /npm\s+install/,
    /npm\s+publish/,
    /npm\s+config/,
    /npmrc/,
    /yarn\s+add/,
    /node_modules/,
    /\.npmignore/,
    /prepublish/,
    /postinstall/,
    /preinstall/
  ],

  // Persistence patterns
  persistence: [
    /\.bashrc/,
    /\.bash_profile/,
    /\.profile/,
    /\.zshrc/,
    /crontab/,
    /pm2/,
    /forever/,
    /systemctl/,
    /launchctl/,
    /startup/,
    /autostart/,
    /registry/i
  ],

  // Anti-debugging patterns
  antiDebugging: [
    /debugger\s*;/,
    /console\s*\.\s*(clear|debug|trace|log)/,
    /performance\s*\.\s*now/,
    /Date\s*\.\s*now/,
    /process\s*\.\s*hrtime/,
    /chrome\s*\.\s*debugger/,
    /sourceURL/,
    /sourceMappingURL/
  ],

  // Fingerprinting patterns
  fingerprinting: [
    /navigator\.userAgent/,
    /screen\.(width|height|availWidth|availHeight)/,
    /navigator\.platform/,
    /navigator\.language/,
    /navigator\.languages/,
    /navigator\.cookieEnabled/,
    /navigator\.doNotTrack/,
    /canvas\.toDataURL/,
    /webgl/i,
    /navigator\.hardwareConcurrency/
  ],

  // Environment detection patterns
  environmentDetection: [
    /process\.platform/,
    /process\.arch/,
    /process\.version/,
    /process\.versions/,
    /process\.release/,
    /process\.env\.NODE_ENV/,
    /process\.env\.PATH/,
    /process\.env\.HOME/,
    /process\.env\.USER/
  ],

  // Known exploit patterns
  knownExploits: [
    /prototype\.pollution/i,
    /\.__proto__/,
    /Object\.prototype/,
    /constructor\.prototype/,
    /\[\s*'constructor'\s*\]/,
    /\[\s*'__proto__'\s*\]/,
    /Buffer\.allocUnsafe/,
    /child_process\.fork/,
    /vm\.runInContext/
  ]
};

// Common malicious file names
exports.maliciousFiles = [
  'mining.js',
  'inject.js',
  'backdoor.js',
  'payload.js',
  'exploit.js',
  'shell.js',
  'hack.js',
  'trojan.js',
  'malware.js',
  'keylogger.js',
  'stealer.js',
  'cipher.js',
  'encrypt.js',
  'decrypt.js',
  'ransom.js',
  'payload.min.js',
  'hidden.js',
  'secret.js',
  'botnet.js',
  'RAT.js'
];

// Suspicious package names
exports.suspiciousPackageNames = [
  'test',
  'temp',
  'tmp',
  'free',
  'trial',
  'crack',
  'hack',
  'patch',
  'keygen',
  'loader',
  'unofficial',
  'modified',
  'cracked',
  'pirated',
  'nulled',
  'warez'
];

// Suspicious script commands
exports.suspiciousCommands = [
  'curl',
  'wget',
  'eval',
  'exec',
  'download',
  'http',
  'env',
  'export',
  'sudo',
  'chmod',
  'chown',
  'rm -rf',
  'del /f',
  'format',
  'reg add',
  'regedit',
  'netsh',
  'iptables',
  'nc',
  'ncat',
  'telnet'
];

// Pattern severity levels
exports.patternSeverity = {
  dataExfiltration: 'high',
  maliciousCode: 'critical',
  systemAccess: 'high',
  cryptoMining: 'critical',
  obfuscation: 'medium',
  packageManipulation: 'medium',
  persistence: 'high',
  antiDebugging: 'low',
  fingerprinting: 'low',
  environmentDetection: 'low',
  knownExploits: 'critical'
};

// Helper function to check multiple patterns
exports.checkPatterns = (content, patternSet) => {
  const matches = [];
  for (const pattern of patternSet) {
    if (pattern.test(content)) {
      matches.push(pattern.toString());
    }
  }
  return matches;
};