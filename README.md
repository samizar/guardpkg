# GuardPkg

NPM package security guardian - protects against malware and suspicious packages.

[![npm version](https://badge.fury.io/js/guardpkg.svg)](https://www.npmjs.com/package/guardpkg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js CI](https://github.com/samizar/guardpkg/actions/workflows/node.js.yml/badge.svg)](https://github.com/samizar/guardpkg/actions/workflows/node.js.yml)
[![Security Rating](https://img.shields.io/badge/security-A+-brightgreen.svg)](https://github.com/samizar/guardpkg/security)
[![npm downloads](https://img.shields.io/npm/dw/guardpkg.svg)](https://www.npmjs.com/package/guardpkg)

## Features
- 🔍 Deep package analysis
- 🛡️ Automatic security checks during npm install
- 🚫 Malware detection
- 📊 Security scoring
- 🌲 Dependency tree analysis
- 🔐 Known vulnerability checks

## Installation

```bash
npm install -g guardpkg
```

## Usage

### Manual Package Check
Check packages before installation:
```bash
# Basic security check
guardpkg express

# Detailed analysis
guardpkg express --detailed

# Show only security score
guardpkg express --score-only

# Check specific version
guardpkg express --version 4.17.1
```

### Automated Protection
GuardPkg automatically checks packages during npm installations:
```bash
# Will trigger automatic security check
npm install express

# Force install (bypass security check)
npm install express --force
```

### Configuration
Configure automated protection settings:
```bash
# Enable/disable automatic checking
guardpkg config --auto-check true

# Set minimum security score (0-100)
guardpkg config --score-threshold 60

# Enable/disable installation blocking
guardpkg config --block-install true
```

## Security Checks
GuardPkg performs comprehensive security analysis including:
- Malicious code patterns
- Suspicious network behavior
- Cryptocurrency mining detection
- Code obfuscation
- Package manipulation
- Known exploits
- Dependency vulnerabilities
- Publisher trust score

## Exit Codes
- 0: Analysis completed successfully
- 1: Security check failed
- 2: Configuration error
- 3: Network error

## Contribution
Help us improve GuardPkg by contributing to the project. 
<a href="http://buymeacoffee.com/azgsami" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" height="41" width="174"></a>

## License
MIT
