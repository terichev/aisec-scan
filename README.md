# aisec-scan

**AI IDE Security Scanner** - Detect prompt injection vulnerabilities and malicious configurations in AI-powered development tools.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)

## Overview

AI-powered IDEs and CLI tools like Cursor, GitHub Copilot, Claude Code, and others are vulnerable to **prompt injection attacks** through configuration files. Attackers can embed malicious instructions in:

- MCP (Model Context Protocol) configurations
- Rules files (`.cursorrules`, `.windsurfrules`)
- VS Code tasks with auto-run enabled
- npm packages in the supply chain

This scanner detects these vulnerabilities before they can be exploited.

## Quick Start

### One-Line Install

```bash
curl -fsSL https://raw.githubusercontent.com/terichev/aisec-scan/main/install.sh | bash
```

### Manual Install

```bash
curl -o /usr/local/bin/aisec-scan https://raw.githubusercontent.com/terichev/aisec-scan/main/scan.sh
chmod +x /usr/local/bin/aisec-scan
```

### Run

```bash
# Scan current directory + global configs
aisec-scan

# Scan specific directory
aisec-scan ~/projects

# JSON output for CI/CD
aisec-scan -f json -o report.json

# SARIF for GitHub Security tab
aisec-scan -f sarif > results.sarif
```

## Supported Tools

| Tool | MCP | Rules | Settings | Supply Chain |
|------|-----|-------|----------|--------------|
| Cursor | ✅ | ✅ `.cursorrules` | ✅ | ✅ npm |
| VS Code + Copilot | ✅ | ✅ `copilot-instructions.md` | ✅ | ✅ npm |
| Claude Code | ✅ | ✅ `.claude/commands/` | ✅ | ✅ npm |
| Claude Desktop | ✅ | - | ✅ | - |
| Kilo Code | ✅ | ✅ `.kilocode/` | ✅ | ✅ npm |
| Windsurf | ✅ | ✅ `.windsurfrules` | ✅ | ✅ npm |
| Gemini CLI | - | ✅ `GEMINI.md` | ✅ | ✅ npm |
| Amazon Q | - | - | ✅ | ✅ npm |
| Aider | - | ✅ `.aider.conf.yml` | ✅ | ✅ pip |

## CVE Coverage

| CVE | Tool | CVSS | Description | Fixed |
|-----|------|------|-------------|-------|
| CVE-2025-54135 | Cursor | 8.6 | MCP config overwrite (CurXecute) | v1.3 |
| CVE-2025-54136 | Cursor | 7.2 | MCP trust bypass (MCPoison) | v1.3 |
| CVE-2025-59944 | Cursor | 8.1 | Case-sensitivity bypass | v1.7 |
| CVE-2025-53773 | Copilot | 7.5 | YOLO mode activation | latest |
| CVE-2025-54794 | Claude | 7.8 | Path restriction bypass | 0.2.111 |
| CVE-2025-54795 | Claude | 7.5 | Command injection bypass | 0.2.111 |
| CVE-2025-52882 | Claude | 8.8 | WebSocket auth bypass | latest |
| TRA-2025-47 | Windsurf | HIGH | Filename prompt injection | unpatched |

## What It Detects

### 1. MCP Configuration Attacks
- Malicious MCP servers with embedded commands
- Suspicious `curl`, `wget`, `nc` commands
- Unknown/untrusted MCP servers

### 2. Unicode Injection (Rules File Backdoor)
- Zero-width spaces (U+200B)
- Zero-width joiners (U+200D)
- Bidirectional text markers (U+202E)
- Hidden instructions in `.cursorrules`, etc.

### 3. Workspace Trust Bypass
- `runOn: folderOpen` in tasks.json
- `autoApprove: true` settings
- Disabled workspace trust

### 4. Supply Chain Attacks
- Known malicious npm packages (`sw-cur`, `aiide-cur`, etc.)
- Suspicious postinstall scripts
- Typosquatted package names

## Output Formats

### Text (Default)
```
╔══════════════════════════════════════════════════════════════════╗
║           AI IDE Security Scanner v2.0                           ║
╚══════════════════════════════════════════════════════════════════╝

SCAN SUMMARY
  Files scanned: 314
  [CRITICAL] 2 issues found
  [WARNING]  1 issues found
```

### JSON
```bash
aisec-scan -f json -o report.json
```

### SARIF (GitHub Security)
```bash
aisec-scan -f sarif > results.sarif
gh api repos/owner/repo/code-scanning/sarifs -X POST -F sarif=@results.sarif
```

### Markdown
```bash
aisec-scan -f markdown > SECURITY_REPORT.md
```

## CI/CD Integration

### GitHub Actions

```yaml
name: AI IDE Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install aisec-scan
        run: |
          curl -fsSL https://raw.githubusercontent.com/terichev/aisec-scan/main/scan.sh -o /usr/local/bin/aisec-scan
          chmod +x /usr/local/bin/aisec-scan

      - name: Run security scan
        run: aisec-scan -f sarif -o results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: aisec-scan
        name: AI IDE Security Scan
        entry: aisec-scan --quiet
        language: system
        pass_filenames: false
        always_run: true
```

## Command Reference

```
aisec-scan [OPTIONS] [DIRECTORY]

Options:
  -h, --help          Show help message
  -v, --version       Show version
  -q, --quiet         Minimal output (only critical issues)
  -f, --format FMT    Output format: text, json, sarif, markdown
  -o, --output FILE   Write report to file
  --no-color          Disable colored output
  --tools TOOLS       Scan specific tools only (comma-separated)
  --skip-npm          Skip npm package scanning
  --skip-global       Skip global configuration scanning

Exit Codes:
  0  No issues found
  1  Critical vulnerabilities found
  2  Warnings only
  3  Scanner error
```

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Adding New CVEs

CVE data is embedded in `scan.sh` for portability. To add new CVEs, edit the `CVE_DATABASE` variable:
```bash
CVE_DATABASE="
CVE-ID|tool|cvss|description|fixed_version
..."
```

### Adding Malicious Packages

Edit the `MALICIOUS_NPM_PACKAGES` array in `scan.sh`:
```bash
MALICIOUS_NPM_PACKAGES=(
    "new-malicious-package"
    ...
)
```

## Security

Found a vulnerability in aisec-scan itself? See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Pillar Security](https://pillar.security) - Rules File Backdoor research
- [Aim Security](https://aim-security.ai) - CurXecute discovery
- [Check Point Research](https://research.checkpoint.com) - MCPoison discovery
- [Lakera](https://lakera.ai) - Case-sensitivity vulnerability
- [Invariant Labs](https://invariant.dev) - mcp-scan tool

---

**Disclaimer**: This tool is for defensive security purposes only. Always follow responsible disclosure when finding vulnerabilities.
