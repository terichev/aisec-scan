# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in aisec-scan, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Use GitHub's private vulnerability reporting: [Report a vulnerability](https://github.com/terichev/aisec-scan/security/advisories/new)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

## Scope

This policy covers:
- The aisec-scan script itself
- Installation mechanisms
- Documentation that could lead to security issues

## Out of Scope

- Vulnerabilities in the tools being scanned (Cursor, VS Code, etc.)
- Social engineering attacks
- Denial of service

## Recognition

We appreciate responsible disclosure and will credit reporters in release notes (unless you prefer anonymity).

## Security Best Practices

When using aisec-scan:

1. **Verify the download** - Check the script before running:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/terichev/aisec-scan/main/scan.sh | less
   ```

2. **Use pinned versions** in CI/CD:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/terichev/aisec-scan/v2.0.0/scan.sh
   ```

3. **Review scan results** - False positives are possible; verify findings manually

4. **Keep updated** - Check for new versions regularly
