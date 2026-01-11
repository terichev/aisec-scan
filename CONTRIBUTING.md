# Contributing to aisec-scan

Thank you for your interest in contributing to aisec-scan!

## How to Contribute

### Reporting Issues

- Check if the issue already exists in [GitHub Issues](https://github.com/terichev/aisec-scan/issues)
- Use the appropriate issue template
- Include reproduction steps and environment details

### Feature Requests

Open an issue with:
- Clear description of the feature
- Use case and expected behavior
- Any relevant CVE or security research

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test your changes (see Testing section)
5. Commit with clear messages
6. Push to your fork
7. Open a Pull Request

### Code Style

- Follow existing bash coding style
- Use `shellcheck` for linting
- Keep functions focused and well-commented
- Prefer readability over cleverness

### Testing

Before submitting:

```bash
# Run the scanner
./scan.sh

# Test all output formats
./scan.sh -f json
./scan.sh -f sarif
./scan.sh -f markdown

# Test with shellcheck (if available)
shellcheck scan.sh
```

### Adding New Detections

1. **New CVE**: Add to `CVE_DATABASE` variable in `scan.sh`
2. **Malicious package**: Add to `MALICIOUS_NPM_PACKAGES` array
3. **Detection pattern**: Add to appropriate check function

## Development Setup

```bash
git clone https://github.com/terichev/aisec-scan.git
cd aisec-scan
chmod +x scan.sh
./scan.sh --help
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
