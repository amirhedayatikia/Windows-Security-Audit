# Contributing to Windows 11 CVE Security Audit

Thank you for your interest in contributing to this project! This document provides guidelines and instructions for contributing.

## How to Contribute

### Reporting Issues

1. **Bug Reports**: Use the "Bug Report" issue template. Provide detailed steps to reproduce the issue.
2. **Feature Requests**: Use the "Feature Request" issue template. Describe the use case and desired behavior.
3. **Security Issues**: Report privately via the security policy (see SECURITY.md) rather than opening a public issue.

### Submitting Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/awesome-feature`
3. Make your changes
4. Run the audit locally to verify: `powershell.exe -ExecutionPolicy Bypass -File win11-cve-audit.ps1`
5. Commit your changes following conventional commits
6. Push to your fork and submit a PR

### Pull Request Guidelines

- Fill out the PR template completely
- Keep changes focused and atomic
- Update documentation if needed
- Ensure the script remains read-only (no system modifications)
- Test on multiple Windows 11 builds if possible

## Development Setup

No installation required. The tool is a single PowerShell script that runs on any Windows 11 machine with PowerShell 5.1+.

## Code Style Guidelines

- Use PowerShell's standard naming conventions (Verb-Noun for functions)
- Keep functions short and focused
- Handle errors gracefully with try/catch blocks
- Comment "why" not "what"
- No hardcoded secrets or credentials

## Questions?

Open an issue with the "Question" label for questions about contribution or development.