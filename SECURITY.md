# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

Thank you for helping keep this project and its users safe. Please report security vulnerabilities privately so we can properly address them before disclosing to the public.

### How to Report

**Preferred method**: Create a private security advisory on GitHub using the "Report a vulnerability" button in the repository's Security tab.

**Steps**:
1. Go to the Security tab of this repository
2. Click "Report a vulnerability"
3. Fill out the form with details

### What to Include

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Potential impact
- Any suggested remediation (optional)

### Response Timeline

- Initial response within **48 hours**
- We will acknowledge receipt of your report
- We will provide an assessment and timeline for fixes

### Disclosure Policy

- We ask that you give us **90 days** to investigate and fix the vulnerability
- We will credit you in the security advisory (unless you prefer anonymity)
- We will coordinate public disclosure after the fix is available

## Known Security Considerations

This project is intentionally designed to be a **read-only security audit tool**:

1. **No system modifications**: The script only reads registry, system information, and public APIs
2. **No data collection**: No telemetry or usage data is collected
3. **No external dependencies**: All functionality is implemented in pure PowerShell
4. **Public APIs only**: All external API calls are to publicly documented services

## Security Best Practices for Users

When running this audit tool:

1. Run from a trusted source - verify the script's integrity
2. Review the commands it executes before running
3. Ensure you trust your network connection (for API calls)
4. Check the generated security-audit-report.md for any sensitive data before sharing

## Reporting Your Own Security Findings

If you discover a security issue while using this tool, please report it through the same channels. This helps us improve the security posture for all users.

Thank you for your responsible disclosure!