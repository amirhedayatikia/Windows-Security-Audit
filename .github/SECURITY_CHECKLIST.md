# GitHub Public Repository Security Audit Checklist

## Core Security Requirements

### 1. Repository Hardening
- [ ] **Secret Scanning Enabled** - Go to Settings > Code Security and analysis > Secret scanning
- [ ] **Push Protection Enabled** - Blocks pushes containing secrets
- [ ] **Dependabot Alerts** - Enabled for vulnerable dependencies
- [ ] **Dependabot Security Updates** - Auto-generate PRs for security patches
- [ ] **Code Scanning** - Use CodeQL or another SAST tool
- [ ] **Branch Protection** - Main/master branch protected

### 2. Branch Protection Rules
- [ ] **Require pull request reviews** - Minimum 1 approval
- [ ] **Require status checks** - CI/CD must pass
- [ ] **Require linear history** - No merge commits
- [ ] **Restrict who can push** - Nobody directly to main
- [ ] **Require signed commits** - Optional but recommended
- [ ] **Allow force pushes** - Disabled
- [ ] **Allow deletions** - Disabled

### 3. Documentation
- [ ] **README.md** - Project description, installation, usage, license
- [ ] **LICENSE.md** - Clear open-source license (MIT, Apache 2.0, etc.)
- [ ] **CONTRIBUTING.md** - Workflow for external contributions
- [ ] **SECURITY.md** - How to report vulnerabilities privately
- [ ] **CODE_OF_CONDUCT.md** - Community standards
- [ ] **.env.example** - Template for environment variables (never commit .env)

### 4. Community Templates
- [ ] **Issue Templates** - Bug report, feature request
- [ ] **Pull Request Template** - Standard PR checklist
- [ ] **GitHub Actions** - CI validation workflow

### 5. Repository Configuration
- [ ] **Topics** - 3-5 relevant topics for discoverability
- [ ] **Description** - Clear one-line description
- [ ] **Website/Documentation** - Links if available
- [ ] **Git Ignore** - Appropriate templates for project type
- [ ] **No sensitive files** - .env, credentials, keys

### 6. Public Visibility Settings
- [ ] **Security & Analysis** - All security features enabled
- [ ] **Merge button** - Enabled (squash, rebase, or merge)
- [ ] **Delete branch** - Auto-delete after merge
- [ ] **Forking** - Allow innersource/forks for collaboration

## PowerShell-Specific Security Checklist

For PowerShell scripts in public repos:

### Script Content
- [ ] **Read-only only** - No system modifications
- [ ] **No hardcoded secrets** - Check for API keys, passwords, tokens
- [ ] **User prompts** - Ask before making any system changes
- [ ] **Error handling** - Graceful failure messages
- [ ] **Output validation** - Sanitize any user input
- [ ] **Code signing** - Consider signing scripts

### External API Calls
- [ ] **Use public endpoints** - No private/internal APIs
- [ ] **Rate limiting** - Handle API throttling gracefully
- [ ] **TLS enforcement** - Use HTTPS only
- [ ] **User-Agent header** - Identify the script properly
- [ ] **Timeout handling** - No infinite hangs

## Self-Check Scoring

Rate each item as:
- **✓** = Properly implemented
- **~** = Partial implementation / needs review
- **✗** = Missing

### Security Score: ___/25
### Documentation Score: ___/15
### Community Score: ___/10
### Total: ___/50

## Recommended Actions

Based on your score:
- **40-50**: Excellent! Repository is well-configured
- **30-39**: Good, but missing some best practices
- **20-29**: Needs improvements before public release
- **<20**: Not ready for public repository

---

## Usage in Claude Code

Run this check by using the skill: `/skill:github-security-check`

The skill will:
1. Automatically check for common missing files
2. Verify .gitignore exists and is appropriate
3. Check for potential secret leaks in code
4. Validate documentation completeness
5. Generate a compliance report
6. Recommend specific fixes

## References

- [GitHub Repository Best Practices](https://github.com/mattinannt/repository-best-practices)
- [GitHub Security Guide](https://docs.github.com/en/code-security)
- [OpenSSF Allstar](https://securityscorecards.github.io/OpenSSFAllstar/)