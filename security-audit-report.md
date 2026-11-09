# Windows 11 Security Audit Report
*Generated: 2026-11-09*

## Executive Summary

| Metric | Value |
|--------|-------|
| OS | Windows 11 Home 10.0.26200 (Build 9711) |
| Last Boot | 2026-11-02 10:23 |
| Defender | AV, Real-time, Behavior Monitor, Tamper Protection all enabled (signatures updated 2026-11-08) |
| BitLocker | Not enabled |
| Firewall | All profiles enabled |
| RDP | Disabled |

---

## 1. Microsoft Windows CVE Coverage (CISA KEV Catalog)

**Installed build 26200.9711 is PATCHED against the following actively-exploited CVEs:**

| CVE | Severity | Exploitation Status | Fix Build | Status |
|-----|----------|---------------------|-----------|--------|
| CVE-2026-96951 | 7.8 (EoP) | EXPLOITED | 26200.9711 | **PATCHED** (Oct 2026 cumulative KB5127648) |
| CVE-2026-81963 | 7.8 (EoP) | EXPLOITED | 26200.9445 | **PATCHED** (Sep 2026 cumulative) |
| CVE-2026-85880 | 7.8 (EoP) | EXPLOITED | **CHECK MANUAL** | Requires manual verification |

**Notes on CVE-2026-85880:** This ALPC EoP appears in the September 2026 release notes (CVSS 7.8), but the specific 26200 fix build was not visible in the CVRF feed processed during this audit. The October 2026 cumulative (KB5127648) should include it; verify with `wmic qfe where "HotFixID='KB5127648'" get InstalledOn` or check the advisory at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880.

---

## 2. Third-Party Applications: CVE Scan

### Table 1 — Core Development / Networking Tools

| App | Installed | Latest | CVEs affecting installed version | Verdict | Advisory |
|-----|-----------|--------|-----------------------------------|---------|----------|
| Git for Windows | 2.56.0.4 | 2.56.0.4 (Oct 26 2026) | **CVE-2026-111497** (critical Brotli UAF, OpenSSL 3.4.6 use-after-free) | **NOT AFFECTED** (fix already applied in 2.56.0.4) | https://github.com/git-for-windows/git/releases/tag/v2.56.0.windows.4 |
| Visual Studio Code | 1.144.1 | **1.145.2** (Nov 4 2026) | Multiple 9.0+ CVEs: CVE-2026-119269, CVE-2026-121189, CVE-2026-121163 | **NOT AFFECTED** (1.144.1 predates CVEs; install latest) | https://code.visualstudio.com/updates |
| GitHub CLI | 2.103.3 | 2.103.3 (Oct 26 2026) | No relevant CVEs affect this version | **NOT AFFECTED** | https://github.com/cli/cli/releases |
| WireGuard | 1.1.1 | 1.1.1 (current) | No Windows-specific CVEs | **NOT AFFECTED** | https://download.wireguard.com/windows-client/ |
| NetBird | 0.81.4 | 0.82.0 (Oct 29 2026) | CVE-2026-105429 (8.0 EoP), CVE-2026-115576 (8.8 EoP) — fixed in 0.76.0+ | **NOT AFFECTED** | https://github.com/netbirdio/netbird/releases |

### Table 2 — Productivity & Microsoft Apps

| App | Installed | Latest | Update Mechanism | Verdict |
|-----|---------|--------|------------------|---------|
| Microsoft Edge | 157.0.4341.42 | 157.0.4341.42 (Nov 5 2026) | Auto-update | Current |
| Edge WebView2 Runtime | 157.0.4341.42 | Same | Auto-update | Current |
| Chrome | **NOT INSTALLED** | N/A | N/A | Not present (no security issue) |
| Teams (new client) | 26260.1717.x | Unknown (Store auto-update) | Microsoft Store/Windows Update | Currency unknown |
| Outlook (new) | 1.2026.609.400 | 1.2026.812.100 | Microsoft Store | **UPDATE AVAILABLE** (winget reports upgrade) |
| Microsoft 365 Apps | 16.0.20527.20112 | 16.0.20527.20150 | Windows Update | **UPDATE AVAILABLE** (minor) |
| Copilot | 157.0.4341.42 | Same as Edge base | Microsoft Store | Current (uses Edge CVE fixes) |
| Cherry Studio | 2.1.4 | 2.1.10 | Manual/GitHub | **UPDATE AVAILABLE** (no CVE but 3 weeks behind) |
| Google Drive | 133.0.2.0 | Unknown | Google Update | Currency unknown |
| Gemini App | 1.18.0 | Unknown | Google Play/Store | Currency unknown |
| OneDrive | 133.0.2.0 | Unknown | Microsoft Store | Currency unknown |

### Table 3 — Media / File Tools

| App | Installed | Latest | CVEs | Verdict |
|-----|---------|--------|------|---------|
| VLC | 3.0.24 | 3.0.24 | None affect this version | **CURRENT** |
| WinSCP | 6.5.7 | 6.7 (Oct 15 2026) | CVE-2026-45447 (OpenSSL UAF) — **fixed in 6.5.7** | **NOT AFFECTED** |
| µTorrent | 3.6.0.47390 | 3.6.0+ (no major version CVEs known) | None public | **NOT KNOWN AFFECTED** |
| 7-Zip | NOT INSTALLED | 24.09 (latest) | N/A | Absent |
| WinRAR | NOT INSTALLED | 6.24 (latest) | N/A | Absent |
| GIMP | NOT INSTALLED | 2.10.38 (latest) | N/A | Absent |
| Notepad++ | NOT INSTALLED | 8.61 (latest) | N/A | Absent |

---

## 3. Available Updates via winget

| Package | Installed | Available | Urgency |
|---------|-----------|-----------|---------|
| App Installer | 1.29.379 | 1.29.380 | Low (tooling) |
| Cherry Studio | 2.1.4 | 2.1.10 | Medium (3 weeks old, no CVE yet) |
| MSVC v14 Redist (x64/x86) | 14.50.35719 | 14.51.36247 | Low (runtime compatibility) |
| Netbird | 0.81.4 | 0.82.0 | Low (no CVE in current version) |
| Outlook | 1.2026.609.400 | 1.2026.812.100 | **Medium** |
| Smart Connect | 9.0.0.011.001 | 9.0.4.003.000 | Informational |
| Windows Terminal | 1.24.12741.0 | 1.25.27333.0 | Medium |
| Windows App Runtime | 1.5.8 | 1.5.9 | Low |
| Lenovo Vantage | 5.1.2606.17 | Unknown | Check Lenovo site |

---

## 4. Hardware Drivers (Windows Update)

| Driver | Current | Available | Security Relevance |
|--------|---------|-----------|-------------------|
| Intel System Driver | - | 20.40.12912.4 | May include Intel-SA-00789, -00790 (ME microcoded) |
| Intel Media Driver | - | 20.40.12912.4 | Platform media pipeline updates |
| Intel Display Driver | - | 32.0.101.8991 | Graphics; check for Intel-SA-2026-xxxx |
| Lenovo Firmware | - | 1.19.0.0 | **BIOS update**; likely fixes Lenovo security advisories |
| Microsoft Audio APO | - | 1.0.4.55794 | Audio driver stack |
| WDC SAM | - | 4.55.25.661 | WD external storage utility |

**Recommendation:** Install pending drivers via Windows Update. Lenovo BIOS update should be verified against https://support.lenovo.com for any critical security notes.

---

## 5. System Posture

| Setting | Status | Note |
|---------|--------|------|
| BitLocker | Disabled | Device encryption not enabled |
| Secure Boot | Unknown (requires admin) | Check in BIOS |
| TPM 2.0 | Present (inferred) | Modern Standby shows TPM expected |
| UAC | Enabled (Level 5) | Default admin consent prompt |
| SMB signing | Enabled | `RequireSecuritySignature=True` |
| RDP | Disabled | `fDenyTSConnections` not found (default OFF) |

---

## 6. Action Recommendations

**Immediate (high priority):**
1. **Update Outlok** to 1.2026.812.100 (winget upgrade `Microsoft.Outlook`)
2. **Update Visual Studio Code** to 1.145.2 (auto-update should catch this)
3. **Update Lenovo Vantage** to latest (check support.lenovo.com for your model)
4. **Verify CVE-2026-85880** is patched — run `wmic qfe get HotFixID` and confirm KB5127648, or check https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85880

**Medium priority:**
5. **Update Cherry Studio** to 2.1.10
6. **Apply pending Windows Update drivers** (Intel, Lenovo, WDC)
7. **Consider BitLocker enablement** if device has TPM

**Informational:**
- Chrome, 7-Zip, WinRAR, GIMP, Notepad++ are **not installed** — no security issue.
- Node.js and Python interpreters are **absent** — may affect dev workflows.

---

## 7. Portable CVE Audit Script

A PowerShell script is available at:
`D:\My Projects\win11-cve-audit\win11-cve-audit.ps1`

This script can be run on any Windows 11 machine to:
1. Enumerate installed applications
2. Check winget upgrade availability
3. Cross-reference CISA KEV catalog vs installed Windows build
4. Output a markdown report

Run with: `powershell.exe -File win11-cve-audit.ps1`

---

*Caveat: This audit is read-only. No system changes were made. Driver versions were reported as "Available" pending installation.*