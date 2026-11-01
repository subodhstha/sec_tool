# International Cybersecurity Standards Alignment: Vyomite DAST Platform
**Version:** 1.0 (Enterprise Release)  
**Standard Coverage:** OWASP Top 10 (2021) / API Top 10 (2023), ISO/IEC 27001:2022, ISO/IEC 27034, NSA/CISA Guidelines, NIST SP 800-53 Rev. 5, & NIST SP 800-218 (SSDF)

---

## Executive Summary
The Vyomite DAST Platform is architected to perform continuous, automated security assessments that satisfy stringent regulatory and operational security frameworks. Every vulnerability detected by Vyomite is automatically mapped to international security controls and exported via standard **OASIS SARIF v2.1.0** defect reports for DevSecOps governance.

---

## 1. Primary Cybersecurity Standards Cross-Reference Matrix

| Threat / Vulnerability Vector | OWASP Top 10 (2021) | ISO/IEC 27001:2022 Annex A | NIST SP 800-53 Rev. 5 | NSA / CISA Guidance |
| :--- | :--- | :--- | :--- | :--- |
| **Insecure Transmission & Missing HSTS** | `A05:2021-Security Misconfiguration` | `A.8.20 Network Security`<br>`A.8.24 Cryptography` | `SC-8 Transmission Confidentiality`<br>`SC-13 Cryptographic Protection` | `CISA-MISCONFIG-04 Insecure Transmission Channels` |
| **Session Cookie Tampering & Missing HttpOnly** | `A05:2021-Security Misconfiguration` | `A.8.26 App Security Requirements`<br>`A.8.28 Secure Coding` | `SC-28 Protection of Info at Rest`<br>`SI-10 Input Validation` | `NSA Web App Security Guide - Section 3.2 Session Protection` |
| **Cross-Site Request Forgery (CSRF) & SameSite** | `A01:2021-Broken Access Control` | `A.5.15 Access Control`<br>`A.8.28 Secure Coding` | `AC-3 Access Enforcement`<br>`SC-23 Session Authenticity` | `CISA Web App Defense - CSRF Protection Directive` |
| **Clickjacking & Framing (X-Frame-Options)** | `A05:2021-Security Misconfiguration` | `A.8.26 App Security Requirements` | `SC-18 Mobile Code`<br>`AC-3 Access Enforcement` | `CISA UI Redress & Clickjacking Advisory` |
| **Missing Content-Security-Policy (CSP)** | `A05:2021-Security Misconfiguration` | `A.8.26 App Security Requirements`<br>`A.8.28 Secure Coding` | `SI-10 Input Validation`<br>`SC-18 Mobile Code` | `NSA Information Sheet - Content Injection Defense` |
| **Permissive Cross-Origin Sharing (CORS)** | `A01:2021-Broken Access Control` | `A.5.15 Access Control`<br>`A.8.20 Network Security` | `AC-3 Access Enforcement`<br>`AC-4 Information Flow Enforcement` | `NSA Web App Security Guide - Section 4.1 Cross-Origin Controls` |
| **Exposed Git / Secrets (/.git, /.env)** | `A05:2021-Security Misconfiguration` | `A.8.8 Tech Vulnerability Mgmt`<br>`A.8.12 Data Leakage Prevention` | `CM-6 Configuration Settings`<br>`SA-11 Developer Testing` | `CISA-MISCONFIG-01 Default Configurations & Exposed Secrets` |
| **SQL Injection (Time-Based Differential)** | `A03:2021-Injection` | `A.8.26 App Security Requirements`<br>`A.8.28 Secure Coding` | `SI-10 Information Input Validation`<br>`RA-5 Vulnerability Scanning` | `CISA-MISCONFIG-02 Improper Separation & Injection` |
| **Blind Server-Side Request Forgery (SSRF)** | `A10:2021-Server-Side Request Forgery` | `A.8.20 Network Security`<br>`A.8.26 App Security Requirements` | `AC-4 Information Flow Enforcement`<br>`SC-7 Boundary Protection` | `NSA Top 10 - Server-Side Request Forgery Mitigation` |

---

## 2. Standard-by-Standard Alignment

### 2.1 OWASP Top 10 (2021) & OWASP API Security Top 10 (2023)
* **A01:2021 - Broken Access Control / API1:2023 (BOLA):** Tested via CORS reflection checks and safe verb enforcement preventing unauthorized state transitions.
* **A02:2021 - Cryptographic Failures:** Audited through missing HSTS and unencrypted session transmission checks.
* **A03:2021 - Injection / API8:2023 (Security Misconfiguration):** Tested through context-aware time-differential injection probes (FR-3.3).
* **A05:2021 - Security Misconfiguration:** Audited via passive analysis of security headers (`CSP`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`) and cookie attributes (`HttpOnly`, `Secure`, `SameSite`).
* **A10:2021 - Server-Side Request Forgery (SSRF) / API7:2023 (SSRF):** Detected via correlation tokens and out-of-band listener verification (FR-3.2).

### 2.2 ISO/IEC 27001:2022 & ISO/IEC 27034 (Application Security)
* **Control A.8.8 (Management of Technical Vulnerabilities):** Vyomite DAST acts as the primary technical vulnerability discovery and continuous monitoring mechanism.
* **Control A.8.20 (Network Security):** Verifies encryption across communication channels and identifies exposed internal ports/services.
* **Control A.8.25 (Secure Development Life Cycle):** Integrates directly into CI/CD pipelines via SARIF v2.1.0 output (FR-5.2) to block vulnerabilities prior to production deployment.
* **Control A.8.26 (Application Security Requirements):** Ensures that baseline security headers and cookie protections are present across all enterprise web assets.
* **Control A.8.29 (Security Testing in Development and Acceptance):** Directly implements automated dynamic application security testing (DAST) in staging and QA environments.

### 2.3 NSA & CISA Cybersecurity Guidance
* **CISA/NSA Top 10 Cybersecurity Misconfigurations:**
  * **Defensive Focus:** Unenforced default configurations, unrestricted web paths (`/.git/HEAD`, `/.env`), missing authentication tokens, and weak TLS transport channels.
* **CISA Zero-Disruption Guidelines:** Enforced via Vyomite's **FR-4 Safety Safeguards** (5xx Circuit Breaker, Dynamic Latency Back-off, and Safe HTTP Verb Enforcement) to protect critical enterprise infrastructure from accidental degradation during testing.

### 2.4 NIST SP 800-53 Rev. 5 & NIST SP 800-218 (SSDF v1.1)
* **RA-5 (Vulnerability Monitoring and Scanning):** Fulfills the requirement for continuous automated vulnerability monitoring.
* **SA-11 (Developer Testing and Evaluation):** Embeds DAST verification into acceptance criteria for deployed code.
* **SI-10 (Information Input Validation):** Tests input validation boundary handling across query strings, headers, and form parameters.
* **SSDF PW.8 (Test Executable Code):** Executes dynamic black-box testing against running applications.
* **SSDF RV.1 (Identify and Confirm Vulnerabilities):** Employs deduplicated, evidence-based proofs (sanitized HTTP request/response transcripts) to confirm flaws without false positives.

---

## 3. SARIF v2.1.0 Compliance Schema

All findings produced by the Vyomite DAST engine include rich metadata tags containing the complete compliance cross-reference:

```json
{
  "ruleId": "COOKIE_SECURE_FLAG",
  "name": "Insecure Cookie Transmission",
  "properties": {
    "security-severity": "5.3",
    "tags": [
      "security",
      "OWASP:A05:2021-Security Misconfiguration",
      "CWE:CWE-614",
      "ISO27001:A.8.20 Network security, A.8.24 Use of cryptography",
      "NIST:SP 800-53 SC-8 Transmission Confidentiality, SC-13 Cryptography",
      "NSA-CISA:CISA-MISCONFIG-04 Insecure Transmission Channels"
    ]
  }
}
```

This ensures full bidirectional traceability across enterprise Governance, Risk, and Compliance (GRC) tools.
