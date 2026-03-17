# Security Policy

ShadowStrike Phantom is a kernel-level endpoint protection platform. Security vulnerabilities in this codebase are taken with the highest priority. This document describes how to report vulnerabilities responsibly and what you can expect from ShadowStrike-Labs in response.

---

## Table of Contents

1. [Supported Versions](#1-supported-versions)
2. [Reporting a Vulnerability](#2-reporting-a-vulnerability)
3. [What To Include In Your Report](#3-what-to-include-in-your-report)
4. [What Happens After You Report](#4-what-happens-after-you-report)
5. [Disclosure Policy](#5-disclosure-policy)
6. [Scope](#6-scope)
7. [Out of Scope](#7-out-of-scope)
8. [Safe Harbor](#8-safe-harbor)
9. [Hall of Fame](#9-hall-of-fame)
10. [Legal](#10-legal)

---

## 1. Supported Versions

ShadowStrike Phantom is currently in **pre-alpha development**. The codebase does not yet produce a compiled binary. Despite this, security reports on the source code itself are welcomed and taken seriously — vulnerabilities found now are far less costly to fix than those found after the first public release.

| Version | Status | Security Reports Accepted |
|---|---|---|
| `master` branch (pre-alpha) | Active development | ✅ Yes |
| Any future tagged release | Not yet published | ✅ Yes |
| Forks / third-party builds | Not maintained by us | ❌ Report to fork owner |

---

## 2. Reporting a Vulnerability

**Do not report security vulnerabilities through GitHub Issues, GitHub Discussions, pull requests, or any other public channel.**

Public disclosure of unpatched vulnerabilities in a kernel-level security product puts all future users at risk. Please use private disclosure only.

### Primary Contact

**Email:** contact@shadowstrike.dev

**Subject line format:** `[SECURITY] Brief description of issue`

**Expected response time:** Within 72 hours for acknowledgment. If you have not received a response within 72 hours, send a follow-up email.

### Encryption

For highly sensitive reports involving exploitable kernel vulnerabilities, you may request a PGP public key by emailing contact@shadowstrike.dev before submitting your full report.

---

## 3. What To Include In Your Report

A good vulnerability report helps us understand, reproduce, and fix the issue faster. Please include as much of the following as possible:

### Required

- A clear description of the vulnerability and its potential impact
- The specific file(s) and line number(s) where the vulnerability exists
- The type of vulnerability (e.g. pool overflow, use-after-free, IRQL violation, integer overflow, race condition, privilege escalation, logic error)
- Steps to reproduce or a proof-of-concept (PoC) — even a code analysis walkthrough is sufficient if no compiled binary exists yet

### Strongly Recommended

- Your assessment of exploitability and severity (Critical / High / Medium / Low)
- Whether the vulnerability exists in kernel-mode or user-mode code
- Suggested fix or mitigation if you have one
- Your name or handle for credit (if you want to be recognized)
- Whether you intend to publish your findings and your intended timeline

### Optional

- CVE request status if you have already contacted MITRE
- Related vulnerabilities in the same module

---

## 4. What Happens After You Report

### Acknowledgment — Within 72 Hours

ShadowStrike-Labs will confirm receipt of your report and assign it an internal tracking reference.

### Initial Assessment — Within 7 Days

We will evaluate the report and provide:
- Confirmation of whether the issue is accepted as a valid vulnerability
- An initial severity assessment
- An estimated timeline for a fix

### Resolution

- **Critical / High severity** (kernel exploits, privilege escalation, self-protection bypass): Target fix within 14 days
- **Medium severity** (logic errors, detection bypasses, information disclosure): Target fix within 30 days
- **Low severity** (minor issues, hardening improvements): Addressed in normal development cycle

Given that ShadowStrike Phantom is a solo-maintained pre-alpha project, these timelines are best-effort. We will communicate openly if circumstances require more time.

### Notification

You will be notified when:
- The fix is committed to the repository
- A public advisory is published (if applicable)

---

## 5. Disclosure Policy

ShadowStrike-Labs follows a **coordinated disclosure** model.

- We ask reporters to allow **90 days** from acknowledgment before public disclosure
- If a fix is committed before 90 days, we will coordinate with you on a disclosure date
- If we cannot fix the issue within 90 days, we will communicate our status and negotiate a timeline extension with you — we will not simply go silent
- We will never ask you to indefinitely suppress a vulnerability report
- We will credit you in the public disclosure unless you request anonymity
- We will not take legal action against researchers who follow this policy in good faith

For critical kernel vulnerabilities that are already being actively exploited in the wild, we will coordinate an accelerated timeline with you.

---

## 6. Scope

The following are in scope for security reports:

### Kernel-Mode (Highest Priority)

- Pool buffer overflows in any kernel module
- Use-after-free vulnerabilities in kernel allocations
- IRQL violations that could cause system instability or be exploited
- Race conditions in kernel callbacks
- Integer overflows in size calculations for kernel allocations
- Self-protection bypass — techniques that allow an attacker to unload, patch, or disable PhantomSensor.sys
- Privilege escalation from user-mode to kernel-mode via any Phantom component
- Vulnerabilities in the FilterConnectPort communication channel
- ELAM alternative driver bypass techniques
- Vulnerabilities that allow an attacker to blind or manipulate Phantom's detection

### User-Mode

- Memory corruption in any user-space detection engine
- IPC channel vulnerabilities between the kernel driver and user-space service
- Authentication or authorization bypass in the Windows service
- Vulnerabilities in the update pipeline that could allow malicious update delivery
- Arbitrary code execution in any Phantom component
- Privilege escalation from standard user to SYSTEM via any Phantom component

### Detection Logic

- Techniques that reliably bypass a specific detection module with broad applicability to real-world malware
- Logic errors that cause false negatives in critical detection paths (injection detection, ransomware detection, etc.)

### Code Quality Security Issues

- Any pattern in the source code that would introduce an exploitable vulnerability when compiled, even if the binary does not yet exist

---

## 7. Out of Scope

The following are **not** considered security vulnerabilities for the purposes of this policy:

- Issues in third-party libraries vendored in the repository (YARA, Zydis, SQLiteCpp, etc.) — report these to the respective upstream projects
- Detection bypasses that require kernel-level access already (if you have kernel access, you have already bypassed endpoint security)
- Theoretical vulnerabilities with no plausible real-world attack path
- Issues that only affect the developer's test environment
- Denial of service against a single test VM with no network exposure
- Missing security features that are already on the roadmap
- Social engineering attacks against ShadowStrike-Labs personnel
- Physical access attacks
- Vulnerabilities in GitHub's infrastructure

If you are unsure whether your finding is in scope, email us anyway — we would rather review an out-of-scope report than miss a real vulnerability.

---

## 8. Safe Harbor

ShadowStrike-Labs considers security research conducted under this policy to be:

- Authorized under applicable computer fraud and abuse laws
- Exempt from restrictions in our license that would interfere with security research
- Lawful, helpful, and conducted in good faith

We will not pursue legal action against researchers who:

- Discover and report vulnerabilities through private disclosure as described in this document
- Avoid accessing, modifying, or destroying data beyond what is necessary to demonstrate the vulnerability
- Do not exploit vulnerabilities beyond a proof-of-concept demonstration
- Do not disclose vulnerabilities publicly before the agreed disclosure date
- Act in good faith to avoid harm to ShadowStrike-Labs, its users, and the broader community

This safe harbor applies specifically to security research on the ShadowStrike Phantom codebase. It does not apply to any other activity.

---

## 9. Hall of Fame

ShadowStrike-Labs maintains a public record of security researchers who have responsibly disclosed vulnerabilities. Recognition will be published in this repository once the project reaches its first public release.

If you report a vulnerability and wish to be credited, please include your preferred name or handle in your report. Anonymous reports are also accepted.

---

## 10. Legal

### Intellectual Property of Reports

By submitting a vulnerability report, you grant ShadowStrike-Labs a non-exclusive, worldwide, royalty-free license to use the information in your report for the purpose of fixing the reported vulnerability and improving the security of ShadowStrike Phantom.

You retain ownership of your original research. ShadowStrike-Labs will not claim credit for your discovery.

### No Bounty Program

ShadowStrike Phantom does not currently operate a paid bug bounty program. Recognition in the Hall of Fame and public credit are the current forms of acknowledgment. If a bounty program is established in the future, it will be documented here.

### Governing Expectations

This policy does not constitute a legal contract. It represents ShadowStrike-Labs' good-faith commitment to working with security researchers responsibly. ShadowStrike-Labs reserves the right to update this policy at any time.

---

## Contact

**Security reports:** contact@shadowstrike.dev
**Subject line:** `[SECURITY] Brief description`
**GitHub:** https://github.com/ShadowStrike-Labs/ShadowStrike

---

*ShadowStrike-Labs · AGPL-3.0 · Pre-Alpha · Not for production use*
