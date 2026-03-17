# Contributing to ShadowStrike Phantom

Thank you for your interest in contributing to ShadowStrike Phantom. This document explains the process, requirements, and legal terms that govern all contributions to this project.

**Please read this entire document before submitting any contribution.** By submitting a contribution, you agree to all terms described here. If you do not agree, do not submit contributions.

---

## Table of Contents

1. [Copyright Assignment Agreement](#1-copyright-assignment-agreement)
2. [Who Can Contribute](#2-who-can-contribute)
3. [What We Accept](#3-what-we-accept)
4. [What We Do Not Accept](#4-what-we-do-not-accept)
5. [Contribution Process](#5-contribution-process)
6. [Code Standards](#6-code-standards)
7. [Kernel-Mode Contributions](#7-kernel-mode-contributions)
8. [Commit Requirements](#8-commit-requirements)
9. [Review Process](#9-review-process)
10. [Recognition](#10-recognition)

---

## 1. Copyright Assignment Agreement

This is the most important section. Read it carefully.

### 1.1 Full Copyright Assignment

By submitting any contribution to this repository — including but not limited to source code, documentation, configuration files, scripts, test cases, build files, comments, or any other material — **you permanently and irrevocably assign all copyright, title, and interest in that contribution to ShadowStrike-Labs.**

This assignment includes:

- All present and future copyright in the contribution worldwide
- The right to use, reproduce, modify, adapt, publish, translate, distribute, and sublicense the contribution in any form and under any license, including proprietary licenses
- The right to commercialize the contribution as part of any ShadowStrike product or service
- The right to enforce copyright against third parties
- All moral rights, to the extent permitted by applicable law, are waived in favor of ShadowStrike-Labs

### 1.2 What This Means In Practice

ShadowStrike Phantom is licensed under AGPL-3.0. However, ShadowStrike-Labs reserves the right to release the software — including your contributions — under additional licenses, including commercial licenses. Your contribution may appear in a future paid enterprise product. By contributing, you agree to this without additional compensation or notification.

### 1.3 Your Representations

By submitting a contribution, you represent and warrant that:

- You are the sole original author of the contribution, or you have the legal right to assign copyright on behalf of all authors
- The contribution does not infringe any third-party intellectual property rights, including patents, copyrights, trade secrets, or trademarks
- The contribution does not contain code copied from projects with incompatible licenses (GPL-only code, proprietary code, etc.)
- If you are contributing on behalf of an employer, you have obtained explicit written authorization from that employer to assign copyright to ShadowStrike-Labs
- You are legally permitted to enter into this agreement under the laws of your jurisdiction
- The contribution does not contain any malicious code, backdoors, or intentional vulnerabilities

### 1.4 No Contributor License Agreement (CLA) — Full Assignment Only

ShadowStrike-Labs does not use a Contributor License Agreement model. We require full copyright assignment. There is no partial licensing option. If you are unwilling to assign copyright, please do not submit contributions. You are welcome to fork the project under the terms of the AGPL-3.0 license.

### 1.5 Assignment Confirmation

Every pull request must include the following sign-off line in the PR description. Without this line, the PR will be closed without review:

```
I assign full copyright of this contribution to ShadowStrike-Labs, 
confirm I have the right to make this assignment, and agree to 
all terms in CONTRIBUTING.md.
```

---

## 2. Who Can Contribute

### 2.1 Individual Contributors

Any individual may contribute provided they:

- Are the original author of the submitted code
- Have not copied the code from any third-party source without verified compatible licensing
- Can legally assign copyright under the laws of their country
- Are not subject to export control restrictions that would prohibit contributing to security software

### 2.2 Employed Contributors

If you are employed and contributing code that relates to your employer's business, you must obtain written permission from your employer before contributing. Many employment contracts assign IP rights to the employer by default. Contributing employer-owned code without authorization could expose both you and ShadowStrike-Labs to legal liability.

### 2.3 Minor Contributors

If you are under 18 years of age, you may not contribute without written consent from a parent or legal guardian who also agrees to the copyright assignment on your behalf.

### 2.4 AI-Assisted Contributions

Contributions that include AI-generated code (GitHub Copilot, Claude, GPT, etc.) are accepted provided:

- You disclose in the PR description that AI tools were used
- You have reviewed and take full responsibility for all AI-generated content
- You verify the AI-generated code does not reproduce copyrighted third-party code
- Copyright of the final submitted work is assigned to ShadowStrike-Labs as with all other contributions

---

## 3. What We Accept

We welcome contributions in the following areas:

### High Priority
- Bug fixes for existing kernel-mode modules (memory safety, IRQL violations, pool overflows)
- Detection rule improvements for the Behavioral Engine
- YARA rule contributions for the SignatureStore
- Performance improvements to hot-path code (PatternStore, HashStore)
- Compilation fixes — helping PhantomSensor reach a clean build state
- Driver Verifier violation fixes
- Documentation improvements and corrections

### Medium Priority
- New detection modules that align with the existing architecture
- Test case additions (unit tests, integration tests)
- Build system improvements
- Code comments and internal documentation

### Lower Priority
- Refactoring that does not fix bugs or improve performance
- New features not yet on the roadmap
- UI/GUI work (not yet started upstream)

---

## 4. What We Do Not Accept

The following will be closed without review:

- Code copied from GPL-only licensed projects without explicit written approval
- Code copied from proprietary or closed-source projects under any circumstances
- Contributions that introduce dependencies with licenses incompatible with AGPL-3.0
- Intentional vulnerabilities, backdoors, or malicious code of any kind
- Contributions that weaken self-protection mechanisms without documented justification
- Code that introduces telemetry, analytics, or data collection without explicit project maintainer approval
- Obfuscated code with no clear explanation of purpose
- Contributions that violate any applicable export control law regarding security software
- Submissions without the required copyright assignment sign-off in the PR description

---

## 5. Contribution Process

### Step 1 — Open an Issue First

Before writing code, open a GitHub Issue describing:
- What you want to fix or add
- Why it is needed
- Your proposed approach

Wait for acknowledgment from the maintainer before investing significant effort. This avoids wasted work on approaches that won't be accepted.

### Step 2 — Fork and Branch

Fork the repository and create a branch with a descriptive name:

```
fix/vad-tracker-null-dereference
feat/heapspray-threshold-tuning
docs/contributing-guide-update
```

### Step 3 — Write Your Code

Follow the code standards in Section 6. For kernel-mode contributions, follow the additional requirements in Section 7.

### Step 4 — Test Your Changes

- Kernel changes must be tested in a VM with Driver Verifier enabled
- Include test results in the PR description
- Document the test environment (Windows version, build number, architecture)

### Step 5 — Submit the Pull Request

Your PR description must include:

1. A clear description of what the change does and why
2. Reference to the related Issue number (`Fixes #123`)
3. Test environment and results
4. Disclosure of any AI-assisted code generation
5. The mandatory copyright assignment sign-off (exact text from Section 1.5)

PRs missing the sign-off will be closed immediately.

---

## 6. Code Standards

### General

- All code must be written in C (kernel-mode) or C++20 (user-mode) unless there is documented justification for another language
- x64 assembly is acceptable for performance-critical or timing-sensitive detection code (see existing AntiEvasion modules for examples)
- No external dependencies may be added without maintainer approval
- All new files must include the standard license header (see existing files for format)

### Style

- Follow the existing code style in the module you are modifying — consistency within a file takes priority over personal preference
- Use descriptive variable and function names — this codebase is intended to be educational
- Comment non-obvious logic, especially kernel-mode constraints and Windows-specific behavior
- Document IRQL requirements for every kernel function

### Memory Safety (Non-Negotiable)

- All kernel allocations must use tagged pool allocation (`ExAllocatePoolWithTag` or `ExAllocatePool2`)
- All pool allocations must be freed on every error path
- All pointers must be validated before use
- Buffer sizes must be verified before any copy operation
- No stack allocations larger than a few hundred bytes in kernel mode

---

## 7. Kernel-Mode Contributions

Kernel contributions are held to a higher standard than user-space contributions because bugs cause system crashes and can introduce security vulnerabilities.

### Requirements

- Test all kernel changes with **Driver Verifier** enabled with at minimum: Pool Tracking, Force IRQL Checking, Deadlock Detection, and Security Checks
- Document the IRQL level at which each function runs
- Ensure all callbacks properly handle the case where associated data structures have been freed
- Do not call pageable functions from DISPATCH_LEVEL or above
- All minifilter pre/post operation callbacks must handle `STATUS_FLT_DO_NOT_ATTACH` and related status codes correctly
- Synchronization primitives must be acquired and released on all code paths including error paths

### Testing Environment

Kernel development must be done in a virtual machine. Never test unsigned or modified kernel drivers on a physical machine you depend on. Recommended setup:

- Windows 11 x64 VM (VMware or Hyper-V)
- Kernel debugging via WinDbg over network or COM port
- Driver Verifier enabled on the test VM
- Snapshots before every driver load test

### Automatic Disqualification

Kernel PRs will be closed without review if they:

- Introduce any allocation without a corresponding free on all code paths
- Call any function that could page fault at elevated IRQL
- Disable or weaken any existing self-protection mechanism without documented justification
- Remove or bypass Driver Verifier compatibility

---

## 8. Commit Requirements

- Write clear commit messages in the imperative mood: `Fix null dereference in VadTracker` not `Fixed` or `Fixes null dereference`
- One logical change per commit — do not bundle unrelated fixes
- Do not include generated files, build artifacts, or IDE configuration files
- Commit messages should reference the issue number where applicable: `Fix IRQL violation in DirectSyscallDetector (#45)`

---

## 9. Review Process

- All PRs are reviewed by the project maintainer (ShadowStrike-Labs)
- Review turnaround is best-effort — this is a solo-maintained project
- Feedback will be provided as PR comments
- You may be asked to revise your contribution before it is accepted
- Accepted contributions may be further modified by the maintainer before merge
- There is no guaranteed timeline for review

ShadowStrike-Labs reserves the right to reject any contribution for any reason, including but not limited to: technical quality, architectural fit, project direction changes, or legal concerns.

---

## 10. Recognition

Contributors whose code is merged will be:

- Listed in the repository contributors (via GitHub's automatic contributor tracking)
- Credited in release notes for the version containing their contribution
- Recognized in the project documentation

Note: Recognition does not imply ongoing rights to the contributed code, which has been fully assigned to ShadowStrike-Labs per Section 1.

---

## Questions

If you have questions about this document or the contribution process, open a GitHub Discussion or email contact@shadowstrike.dev before submitting code.

---

*ShadowStrike-Labs · AGPL-3.0 · contact@shadowstrike.dev*
