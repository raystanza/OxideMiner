# Security Policy

OxideMiner values the security of users, operators, and pool partners. We follow a coordinated disclosure
process to ensure vulnerabilities are addressed responsibly and quickly. This document outlines how to report
security issues and how we handle them.

## Supported Versions

Security updates are applied to the latest `main` branch and the most recent tagged release. Older releases may
not receive patches; please upgrade to the latest version for security fixes.

## Reporting a Vulnerability

- **Private reports only.** Please do not open public GitHub issues for suspected vulnerabilities.
- Use the [GitHub security advisory form](https://github.com/raystanza/OxideMiner/security/advisories/new)
  to submit a private report, or email [security@oxideminer.com](mailto:security@oxideminer.com) for immediate emergencies.
- Include as much detail as possible: affected components, reproduction steps, logs, and potential impact.
- If the issue involves third-party infrastructure (e.g., mining pools), let us know so coordinated notification
  can be arranged.

## What to Expect

1. **Acknowledgment** – We will confirm receipt of your report within 3 business days.
2. **Investigation** – Maintainers will assess severity, verify the issue, and determine mitigation steps. You may
   be contacted for additional information.
3. **Resolution** – We will develop a fix or workaround. When appropriate, we may create a private security
   advisory with coordinated disclosure timelines.
4. **Release** – Once a fix is ready, we will publish patched releases, update documentation, and credit reporters
   who wish to be acknowledged.

We strive to keep reporters informed throughout the process, especially if timelines need adjustment.

## Scope and Expectations

- Submit only vulnerabilities you have permission to test. Do not violate laws or agreements while researching.
- Avoid tests that degrade pool performance or mining operations for other users.
- Respect the confidentiality of pre-release information.
- Security-related contributions are accepted under the Business Source License 1.1 (BSL-1.1). By reporting
  vulnerabilities or contributing fixes, you agree to the licensing terms in [LICENSE](LICENSE).

Thank you for helping keep OxideMiner safe.
