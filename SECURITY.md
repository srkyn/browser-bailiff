# Security Policy

Browser Bailiff is defensive software intended for authorized local review.

## Reporting a Vulnerability

Please report security issues through GitHub's private vulnerability reporting
feature when available, or by opening a minimal issue that avoids posting
sensitive exploit details publicly.

Useful reports include:

- Affected version or commit
- Operating system and browser family
- Steps to reproduce
- Expected behavior
- Actual behavior
- Any sensitive details redacted from logs or output

## Scope

In scope:

- Bugs that cause Browser Bailiff to misreport extension permissions or risk
- Unsafe file handling
- Incorrect parsing of browser extension manifests
- Problems that expose data outside the local audit context

Out of scope:

- Reports about malicious third-party browser extensions themselves
- Requests to bypass browser or operating system protections
- Social engineering, spam, or denial-of-service testing
