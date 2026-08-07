# Security Policy

## Reporting a vulnerability

Please report suspected security issues privately to **security@holdingco.com**
(or open a [private security advisory](https://docs.github.com/code-security/security-advisories)).
Do **not** open a public issue for security reports.

We aim to acknowledge within 2 business days and to provide a remediation
timeline within 7 days.

## Supported

The latest `v1` release is the only supported version.

## Secrets

This repository must never contain secrets. The action requires none: it only
fetches the skill under test and the publisher's public `did:web` document.
Secret scanning with push protection is enabled — if a push is blocked, rotate
the credential, do not bypass.
