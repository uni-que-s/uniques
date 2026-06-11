# Security Policy

QuantumVault is a security tool, so we hold its own security to a high bar.
Thank you for helping keep it and its users safe.

## Supported versions

QuantumVault is pre-1.0 and ships from `main`. Security fixes land on `main` and
in the latest tagged release. Older tags are not patched in place — upgrade to
the latest release to receive fixes.

| Version | Supported |
| --- | :---: |
| `0.1.x` (latest) | ✅ |
| `< 0.1.0` | ❌ |

## Reporting a vulnerability

**Please do not open a public issue, pull request, or discussion for a security
vulnerability.** Public disclosure before a fix is available puts users at risk.

Report privately through GitHub's **private vulnerability reporting**:

1. Go to the **Security** tab of the repository.
2. Click **Report a vulnerability** to open a private advisory draft.
3. Include the details below.

This routes the report directly and confidentially to the maintainers.

### What to include

- The component affected (scanner/discovery, risk engine, compliance reports,
  auth/sessions, server API, web dashboard, CLI, or the GitHub Action).
- The version, commit SHA, or release tag you tested against.
- Reproduction steps or a proof of concept.
- The impact you believe it has (e.g. cross-org data exposure, auth bypass,
  token leakage, RCE, SSRF via repo scanning, denial of service).
- Any suggested remediation, if you have one.

### Our commitment

- **Acknowledge** your report within **3 business days**.
- Provide an initial **assessment** (accepted / needs-info / not-a-vuln) within
  **10 business days**.
- Keep you updated on remediation progress, and credit you in the release notes
  and advisory once a fix ships — unless you prefer to remain anonymous.
- Coordinate a disclosure timeline with you; our default target is a fix within
  **90 days** of confirmation, sooner for actively exploited issues.

## Scope

In scope: the QuantumVault server API, web dashboard, CLI, discovery/scanning
engine, risk and compliance modules, auth/session handling, the published Docker
images (`ghcr.io/demigoddsk/quantumvault-*`), and the GitHub Action
(`action.yml` / `action.Dockerfile`).

Out of scope: vulnerabilities in third-party dependencies (report those upstream,
though we welcome a heads-up so we can bump), findings that require a compromised
host or privileged local access, and theoretical issues without a practical
impact on confidentiality, integrity, or availability.

## Handling secrets and scan targets

QuantumVault scans codebases, which may contain secrets. When reporting an issue,
**never include real private keys, access tokens, or customer data** in your
report — redact them or use synthetic equivalents. Private-repo access tokens
passed to the Git scanner are used only for the clone and are never persisted or
logged by design; if you find a case where a credential is logged or stored,
treat it as a high-severity report.
