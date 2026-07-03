# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public
issue for security reports.

- **Preferred:** GitHub's [Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  (repository **Security** tab → *Report a vulnerability*).
- **Or email:** `security@<your-domain>` — *set this up before publishing; do
  not use a personal address.*

You'll receive an acknowledgment within a few business days.

## Assurance status (please read)

This project wraps the independently-audited
[`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
primitives in a Model Context Protocol server. Honestly:

- The **MCP wrapper, key management, and protocol layer in this repository have
  not undergone a formal third-party security audit.** The underlying NIST PQC
  primitives are audited; the integration around them is not.
- Do not rely on this to protect production secrets without your own review.
- Parameter choices follow NIST **FIPS 203 / 204 / 205**. Report any deviation
  as a security issue.

## Supported versions

Security fixes are applied to the latest released version on the default branch.
