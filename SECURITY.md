# Security Policy

## Supported Versions

There are no releases; fixes land on `main`, the only supported version.

## Reporting a Vulnerability

Report privately through the repository's **Security** tab, **Report a vulnerability**; never in a public issue,
pull request or discussion. Include the commit (`git rev-parse HEAD`), your operating system, what an attacker can
reach, and reproduction steps. Redact OIDC ID tokens, Dev Tunnel host and connect tokens, link tokens and Jupyter tokens.

We acknowledge the report, say whether we can reproduce it before a fix is published, and credit you in the
advisory unless you decline.

## Scope

cs-plane is a shared service behind a TLS reverse proxy. A useful report shows one of the
[trust boundaries](docs/ARCHITECTURE.md#trust-boundaries) failing.

Out of scope: findings that assume control of the user's account or their CILogon or Dev Tunnels credentials, and
vulnerabilities in Jupyter Server, Dev Tunnels, CILogon or [Linkspan](https://github.com/cyber-shuttle/linkspan), which
have their own channels.
