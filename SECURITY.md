# Security Policy

## Reporting a vulnerability

If you find a security issue in VulnWatch (for example, an XSS in the web UI or an unsafe handling of feed data), please **do not open a public issue**.

Report it privately through GitHub: **Security → Report a vulnerability** on this repository (private vulnerability reporting).

Please include the steps to reproduce it and the potential impact. I will acknowledge the report within 7 days.

## Security design notes

- **No secrets in code.** API keys and tokens (`NVD_API_KEY`, `TELEGRAM_TOKEN`) live only in GitHub Actions secrets.
- **Untrusted input.** All data coming from external feeds (CVE descriptions, RSS titles, URLs) is HTML-escaped before rendering.
- **Least privilege.** Each workflow declares only the permissions it needs.
- **Static site.** There is no server, database or login, so the attack surface is minimal.
- **Supply chain.** There are no third-party Python or JS dependencies. GitHub Actions are kept up to date by Dependabot, and the code is analyzed by CodeQL.
