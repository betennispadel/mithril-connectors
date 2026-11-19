# OASM Connectors (Whitelabel)

Custom connectors for the OASM platform — CTI tools, SAST scanner, and SCA wrappers.

## Structure

- `cti/brand-protection` — Brand Protection: monitors brand mentions across web/dark web
- `cti/crypto` — Crypto Intelligence: tracks wallet addresses and crypto threats
- `cti/darkweb` — Dark Web Monitor: scans dark web marketplaces and forums
- `cti/data-leaks` — Data Leaks: detects leaked credentials and sensitive data
- `cti/ioc-feed` — IOC Feed: checks IPs/domains/hashes against threat intel feeds
- `cti/social-monitor` — Social Monitor: monitors social media for brand/threat mentions
- `cti/supplier-risk` — Supplier Risk: assesses third-party vendor security posture
- `sast/semgrep` — Semgrep SAST: static code analysis for security vulnerabilities
- `sca/gitleaks-wrap` — Gitleaks wrapper: secret scanning in git repos
- `sca/trivy-wrap` — Trivy wrapper: container/filesystem vulnerability scanning

## Building

Each Go connector:
```bash
cd cti/ioc-feed
docker build -t connector-ioc-feed:latest .
```

## SDK

Connectors use the OASM Connector SDK:
```
github.com/oasm-platform/oasm-connectors/sdk
```
