# Security Policy

## Local-By-Default Design

- Aegis binds its Web Console strictly to `127.0.0.1:8765` by default so telemetry is never exposed to LAN or WAN interfaces unless explicitly overridden via `--host` / `AEGIS_BIND_HOST`.
- `.env`, `.pcap` captures, GeoIP caches, and local executable signature caches (`data/`) are excluded via `.gitignore`.
- Router connections use OpenSSH `BatchMode=yes` (public-key authentication only; Aegis never stores or prompts for plaintext router passwords).

## Reporting a Vulnerability

Please **do not** open public GitHub issues for exploitable security vulnerabilities (e.g., packet parser memory exhaustion, XSS in the SOC UI, or command injection). Instead, use GitHub's **Private Vulnerability Reporting** ("Report a vulnerability" under the repository's **Security** tab).
