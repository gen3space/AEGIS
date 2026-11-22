# Contributing to Aegis

Contributions are welcome! Whether you are adding new L7 protocol decoders, MITRE ATT&CK behavioral rules, router platform bootstrap scripts, or UI improvements:

1. **Fork & Create a Feature Branch:** `git checkout -b feat/your-feature`
2. **Zero-Secret & Privacy Guarantee:** Never include real personal/ISP IP addresses, hardware MAC addresses, SSH keys, or local user paths in code, tests, or `.pcap` fixtures. Use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 1918 (`192.168.1.0/24`), and RFC 7042 documentation MACs (`00:00:5e:00:53:xx`).
3. **Run Automated Checks Before Opening a PR:**
   ```bash
   pip install -e ".[dev]"
   python scripts/verify_clean_repo.py
   ruff check aegis tests scripts
   pytest -v
   ```
