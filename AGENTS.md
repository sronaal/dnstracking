# DNSTRACKING

Python CLI tool for DNS reconnaissance and vulnerability scanning.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r src/requirements.txt
python main.py example.com -w wordlists/subdomains-medium.txt -t 30 --vulns
```

## Structure

- `main.py` — CLI entrypoint (Click), adds `src/` to `sys.path` at line 10
- `src/` — all application code, flat module layout
- `resultados/<dominio>/` — output directory (gitignored)
- `/tmp/dnstraking_*` — temp permutation wordlists (gitignored)
- 11 tests (resolver 5, DoH 4, WHOIS 2) in `tests/` via pytest (mocked, no network)
- Ruff & mypy config exists in `pyproject.toml` (tools not installed)

## Notes

- `requests==2.31.0` in `requirements.txt` (was previously missing, now resolved)

## Commands

```bash
python main.py <dominio> -w wordlists/subdomains-medium.txt -t 30 --vulns
```

`-o all` (default) writes TXT, JSON, CSV, HTML, NDJSON, YAML to `resultados/<dominio>/`. Use `-d <dir>` to change base dir (default: `resultados`).

## Key flags

| Flag | Purpose |
|------|---------|
| `-w` | subdomain wordlist path |
| `-t` | threads (default 20) |
| `-p` | subdomain permutations |
| `--passive` | passive sources (crt.sh, HackerTarget, CertSpotter, RapidDNS, AlienVault, ThreatCrowd) |
| `--passive-only` | skip direct DNS queries entirely |
| `--vulns` | security checks (11 checks, CRITICAL to INFO) |
| `--vulns-only` | skip subdomain enumeration, just check vulns |
| `--no-takeover` | skip HTTP takeover verification |
| `--no-infra` | skip infrastructure checks (CAA, TTL, NS, MX, amplification) |
| `--dns-server` | custom DNS server |
| `--tipos-dns` | record types to query (default: A) |
| `--whois` | WHOIS / RDAP domain registration lookup |
| `--ssl` | SSL/TLS certificate inspection of subdomains |
| `--geo` | IP geolocation & ASN lookup |
| `--doh` | DNS-over-HTTPS (Cloudflare) |
| `--ports` | Port scan common ports on discovered IPs |
| `--diff` | Compare against previous JSON scan results |

## Passive sources

Uses **no API keys**. Sources: crt.sh, HackerTarget, CertSpotter, RapidDNS, AlienVault OTX, ThreatCrowd. All called via `requests.get` with generous timeouts.

## WHOIS

Uses system `whois` command first, falls back to RDAP API (no key needed). Supports TLDs: com, net, org, info, io, co.

## SSL certificates

Certificate inspection uses Python's built-in `ssl` and `socket` modules (no extra deps). Checks each subdomain on port 443, extracts issuer, validity, SANs, days remaining.

## DNS-over-HTTPS

Uses Cloudflare JSON API (no extra deps). Replaces system DNS resolver entirely when `--doh` is set.

## Tests

```bash
pip install pytest
pytest tests/
```

11 tests: resolver (5), DoH (4), WHOIS (2). Uses mocking, no network required.

