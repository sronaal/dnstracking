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
- No tests, no CI, no lint/format/typecheck config exist

## Known dependency issues

- `requests==2.31.0` is now listed in `requirements.txt` (was previously missing)
- `colorama==0.4.6` is listed but not yet imported by any source file

## Commands

```bash
python main.py <dominio> -w wordlists/subdomains-medium.txt -t 30 --vulns
```

`-o all` (default) writes JSON, TXT, HTML, CSV to `resultados/<dominio>/`. Use `-d <dir>` to change base dir.

## Key flags

| Flag | Purpose |
|------|---------|
| `-w` | subdomain wordlist path |
| `-t` | threads (default 20) |
| `-p` | subdomain permutations |
| `--passive` | passive sources (crt.sh, HackerTarget, CertSpotter, RapidDNS) |
| `--passive-only` | skip direct DNS queries entirely |
| `--vulns` | security checks (14 checks, CRITICAL to INFO) |
| `--vulns-only` | skip subdomain enumeration, just check vulns |
| `--no-takeover` | skip HTTP takeover verification |
| `--dns-server` | custom DNS server |
| `--tipos-dns` | record types to query (default: A) |
| `--whois` | WHOIS / RDAP domain registration lookup |
| `--ssl` | SSL/TLS certificate inspection of subdomains |
| `--geo` | IP geolocation & ASN lookup |

## Passive sources

Uses **no API keys**. Sources: crt.sh, HackerTarget, CertSpotter, RapidDNS. All called via `requests.get` with generous timeouts.

## WHOIS

Uses system `whois` command first, falls back to RDAP API (no key needed). Supports TLDs: com, net, org, info, io, co.

## SSL certificates

Certificate inspection uses Python's built-in `ssl` and `socket` modules (no extra deps). Checks each subdomain on port 443, extracts issuer, validity, SANs, days remaining.
