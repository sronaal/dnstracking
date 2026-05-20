# DNSTRACKING

Escáner DNS de reconocimiento y detección de vulnerabilidades en Python.

## Instalación

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

## Uso

```bash
# Escaneo básico
python main.py example.com

# Con subdominios y threading
python main.py example.com -w wordlists/subdomains-medium.txt -t 30

# Con vulnerabilidades
python main.py example.com --vulns

# Solo vulnerabilidades
python main.py example.com --vulns-only

# Escaneo completo
python main.py example.com -w wordlists/subdomains-medium.txt -p --passive --vulns -o all
```

## Opciones

| Opción | Descripción |
|--------|-------------|
| `-w, --wordlist` | Wordlist para subdominios |
| `-t, --threads` | Hilos concurrentes (default: 20) |
| `-p, --permutations` | Permutaciones de subdominios |
| `--passive` | Fuentes pasivas (crt.sh, HackerTarget, etc) |
| `--passive-only` | Solo pasivo, sin consultas DNS |
| `--vulns` | Análisis de vulnerabilidades |
| `--vulns-only` | Solo vulnerabilidades |
| `--no-takeover` | Saltar subdomain takeover |
| `--no-infra` | Saltar checks de infraestructura |
| `--no-axfr` | Sin transferencia de zona |
| `--no-reverse` | Sin búsqueda inversa |
| `-o, --output` | Formato: txt, json, csv, html, all |
| `-d, --output-dir` | Directorio de resultados |
| `-v, --verbose` | Modo verbose |

## Vulnerabilidades

| Check | Severidad |
|-------|-----------|
| AXFR Zone Transfer | CRITICAL |
| Subdomain Takeover (20 servicios cloud) | CRITICAL |
| SPF Missing / Permissive | HIGH |
| DMARC Missing | HIGH |
| Private NS | HIGH |
| DNSSEC Missing | MEDIUM |
| DMARC None | MEDIUM |
| DKIM Missing | MEDIUM |
| CAA Missing | MEDIUM |
| DNS Amplification | MEDIUM |
| Low TTL | LOW |
| External MX | INFO |

## Estructura

```
dnstraking/
├── main.py              # CLI
├── scanner.py           # Coordinador
├── resolver.py          # Consultas DNS
├── subdomain_scanner.py # Threading + wildcards
├── sources.py           # APIs pasivas
├── vulnerabilities.py   # Detección de vulnerabilidades
├── reporter.py          # Reportes JSON/TXT/CSV/HTML
├── wordlists/           # Wordlists
└── resultados/          # Resultados por dominio
```

## Disclaimer

Solo para uso educativo y autorizado. Usar únicamente en dominios con permiso explícito.
