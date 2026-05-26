# DNSTRACKING

Escáner DNS de reconocimiento y detección de vulnerabilidades en Python.

## Instalación

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r src/requirements.txt
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

# Con WHOIS del dominio
python main.py example.com --whois

# Con inspección SSL/TLS de subdominios
python main.py example.com -w wordlists/subdomains-medium.txt --ssl

# Con geolocalización de IPs
python main.py example.com --geo

# Con DNS-over-HTTPS (Cloudflare)
python main.py example.com --doh

# Con escaneo de puertos comunes
python main.py example.com -w wordlists/subdomains-medium.txt --ports

# Comparar con un escaneo anterior
python main.py example.com --diff resultados/example.com/scan_20250101_120000.json

# Escaneo completo
python main.py example.com -w wordlists/subdomains-medium.txt -p --passive --vulns --whois --ssl --geo --doh --ports -o all
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
| `--no-wildcard` | Desactivar detección de wildcards |
| `-o, --output` | Formato: txt, json, csv, html, ndjson, yaml, all |
| `-d, --output-dir` | Directorio de resultados (default: resultados) |
| `-v, --verbose` | Modo verbose |
| `--dns-server` | Servidor DNS personalizado |
| `--tipos-dns` | Tipos DNS separados por coma (A,AAAA,CNAME) |
| `--timeout` | Timeout en segundos para consultas DNS (default: 5) |
| `--delay` | Delay en segundos entre lotes de consultas |
| `--max-sub` | Limitar número de subdominios encontrados |
| `--whois` | Consultar WHOIS del dominio |
| `--ssl` | Inspeccionar certificados SSL/TLS |
| `--geo` | Geolocalizar IPs encontradas |
| `--doh` | Usar DNS-over-HTTPS (Cloudflare) |
| `--ports` | Escanear puertos comunes en IPs |
| `--diff` | Comparar con resultado JSON anterior (ruta) |

## Estructura

```
dnstraking/
├── main.py                    # Entry point CLI
├── README.md                  # Documentación
├── .gitignore
├── pyproject.toml             # Configuración del proyecto (pytest, ruff, mypy)
├── src/                       # Código fuente
│   ├── __init__.py
│   ├── scanner.py             # Coordinador de escaneo
│   ├── resolver.py            # Consultas DNS de bajo nivel
│   ├── subdomain_scanner.py   # Motor de subdominios con threading
│   ├── sources.py             # Fuentes pasivas (6 APIs externas)
│   ├── vulnerabilities.py     # Motor de detección de vulnerabilidades
│   ├── reporter.py            # Generación de reportes (JSON/TXT/CSV/HTML/NDJSON/YAML)
│   ├── certificate.py         # Inspección SSL/TLS
│   ├── color_util.py          # Colores en terminal (colorama)
│   ├── doh_resolver.py        # DNS-over-HTTPS
│   ├── geo.py                 # Geolocalización + ASN
│   ├── port_scanner.py        # Escaneo de puertos
│   ├── whois_lookup.py        # Consulta WHOIS
│   └── requirements.txt       # Dependencias
├── tests/                     # Tests unitarios (pytest)
│   ├── test_resolver.py
│   ├── test_doh.py
│   └── test_whois.py
├── wordlists/                 # Listas de palabras
│   ├── subdomains-small.txt   (30 palabras)
│   ├── subdomains-medium.txt  (180 palabras)
│   └── subdomains-large.txt   (400+ palabras)
├── docs/                      # Documentación de referencia
│   ├── DNS_SCANNER_PLAN.md
│   ├── EJEMPLOS_CODIGO.py
│   ├── GUIA_IMPLEMENTACION_PASO_A_PASO.md
│   ├── INDEX.md
│   └── RESUMEN_EJECUTIVO.md
└── resultados/                # Resultados por dominio (gitignored)
```

## Módulos

| Módulo | Función |
|--------|---------|
| `main.py` | CLI con Click, parsea argumentos y orquesta el escaneo |
| `scanner.py` | Clase DNSScanner, coordina todas las fases del escaneo |
| `resolver.py` | Clase DNSResolver, consultas DNS de bajo nivel con dnspython |
| `subdomain_scanner.py` | Threading, wildcard detection, permutaciones avanzadas |
| `sources.py` | APIs pasivas: crt.sh, HackerTarget, CertSpotter, RapidDNS, AlienVault OTX, ThreatCrowd |
| `vulnerabilities.py` | 11 checks de seguridad con severidades y CVSS |
| `reporter.py` | Genera reportes en JSON, TXT, CSV, HTML, NDJSON y YAML |
| `whois_lookup.py` | WHOIS via sistema + fallback RDAP (com, net, org, info, io, co) |
| `certificate.py` | Certificados SSL/TLS via socket+ssl (stdlib, sin deps extra) |
| `geo.py` | Geolocalización + ASN via ip-api.com (gratis, sin API key) |
| `doh_resolver.py` | Resolución DNS-over-HTTPS (Cloudflare/Google) |
| `port_scanner.py` | Escaneo concurrente de 24 puertos comunes |
| `color_util.py` | Funciones de color con colorama |

## Vulnerabilidades

| Check | Severidad |
|-------|-----------|
| AXFR Zone Transfer | CRITICAL |
| Subdomain Takeover (20+ servicios cloud) | CRITICAL |
| SPF Missing / Permissive | HIGH |
| DMARC Missing | HIGH |
| Private NS | HIGH |
| DNSSEC Keys Present but No Signatures | HIGH |
| DNSSEC Missing | MEDIUM |
| DMARC Policy None | MEDIUM |
| DKIM Missing | MEDIUM |
| CAA Missing | MEDIUM |
| DNS Amplification | MEDIUM |
| SPF Permissive (?all / ~all) | MEDIUM |
| SPF Too Many Includes | LOW |
| Low TTL | LOW |
| DMARC Policy Quarantine | LOW |
| External MX | INFO |

## Tests

```bash
pip install pytest
pytest tests/
```

11 tests: resolver (5), DoH (4), WHOIS (2). Usan mocking, no requieren red.

## Dependencias

- **dnspython** - Consultas DNS
- **click** - Interfaz CLI
- **colorama** - Colores en terminal
- **tabulate** - Tablas formateadas
- **requests** - APIs externas y verificación HTTP

## Disclaimer

Solo para uso educativo y autorizado. Usar únicamente en dominios con permiso explícito.
