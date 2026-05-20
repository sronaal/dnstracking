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

## Estructura

```
dnstraking/
├── main.py                    # Entry point CLI
├── README.md                  # Documentación
├── .gitignore
├── src/                       # Código fuente
│   ├── __init__.py
│   ├── scanner.py             # Coordinador de escaneo
│   ├── resolver.py            # Consultas DNS de bajo nivel
│   ├── subdomain_scanner.py   # Motor de subdominios con threading
│   ├── sources.py             # Fuentes pasivas (APIs externas)
│   ├── vulnerabilities.py     # Motor de detección de vulnerabilidades
│   ├── reporter.py            # Generación de reportes (JSON/TXT/CSV/HTML)
│   └── requirements.txt       # Dependencias
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
| `sources.py` | APIs pasivas: crt.sh, HackerTarget, CertSpotter, RapidDNS |
| `vulnerabilities.py` | 14 checks de seguridad con severidades y CVSS |
| `reporter.py` | Genera reportes en JSON, TXT, CSV y HTML con dashboard |

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

## Dependencias

- **dnspython** - Consultas DNS
- **click** - Interfaz CLI
- **colorama** - Colores en terminal
- **tabulate** - Tablas formateadas
- **requests** - APIs externas y verificación HTTP

## Disclaimer

Solo para uso educativo y autorizado. Usar únicamente en dominios con permiso explícito.
