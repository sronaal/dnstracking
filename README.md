# DNSTRACKING - Escáner DNS de Reconocimiento y Vulnerabilidades

Herramienta avanzada de reconocimiento DNS escrita en Python para auditoría y análisis de infraestructura DNS. Realiza enumeración de registros, descubrimiento de subdominios, transferencia de zona AXFR, búsquedas inversas, fuentes pasivas y **detección automática de vulnerabilidades DNS**.

## Características

### Reconocimiento DNS
- **Enumeración de registros DNS**: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA
- **Escaneo de subdominios**: Fuerza bruta con wordlists y threading configurable
- **Enumeración pasiva**: crt.sh, HackerTarget, RapidDNS, CertSpotter
- **Transferencia de zona AXFR**: Detección de misconfiguraciones DNS
- **Búsqueda inversa**: Resolución PTR de IPs a dominios
- **Detección de wildcards**: Filtrado automático de DNS wildcards
- **Permutaciones**: Generación avanzada de permutaciones de subdominios
- **Threaded scanning**: Escaneo concurrente configurable con barra de progreso y ETA

### Detección de Vulnerabilidades
- **AXFR Zone Transfer**: Detección de transferencia de zona permitida
- **DNSSEC**: Verificación de configuración y firmas digitales
- **SPF**: Análisis de política de email (missing, permissive, too many includes)
- **DMARC**: Verificación de política (missing, none, quarantine)
- **DKIM**: Detección de registros con múltiples selectores
- **Subdomain Takeover**: 20 fingerprints de servicios cloud (AWS S3, GitHub Pages, Heroku, Azure, Bitbucket, Shopify, Ghost, Zendesk, Surge.sh, Netlify, Tumblr, WordPress, Teamwork, Helpjuice, Campaign Monitor, Intercom, Webflow, SmugMug, Strikingly, UptimeRobot)
- **CAA**: Verificación de restricción de autoridades de certificación
- **Low TTL**: Detección de TTLs peligrosamente bajos (< 300s)
- **Private NS**: Nameservers apuntando a IPs RFC1918
- **DNS Amplification**: Factor de amplificación en consultas ANY
- **External MX**: Detección de servicios de email externos

### Reportes
- **JSON**: Datos completos estructurados
- **TXT**: Reporte en texto plano con tablas alineadas
- **CSV**: Tabla de subdominios con IPs y fuente
- **HTML**: Dashboard visual con dark theme, badges de severidad y estadísticas

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Uso

### Básico

```bash
python main.py example.com
```

### Con wordlist y threading

```bash
python main.py example.com -w wordlists/subdomains-medium.txt -t 30
```

### Escaneo completo con vulnerabilidades

```bash
python main.py example.com \
  -w wordlists/subdomains-medium.txt \
  -p \
  --passive \
  --vulns \
  --tipos-dns A,AAAA,CNAME \
  -o all \
  -v
```

### Solo análisis de vulnerabilidades

```bash
python main.py example.com --vulns-only
```

### Solo fuentes pasivas

```bash
python main.py example.com --passive-only
```

### Opciones avanzadas

| Opción | Descripción | Default |
|--------|-------------|---------|
| `-w, --wordlist` | Archivo con palabras para enumeración | - |
| `--no-axfr` | No intentar transferencia de zona | false |
| `--no-reverse` | No realizar búsquedas inversas | false |
| `-v, --verbose` | Modo verbose | false |
| `-o, --output` | Formato: txt, json, csv, html, all | all |
| `--timeout` | Timeout en segundos | 5 |
| `--max-sub` | Limitar subdominios encontrados | - |
| `--delay` | Delay entre lotes (segundos) | 0.0 |
| `--dns-server` | Servidor DNS personalizado | - |
| `-t, --threads` | Hilos concurrentes | 20 |
| `--tipos-dns` | Tipos DNS a consultar | A |
| `--no-wildcard` | Desactivar detección de wildcards | false |
| `-p, --permutations` | Generar permutaciones de subdominios | false |
| `--passive` | Incluir fuentes pasivas | false |
| `--passive-only` | Solo fuentes pasivas | false |
| `-d, --output-dir` | Directorio de resultados | resultados |
| `--vulns` | Ejecutar análisis de vulnerabilidades | false |
| `--vulns-only` | Solo análisis de vulnerabilidades | false |
| `--no-takeover` | Saltar check de subdomain takeover | false |
| `--no-infra` | Saltar checks de infraestructura | false |

## Estructura

```
dnstraking/
├── main.py              # CLI principal con Click
├── scanner.py           # Coordinador de escaneo (DNSScanner)
├── resolver.py          # Consultas DNS de bajo nivel (DNSResolver)
├── subdomain_scanner.py # Motor de subdominios con threading
├── sources.py           # Fuentes pasivas (crt.sh, HackerTarget, etc.)
├── vulnerabilities.py   # Motor de detección de vulnerabilidades
├── reporter.py          # Generación de reportes (JSON, CSV, TXT, HTML)
├── requirements.txt     # Dependencias
├── wordlists/           # Wordlists para enumeración
└── resultados/          # Resultados organizados por dominio
```

## Vulnerabilidades Detectadas

| Vulnerabilidad | Severidad | Descripción |
|---------------|-----------|-------------|
| AXFR Zone Transfer | CRITICAL | Transferencia de zona completa permitida |
| Subdomain Takeover | CRITICAL | CNAME huérfano a servicio cloud no configurado |
| SPF Record Missing | HIGH | Sin política de email, riesgo de spoofing |
| SPF Permissive | HIGH/MEDIUM | Política +all, ?all o ~all |
| DMARC Record Missing | HIGH | Sin política DMARC |
| DNSSEC Not Configured | MEDIUM | Sin firmas digitales DNS |
| DMARC Policy None | MEDIUM | Política no enforce, solo reportes |
| DKIM Record Missing | MEDIUM | Sin firma criptográfica de email |
| CAA Record Missing | MEDIUM | Cualquier CA puede emitir certificados |
| DNS Amplification | MEDIUM | Factor de amplificación > 10x |
| Low TTL | LOW | TTL < 300s, riesgo de DNS rebinding |
| SPF Too Many Includes | LOW | Riesgo de permerror por límite de 10 consultas |
| Private NS | HIGH | Nameservers con IPs RFC1918 |
| External MX | INFO | Servicio de email externo detectado |

## Dependencias

- **dnspython** - Consultas DNS
- **click** - Interfaz CLI
- **colorama** - Colores en terminal
- **tabulate** - Tablas formateadas
- **requests** - APIs externas (fuentes pasivas, subdomain takeover)

## Ejemplos de salida

Los resultados se guardan en `resultados/<dominio>/` con timestamp:

```
resultados/
├── google.com/
│   ├── scan_20260520_080647.json
│   ├── scan_20260520_080647.txt
│   ├── subdominios_20260520_080647.csv
│   └── reporte_20260520_080647.html
└── cloudflare.com/
    ├── scan_20260520_080719.json
    ├── scan_20260520_080719.txt
    └── reporte_20260520_080719.html
```

## Disclaimer

**Esta herramienta es SOLO para uso educativo y autorizado.**

- Usar únicamente en dominios con autorización explícita
- Obtener permiso escrito antes de realizar escaneos
- Respetar leyes locales y regulaciones aplicables
- El usuario es responsable del cumplimiento legal y uso ético

## Licencia

Uso educativo y de auditoría autorizada.
