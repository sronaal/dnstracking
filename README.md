# DNSTRACKING - Escáner DNS de Reconocimiento

Herramienta avanzada de reconocimiento DNS escrita en Python para auditoría y análisis de infraestructura DNS. Realiza enumeración de registros, descubrimiento de subdominios, transferencia de zona AXFR, búsquedas inversas y fuentes pasivas.

## Características

- **Enumeración de registros DNS**: A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA
- **Escaneo de subdominios**: Fuerza bruta con wordlists y threading configurable
- **Enumeración pasiva**: crt.sh, HackerTarget, RapidDNS, CertSpotter
- **Transferencia de zona AXFR**: Detección de misconfiguraciones DNS
- **Búsqueda inversa**: Resolución PTR de IPs a dominios
- **Detección de wildcards**: Filtrado automático de DNS wildcards
- **Permutaciones**: Generación avanzada de permutaciones de subdominios
- **Reportes múltiples**: JSON, CSV, TXT, HTML con dashboard visual
- **Threaded scanning**: Escaneo concurrente configurable con barra de progreso

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

### Escaneo completo

```bash
python main.py example.com \
  -w wordlists/subdomains-medium.txt \
  -p \
  --passive \
  --tipos-dns A,AAAA,CNAME \
  -o all \
  -v
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

## Estructura

```
dnstraking/
├── main.py              # CLI principal con Click
├── scanner.py           # Coordinador de escaneo (DNSScanner)
├── resolver.py          # Consultas DNS de bajo nivel (DNSResolver)
├── subdomain_scanner.py # Motor de subdominios con threading
├── sources.py           # Fuentes pasivas (crt.sh, HackerTarget, etc.)
├── reporter.py          # Generación de reportes (JSON, CSV, TXT, HTML)
├── requirements.txt     # Dependencias
├── wordlists/           # Wordlists para enumeración
└── resultados/          # Resultados organizados por dominio
```

## Dependencias

- **dnspython** - Consultas DNS
- **click** - Interfaz CLI
- **colorama** - Colores en terminal
- **tabulate** - Tablas formateadas
- **requests** - APIs externas (fuentes pasivas)

## Ejemplos de salida

Los resultados se guardan en `resultados/<dominio>/` con timestamp:

```
resultados/
└── google.com/
    ├── scan_20260519_143022.json
    ├── scan_20260519_143022.txt
    ├── subdominios_20260519_143022.csv
    └── reporte_20260519_143022.html
```

## Disclaimer

**Esta herramienta es SOLO para uso educativo y autorizado.**

- Usar únicamente en dominios con autorización explícita
- Obtener permiso escrito antes de realizar escaneos
- Respetar leyes locales y regulaciones aplicables
- El usuario es responsable del cumplimiento legal y uso ético

## Licencia

Uso educativo y de auditoría autorizada.
