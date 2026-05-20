# ESCÁNER DNS - RESUMEN EJECUTIVO

## 📊 VISIÓN GENERAL DEL PROYECTO

```
┌──────────────────────────────────────────────────────────────┐
│                  ESCÁNER DNS DE RECONOCIMIENTO               │
│                                                              │
│  Recopila información pública sobre la infraestructura      │
│  DNS de un dominio para análisis de seguridad               │
│                                                              │
│  ✓ Herramienta educativa                                    │
│  ✓ Consultas públicas (no invasivas)                        │
│  ✓ Automatiza investigación manual                          │
│  ✓ Genera reportes detallados                              │
└──────────────────────────────────────────────────────────────┘
```

---

## 🎯 OBJETIVOS PRINCIPALES

### 1. ENUMERACIÓN DE REGISTROS BÁSICOS
```
Objetivo: Descubrir información de infraestructura pública
├─ Direcciones IP (A, AAAA)
├─ Servidores de correo (MX)
├─ Servidores DNS (NS)
├─ Registros de texto (TXT, SPF, DKIM)
└─ Aliases (CNAME)

Información obtenida:
✓ Servidores principales
✓ Configuración de correo
✓ Políticas de seguridad (SPF/DKIM/DMARC)
✓ Certificados SSL (CAA)
```

### 2. ENUMERACIÓN DE SUBDOMINIOS
```
Objetivo: Descubrir hosts y servidores asociados
├─ www.example.com
├─ mail.example.com
├─ api.example.com
├─ admin.example.com
└─ dev.example.com

Método: Fuerza bruta con wordlist
✓ Rápido y confiable
✓ No requiere apis externas
✓ Privado
✓ Personalizable
```

### 3. TRANSFERENCIA DE ZONA (AXFR)
```
Objetivo: Intentar copiar base de datos DNS completa
├─ Raramente permitido
├─ Indica mal configuración
└─ Acceso completo a infraestructura

Resultado esperado:
✗ AXFR no permitido (99.9% de casos)
✓ AXFR permitido (0.1% - Jackpot!)
```

### 4. BÚSQUEDA INVERSA
```
Objetivo: Convertir IPs a dominios
└─ Descubrir hosts adicionales

Ejemplo:
93.184.216.34 → example.com
93.184.216.35 → mail.example.com
```

---

## 📦 ESTRUCTURA DEL CÓDIGO

```
dns-scanner/
│
├── main.py                      # Punto de entrada
│   └─ Interfaz CLI con Click
│
├── scanner.py                   # Lógica principal
│   ├─ class DNSScanner
│   ├─ enumerar_registros()
│   ├─ enumerar_subdominios()
│   ├─ transferencia_zona()
│   └─ escanear_completo()
│
├── resolver.py                  # Bajo nivel
│   ├─ class DNSResolver
│   ├─ resolver_registro()
│   └─ es_dominio_valido()
│
├── reporter.py                  # Reportes
│   ├─ guardar_json()
│   ├─ guardar_csv()
│   └─ guardar_html() [futuro]
│
├── requirements.txt             # Dependencias
├── wordlist-small.txt          # Palabras para pruebas
│
└── output/                      # Resultados
    ├─ example.com.json
    ├─ example.com.csv
    └─ example.com.html
```

---

## 🔄 FLUJO DE EJECUCIÓN

```
USUARIO
  │
  ▼
┌─────────────────────────────────┐
│  main.py                        │
│  - Parsear argumentos CLI       │
│  - Validar parámetros           │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Crear DNSScanner(dominio)      │
│  - Inicializar                  │
│  - Configurar timeout           │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  FASE 1: Validar dominio        │
│  - ¿Es válido?                  │
│  - ¿Es resoluble?               │
└──────────────┬──────────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
    [Válido]     [Inválido]
        │             │
        │             └─→ ERROR y salida
        │
        ▼
┌─────────────────────────────────┐
│  FASE 2: Enumeración Básica     │
│  - Consultar A, AAAA, MX, NS... │
│  - Mostrar resultados           │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  FASE 3: Enumeración Subdominios│
│  - Leer wordlist                │
│  - Probar combinaciones         │
│  - Guardar encontrados          │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  FASE 4: Transferencia de Zona  │
│  - Intentar AXFR                │
│  - Mostrar resultados           │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Generar Reportes               │
│  - JSON                         │
│  - CSV                          │
│  - HTML [futuro]                │
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│  Mostrar Resultados             │
│  - Resumen en pantalla          │
│  - Archivos guardados           │
└─────────────────────────────────┘
```

---

## 💾 DATOS DE ENTRADA Y SALIDA

### ENTRADA
```
Obligatorio:
  - Dominio: example.com

Opcional:
  -w, --wordlist    Archivo de palabras
  --no-axfr        No intentar AXFR
  -v, --verbose    Modo detallado
  -o, --output     Formato: txt, json, csv, all
```

### SALIDA
```
Pantalla:
  - Enumeración en tiempo real
  - Progreso de escaneo
  - Resultados encontrados
  - Resumen final

Archivos:
  - example.com.json    (Datos estructurados)
  - example.com.csv     (Compatible Excel)
  - example.com.html    (Visualización)
```

---

## 📋 EJEMPLO DE USO

```bash
# Instalación
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Uso básico
python3 main.py example.com

# Con wordlist
python3 main.py example.com -w wordlist-small.txt

# Generar JSON
python3 main.py example.com -w wordlist-small.txt -o json

# Todas las opciones
python3 main.py example.com \
  -w wordlist-small.txt \
  -o all \
  -v

# Sin AXFR (más rápido)
python3 main.py example.com --no-axfr
```

---

## 🎓 CONCEPTOS DNS EXPLICADOS

### Registros DNS Principales

```
┌──────┬─────────────────────────────────────────┐
│ A    │ Dirección IPv4 del servidor            │
│      │ example.com → 93.184.216.34            │
├──────┼─────────────────────────────────────────┤
│ AAAA │ Dirección IPv6 del servidor            │
│      │ example.com → 2606:2800:220:1:...     │
├──────┼─────────────────────────────────────────┤
│ MX   │ Servidor de correo                      │
│      │ 10 mail.example.com                     │
├──────┼─────────────────────────────────────────┤
│ NS   │ Servidor de nombres (DNS)              │
│      │ ns1.example.com                        │
├──────┼─────────────────────────────────────────┤
│ TXT  │ Registros de texto (SPF, DKIM)         │
│      │ v=spf1 include:... ~all                │
├──────┼─────────────────────────────────────────┤
│CNAME │ Alias del dominio                      │
│      │ www.example.com → example.com          │
├──────┼─────────────────────────────────────────┤
│ SOA  │ Autoridad de zona                       │
│      │ Información de administración           │
├──────┼─────────────────────────────────────────┤
│ CAA  │ Autoridad de certificado                │
│      │ Emisores SSL autorizados               │
└──────┴─────────────────────────────────────────┘
```

### ¿Cómo funcionan las consultas DNS?

```
1. Cliente DNS
   │
   ├─→ "¿Cuál es la IP de example.com?"
   │
   ▼
2. Servidor Recursivo
   │
   ├─→ "No lo tengo en caché, preguntaré"
   │
   ▼
3. Servidor Raíz
   │
   ├─→ "Pregunta a los NS de .com"
   │
   ▼
4. Servidor TLD (.com)
   │
   ├─→ "Pregunta a los NS de example.com"
   │
   ▼
5. Servidor Autoritario
   │
   ├─→ "La IP es 93.184.216.34"
   │
   ▼
6. Cliente recibe respuesta
   └─→ Respuesta cacheada 3600 segundos
```

---

## 🔐 CONSIDERACIONES DE SEGURIDAD

### ✅ BUENAS PRÁCTICAS

```
Código Responsable:
┌────────────────────────────────────────────┐
│ ✓ Usar solo en dominios autorizados       │
│ ✓ Obtener permiso escrito                 │
│ ✓ Documentar todas las actividades        │
│ ✓ Respetar rate limiting                  │
│ ✓ No usar para propósitos maliciosos      │
│ ✓ Cumplir leyes locales                   │
└────────────────────────────────────────────┘
```

### ⚠️ RIESGOS LEGALES

```
ILEGAL si:
✗ Acceso no autorizado
✗ Intención criminal
✗ Violación de privacidad
✗ Incumplimiento de leyes CFAA/GDPR

Penas:
✗ Hasta 10 años de prisión
✗ Multas de $100,000+
✗ Responsabilidad civil
```

### 🛡️ MITIGACIÓN

```
Protecc en tu código:
├─ Verificar autorización
├─ Registrar auditoría
├─ Limitar rate
├─ Respetar robots.txt
└─ Cumplir GDPR/CCPA
```

---

## 📈 FASES DE DESARROLLO

### Fase 1: MVP (Semana 1)
```
✓ Enumeración básica (A, AAAA, MX, NS)
✓ CLI funcional
✓ Validación de dominio
✓ Salida a pantalla
```

### Fase 2: Core (Semana 2)
```
✓ Enumeración de subdominios
✓ AXFR
✓ Reportes JSON/CSV
✓ Manejo de errores
```

### Fase 3: Optimización (Semana 3)
```
✓ Threading para velocidad
✓ Reportes HTML
✓ Caché de resultados
✓ APIs externas (VirusTotal)
```

### Fase 4: Extras (Futuro)
```
✓ Dashboard web
✓ Base de datos
✓ Análisis automático
✓ Alertas
```

---

## 📊 TABLA COMPARATIVA - MÉTODOS DE ESCANEO

```
┌──────────────┬──────────┬──────────┬─────────┬──────────┐
│ Método       │ Rápido   │ Preciso  │ Privado │ Permisos │
├──────────────┼──────────┼──────────┼─────────┼──────────┤
│ A/AAAA Query │ ✓✓✓      │ ✓✓✓      │ ✓✓      │ Público  │
│ Wordlist     │ ✓✓       │ ✓✓       │ ✓✓✓     │ Público  │
│ AXFR         │ ✓✓✓      │ ✓✓✓      │ ✓       │ Privado  │
│ APIs públicas│ ✓        │ ✓✓✓      │ ✗       │ Auth     │
│ Reverse IP   │ ✓✓       │ ✓✓       │ ✓✓      │ Público  │
└──────────────┴──────────┴──────────┴─────────┴──────────┘
```

---

## 🎯 CASOS DE USO

### 1. Pentesting Autorizado
```
Preparación:
- Contrato de servicio
- Alcance definido
- Autorización escrita

Proceso:
- Ejecutar escaneo completo
- Documentar hallazgos
- Generar reporte
- Presentar vulnerabilidades
```

### 2. Auditoría Interna
```
Objetivo:
- Verificar configuración DNS
- Validar seguridad
- Descubrir hosts desconocidos

Ejecución:
- Escaneo sin AXFR (discreto)
- Auditar resultados
- Actualizar inventario
```

### 3. Investigación de Amenazas
```
Función:
- Investigación pasiva
- Recopilación de inteligencia
- Mapeo de infraestructura

Método:
- Múltiples fuentes
- Análisis de datos
- Correlación de información
```

---

## 📚 RECURSOS DE APRENDIZAJE

### Libros
```
📖 "The Web Application Hacker's Handbook" - Stuttard, Pinto
📖 "Mastering Modern Linux" - Fenlason
📖 "Black Hat Python" - Justin Seitz
```

### Online
```
🌐 https://owasp.org/ - Seguridad web
🌐 https://tools.ietf.org/html/rfc1035 - DNS RFC
🌐 https://dnsdumpster.com/ - Herramienta visual
🌐 https://www.dnspython.org/ - Documentación
```

### Certificaciones
```
🏆 CompTIA Security+
🏆 Certified Ethical Hacker (CEH)
🏆 Offensive Security Certified Professional (OSCP)
🏆 GIAC Security Essentials (GSEC)
```

---

## ⚡ QUICK START (5 MINUTOS)

```bash
# 1. Clonar/descargar
git clone <repo>
cd dns-scanner

# 2. Instalar
pip install -r requirements.txt

# 3. Ejecutar
python3 main.py example.com -w wordlist-small.txt

# 4. Ver resultados
cat example.com.json
cat example.com.csv

# 5. Personalizar
# Editar wordlist-small.txt con tus palabras
# Ejecutar con opciones personalizadas
```

---

## 🚀 PRÓXIMOS PASOS

```
Hoy:
□ Configurar entorno
□ Instalar dependencias
□ Ejecutar primer escaneo

Mañana:
□ Implementar todas las fases
□ Crear wordlists
□ Generar reportes

Semana próxima:
□ Agregar threading
□ Integrar APIs
□ Crear interfaz web
```

---

## 📞 SOPORTE

```
Preguntas frecuentes:
→ Ver FAQ.md

Documentación completa:
→ Ver GUIA_IMPLEMENTACION_PASO_A_PASO.md

Ejemplos de código:
→ Ver EJEMPLOS_CODIGO.py

Desglose del proyecto:
→ Ver DNS_SCANNER_PLAN.md
```

---

## 📄 LICENCIA Y DISCLAIMER

```
DISCLAIMER IMPORTANTE:
═════════════════════════════════════════════

Esta herramienta es SOLO para uso educativo y autorizado.

❌ NO usar sin:
   - Autorización explícita
   - Contrato firmado
   - Respeto a leyes locales

⚖️ El usuario es responsable de:
   - Cumplimiento legal
   - Uso ético
   - Consecuencias legales

El autor NO es responsable de:
   - Uso malicioso
   - Daños causados
   - Actividades ilegales
```

---

## ✨ RESUMEN FINAL

```
╔════════════════════════════════════════════════════╗
║                                                    ║
║    ESCÁNER DNS - HERRAMIENTA PODEROSA Y SEGURA   ║
║                                                    ║
║  ✓ Educativa        (aprende conceptos DNS)       ║
║  ✓ Práctica         (usa en tu propia empresa)    ║
║  ✓ Profesional      (genera reportes)             ║
║  ✓ Extensible       (agrega tus propias features) ║
║                                                    ║
║     Úsala responsablemente y con permiso          ║
║                                                    ║
╚════════════════════════════════════════════════════╝
```

¡Esperamos que disfrutes construyendo este proyecto!

Para cualquier duda, consulta los otros archivos de documentación.
