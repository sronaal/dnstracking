# Escáner de Reconocimiento DNS en Python
## Desglose Completo del Proyecto

---

## 1. VISIÓN GENERAL DEL PROYECTO

Un **escáner DNS** es una herramienta que recopila información sobre la infraestructura DNS de un dominio sin explotar vulnerabilidades. Se usa para:
- **Pentesting**: Pruebas autorizadas de seguridad
- **Reconocimiento**: Recopilar datos públicos del objetivo
- **Administración**: Auditar la configuración DNS propia

**No daña ni accede a sistemas**, solo consulta información pública.

---

## 2. ARQUITECTURA DEL PROYECTO

```
┌─────────────────────────────────────────────────────────────┐
│         DNS SCANNER - ESTRUCTURA GENERAL                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         MÓDULO PRINCIPAL (main.py)                  │   │
│  │  - Interfaz CLI                                     │   │
│  │  - Orquestación de escaneos                        │   │
│  │  - Gestión de argumentos                           │   │
│  └────────────────┬────────────────────────────────────┘   │
│                   │                                         │
│    ┌──────────────┼──────────────┐                         │
│    │              │              │                         │
│    ▼              ▼              ▼                         │
│  ┌──────┐  ┌──────────┐  ┌───────────┐                    │
│  │ENUM  │  │TRANSFER  │  │REVERSE    │                    │
│  │BASIC │  │ZONE      │  │LOOKUP     │                    │
│  │      │  │          │  │           │                    │
│  └──┬───┘  └────┬─────┘  └─────┬─────┘                    │
│     │           │              │                           │
│     └───────────┼──────────────┘                           │
│                 │                                           │
│     ┌───────────▼──────────────────┐                       │
│     │   DNS RESOLVER (dnspython)   │                       │
│     │  - Consultas DNS             │                       │
│     │  - Manejo de respuestas       │                       │
│     │  - Gestión de errores         │                       │
│     └───────────┬──────────────────┘                       │
│                 │                                           │
│     ┌───────────▼──────────────────┐                       │
│     │   GENERADOR DE REPORTES      │                       │
│     │  - JSON                      │                       │
│     │  - CSV                       │                       │
│     │  - HTML                      │                       │
│     └──────────────────────────────┘                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. COMPONENTES PRINCIPALES

### 3.1 ENUMERACIÓN DE REGISTROS BÁSICOS

**Objetivo**: Consultar tipos de registros DNS estándar

**Registros a enumerar**:
```
┌─────────────────────────────────────────┐
│ TIPO DE REGISTRO │ PROPÓSITO            │
├─────────────────────────────────────────┤
│ A               │ Dirección IPv4       │
│ AAAA            │ Dirección IPv6       │
│ CNAME           │ Alias del dominio    │
│ MX              │ Servidores de correo │
│ NS              │ Servidores de nombres│
│ TXT             │ Registros de texto   │
│ SOA             │ Autoridad de zona    │
│ SRV             │ Servicios            │
│ CAA             │ Autoridad de cert.   │
└─────────────────────────────────────────┘
```

**Ejemplo de salida**:
```
example.com A -> 93.184.216.34
example.com AAAA -> 2606:2800:220:1:248:1893:25c8:1946
example.com MX -> 0 mail.example.com
example.com NS -> ns1.example.com
example.com TXT -> "v=spf1 -all"
```

**Información obtenida**:
- IPs del servidor web
- Localización geográfica (posterior)
- Infraestructura de correo
- Configuración de SPF/DKIM/DMARC
- Certificados SSL (CAA)

---

### 3.2 ENUMERACIÓN DE SUBDOMINIOS

**Objetivo**: Descubrir subdominios asociados al dominio

**Métodos**:

#### 3.2.1 Fuerza Bruta
```python
Concepto:
1. Tomar lista de palabras comunes (www, mail, api, admin, etc.)
2. Combinar con el dominio: www.example.com, mail.example.com
3. Resolver cada combinación
4. Guardar los que existen

Ventajas:
✓ No requiere conexión a servicios externos
✓ Privado
✓ Rápido

Desventajas:
✗ Limitado a palabras de la lista
✗ Palabras personalizadas pueden no encontrarse
```

#### 3.2.2 Wordlists
```
Tamaños comunes:
- Pequeña: 100-500 palabras (rápido)
- Mediana: 1,000-10,000 palabras (equilibrio)
- Grande: 50,000+ palabras (exhaustivo)

Ejemplos de wordlists:
- SecLists: https://github.com/danielmiessler/SecLists
- DNS-Dumpster: Descargable
- Crunchbase: Datos reales
```

**Resultado esperado**:
```
api.example.com -> 10.0.0.5
dev.example.com -> 10.0.0.10
mail.example.com -> 10.0.0.15
admin.example.com -> 10.0.0.20
```

---

### 3.3 TRANSFERENCIA DE ZONA DNS (AXFR)

**Objetivo**: Intentar copiar toda la zona DNS (si es permitido)

**¿Qué es AXFR?**
```
AXFR (Zone Transfer):
- Protocolo para copiar base de datos DNS completa
- Antiguamente permitido entre servidores DNS legítimos
- HOY: Raramente permitido (mal configuración)
- Es como obtener un "backup" de todos los registros
```

**Proceso**:
```
1. Identificar servidores NS del dominio
2. Intentar conexión AXFR a cada servidor
3. Si es permitido → obtener TODOS los registros
4. Si no → falla elegantemente
```

**Información obtenida**:
- Todos los hosts de la red
- Servidores internos
- Infraestructura completa
- Información sensible

**Ejemplo**:
```
Dominio: example.com
Servidor NS: ns1.example.com

Resultado de AXFR:
example.com         SOA
example.com         NS    ns1.example.com
www.example.com     A     93.184.216.34
mail.example.com    A     93.184.216.35
ftp.example.com     A     93.184.216.36
internal.example.com A    192.168.1.100  ← ¡ENCONTRADO!
vpn.example.com     A     192.168.1.101  ← ¡ENCONTRADO!
db.example.com      A     192.168.1.102  ← ¡ENCONTRADO!
```

---

### 3.4 BÚSQUEDA INVERSA (Reverse Lookup)

**Objetivo**: Convertir IP a dominio

**¿Cómo funciona?**
```
IP: 93.184.216.34

Proceso:
1. Invertir octetos: 34.216.184.93
2. Agregar .in-addr.arpa: 34.216.184.93.in-addr.arpa
3. Consultar registro PTR
4. Obtener dominio asociado

Resultado: example.com
```

**Aplicación**:
- Encontrar dominios alojados en misma IP
- Descubrir hosts internos
- Mapear infraestructura

---

### 3.5 ENUMERACIÓN MEDIANTE APIs PÚBLICAS

**Fuentes de datos públicos**:

```
┌──────────────────────────────────────┐
│ SERVICIO         │ INFORMACIÓN       │
├──────────────────────────────────────┤
│ Shodan           │ Servicios abiertos│
│ VirusTotal       │ Historial DNS     │
│ SecurityTrails   │ Registros históricos
│ PassiveTotal     │ Datos pasivos     │
│ Whois            │ Registrante       │
│ Censys           │ Certificados SSL  │
└──────────────────────────────────────┘
```

---

## 4. FLUJO DE EJECUCIÓN

```
┌─────────────────────────────────────────────────────────┐
│ INICIO: Usuario especifica dominio y opciones           │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
        ┌────────────────────────────┐
        │ Validar dominio            │
        │ ¿Formato correcto?         │
        │ ¿Es resoluble?             │
        └────────┬───────────────────┘
                 │
         ┌───────┴────────┐
         ▼                ▼
    ┌────────┐      ┌──────────────┐
    │ Válido │      │ Inválido     │
    └───┬────┘      └─────┬────────┘
        │                 │
        ▼                 ▼
    ┌─────────────────────────────┐
    │ Mostrar error y salir       │
    └─────────────────────────────┘
        │
        │ (Continuación si es válido)
        │
        ▼
    ┌─────────────────────────────┐
    │ ENUMERACIÓN BÁSICA          │
    │ Consultar: A, AAAA, MX, etc │
    └─────────┬───────────────────┘
              │
              ▼
    ┌─────────────────────────────┐
    │ ENUMERACIÓN SUBDOMINIOS     │
    │ Cargar wordlist             │
    │ Probar cada combinación     │
    └─────────┬───────────────────┘
              │
              ▼
    ┌─────────────────────────────┐
    │ TRANSFERENCIA DE ZONA       │
    │ Intentar AXFR               │
    └─────────┬───────────────────┘
              │
              ▼
    ┌─────────────────────────────┐
    │ BÚSQUEDA INVERSA (opcional) │
    │ Convertir IPs encontradas   │
    └─────────┬───────────────────┘
              │
              ▼
    ┌─────────────────────────────┐
    │ GENERAR REPORTE             │
    │ - JSON                      │
    │ - HTML                      │
    │ - CSV                       │
    └─────────┬───────────────────┘
              │
              ▼
    ┌─────────────────────────────┐
    │ FIN: Mostrar resultados     │
    └─────────────────────────────┘
```

---

## 5. ESTRUCTURA DE ARCHIVOS

```
dns-scanner/
├── main.py                 # Punto de entrada principal
├── scanner.py              # Clase DNSScanner (lógica principal)
├── resolver.py             # Funciones de resolución DNS
├── reporter.py             # Generación de reportes
├── requirements.txt        # Dependencias del proyecto
├── wordlists/              # Listas de palabras
│   ├── subdomains-small.txt
│   ├── subdomains-medium.txt
│   └── subdomains-large.txt
├── output/                 # Resultados de escaneos
│   ├── example.com_2024-01-15.json
│   ├── example.com_2024-01-15.html
│   └── example.com_2024-01-15.csv
├── docs/                   # Documentación
│   ├── README.md
│   ├── USAGE.md
│   └── EXAMPLES.md
└── tests/                  # Tests unitarios
    ├── test_scanner.py
    └── test_resolver.py
```

---

## 6. DEPENDENCIAS

```python
# requirements.txt

dnspython==2.6.1          # Consultas y operaciones DNS
requests==2.31.0          # Llamadas HTTP (APIs)
click==8.1.7              # CLI interface
colorama==0.4.6           # Colores en terminal
tabulate==0.9.0           # Tablas formateadas
validators==0.22.0        # Validar dominios
python-whois==0.8.0       # Consultas WHOIS
beautifulsoup4==4.12.0    # Parse HTML (reportes)
jinja2==3.1.2             # Templates HTML
```

---

## 7. CASOS DE USO

### Caso 1: Pentesting Autorizado
```bash
$ python main.py scan example.com --full --output json
- Enumeración completa
- Generar reporte JSON
- Análisis de seguridad DNS
```

### Caso 2: Auditoría Interna
```bash
$ python main.py scan company.com --enum-records --enum-subdomains
- Verificar configuración DNS
- Descubrir servidores
- Validar seguridad
```

### Caso 3: Investigación Pasiva
```bash
$ python main.py scan target.com --no-zone-transfer --quiet
- Sin intentos agresivos
- No generar logs
- Bajo perfil
```

---

## 8. CARACTERÍSTICAS PRINCIPALES

### Implementación Básica (Fase 1)
- ✅ Enumeración de registros A, AAAA, MX, NS
- ✅ Búsqueda de subdominios por fuerza bruta
- ✅ Interfaz CLI simple
- ✅ Salida a consola

### Mejoras Intermedias (Fase 2)
- ✅ Transferencia de zona AXFR
- ✅ Búsqueda inversa
- ✅ Reportes JSON/CSV
- ✅ Gestión de errores mejorada

### Funciones Avanzadas (Fase 3)
- ✅ Integración con APIs (VirusTotal, SecurityTrails)
- ✅ Reportes HTML con visualizaciones
- ✅ Base de datos de resultados
- ✅ Programa de escaneos automáticos
- ✅ Estadísticas y análisis

---

## 9. SEGURIDAD Y ÉTICA

### Consideraciones Importantes:
```
⚠️ LEGAL:
   - Solo usar en dominios propios o con autorización
   - Consultar con equipo legal antes de pentesting
   - Documentar autorización escrita

⚠️ ÉTICO:
   - No acceder a sistemas sin permiso
   - No usar para vigilancia
   - Respetar privacidad

⚠️ TÉCNICO:
   - Limitar rate de consultas (no DOS)
   - Usar timeouts apropiados
   - Registrar acciones en logs
```

---

## 10. MÉTRICAS DE ÉXITO

```
✓ Registros DNS encontrados: 10+
✓ Subdominios descubiertos: 5+
✓ Transferencia de zona: Intentada
✓ Tiempo de ejecución: < 5 minutos
✓ Precisión de resultados: 99%+
✓ Tasa de error: < 1%
```

---

## 11. PRÓXIMOS PASOS

1. **Setup inicial**
   - [ ] Crear repositorio git
   - [ ] Instalar dependencias
   - [ ] Configurar estructura

2. **Desarrollo Fase 1**
   - [ ] Implementar scanner básico
   - [ ] Enumeración de registros
   - [ ] CLI funcional

3. **Desarrollo Fase 2**
   - [ ] Transferencia de zona
   - [ ] Reportes
   - [ ] Gestión de errores

4. **Testing**
   - [ ] Tests unitarios
   - [ ] Tests de integración
   - [ ] Testing manual

5. **Documentación**
   - [ ] README
   - [ ] Ejemplos de uso
   - [ ] Guía de instalación

---

## CONCLUSIÓN

Este es un proyecto educativo que enseña:
- 🔹 Conceptos de DNS
- 🔹 Programación en Python
- 🔹 Ciberseguridad ofensiva
- 🔹 Ingeniería inversa de información
- 🔹 Buenas prácticas de código

**Recuerda**: La información es poder. Úsalo responsablemente.
