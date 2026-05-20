# GUÍA DE IMPLEMENTACIÓN - Escáner DNS Paso a Paso

## Fase 0: Preparación del Entorno

### 0.1 Requisitos del Sistema
```bash
# Verificar versión de Python (3.8+)
python3 --version

# Ejemplo de salida esperado:
# Python 3.10.12

# Crear directorio del proyecto
mkdir dns-scanner
cd dns-scanner

# Crear entorno virtual (recomendado)
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# o
venv\Scripts\activate  # Windows
```

### 0.2 Instalar Dependencias
```bash
# Crear archivo requirements.txt
cat > requirements.txt << 'EOF'
dnspython==2.6.1
click==8.1.7
colorama==0.4.6
tabulate==0.9.0
EOF

# Instalar
pip install -r requirements.txt

# Verificar instalación
python3 -c "import dns; print('dnspython OK')"
```

---

## Fase 1: Construir el Módulo Base (resolver.py)

### 1.1 Crear resolver.py - Funciones de Resolución

```python
# resolver.py
"""
Módulo de bajo nivel para consultas DNS
Maneja toda la interacción con los servidores DNS
"""

import dns.resolver
import dns.reversename
import dns.exception
from typing import List, Dict

class DNSResolver:
    """Clase para manejar todas las consultas DNS"""
    
    def __init__(self, timeout: int = 5):
        """
        Inicializar resolver
        
        Args:
            timeout: Tiempo máximo de espera en segundos
        """
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.timeout = timeout
    
    def resolver_registro(self, dominio: str, tipo: str) -> List[str]:
        """
        Resolver un registro DNS específico
        
        Args:
            dominio: ejemplo.com
            tipo: A, AAAA, MX, NS, TXT, etc
        
        Returns:
            Lista de resultados
        """
        try:
            respuestas = self.resolver.resolve(dominio, tipo)
            return [str(rdata).rstrip('.') for rdata in respuestas]
        except dns.resolver.NXDOMAIN:
            raise Exception(f"Dominio {dominio} no existe")
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.Timeout:
            raise Exception(f"Timeout resolviendo {tipo} para {dominio}")
        except Exception as e:
            raise Exception(f"Error: {str(e)}")
    
    def es_dominio_valido(self, dominio: str) -> bool:
        """Verificar si el dominio es válido y resoluble"""
        try:
            self.resolver_registro(dominio, 'A')
            return True
        except:
            return False
```

### 1.2 Crear enumerador básico en resolver.py

```python
# Agregar a resolver.py

def enumerar_basicos(self, dominio: str) -> Dict[str, List[str]]:
    """Enumera registros DNS básicos"""
    
    tipos = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    resultados = {}
    
    for tipo in tipos:
        try:
            resultados[tipo] = self.resolver_registro(dominio, tipo)
        except:
            resultados[tipo] = []
    
    return resultados
```

---

## Fase 2: Crear el Scanner Principal (scanner.py)

### 2.1 Estructura Básica

```python
# scanner.py
"""
Módulo principal del escáner DNS
Coordina todas las operaciones de escaneo
"""

import sys
from datetime import datetime
from typing import List, Dict, Set
from resolver import DNSResolver

class DNSScanner:
    """Escáner DNS principal"""
    
    def __init__(self, dominio: str, verbose: bool = False):
        self.dominio = dominio.rstrip('.')
        self.verbose = verbose
        self.resolver = DNSResolver()
        self.resultados = {
            'dominio': dominio,
            'fecha': datetime.now().isoformat(),
            'basicos': {},
            'subdominios': [],
            'axfr': False
        }
    
    def log(self, msg: str, level: str = 'INFO'):
        """Mostrar mensajes"""
        if self.verbose:
            print(f"[{level}] {msg}")
    
    def _mostrar_progreso(self, actual: int, total: int, prefijo: str = ""):
        """Mostrar barra de progreso"""
        porcentaje = (actual / total) * 100
        barras = int(porcentaje / 5)
        barra = "█" * barras + "░" * (20 - barras)
        
        sys.stdout.write(f"\r{prefijo} [{barra}] {porcentaje:.1f}%")
        sys.stdout.flush()
```

### 2.2 Implementar enumeración de subdominios

```python
# Agregar a scanner.py

def enumerar_subdominios(self, 
                         wordlist: str, 
                         max_resultados: int = None) -> List[Dict]:
    """
    Enumera subdominios por fuerza bruta
    
    Args:
        wordlist: Archivo con palabras
        max_resultados: Limitar número de resultados
    
    Returns:
        Lista de subdominios encontrados
    """
    
    print(f"\n[+] Enumerando subdominios")
    print("-" * 60)
    
    # Leer wordlist
    try:
        with open(wordlist, 'r') as f:
            palabras = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        print(f"[-] Wordlist no encontrada: {wordlist}")
        return []
    
    subdominios = []
    total = len(palabras)
    encontrados = 0
    
    print(f"[*] Probando {total} palabras...\n")
    
    for i, palabra in enumerate(palabras, 1):
        subdominio = f"{palabra}.{self.dominio}"
        
        try:
            # Intentar resolver
            ips = self.resolver.resolver_registro(subdominio, 'A')
            
            if ips:
                print(f"\n[FOUND] {subdominio}")
                for ip in ips:
                    print(f"        └─ {ip}")
                
                subdominios.append({
                    'dominio': subdominio,
                    'ips': ips
                })
                encontrados += 1
                
                # Limitar resultados
                if max_resultados and encontrados >= max_resultados:
                    break
        
        except:
            pass  # Subdominio no existe
        
        # Mostrar progreso
        if i % 50 == 0:
            self._mostrar_progreso(i, total, "Progreso")
    
    print(f"\n\n[+] Subdominios encontrados: {len(subdominios)}")
    self.resultados['subdominios'] = subdominios
    return subdominios
```

### 2.3 Implementar transferencia de zona

```python
# Agregar a scanner.py

import dns.zone
import dns.query

def transferencia_zona(self) -> bool:
    """Intenta transferencia de zona AXFR"""
    
    print(f"\n[+] Intentando transferencia de zona")
    print("-" * 60)
    
    try:
        # Obtener servidores NS
        ns_servidores = self.resolver.resolver_registro(
            self.dominio, 'NS'
        )
        
        print(f"[*] Servidores NS: {', '.join(ns_servidores)}\n")
        
        for ns in ns_servidores:
            try:
                print(f"[*] Intentando con {ns}...")
                
                # Realizar AXFR
                zona = dns.zone.from_xfr(
                    dns.query.xfr(ns, self.dominio, lifetime=10)
                )
                
                print(f"[SUCCESS] ¡AXFR permitido en {ns}!")
                print(f"[+] Registros encontrados: {len(zona)}\n")
                
                # Mostrar registros
                for nombre, nodo in zona.items():
                    for rdataset in nodo:
                        for rdata in rdataset:
                            print(f"  {nombre} {rdataset.rdtype} {rdata}")
                
                self.resultados['axfr'] = True
                return True
            
            except dns.exception.TransferFailed:
                self.log(f"Transferencia rechazada en {ns}")
            except Exception as e:
                self.log(f"Error en {ns}: {e}")
        
        print("[-] AXFR no permitido")
        return False
    
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
```

### 2.4 Función de escaneo completo

```python
# Agregar a scanner.py

def escanear_completo(self, 
                      wordlist: str = None,
                      intentar_axfr: bool = True) -> Dict:
    """
    Ejecuta escaneo completo del dominio
    
    Args:
        wordlist: Archivo de palabras para subdominios
        intentar_axfr: Intentar transferencia de zona
    
    Returns:
        Diccionario con todos los resultados
    """
    
    print("\n" + "="*60)
    print(f"ESCÁNER DNS - {self.dominio}")
    print("="*60 + "\n")
    
    # Validar dominio
    print("[*] Validando dominio...")
    if not self.resolver.es_dominio_valido(self.dominio):
        print(f"[-] Dominio inválido: {self.dominio}")
        return self.resultados
    print("[✓] Dominio válido\n")
    
    # Fase 1: Registros básicos
    print("[FASE 1/3] Enumeración de registros básicos\n")
    try:
        self.resultados['basicos'] = self.resolver.enumerar_basicos(
            self.dominio
        )
        
        for tipo, valores in self.resultados['basicos'].items():
            if valores:
                print(f"[{tipo}]")
                for valor in valores:
                    print(f"      {valor}")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    # Fase 2: Subdominios
    if wordlist:
        print("\n[FASE 2/3] Enumeración de subdominios\n")
        self.enumerar_subdominios(wordlist)
    else:
        print("\n[FASE 2/3] Enumeración de subdominios - OMITIDA")
        print("    (Sin wordlist)")
    
    # Fase 3: AXFR
    if intentar_axfr:
        print("\n[FASE 3/3] Transferencia de zona DNS")
        self.transferencia_zona()
    
    print("\n" + "="*60)
    print("ESCANEO COMPLETADO")
    print("="*60 + "\n")
    
    return self.resultados
```

---

## Fase 3: Crear Reportes (reporter.py)

### 3.1 Generar JSON

```python
# reporter.py
"""
Módulo para generar reportes en diferentes formatos
"""

import json
import csv
from typing import Dict, List

class Reporter:
    """Generador de reportes"""
    
    @staticmethod
    def guardar_json(resultados: Dict, archivo: str):
        """Guardar resultados en JSON"""
        try:
            with open(archivo, 'w') as f:
                json.dump(resultados, f, indent=2)
            print(f"[✓] JSON guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error: {e}")
    
    @staticmethod
    def guardar_csv(subdominios: List[Dict], archivo: str):
        """Guardar subdominios en CSV"""
        try:
            with open(archivo, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdominio', 'IP'])
                
                for sub in subdominios:
                    for ip in sub['ips']:
                        writer.writerow([sub['dominio'], ip])
            
            print(f"[✓] CSV guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error: {e}")
```

---

## Fase 4: Interfaz CLI (main.py)

### 4.1 Script Principal

```python
#!/usr/bin/env python3
# main.py

import click
from scanner import DNSScanner
from reporter import Reporter

@click.command()
@click.argument('dominio')
@click.option('-w', '--wordlist', 
              help='Archivo con palabras para subdominios')
@click.option('--no-axfr', 
              is_flag=True, 
              help='No intentar transferencia de zona')
@click.option('-v', '--verbose', 
              is_flag=True, 
              help='Modo verbose')
@click.option('-o', '--output', 
              default='txt',
              type=click.Choice(['txt', 'json', 'csv', 'all']),
              help='Formato de salida')
def scan(dominio, wordlist, no_axfr, verbose, output):
    """
    Escáner DNS de reconocimiento
    
    Ejemplo:
        python main.py example.com -w wordlist.txt -o json
    """
    
    # Crear scanner
    scanner = DNSScanner(dominio, verbose=verbose)
    
    # Ejecutar escaneo
    resultados = scanner.escanear_completo(
        wordlist=wordlist,
        intentar_axfr=not no_axfr
    )
    
    # Guardar reportes
    if output in ['json', 'all']:
        Reporter.guardar_json(resultados, f"{dominio}.json")
    
    if output in ['csv', 'all'] and resultados['subdominios']:
        Reporter.guardar_csv(resultados['subdominios'], f"{dominio}.csv")

if __name__ == '__main__':
    scan()
```

### 4.2 Hacer ejecutable

```bash
chmod +x main.py
```

---

## Fase 5: Crear Wordlist

### 5.1 Subdominios Comunes

```bash
cat > wordlist-small.txt << 'EOF'
www
mail
ftp
localhost
webmail
smtp
pop
ns1
webdisk
ns2
cpanel
whm
autodiscover
autoconfig
m
git
api
dev
test
admin
staging
prod
EOF
```

### 5.2 Descarga de Wordlists Profesionales

```bash
# Descargar SecLists (extenso)
git clone https://github.com/danielmiessler/SecLists.git

# O usar versión comprimida
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## Fase 6: Testing

### 6.1 Prueba Básica

```bash
# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Ejecutar en dominio público
python3 main.py google.com -v

# Con wordlist
python3 main.py example.com -w wordlist-small.txt

# Generar JSON
python3 main.py example.com -w wordlist-small.txt -o json

# Todas las opciones
python3 main.py example.com -w wordlist-small.txt -o all -v
```

### 6.2 Salida Esperada

```
============================================================
ESCÁNER DNS - example.com
============================================================

[*] Validando dominio...
[✓] Dominio válido

[FASE 1/3] Enumeración de registros básicos

[A]
      93.184.216.34
[AAAA]
      2606:2800:220:1:248:1893:25c8:1946
[MX]
      0 aspmx.l.google.com.

[FASE 2/3] Enumeración de subdominios

[*] Probando 20 palabras...

[FOUND] www.example.com
        └─ 93.184.216.34

[+] Subdominios encontrados: 1

[FASE 3/3] Transferencia de zona DNS

[+] Intentando transferencia de zona
[*] Servidores NS: ns1.example.com, ns2.example.com

[-] AXFR no permitido

============================================================
ESCANEO COMPLETADO
============================================================

[✓] JSON guardado: example.com.json
```

---

## Fase 7: Optimizaciones

### 7.1 Agregar Manejo de Errores

```python
# En scanner.py - mejorar excepciones

try:
    resultados = scanner.escanear_completo(wordlist)
except KeyboardInterrupt:
    print("\n[-] Escaneo cancelado por usuario")
except Exception as e:
    print(f"[-] Error fatal: {e}")
```

### 7.2 Agregar Control de Rate Limiting

```python
import time

# En enumerar_subdominios()
time.sleep(0.1)  # Esperar 100ms entre consultas
```

### 7.3 Agregar Caché de Resultados

```python
import pickle

def guardar_cache(self, archivo: str):
    with open(archivo, 'wb') as f:
        pickle.dump(self.resultados, f)

def cargar_cache(self, archivo: str):
    with open(archivo, 'rb') as f:
        self.resultados = pickle.load(f)
```

---

## Checklist de Implementación

- [ ] **Fase 0**: Entorno configurado
- [ ] **Fase 1**: resolver.py completo
- [ ] **Fase 2**: scanner.py con enumeración básica
- [ ] **Fase 2b**: scanner.py con subdominios
- [ ] **Fase 2c**: scanner.py con AXFR
- [ ] **Fase 3**: reporter.py funcionando
- [ ] **Fase 4**: main.py con CLI
- [ ] **Fase 5**: Wordlist creada
- [ ] **Fase 6**: Testing exitoso
- [ ] **Fase 7**: Optimizaciones aplicadas

---

## Comandos de Ejecución Rápida

```bash
# Instalar todo
pip install -r requirements.txt

# Test rápido
python3 main.py google.com -v

# Escaneo completo
python3 main.py example.com -w wordlist-small.txt -o json -v

# Sin AXFR (más rápido)
python3 main.py example.com --no-axfr -w wordlist-small.txt

# Solo registros básicos
python3 main.py example.com --no-axfr
```

---

## Próximos Pasos Avanzados

1. **Agregar APIs externas**
   - VirusTotal
   - SecurityTrails
   - Shodan

2. **Mejorar reportes**
   - HTML con gráficos
   - PDF exportable
   - Dashboard interactivo

3. **Optimizar velocidad**
   - Threading/Async
   - Procesamiento paralelo
   - Caché distribuido

4. **Agregar análisis**
   - Detección de anomalías
   - Puntuación de riesgo
   - Comparación histórica

¡Éxito con tu proyecto!
