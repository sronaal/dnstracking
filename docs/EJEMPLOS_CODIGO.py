"""
EJEMPLOS DE CÓDIGO - Componentes del Escáner DNS
Cada sección muestra cómo implementar un componente específico
"""

# ============================================================
# 1. ENUMERACIÓN DE REGISTROS BÁSICOS
# ============================================================

import dns.resolver

def enumerar_registros_basicos(dominio):
    """
    Consulta los registros DNS básicos de un dominio
    
    Registros consultados:
    - A: Dirección IPv4 del servidor
    - AAAA: Dirección IPv6 del servidor
    - MX: Servidores de correo
    - NS: Servidores de nombres (DNS)
    - TXT: Registros de texto (SPF, DKIM, etc)
    - CNAME: Alias del dominio
    """
    
    print(f"[+] Enumerando registros de {dominio}\n")
    
    registros = {
        'A': 'Dirección IPv4',
        'AAAA': 'Dirección IPv6',
        'MX': 'Servidor de correo',
        'NS': 'Servidor de nombres',
        'TXT': 'Registro de texto',
        'CNAME': 'Alias'
    }
    
    resultados = {}
    
    for tipo, descripcion in registros.items():
        try:
            print(f"[*] Consultando {tipo} ({descripcion})...")
            respuestas = dns.resolver.resolve(dominio, tipo, lifetime=5)
            resultados[tipo] = []
            
            for rdata in respuestas:
                resultado = str(rdata).rstrip('.')
                resultados[tipo].append(resultado)
                print(f"    ✓ {tipo}: {resultado}")
                
        except dns.resolver.NXDOMAIN:
            print(f"    ✗ Dominio no existe")
        except dns.resolver.NoAnswer:
            print(f"    ✗ No hay registros {tipo}")
        except dns.exception.Timeout:
            print(f"    ✗ Timeout")
        except Exception as e:
            print(f"    ✗ Error: {e}")
    
    return resultados


# EJEMPLO DE USO:
# resultados = enumerar_registros_basicos("google.com")
# 
# Output esperado:
# [+] Enumerando registros de google.com
# 
# [*] Consultando A (Dirección IPv4)...
#     ✓ A: 142.250.185.46
# [*] Consultando AAAA (Dirección IPv6)...
#     ✓ AAAA: 2607:f8b0:4004:809::200e
# [*] Consultando MX (Servidor de correo)...
#     ✓ MX: 10 smtp.google.com.
# [*] Consultando NS (Servidor de nombres)...
#     ✓ NS: ns1.google.com.
#     ✓ NS: ns2.google.com.
# [*] Consultando TXT (Registro de texto)...
#     ✓ TXT: "v=spf1 include:_spf.google.com ~all"


# ============================================================
# 2. ENUMERACIÓN DE SUBDOMINIOS - FUERZA BRUTA
# ============================================================

def enumerar_subdominios(dominio, wordlist):
    """
    Prueba combinaciones de subdominios usando una wordlist
    
    Proceso:
    1. Leer lista de palabras comunes
    2. Para cada palabra, crear: palabra.dominio.com
    3. Intentar resolver cada combinación
    4. Si resuelve → es un subdominio válido
    
    Parámetros:
    - dominio: ejemplo.com
    - wordlist: archivo con palabras (una por línea)
    """
    
    print(f"[+] Enumerando subdominios de {dominio}\n")
    
    # Leer wordlist
    try:
        with open(wordlist, 'r') as f:
            palabras = [linea.strip() for linea in f if linea.strip()]
    except FileNotFoundError:
        print(f"[-] Archivo no encontrado: {wordlist}")
        return []
    
    subdominios_encontrados = []
    total = len(palabras)
    
    print(f"[*] Probando {total} palabras...\n")
    
    for i, palabra in enumerate(palabras, 1):
        subdominio = f"{palabra}.{dominio}"
        
        try:
            # Intentar resolver
            respuestas = dns.resolver.resolve(subdominio, 'A', lifetime=2)
            
            # Si resuelve, obtener IPs
            ips = [str(ip) for ip in respuestas]
            print(f"[FOUND] {subdominio} -> {', '.join(ips)}")
            
            subdominios_encontrados.append({
                'dominio': subdominio,
                'ips': ips
            })
            
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, 
                dns.exception.Timeout):
            # Subdominio no existe, continuar
            pass
        except Exception as e:
            print(f"[!] Error con {subdominio}: {e}")
        
        # Mostrar progreso cada 50 intentos
        if i % 50 == 0:
            print(f"[*] Progreso: {i}/{total}\n")
    
    print(f"\n[+] Subdominios encontrados: {len(subdominios_encontrados)}")
    return subdominios_encontrados


# EJEMPLO DE USO CON WORDLIST:
# 
# wordlist.txt:
# www
# mail
# ftp
# admin
# api
# dev
# test
# ...
#
# subdominios = enumerar_subdominios("google.com", "wordlist.txt")
#
# Output esperado:
# [+] Enumerando subdominios de google.com
# 
# [*] Probando 1000 palabras...
# 
# [FOUND] www.google.com -> 142.250.185.46
# [FOUND] mail.google.com -> 142.251.41.230
# [FOUND] api.google.com -> 142.250.80.46
# ...


# ============================================================
# 3. TRANSFERENCIA DE ZONA (AXFR)
# ============================================================

import dns.zone
import dns.axfr
import dns.query

def transferencia_zona(dominio):
    """
    Intenta realizar una transferencia de zona DNS (AXFR)
    
    AXFR es un protocolo para copiar la base de datos DNS completa.
    Si es permitido (raramente), obtenemos TODOS los registros.
    
    Proceso:
    1. Obtener servidores NS del dominio
    2. Intentar AXFR con cada servidor
    3. Si permitido → copiar toda la zona
    4. Si no → mostrar error (normal)
    """
    
    print(f"[+] Intentando transferencia de zona para {dominio}\n")
    
    try:
        # Paso 1: Obtener servidores NS
        print("[*] Obteniendo servidores NS...")
        ns_respuestas = dns.resolver.resolve(dominio, 'NS')
        ns_servidores = [str(ns).rstrip('.') for ns in ns_respuestas]
        
        print(f"[+] Servidores NS encontrados:")
        for ns in ns_servidores:
            print(f"    - {ns}")
        
        # Paso 2: Intentar AXFR con cada servidor
        for ns in ns_servidores:
            try:
                print(f"\n[*] Intentando transferencia con {ns}...")
                
                # Realizar transferencia
                zona = dns.zone.from_xfr(dns.query.xfr(
                    ns, dominio, lifetime=10
                ))
                
                print(f"[✓] ¡TRANSFERENCIA EXITOSA desde {ns}!")
                print(f"[+] Registros encontrados: {len(zona)}\n")
                
                # Mostrar algunos registros
                contador = 0
                for nombre, nodo in zona.items():
                    for rdataset in nodo:
                        for rdata in rdataset:
                            print(f"    {nombre} {rdataset.ttl} {rdataset.rdtype} {rdata}")
                            contador += 1
                            if contador >= 20:
                                print(f"    ... y {len(zona) - contador} registros más")
                                break
                
                return True
                
            except dns.exception.TransferFailed:
                print(f"    ✗ Transferencia rechazada (normal)")
            except Exception as e:
                print(f"    ✗ Error: {str(e)[:60]}")
        
        print("\n[-] No fue posible la transferencia de zona")
        return False
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False


# EJEMPLO DE SALIDA:
#
# [+] Intentando transferencia de zona para vulnerable.com
# 
# [*] Obteniendo servidores NS...
# [+] Servidores NS encontrados:
#     - ns1.vulnerable.com
#     - ns2.vulnerable.com
# 
# [*] Intentando transferencia con ns1.vulnerable.com...
# [✓] ¡TRANSFERENCIA EXITOSA desde ns1.vulnerable.com!
# [+] Registros encontrados: 47
# 
#     vulnerable.com 3600 SOA
#     www 3600 A 192.168.1.10
#     mail 3600 A 192.168.1.20
#     admin 3600 A 192.168.1.30  ← ENCONTRADO!
#     internal 3600 A 192.168.1.40 ← ENCONTRADO!
#     ...


# ============================================================
# 4. BÚSQUEDA INVERSA (REVERSE LOOKUP)
# ============================================================

import dns.reversename

def busqueda_inversa(ip):
    """
    Convierte una IP a su nombre de dominio asociado
    
    Proceso:
    1. Invertir octetos: 93.184.216.34 → 34.216.184.93
    2. Agregar .in-addr.arpa: 34.216.184.93.in-addr.arpa
    3. Consultar registro PTR
    4. Obtener nombre del host
    """
    
    try:
        print(f"[*] Búsqueda inversa de {ip}...")
        
        # Crear dirección invertida
        addr_inversa = dns.reversename.from_address(ip)
        
        # Consultar registro PTR
        respuesta = dns.resolver.resolve(addr_inversa, 'PTR')
        
        for rdata in respuesta:
            dominio = str(rdata).rstrip('.')
            print(f"[✓] IP {ip} → {dominio}")
            return dominio
            
    except dns.resolver.NXDOMAIN:
        print(f"[-] No hay registro PTR para {ip}")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return None


# EJEMPLO DE USO:
# busqueda_inversa("93.184.216.34")
# 
# Output:
# [*] Búsqueda inversa de 93.184.216.34...
# [✓] IP 93.184.216.34 → example.com


# ============================================================
# 5. GENERADOR DE REPORTES
# ============================================================

import json
import csv
from datetime import datetime

def generar_reporte_json(dominio, resultados, archivo_salida):
    """
    Genera un reporte en formato JSON
    
    Estructura:
    {
        "dominio": "example.com",
        "fecha": "2024-01-15T10:30:00",
        "registros_basicos": {
            "A": ["93.184.216.34"],
            "MX": ["10 mail.example.com"]
        },
        "subdominios": [
            {"dominio": "www.example.com", "ips": ["93.184.216.34"]},
            {"dominio": "mail.example.com", "ips": ["93.184.216.35"]}
        ]
    }
    """
    
    reporte = {
        'dominio': dominio,
        'fecha': datetime.now().isoformat(),
        'resultados': resultados
    }
    
    try:
        with open(archivo_salida, 'w') as f:
            json.dump(reporte, f, indent=2)
        print(f"[✓] Reporte JSON guardado: {archivo_salida}")
    except Exception as e:
        print(f"[-] Error al guardar JSON: {e}")


def generar_reporte_csv(subdominios, archivo_salida):
    """
    Genera un reporte en formato CSV para hoja de cálculo
    
    Formato:
    Subdominio, IP
    www.example.com, 93.184.216.34
    mail.example.com, 93.184.216.35
    """
    
    try:
        with open(archivo_salida, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Subdominio', 'IP'])
            
            for sub in subdominios:
                for ip in sub['ips']:
                    writer.writerow([sub['dominio'], ip])
        
        print(f"[✓] Reporte CSV guardado: {archivo_salida}")
    except Exception as e:
        print(f"[-] Error al guardar CSV: {e}")


# EJEMPLO DE SALIDA JSON:
# {
#   "dominio": "example.com",
#   "fecha": "2024-01-15T10:30:45.123456",
#   "resultados": {
#     "registros_basicos": {
#       "A": ["93.184.216.34"],
#       "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
#       "MX": ["10 mail.example.com"],
#       "NS": ["ns1.example.com", "ns2.example.com"]
#     },
#     "subdominios": [
#       {
#         "dominio": "www.example.com",
#         "ips": ["93.184.216.34"]
#       },
#       {
#         "dominio": "mail.example.com",
#         "ips": ["93.184.216.35"]
#       }
#     ]
#   }
# }


# ============================================================
# 6. CLASE PRINCIPAL - ORQUESTACIÓN
# ============================================================

class DNSScanner:
    """
    Escáner DNS completo que coordina todos los componentes
    """
    
    def __init__(self, dominio):
        self.dominio = dominio.rstrip('.')
        self.resultados = {}
    
    def escanear_completo(self, wordlist=None, intentar_axfr=True):
        """
        Ejecuta un escaneo completo del dominio
        
        Proceso:
        1. Enumeración básica
        2. Enumeración de subdominios
        3. Transferencia de zona (opcional)
        4. Recolectar resultados
        """
        
        print("="*60)
        print(f"ESCANEADOR DNS - {self.dominio}")
        print("="*60 + "\n")
        
        # Paso 1: Enumeración básica
        print("[FASE 1/3] Enumeración de registros básicos\n")
        self.resultados['basicos'] = enumerar_registros_basicos(self.dominio)
        
        # Paso 2: Enumeración de subdominios
        print("\n[FASE 2/3] Enumeración de subdominios\n")
        if wordlist:
            self.resultados['subdominios'] = enumerar_subdominios(
                self.dominio, 
                wordlist
            )
        
        # Paso 3: Transferencia de zona
        if intentar_axfr:
            print("\n[FASE 3/3] Intento de transferencia de zona\n")
            self.resultados['axfr'] = transferencia_zona(self.dominio)
        
        print("\n" + "="*60)
        print("ESCANEO COMPLETADO")
        print("="*60)
        
        return self.resultados


# EJEMPLO DE USO COMPLETO:
#
# scanner = DNSScanner("example.com")
# resultados = scanner.escanear_completo(
#     wordlist="wordlist.txt",
#     intentar_axfr=True
# )
#
# generar_reporte_json("example.com", resultados, "example.com.json")
# generar_reporte_csv(resultados['subdominios'], "example.com.csv")


# ============================================================
# 7. INSTALACIÓN DE DEPENDENCIAS
# ============================================================

"""
# Instalar las librerías necesarias:

pip install dnspython        # Para operaciones DNS
pip install click            # Para CLI mejorada
pip install colorama         # Para colores en terminal
pip install tabulate         # Para tablas formateadas

# Comando:
pip install -r requirements.txt
"""

# ============================================================
# 8. FLUJO COMPLETO - PROGRAMA PRINCIPAL
# ============================================================

"""
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Uso: python dns_scanner.py <dominio> [wordlist]")
        sys.exit(1)
    
    dominio = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Crear scanner
    scanner = DNSScanner(dominio)
    
    # Ejecutar escaneo
    resultados = scanner.escanear_completo(
        wordlist=wordlist,
        intentar_axfr=True
    )
    
    # Guardar reportes
    generar_reporte_json(dominio, resultados, f"{dominio}.json")
    if resultados.get('subdominios'):
        generar_reporte_csv(resultados['subdominios'], f"{dominio}.csv")
    
    print(f"\n[✓] Reportes generados")
"""
