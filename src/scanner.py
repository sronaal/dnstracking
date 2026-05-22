"""
Modulo principal del escaner DNS
Coordina todas las operaciones de escaneo
"""

import sys
import os
import time
from datetime import datetime
from typing import List, Dict, Optional
from resolver import DNSResolver
from doh_resolver import DohResolver
from subdomain_scanner import SubdomainScanner
from sources import PassiveSources
from vulnerabilities import VulnerabilityScanner
from whois_lookup import WhoisLookup
from certificate import CertificateInspector
from geo import GeoLocator
from color_util import icono_ok, icono_error, icono_exito, icono_info, cian, negrita, verde, amarillo, rojo

import dns.zone
import dns.query
import dns.exception


class DNSScanner:
    """Escaner DNS principal"""

    def __init__(self, dominio: str, verbose: bool = False, timeout: int = 5,
                 resolver=None):
        self.dominio = dominio.rstrip('.')
        self.verbose = verbose
        self.resolver = resolver if resolver else DNSResolver(timeout=timeout)
        self.subdomain_scanner = SubdomainScanner(self.resolver, self.dominio, verbose=verbose)
        self.resultados = {
            'dominio': self.dominio,
            'fecha': datetime.now().isoformat(),
            'basicos': {},
            'subdominios': [],
            'subdominios_pasivos': [],
            'axfr': False,
            'axfr_records': [],
            'reverse_lookups': {},
            'estadisticas': {},
            'vulnerabilidades': [],
            'resumen_vulnerabilidades': {},
        }
        self.tiempos_fases = {}

    def log(self, msg: str, level: str = 'INFO'):
        if self.verbose:
            print(f"[{level}] {msg}")

    def _mostrar_progreso(self, actual: int, total: int, prefijo: str = ""):
        porcentaje = (actual / total) * 100
        barras = int(porcentaje / 5)
        barra = "\u2588" * barras + "\u2591" * (20 - barras)
        sys.stdout.write(f"\r{prefijo} [{barra}] {porcentaje:.1f}%")
        sys.stdout.flush()

    def enumerar_registros_basicos(self) -> Dict[str, List[str]]:
        inicio = time.time()
        print(f"\n[+] Enumerando registros DNS de {self.dominio}")
        print("-" * 60)

        resultados = self.resolver.enumerar_basicos(self.dominio)
        self.resultados['basicos'] = resultados

        for tipo, valores in resultados.items():
            if valores:
                print(f"\n  [{tipo}]")
                for valor in valores:
                    display_val = valor[:100] + "..." if len(valor) > 100 else valor
                    print(f"    {display_val}")
            else:
                self.log(f"No se encontraron registros {tipo}")

        encontrados = sum(1 for v in resultados.values() if v)
        print(f"\n[+] Tipos de registro encontrados: {encontrados}/{len(resultados)}")

        self.tiempos_fases['registros_basicos'] = time.time() - inicio
        return resultados

    def enumeracion_pasiva(self) -> List[Dict]:
        """Enumeracion de subdominios via fuentes pasivas"""
        inicio = time.time()
        print(f"\n[+] Enumeracion pasiva de subdominios")
        print("-" * 60)

        passive = PassiveSources(self.dominio, timeout=10)
        subdominios_pasivos = passive.enumerar_todas()

        self.resultados['subdominios_pasivos'] = subdominios_pasivos
        self.tiempos_fases['enumeracion_pasiva'] = time.time() - inicio
        return subdominios_pasivos

    def enumerar_subdominios(
        self,
        wordlist: str,
        threads: int = 20,
        tipos_dns: List[str] = None,
        max_resultados: int = None,
        delay: float = 0.0,
        detectar_wildcards: bool = True,
        con_permutaciones: bool = False
    ) -> List[Dict]:
        inicio = time.time()
        print(f"\n[+] Enumerando subdominios de {self.dominio}")
        print("-" * 60)

        subdominios = self.subdomain_scanner.escanear_con_threading(
            wordlist=wordlist,
            threads=threads,
            tipos_dns=tipos_dns,
            max_resultados=max_resultados,
            delay=delay,
            detectar_wildcards=detectar_wildcards,
        )

        tiempo_base = time.time() - inicio
        permutaciones_count = 0
        tiempo_permutaciones = 0

        if con_permutaciones and subdominios:
            perm_inicio = time.time()
            print(f"\n  [*] Generando permutaciones avanzadas de {len(subdominios)} subdominios...")
            permutaciones = self.subdomain_scanner.generar_permutaciones_avanzadas(subdominios)
            print(f"  [*] {len(permutaciones)} permutaciones generadas")

            if permutaciones:
                temp_wordlist = f"/tmp/dnstraking_permutations_{self.dominio}.txt"
                with open(temp_wordlist, 'w') as f:
                    f.write('\n'.join(permutaciones))

                print(f"  [*] Escaneando permutaciones con {threads} hilos...")
                permutaciones_encontradas = self.subdomain_scanner.escanear_con_threading(
                    wordlist=temp_wordlist,
                    threads=threads,
                    tipos_dns=tipos_dns,
                    detectar_wildcards=detectar_wildcards,
                    mostrar_progreso=True,
                )

                existentes = {s['dominio'] for s in subdominios}
                nuevos = 0
                for p in permutaciones_encontradas:
                    if p['dominio'] not in existentes:
                        subdominios.append(p)
                        existentes.add(p['dominio'])
                        nuevos += 1

                permutaciones_count = nuevos
                print(f"\n  [+] Permutaciones nuevas encontradas: {nuevos}")

                try:
                    os.remove(temp_wordlist)
                except Exception:
                    pass

            tiempo_permutaciones = time.time() - perm_inicio

        self.tiempos_fases['subdominios'] = time.time() - inicio
        self.tiempos_fases['permutaciones'] = tiempo_permutaciones
        self.resultados['subdominios'] = subdominios
        self.resultados['estadisticas']['permutaciones_generadas'] = len(permutaciones) if con_permutaciones else 0
        self.resultados['estadisticas']['permutaciones_nuevas'] = permutaciones_count
        return subdominios

    def transferencia_zona(self) -> bool:
        inicio = time.time()
        print(f"\n[+] Intentando transferencia de zona (AXFR)")
        print("-" * 60)

        try:
            ns_servidores = self.resolver.obtener_ns_servidores(self.dominio)
            if not ns_servidores:
                print("[-] No se encontraron servidores NS")
                return False

            print(f"[*] Servidores NS: {', '.join(ns_servidores)}\n")

            for ns in ns_servidores:
                try:
                    print(f"[*] Intentando con {ns}...")
                    zona = dns.zone.from_xfr(
                        dns.query.xfr(ns, self.dominio, lifetime=10)
                    )

                    print(f"[SUCCESS] \u00a1AXFR permitido en {ns}!")
                    print(f"[+] Registros encontrados: {len(zona)}\n")

                    axfr_records = []
                    for nombre, nodo in zona.items():
                        for rdataset in nodo:
                            for rdata in rdataset:
                                record_str = f"{nombre} {rdataset.rdtype} {rdata}"
                                axfr_records.append(record_str)
                                print(f"  {record_str}")

                    self.resultados['axfr'] = True
                    self.resultados['axfr_records'] = axfr_records
                    self.tiempos_fases['axfr'] = time.time() - inicio
                    return True

                except dns.exception.TransferFailed:
                    self.log(f"Transferencia rechazada en {ns}")
                except ConnectionRefusedError:
                    self.log(f"Conexion rechazada en {ns}")
                except Exception as e:
                    self.log(f"Error en {ns}: {e}")

            print("[-] AXFR no permitido en ningun servidor")
            self.tiempos_fases['axfr'] = time.time() - inicio
            return False

        except Exception as e:
            print(f"[-] Error: {e}")
            self.tiempos_fases['axfr'] = time.time() - inicio
            return False

    def busquedas_inversas(self, ips: List[str]) -> Dict[str, Optional[str]]:
        inicio = time.time()
        print(f"\n[+] Realizando busquedas inversas")
        print("-" * 60)

        resultados_reverse = {}
        for ip in ips:
            dominio = self.resolver.busqueda_inversa(ip)
            resultados_reverse[ip] = dominio
            if dominio:
                print(f"  {ip} \u2192 {dominio}")
            else:
                self.log(f"No hay PTR para {ip}")

        self.resultados['reverse_lookups'] = resultados_reverse
        encontrados = sum(1 for v in resultados_reverse.values() if v)
        print(f"\n[+] Reverse lookups exitosos: {encontrados}/{len(ips)}")

        self.tiempos_fases['reverse_lookups'] = time.time() - inicio
        return resultados_reverse

    def analisis_vulnerabilidades(self, check_takeover: bool = True, check_infrastructure: bool = True) -> List:
        """Ejecuta analisis de vulnerabilidades DNS"""
        inicio = time.time()
        vuln_scanner = VulnerabilityScanner(
            self.dominio, self.resolver, self.resultados, verbose=self.verbose
        )
        findings = vuln_scanner.run_all(
            check_takeover=check_takeover,
            check_infrastructure=check_infrastructure,
        )

        self.resultados['vulnerabilidades'] = [f.to_dict() for f in findings]
        self.resultados['resumen_vulnerabilidades'] = vuln_scanner.get_summary()
        self.tiempos_fases['vulnerabilidades'] = time.time() - inicio
        return findings

    def consulta_whois(self):
        inicio = time.time()
        print(f"\n[+] Consulta WHOIS para {self.dominio}")
        print("-" * 60)

        whois = WhoisLookup(timeout=10)
        resultado = whois.consultar(self.dominio)
        self.resultados['whois'] = resultado

        if resultado.get('registrar'):
            print(f"  Registrar: {resultado['registrar']}")
        if resultado.get('creacion'):
            print(f"  Creacion:  {resultado['creacion']}")
        if resultado.get('expiracion'):
            print(f"  Expira:    {resultado['expiracion']}")
        if resultado.get('name_servers'):
            print(f"  NS:        {', '.join(resultado['name_servers'][:5])}")
            if len(resultado['name_servers']) > 5:
                print(f"             ... y {len(resultado['name_servers']) - 5} mas")
        if resultado.get('estado'):
            print(f"  Estado:    {resultado['estado']}")
        if resultado.get('notas'):
            for nota in resultado['notas']:
                print(f"  [!] {nota}")

        if not resultado.get('registrar') and not resultado.get('error'):
            print("  [-] No se obtuvo informacion del registro")

        self.tiempos_fases['whois'] = time.time() - inicio
        return resultado

    def inspeccionar_certificados(self):
        inicio = time.time()
        subdominios = (
            self.resultados.get('subdominios', []) +
            self.resultados.get('subdominios_pasivos', [])
        )
        if not subdominios:
            print(f"\n {icono_info()} Sin subdominios para inspeccionar SSL")
            return []

        print(f"\n[+] Inspeccionando certificados SSL/TLS ({len(subdominios)} hosts)")
        print("-" * 60)

        inspector = CertificateInspector(timeout=5)
        certificados = inspector.inspeccionar_subdominios(subdominios)
        self.resultados['certificados'] = certificados

        if certificados:
            vencidos = [c for c in certificados if c.get('expirado')]
            proximos = [c for c in certificados if not c.get('expirado')
                        and c.get('dias_restantes', 999) < 30]

            print(f"\n  {icono_exito()} Certificados obtenidos: {len(certificados)}")
            for cert in certificados[:10]:
                host = cert['hostname']
                dias = cert.get('dias_restantes')
                if cert.get('expirado'):
                    estado = rojo(f"VENCIDO ({abs(dias)} dias)")
                elif dias is not None and dias < 7:
                    estado = rojo(f"{dias} dias")
                elif dias is not None and dias < 30:
                    estado = amarillo(f"{dias} dias")
                else:
                    estado = verde(f"{dias} dias")

                emisor = cert.get('emisor', {}).get('organizationName', '?')
                print(f"    {host:<40} {estado:<15} {emisor[:30]}")

            if vencidos:
                print(f"\n  {rojo('Certificados VENCIDOS:')} {len(vencidos)}")
            if len(certificados) > 10:
                print(f"  ... y {len(certificados) - 10} mas")

            sans_extra = self._extraer_sans(certificados)
            if sans_extra:
                print(f"\n  {icono_info()} {len(sans_extra)} subdominios adicionales via SANs")
        else:
            print(f"\n  {icono_error()} No se pudieron obtener certificados")

        self.tiempos_fases['certificados'] = time.time() - inicio
        return certificados

    def _extraer_sans(self, certificados: List) -> List[str]:
        existentes = set()
        for sub in self.resultados.get('subdominios', []):
            existentes.add(sub['dominio'])
        for sub in self.resultados.get('subdominios_pasivos', []):
            existentes.add(sub['dominio'])

        nuevos = []
        for cert in certificados:
            for san in cert.get('sans', []):
                if san.startswith('*.') or san.startswith('*.'):
                    continue
                if san not in existentes:
                    nuevos.append(san)
                    existentes.add(san)
        return nuevos

    def localizar_ips(self):
        inicio = time.time()
        ips = set()
        for sub in self.resultados.get('subdominios', []):
            ips.update(sub.get('ips', []))
        for sub in self.resultados.get('subdominios_pasivos', []):
            ips.update(sub.get('ips', []))
        for tipo in ('A', 'AAAA'):
            ips.update(self.resultados.get('basicos', {}).get(tipo, []))

        if not ips:
            print(f"\n {icono_info()} Sin IPs para geolocalizar")
            return []

        print(f"\n[+] Geolocalizando {len(ips)} IPs...")
        print("-" * 60)

        geo = GeoLocator(timeout=5)
        resultados = geo.localizar_multiples(list(ips))
        self.resultados['geo'] = resultados

        for g in resultados[:15]:
            print(f"  {g['ip']:<18} {g.get('pais', '?'):<20} "
                  f"{g.get('asn', '?'):<20} {g.get('isp', '?')[:30]}")
        if len(resultados) > 15:
            print(f"  ... y {len(resultados) - 15} mas")

        print(f"\n  {icono_exito()} IPs localizadas: {len(resultados)}/{len(ips)}")

        self.tiempos_fases['geo'] = time.time() - inicio
        return resultados

    def escanear_completo(
        self,
        wordlist: str = None,
        intentar_axfr: bool = True,
        reverse_lookup: bool = False,
        max_subdominios: int = None,
        delay: float = 0.0,
        threads: int = 20,
        tipos_dns: List[str] = None,
        detectar_wildcards: bool = True,
        con_permutaciones: bool = False,
        solo_pasivo: bool = False,
        con_pasivo: bool = False,
        con_vulnerabilidades: bool = False,
        solo_vulnerabilidades: bool = False,
        check_takeover: bool = True,
        check_infrastructure: bool = True,
        con_whois: bool = False,
        con_ssl: bool = False,
        con_geo: bool = False,
        con_doh: bool = False,
    ) -> Dict:
        tiempo_total_inicio = time.time()

        print("\n" + "=" * 60)
        print(f"  {cian(negrita('DNSTRACKING'))} - {cian('Escáner DNS')}")
        print(f"  {negrita('Dominio:')} {self.dominio}")
        print(f"  {negrita('Fecha:')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        if solo_vulnerabilidades:
            print("\n[*] Modo solo vulnerabilidades")
            print("[*] Ejecutando enumeracion basica requerida...")
            self.enumerar_registros_basicos()
            if con_whois:
                self.consulta_whois()
            self.analisis_vulnerabilidades(
                check_takeover=check_takeover,
                check_infrastructure=check_infrastructure,
            )
            self.resultados['estadisticas']['tiempo_total'] = time.time() - tiempo_total_inicio
            print("\n" + "=" * 60)
            print(f"  {verde(negrita('ESCANEO COMPLETADO'))}")
            print("=" * 60)
            self._mostrar_resumen()
            return self.resultados

        if solo_pasivo:
            print("\n[*] Modo solo pasivo - Sin consultas DNS directas")
            self.enumeracion_pasiva()
            if con_whois:
                self.consulta_whois()
            self.resultados['estadisticas']['tiempo_total'] = time.time() - tiempo_total_inicio
            print("\n" + "=" * 60)
            print(f"  {verde(negrita('ESCANEO COMPLETADO'))}")
            print("=" * 60)
            self._mostrar_resumen()
            return self.resultados

        print("\n[*] Validando dominio...")
        if not self.resolver.es_dominio_valido(self.dominio):
            print(f" {icono_error()} Dominio invalido o no resoluble: {self.dominio}")
            return self.resultados
        print(f" {icono_ok()} Dominio valido\n")

        fases_activas = 1  # registros basicos
        if con_whois:
            fases_activas += 1
        if con_pasivo:
            fases_activas += 1
        if wordlist:
            fases_activas += 1
        if intentar_axfr:
            fases_activas += 1
        if reverse_lookup:
            fases_activas += 1
        if con_vulnerabilidades:
            fases_activas += 1
        if con_ssl and (wordlist or con_pasivo):
            fases_activas += 1
        if con_geo:
            fases_activas += 1

        fase = 1
        print(f"\n[FASE {fase}/{fases_activas}] Enumeracion de registros basicos")
        try:
            self.enumerar_registros_basicos()
        except Exception as e:
            print(f"[-] Error en enumeracion basica: {e}")

        fase += 1
        if con_whois:
            print(f"\n[FASE {fase}/{fases_activas}] Consulta WHOIS")
            try:
                self.consulta_whois()
            except Exception as e:
                print(f"[-] Error en WHOIS: {e}")
            fase += 1

        if con_pasivo:
            print(f"\n[FASE {fase}/{fases_activas}] Enumeracion pasiva (APIs externas)")
            try:
                self.enumeracion_pasiva()
            except Exception as e:
                print(f"[-] Error en enumeracion pasiva: {e}")
            fase += 1

        if wordlist:
            print(f"\n[FASE {fase}/{fases_activas}] Enumeracion de subdominios")
            try:
                self.enumerar_subdominios(
                    wordlist=wordlist,
                    threads=threads,
                    tipos_dns=tipos_dns,
                    max_resultados=max_subdominios,
                    delay=delay,
                    detectar_wildcards=detectar_wildcards,
                    con_permutaciones=con_permutaciones,
                )
            except KeyboardInterrupt:
                print("\n[-] Enumeracion de subdominios cancelada")
            except Exception as e:
                print(f"[-] Error en enumeracion de subdominios: {e}")
            fase += 1

        if intentar_axfr:
            print(f"\n[FASE {fase}/{fases_activas}] Transferencia de zona DNS")
            try:
                self.transferencia_zona()
            except KeyboardInterrupt:
                print("\n[-] Transferencia de zona cancelada")
            except Exception as e:
                print(f"[-] Error en transferencia de zona: {e}")
            fase += 1

        if reverse_lookup:
            print(f"\n[FASE {fase}/{fases_activas}] Busquedas inversas")
            ips_a_resolver = []
            for tipo, valores in self.resultados['basicos'].items():
                if tipo in ('A', 'AAAA'):
                    ips_a_resolver.extend(valores)
            for sub in self.resultados['subdominios']:
                ips_a_resolver.extend(sub.get('ips', []))
            ips_unicas = list(set(ips_a_resolver))
            if ips_unicas:
                self.busquedas_inversas(ips_unicas)
            fase += 1

        if con_vulnerabilidades:
            print(f"\n[FASE {fase}/{fases_activas}] Analisis de vulnerabilidades")
            try:
                self.analisis_vulnerabilidades(
                    check_takeover=check_takeover,
                    check_infrastructure=check_infrastructure,
                )
            except KeyboardInterrupt:
                print("\n[-] Analisis de vulnerabilidades cancelado")
            except Exception as e:
                print(f"[-] Error en analisis de vulnerabilidades: {e}")
            fase += 1

        if con_ssl and (self.resultados.get('subdominios') or self.resultados.get('subdominios_pasivos')):
            print(f"\n[FASE {fase}/{fases_activas}] Inspeccion de certificados SSL/TLS")
            try:
                self.inspeccionar_certificados()
            except Exception as e:
                print(f"  {icono_error()} Error en SSL: {e}")
            fase += 1

        if con_geo:
            print(f"\n[FASE {fase}/{fases_activas}] Geolocalizacion de IPs")
            try:
                self.localizar_ips()
            except Exception as e:
                print(f"  {icono_error()} Error en geo: {e}")
            fase += 1

        tiempo_total = time.time() - tiempo_total_inicio
        self.resultados['estadisticas']['tiempo_total'] = tiempo_total
        self.resultados['estadisticas']['tiempos_fases'] = {k: round(v, 2) for k, v in self.tiempos_fases.items()}
        self.resultados['estadisticas']['hilos'] = threads
        self.resultados['estadisticas']['wildcard_detectado'] = bool(self.subdomain_scanner.wildcard_ips)

        print("\n" + "=" * 60)
        print(f"  {verde(negrita('ESCANEO COMPLETADO'))}")
        print("=" * 60)

        self._mostrar_resumen()

        return self.resultados

    def _mostrar_resumen(self):
        print("\n" + "=" * 60)
        print("  RESUMEN FINAL")
        print("=" * 60)

        print(f"\n  Dominio: {self.dominio}")
        print(f"  Fecha: {self.resultados['fecha']}")

        registros_con_datos = sum(1 for v in self.resultados['basicos'].values() if v)
        print(f"\n  {'Registros DNS':.<40} {registros_con_datos} tipos")

        whois_data = self.resultados.get('whois', {})
        if whois_data and whois_data.get('registrar'):
            print(f"  {'WHOIS Registrar':.<40} {whois_data['registrar'][:50]}")
            if whois_data.get('creacion'):
                print(f"  {'WHOIS Creacion':.<40} {whois_data['creacion'][:25]}")
            if whois_data.get('expiracion'):
                print(f"  {'WHOIS Expira':.<40} {whois_data['expiracion'][:25]}")

        num_subdominios = len(self.resultados['subdominios'])
        print(f"  {'Subdominios (activo)':.<40} {num_subdominios}")

        num_pasivos = len(self.resultados.get('subdominios_pasivos', []))
        if num_pasivos > 0:
            print(f"  {'Subdominios (pasivo)':.<40} {num_pasivos}")

        total_subdominios = num_subdominios + num_pasivos
        print(f"  {'Total subdominios':.<40} {total_subdominios}")

        if self.resultados['axfr']:
            print(f"  {'AXFR':.<40} EXITOSO ({len(self.resultados['axfr_records'])} registros)")
        else:
            print(f"  {'AXFR':.<40} No permitido")

        reverse_exitosos = sum(1 for v in self.resultados['reverse_lookups'].values() if v)
        if reverse_exitosos > 0:
            print(f"  {'Reverse lookups':.<40} {reverse_exitosos} exitosos")

        vuln_summary = self.resultados.get('resumen_vulnerabilidades', {})
        if vuln_summary and vuln_summary.get('total', 0) > 0:
            print(f"\n  {'VULNERABILIDADES':.<40} {vuln_summary['total']} encontradas")
            if vuln_summary.get('critical', 0) > 0:
                print(f"  {'  CRITICAL':.<40} {vuln_summary['critical']}")
            if vuln_summary.get('high', 0) > 0:
                print(f"  {'  HIGH':.<40} {vuln_summary['high']}")
            if vuln_summary.get('medium', 0) > 0:
                print(f"  {'  MEDIUM':.<40} {vuln_summary['medium']}")
            if vuln_summary.get('low', 0) > 0:
                print(f"  {'  LOW':.<40} {vuln_summary['low']}")
            if vuln_summary.get('info', 0) > 0:
                print(f"  {'  INFO':.<40} {vuln_summary['info']}")

        stats = self.resultados.get('estadisticas', {})
        if stats.get('permutaciones_generadas', 0) > 0:
            print(f"  {'Permutaciones generadas':.<40} {stats['permutaciones_generadas']}")
            print(f"  {'Permutaciones nuevas':.<40} {stats.get('permutaciones_nuevas', 0)}")

        if stats.get('tiempos_fases'):
            print(f"\n  {'Tiempos por fase':}")
            for fase, tiempo in stats['tiempos_fases'].items():
                print(f"    {fase:.<38} {tiempo:.2f}s")

        if stats.get('tiempo_total'):
            print(f"\n  {'TIEMPO TOTAL':.<40} {stats['tiempo_total']:.2f}s")

        if stats.get('wildcard_detectado'):
            print(f"  {'Wildcard DNS':.<40} Detectado y filtrado")

        ips_unicas = set()
        for sub in self.resultados['subdominios']:
            ips_unicas.update(sub.get('ips', []))
        if ips_unicas:
            print(f"  {'IPs unicas encontradas':.<40} {len(ips_unicas)}")

        print("\n" + "=" * 60)
