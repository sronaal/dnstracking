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
from subdomain_scanner import SubdomainScanner
from sources import PassiveSources

import dns.zone
import dns.query
import dns.exception


class DNSScanner:
    """Escaner DNS principal"""

    def __init__(self, dominio: str, verbose: bool = False, timeout: int = 5):
        self.dominio = dominio.rstrip('.')
        self.verbose = verbose
        self.resolver = DNSResolver(timeout=timeout)
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
    ) -> Dict:
        tiempo_total_inicio = time.time()

        print("\n" + "=" * 60)
        print(f"  DNSTRACKING - Escaner DNS")
        print(f"  Dominio: {self.dominio}")
        print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        if solo_pasivo:
            print("\n[*] Modo solo pasivo - Sin consultas DNS directas")
            self.enumeracion_pasiva()
            self.resultados['estadisticas']['tiempo_total'] = time.time() - tiempo_total_inicio
            print("\n" + "=" * 60)
            print("  ESCANEO COMPLETADO")
            print("=" * 60)
            self._mostrar_resumen()
            return self.resultados

        print("\n[*] Validando dominio...")
        if not self.resolver.es_dominio_valido(self.dominio):
            print(f"[-] Dominio invalido o no resoluble: {self.dominio}")
            return self.resultados
        print("[OK] Dominio valido\n")

        print("[FASE 1/5] Enumeracion de registros basicos")
        try:
            self.enumerar_registros_basicos()
        except Exception as e:
            print(f"[-] Error en enumeracion basica: {e}")

        if con_pasivo:
            print("\n[FASE 2/5] Enumeracion pasiva (APIs externas)")
            try:
                self.enumeracion_pasiva()
            except Exception as e:
                print(f"[-] Error en enumeracion pasiva: {e}")

        if wordlist:
            fase_num = "3/5" if con_pasivo else "2/4"
            print(f"\n[FASE {fase_num}] Enumeracion de subdominios")
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
        else:
            print("\n[FASE 2/4] Enumeracion de subdominios - OMITIDA")

        if intentar_axfr:
            print("\n[FASE 3/4] Transferencia de zona DNS")
            try:
                self.transferencia_zona()
            except KeyboardInterrupt:
                print("\n[-] Transferencia de zona cancelada")
            except Exception as e:
                print(f"[-] Error en transferencia de zona: {e}")
        else:
            print("\n[FASE 3/4] Transferencia de zona - OMITIDA")

        if reverse_lookup:
            print("\n[FASE 4/4] Busquedas inversas")
            ips_a_resolver = []
            for tipo, valores in self.resultados['basicos'].items():
                if tipo in ('A', 'AAAA'):
                    ips_a_resolver.extend(valores)
            for sub in self.resultados['subdominios']:
                ips_a_resolver.extend(sub.get('ips', []))
            ips_unicas = list(set(ips_a_resolver))
            if ips_unicas:
                self.busquedas_inversas(ips_unicas)
        else:
            print("\n[FASE 4/4] Busquedas inversas - OMITIDA")

        tiempo_total = time.time() - tiempo_total_inicio
        self.resultados['estadisticas']['tiempo_total'] = tiempo_total
        self.resultados['estadisticas']['tiempos_fases'] = {k: round(v, 2) for k, v in self.tiempos_fases.items()}
        self.resultados['estadisticas']['hilos'] = threads
        self.resultados['estadisticas']['wildcard_detectado'] = bool(self.subdomain_scanner.wildcard_ips)

        print("\n" + "=" * 60)
        print("  ESCANEO COMPLETADO")
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
