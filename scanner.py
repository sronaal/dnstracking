"""
Módulo principal del escáner DNS
Coordina todas las operaciones de escaneo
"""

import sys
import os
import time
from datetime import datetime
from typing import List, Dict, Optional
from resolver import DNSResolver

import dns.zone
import dns.query
import dns.exception


class DNSScanner:
    """Escáner DNS principal"""

    def __init__(self, dominio: str, verbose: bool = False, timeout: int = 5):
        self.dominio = dominio.rstrip('.')
        self.verbose = verbose
        self.resolver = DNSResolver(timeout=timeout)
        self.resultados = {
            'dominio': self.dominio,
            'fecha': datetime.now().isoformat(),
            'basicos': {},
            'subdominios': [],
            'axfr': False,
            'axfr_records': [],
            'reverse_lookups': {},
        }

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
        return resultados

    def enumerar_subdominios(self, wordlist: str, max_resultados: int = None, delay: float = 0.0) -> List[Dict]:
        print(f"\n[+] Enumerando subdominios de {self.dominio}")
        print("-" * 60)

        wordlist_path = wordlist
        if not os.path.exists(wordlist_path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            wordlist_path = os.path.join(base_dir, 'wordlists', wordlist)

        if not os.path.exists(wordlist_path):
            print(f"[-] Wordlist no encontrada: {wordlist}")
            return []

        with open(wordlist_path, 'r') as f:
            palabras = [linea.strip() for linea in f if linea.strip()]

        subdominios = []
        total = len(palabras)
        print(f"[*] Probando {total} palabras...\n")

        for i, palabra in enumerate(palabras, 1):
            subdominio = f"{palabra}.{self.dominio}"

            try:
                ips = self.resolver.resolver_registro(subdominio, 'A')
                if ips:
                    print(f"  [FOUND] {subdominio}")
                    for ip in ips:
                        print(f"          \u2514\u2500 {ip}")
                    subdominios.append({
                        'dominio': subdominio,
                        'ips': ips
                    })
                    if max_resultados and len(subdominios) >= max_resultados:
                        break
            except Exception:
                pass

            if delay > 0:
                time.sleep(delay)

            if i % 50 == 0:
                self._mostrar_progreso(i, total, "  Progreso")

        if total >= 50:
            print()

        print(f"\n[+] Subdominios encontrados: {len(subdominios)}")
        self.resultados['subdominios'] = subdominios
        return subdominios

    def transferencia_zona(self) -> bool:
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
                    return True

                except dns.exception.TransferFailed:
                    self.log(f"Transferencia rechazada en {ns}")
                except ConnectionRefusedError:
                    self.log(f"Conexi\u00f3n rechazada en {ns}")
                except Exception as e:
                    self.log(f"Error en {ns}: {e}")

            print("[-] AXFR no permitido en ning\u00fan servidor")
            return False

        except Exception as e:
            print(f"[-] Error: {e}")
            return False

    def busquedas_inversas(self, ips: List[str]) -> Dict[str, Optional[str]]:
        print(f"\n[+] Realizando b\u00fasquedas inversas")
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
        return resultados_reverse

    def escanear_completo(self,
                          wordlist: str = None,
                          intentar_axfr: bool = True,
                          reverse_lookup: bool = False,
                          max_subdominios: int = None,
                          delay: float = 0.0) -> Dict:
        print("\n" + "=" * 60)
        print(f"  DNSTRACKING - Esc\u00e1ner DNS")
        print(f"  Dominio: {self.dominio}")
        print(f"  Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        print("\n[*] Validando dominio...")
        if not self.resolver.es_dominio_valido(self.dominio):
            print(f"[-] Dominio inv\u00e1lido o no resoluble: {self.dominio}")
            return self.resultados
        print("[OK] Dominio v\u00e1lido\n")

        print("[FASE 1/4] Enumeraci\u00f3n de registros b\u00e1sicos")
        try:
            self.enumerar_registros_basicos()
        except Exception as e:
            print(f"[-] Error en enumeraci\u00f3n b\u00e1sica: {e}")

        if wordlist:
            print("\n[FASE 2/4] Enumeraci\u00f3n de subdominios")
            try:
                self.enumerar_subdominios(wordlist, max_resultados=max_subdominios, delay=delay)
            except KeyboardInterrupt:
                print("\n[-] Enumeraci\u00f3n de subdominios cancelada")
            except Exception as e:
                print(f"[-] Error en enumeraci\u00f3n de subdominios: {e}")
        else:
            print("\n[FASE 2/4] Enumeraci\u00f3n de subdominios - OMITIDA")

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
            print("\n[FASE 4/4] B\u00fasquedas inversas")
            ips_a_resolver = []
            for tipo, valores in self.resultados['basicos'].items():
                if tipo in ('A', 'AAAA'):
                    ips_a_resolver.extend(valores)
            for sub in self.resultados['subdominios']:
                ips_a_resolver.extend(sub['ips'])
            ips_unicas = list(set(ips_a_resolver))
            if ips_unicas:
                self.busquedas_inversas(ips_unicas)
        else:
            print("\n[FASE 4/4] B\u00fasquedas inversas - OMITIDA")

        print("\n" + "=" * 60)
        print("  ESCANEO COMPLETADO")
        print("=" * 60)

        self._mostrar_resumen()

        return self.resultados

    def _mostrar_resumen(self):
        print("\n[RESUMEN]")
        print(f"  Dominio: {self.dominio}")

        registros_con_datos = sum(1 for v in self.resultados['basicos'].values() if v)
        print(f"  Registros DNS encontrados: {registros_con_datos} tipos")

        num_subdominios = len(self.resultados['subdominios'])
        print(f"  Subdominios encontrados: {num_subdominios}")

        if self.resultados['axfr']:
            print(f"  AXFR: EXITOSO ({len(self.resultados['axfr_records'])} registros)")
        else:
            print(f"  AXFR: No permitido")

        reverse_exitosos = sum(1 for v in self.resultados['reverse_lookups'].values() if v)
        if reverse_exitosos > 0:
            print(f"  Reverse lookups: {reverse_exitosos} exitosos")
