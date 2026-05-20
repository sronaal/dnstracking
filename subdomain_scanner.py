"""
Motor avanzado de escaneo de subdominios
Soporta threading, deteccion de wildcards, CNAME chains, y multiples tipos DNS
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set, Optional, Tuple
from threading import Lock


class SubdomainScanner:
    """Escaneo de subdominios con threading y optimizaciones"""

    def __init__(self, dns_resolver, dominio: str, verbose: bool = False):
        self.resolver = dns_resolver
        self.dominio = dominio.rstrip('.')
        self.verbose = verbose
        self.encontrados: List[Dict] = []
        self.lock = Lock()
        self.total_probados = 0
        self.encontrados_count = 0
        self.start_time = None
        self.wildcard_ips: Set[str] = set()
        self.wildcard_cnames: Set[str] = set()

    def _probar_subdominio(
        self,
        palabra: str,
        tipos_dns: List[str] = None,
        filtrar_wildcards: bool = True
    ) -> Optional[Dict]:
        """Prueba un subdominio con multiples tipos DNS y resuelve CNAME chains"""
        if tipos_dns is None:
            tipos_dns = ['A']

        subdominio = f"{palabra}.{self.dominio}"
        resultados = {}
        cname_chain = []

        for tipo in tipos_dns:
            try:
                valores = self.resolver.resolver_registro(subdominio, tipo)
                if valores:
                    if tipo == 'CNAME':
                        cname_chain = valores
                        resultados[tipo] = valores
                    else:
                        resultados[tipo] = valores
            except Exception:
                pass

        if not resultados:
            return None

        if filtrar_wildcards and self._es_wildcard(resultados):
            return None

        ips = resultados.get('A', []) + resultados.get('AAAA', [])

        return {
            'dominio': subdominio,
            'resultados': resultados,
            'ips': ips,
            'cname_chain': cname_chain,
        }

    def _es_wildcard(self, resultados: Dict) -> bool:
        """Determina si los resultados son producto de wildcard DNS"""
        if not self.wildcard_ips and not self.wildcard_cnames:
            return False

        ips_resultado = set(resultados.get('A', []) + resultados.get('AAAA', []))
        cnames_resultado = set(resultados.get('CNAME', []))

        if ips_resultado and self.wildcard_ips:
            if ips_resultado & self.wildcard_ips:
                return True

        if cnames_resultado and self.wildcard_cnames:
            if cnames_resultado & self.wildcard_cnames:
                return True

        return False

    def _actualizar_progreso(self, actual: int, total: int, encontrados: int):
        """Muestra barra de progreso con estadisticas"""
        porcentaje = (actual / total) * 100
        barras = int(porcentaje / 5)
        barra = "\u2588" * barras + "\u2591" * (20 - barras)

        elapsed = time.time() - self.start_time if self.start_time else 0
        rate = actual / elapsed if elapsed > 0 else 0
        eta = (total - actual) / rate if rate > 0 else 0

        if eta < 60:
            eta_str = f"{int(eta)}s"
        elif eta < 3600:
            eta_str = f"{int(eta // 60)}m {int(eta % 60)}s"
        else:
            eta_str = f"{eta / 3600:.1f}h"

        import sys
        sys.stdout.write(
            f"\r  [{barra}] {porcentaje:.1f}% | "
            f"{actual}/{total} | "
            f"Encontrados: {encontrados} | "
            f"Rate: {rate:.1f}/s | "
            f"ETA: {eta_str}"
        )
        sys.stdout.flush()

    def detectar_wildcard(self) -> Tuple[Set[str], Set[str]]:
        """
        Detecta wildcard DNS de forma robusta
        Retorna (wildcard_ips, wildcard_cnames)
        """
        import random
        import string

        wildcard_ips = set()
        wildcard_cnames = set()

        test_strings = [
            ''.join(random.choices(string.ascii_lowercase, k=16)),
            ''.join(random.choices(string.ascii_lowercase, k=16)),
            ''.join(random.choices(string.ascii_lowercase, k=16)),
            f"xn--{''.join(random.choices(string.ascii_lowercase, k=8))}",
        ]

        for test in test_strings:
            subdominio = f"{test}.{self.dominio}"
            try:
                ips = self.resolver.resolver_registro(subdominio, 'A')
                if ips:
                    wildcard_ips.update(ips)
            except Exception:
                pass

            try:
                cnames = self.resolver.resolver_registro(subdominio, 'CNAME')
                if cnames:
                    wildcard_cnames.update(cnames)
            except Exception:
                pass

        self.wildcard_ips = wildcard_ips
        self.wildcard_cnames = wildcard_cnames
        return wildcard_ips, wildcard_cnames

    def escanear_con_threading(
        self,
        wordlist: str,
        threads: int = 20,
        tipos_dns: List[str] = None,
        max_resultados: int = None,
        delay: float = 0.0,
        detectar_wildcards: bool = True,
        mostrar_progreso: bool = True
    ) -> List[Dict]:
        """
        Escaneo de subdominios con threading

        Args:
            wordlist: Archivo o nombre de wordlist
            threads: Numero de hilos concurrentes
            tipos_dns: Tipos DNS a consultar (default: ['A'])
            max_resultados: Limite de resultados
            delay: Delay entre lotes
            detectar_wildcards: Detectar y filtrar wildcards
            mostrar_progreso: Mostrar barra de progreso
        """
        if tipos_dns is None:
            tipos_dns = ['A']

        wordlist_path = wordlist
        if not os.path.exists(wordlist_path):
            base_dir = os.path.dirname(os.path.abspath(__file__))
            wordlist_path = os.path.join(base_dir, 'wordlists', wordlist)

        if not os.path.exists(wordlist_path):
            print(f"[-] Wordlist no encontrada: {wordlist}")
            return []

        with open(wordlist_path, 'r') as f:
            palabras = [linea.strip() for linea in f if linea.strip()]

        total = len(palabras)
        self.encontrados = []
        self.total_probados = 0
        self.encontrados_count = 0
        self.start_time = time.time()

        wildcard_ips = set()
        wildcard_cnames = set()

        if detectar_wildcards:
            wildcard_ips, wildcard_cnames = self.detectar_wildcard()
            if wildcard_ips:
                print(f"  [!] Wildcard IPs detectado: {len(wildcard_ips)} IPs filtradas")
            if wildcard_cnames:
                print(f"  [!] Wildcard CNAME detectado: {len(wildcard_cnames)} CNAMEs filtrados")

        print(f"  [*] Escaneando {total} subdominios con {threads} hilos...")
        print(f"  [*] Tipos DNS: {', '.join(tipos_dns)}")
        print()

        batch_size = threads
        for i in range(0, total, batch_size):
            batch = palabras[i:i + batch_size]

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(
                        self._probar_subdominio,
                        palabra,
                        tipos_dns,
                        detectar_wildcards
                    ): palabra
                    for palabra in batch
                }

                for future in as_completed(futures):
                    palabra = futures[future]
                    try:
                        resultado = future.result()
                        if resultado:
                            with self.lock:
                                self.encontrados.append(resultado)
                                self.encontrados_count += 1
                                print(f"  [FOUND] {resultado['dominio']}")
                                for tipo, valores in resultado['resultados'].items():
                                    for valor in valores:
                                        print(f"          \u2514\u2500 [{tipo}] {valor}")
                                if resultado.get('cname_chain'):
                                    print(f"          \u2514\u2500 [CHAIN] -> {' -> '.join(resultado['cname_chain'])}")
                    except Exception:
                        pass

                    with self.lock:
                        self.total_probados += 1
                        if mostrar_progreso and self.total_probados % 10 == 0:
                            self._actualizar_progreso(
                                self.total_probados, total, self.encontrados_count
                            )

            if delay > 0:
                time.sleep(delay)

            if max_resultados and self.encontrados_count >= max_resultados:
                break

        print()
        elapsed = time.time() - self.start_time
        print(f"\n  [+] Subdominios encontrados: {self.encontrados_count}")
        print(f"  [+] Tiempo: {elapsed:.1f}s | Rate: {total / elapsed:.1f} subdominios/s")

        return self.encontrados

    def generar_permutaciones(self, subdominios: List[Dict]) -> List[str]:
        """Genera permutaciones de subdominios encontrados"""
        prefijos = [
            'dev', 'staging', 'test', 'qa', 'uat', 'prod',
            'api', 'v2', 'v3', 'new', 'old', 'backup',
            'internal', 'private', 'public', 'demo', 'sandbox',
            'pre', 'preprod', 'stage', 'acc', 'acceptance',
        ]
        sufijos = [
            '-dev', '-staging', '-test', '-api', '-v2', '-backup',
            '-old', '-new', '-prod', '-internal', '-demo',
        ]

        palabras_base = []
        for sub in subdominios:
            nombre = sub['dominio'].replace(f'.{self.dominio}', '')
            partes = nombre.split('.')
            palabras_base.extend(partes)

        palabras_base = list(set(palabras_base))

        permutaciones = []

        for palabra in palabras_base:
            for prefijo in prefijos:
                permutaciones.append(f"{prefijo}-{palabra}")
                permutaciones.append(f"{prefijo}.{palabra}")

            for sufijo in sufijos:
                permutaciones.append(f"{palabra}{sufijo}")

        return list(set(permutaciones))
