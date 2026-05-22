"""
Escaneo de puertos comunes en IPs descubiertas
"""

import socket
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


PUERTOS_COMUNES = [
    22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    8080, 8443, 9090, 9443,
    3306, 5432, 6379, 27017,
    389, 636, 3389, 5900, 8081, 9200, 11211,
]


class PortScanner:
    def __init__(self, timeout: float = 2.0, hilos: int = 20):
        self.timeout = timeout
        self.hilos = hilos

    def escanear_ip(self, ip: str, puertos: List[int] = None) -> List[int]:
        if puertos is None:
            puertos = PUERTOS_COMUNES
        abiertos = []

        def _probar(puerto):
            try:
                with socket.create_connection((ip, puerto), timeout=self.timeout):
                    return puerto
            except (socket.timeout, ConnectionRefusedError, OSError):
                return None

        with ThreadPoolExecutor(max_workers=self.hilos) as pool:
            futuros = {pool.submit(_probar, p): p for p in puertos}
            for futuro in as_completed(futuros):
                try:
                    resultado = futuro.result()
                    if resultado is not None:
                        abiertos.append(resultado)
                except Exception:
                    pass

        return sorted(abiertos)

    def escanear_ips(self, ips: List[str], puertos: List[int] = None) -> Dict[str, List[int]]:
        resultados = {}
        for ip in ips:
            abiertos = self.escanear_ip(ip, puertos)
            if abiertos:
                resultados[ip] = abiertos
        return resultados
