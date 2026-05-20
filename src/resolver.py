"""
Módulo de bajo nivel para consultas DNS
Maneja toda la interacción con los servidores DNS
"""

import dns.resolver
import dns.reversename
import dns.exception
from typing import List, Dict, Optional


class DNSResolver:
    """Clase para manejar todas las consultas DNS"""

    BASIC_RECORDS = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA']

    def __init__(self, timeout: int = 5, nameservers: Optional[List[str]] = None):
        self.resolver = dns.resolver.Resolver()
        self.resolver.lifetime = timeout
        self.timeout = timeout
        if nameservers:
            self.resolver.nameservers = nameservers

    def resolver_registro(self, dominio: str, tipo: str) -> List[str]:
        try:
            respuestas = self.resolver.resolve(dominio, tipo)
            return [str(rdata).rstrip('.') for rdata in respuestas]
        except dns.resolver.NXDOMAIN:
            return []
        except dns.resolver.NoAnswer:
            return []
        except dns.exception.Timeout:
            return []
        except Exception:
            return []

    def es_dominio_valido(self, dominio: str) -> bool:
        try:
            self.resolver.resolve(dominio, 'A')
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return False
        except Exception:
            return False

    def enumerar_basicos(self, dominio: str) -> Dict[str, List[str]]:
        resultados = {}
        for tipo in self.BASIC_RECORDS:
            try:
                resultados[tipo] = self.resolver_registro(dominio, tipo)
            except Exception:
                resultados[tipo] = []
        return resultados

    def busqueda_inversa(self, ip: str) -> Optional[str]:
        try:
            addr_inversa = dns.reversename.from_address(ip)
            respuesta = self.resolver.resolve(addr_inversa, 'PTR')
            for rdata in respuesta:
                return str(rdata).rstrip('.')
        except Exception:
            pass
        return None

    def obtener_ns_servidores(self, dominio: str) -> List[str]:
        return self.resolver_registro(dominio, 'NS')
