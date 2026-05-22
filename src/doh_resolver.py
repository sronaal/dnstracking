"""
Resolucion DNS via DNS-over-HTTPS (DoH)
Usa Cloudflare o Google como resolver alternativo
"""

import requests
import dns.exception
from typing import List, Dict, Optional


class DohResolver:
    PROVEEDORES = {
        'cloudflare': {
            'url': 'https://cloudflare-dns.com/dns-query',
            'name': 'Cloudflare',
        },
        'google': {
            'url': 'https://dns.google/resolve',
            'name': 'Google',
        },
    }

    TIPOS_DNS = {
        'A': 1, 'AAAA': 28, 'MX': 15, 'NS': 2,
        'TXT': 16, 'CNAME': 5, 'SOA': 6, 'SRV': 33, 'CAA': 257,
    }

    def __init__(self, proveedor: str = 'cloudflare', timeout: int = 5):
        cfg = self.PROVEEDORES.get(proveedor)
        if not cfg:
            raise ValueError(f"Proveedor DoH no valido: {proveedor}")
        self.url = cfg['url']
        self.nombre = cfg['name']
        self.timeout = timeout

    def resolver(self, dominio: str, tipo: str) -> List[str]:
        tipo_num = self.TIPOS_DNS.get(tipo.upper())
        if tipo_num is None:
            return []

        try:
            resp = requests.get(
                self.url,
                params={
                    'name': dominio,
                    'type': tipo_num,
                    'do': 'false',
                },
                headers={
                    'Accept': 'application/dns-json',
                    'User-Agent': 'DNSTRACKING/1.0',
                },
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return []

            data = resp.json()
            if data.get('Status') != 0:
                return []

            resultados = []
            for answer in data.get('Answer', []):
                tipo_resp = answer.get('type')
                datos = answer.get('data', '')
                if tipo_resp == tipo_num:
                    if tipo in ('MX',):
                        resultados.append(datos)
                    elif tipo == 'SOA':
                        resultados.append(datos)
                    elif tipo == 'TXT':
                        resultados.append(datos.strip('"'))
                    else:
                        resultados.append(datos.rstrip('.'))

            return resultados

        except requests.exceptions.RequestException:
            return []
        except (ValueError, KeyError):
            return []

    def enumerar_basicos(self, dominio: str) -> Dict[str, List[str]]:
        tipos = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'CAA']
        resultados = {}
        for tipo in tipos:
            resultados[tipo] = self.resolver(dominio, tipo)
        return resultados

    def es_dominio_valido(self, dominio: str) -> bool:
        return len(self.resolver(dominio, 'A')) > 0

    def resolver_registro(self, dominio: str, tipo: str) -> List[str]:
        return self.resolver(dominio, tipo)

    def busqueda_inversa(self, ip: str) -> Optional[str]:
        try:
            from dns.reversename import from_address
            import dns.resolver as dnsr
            ptr = from_address(ip)
            return self.resolver(str(ptr), 'PTR')[0] if self.resolver(str(ptr), 'PTR') else None
        except Exception:
            return None

    def obtener_ns_servidores(self, dominio: str) -> List[str]:
        return self.resolver(dominio, 'NS')
