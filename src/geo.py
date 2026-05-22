"""
Geolocalizacion y ASN de direcciones IP
Usa ip-api.com (gratuito, sin API key)
"""

import requests
import time
from typing import Dict, List, Optional


class GeoLocator:
    URL = "http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query,lat,lon"

    def __init__(self, timeout: int = 5, delay: float = 0.1):
        self.timeout = timeout
        self.delay = delay
        self.cache: Dict[str, Dict] = {}

    def localizar(self, ip: str) -> Optional[Dict]:
        if ip in self.cache:
            return self.cache[ip]

        try:
            resp = requests.get(
                self.URL.format(ip=ip),
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return None

            data = resp.json()
            if data.get('status') != 'success':
                return None

            resultado = {
                'ip': data['query'],
                'pais': data.get('country'),
                'codigo_pais': data.get('countryCode'),
                'region': data.get('regionName'),
                'ciudad': data.get('city'),
                'isp': data.get('isp'),
                'org': data.get('org'),
                'asn': data.get('as'),
            }
            self.cache[ip] = resultado
            time.sleep(self.delay)
            return resultado

        except requests.exceptions.RequestException:
            return None

    def localizar_multiples(self, ips: List[str]) -> List[Dict]:
        resultados = []
        for ip in ips:
            geo = self.localizar(ip)
            if geo:
                resultados.append(geo)
        return resultados
