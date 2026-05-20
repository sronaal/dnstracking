"""
Fuentes pasivas de enumeracion de subdominios
APIs externas sin necesidad de enviar consultas DNS directas
"""

import requests
from typing import List, Dict, Set
from urllib.parse import quote


class PassiveSources:
    """Fuentes pasivas para descubrimiento de subdominios"""

    def __init__(self, dominio: str, timeout: int = 10):
        self.dominio = dominio.rstrip('.')
        self.timeout = timeout
        self.subdominios: Dict[str, Dict] = {}

    def _agregar_subdominio(self, subdominio: str, fuente: str, ip: str = None):
        sub = subdominio.rstrip('.').lower()
        if sub not in self.subdominios:
            self.subdominios[sub] = {'fuentes': set(), 'ips': set()}
        self.subdominios[sub]['fuentes'].add(fuente)
        if ip:
            self.subdominios[sub]['ips'].add(ip)

    def crtsh(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios de certificados SSL via crt.sh
        No requiere API key
        """
        print(f"  [*] Consultando crt.sh...")
        url = f"https://crt.sh/?q={quote(self.dominio)}&output=json"
        headers = {'User-Agent': 'DNSTRACKING/1.0'}

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                datos = resp.json()
                for entry in datos:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub and sub.endswith(self.dominio) and '*' not in sub:
                            self._agregar_subdominio(sub, 'crt.sh')

                count = len([s for s in self.subdominios.values() if 'crt.sh' in s['fuentes']])
                print(f"  [+] crt.sh: {count} subdominios encontrados")
        except Exception as e:
            print(f"  [-] crt.sh error: {e}")

        return self.subdominios

    def hackertarget(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios via HackerTarget API
        Gratuito, sin API key
        """
        print(f"  [*] Consultando HackerTarget...")
        url = f"https://api.hackertarget.com/hostsearch/?q={quote(self.dominio)}"

        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200 and resp.text.strip():
                lineas = resp.text.strip().split('\n')
                for linea in lineas:
                    partes = linea.split(',')
                    if len(partes) >= 2:
                        subdominio = partes[0].strip().lower()
                        ip = partes[1].strip()
                        if subdominio and subdominio.endswith(self.dominio):
                            self._agregar_subdominio(subdominio, 'hackertarget', ip)

                count = len([s for s in self.subdominios.values() if 'hackertarget' in s['fuentes']])
                print(f"  [+] HackerTarget: {count} subdominios encontrados")
        except Exception as e:
            print(f"  [-] HackerTarget error: {e}")

        return self.subdominios

    def rapiddns(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios via RapidDNS
        Gratuito, sin API key
        """
        print(f"  [*] Consultando RapidDNS...")
        url = f"https://rapiddns.io/subdomain/{self.dominio}?full=1"
        headers = {'User-Agent': 'Mozilla/5.0'}

        try:
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                import re
                pattern = rf'([\w.-]+\.{re.escape(self.dominio)})'
                matches = re.findall(pattern, resp.text)
                for sub in matches:
                    sub = sub.lower().strip()
                    if sub and sub != self.dominio:
                        self._agregar_subdominio(sub, 'rapiddns')

                count = len([s for s in self.subdominios.values() if 'rapiddns' in s['fuentes']])
                print(f"  [+] RapidDNS: {count} subdominios encontrados")
        except Exception as e:
            print(f"  [-] RapidDNS error: {e}")

        return self.subdominios

    def certspotter(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios de certificados SSL via CertSpotter API
        Gratuito, sin API key
        """
        print(f"  [*] Consultando CertSpotter...")
        url = f"https://api.certspotter.com/v1/issuances?domain={quote(self.dominio)}&include_subdomains=true&expand=dns_names"

        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                datos = resp.json()
                for entry in datos:
                    dns_names = entry.get('dns_names', [])
                    for name in dns_names:
                        name = name.lstrip('*.').lower()
                        if name.endswith(self.dominio) and name != self.dominio:
                            self._agregar_subdominio(name, 'certspotter')

                count = len([s for s in self.subdominios.values() if 'certspotter' in s['fuentes']])
                print(f"  [+] CertSpotter: {count} subdominios encontrados")
        except Exception as e:
            print(f"  [-] CertSpotter error: {e}")

        return self.subdominios

    def enumerar_todas(self) -> List[Dict]:
        """
        Ejecuta todas las fuentes pasivas
        Retorna lista de subdominios con metadata
        """
        print(f"\n[+] Enumeracion pasiva de subdominios para {self.dominio}")
        print("-" * 60)

        self.crtsh()
        self.hackertarget()
        self.certspotter()
        self.rapiddns()

        resultados = []
        for sub, data in self.subdominios.items():
            resultados.append({
                'dominio': sub,
                'ips': list(data['ips']),
                'fuentes': list(data['fuentes']),
            })

        print(f"\n  [+] Total subdominios unicos: {len(resultados)}")
        return resultados
