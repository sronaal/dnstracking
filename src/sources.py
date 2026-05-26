"""
Fuentes pasivas de enumeracion de subdominios
APIs externas sin necesidad de enviar consultas DNS directas
"""

import requests
from typing import List, Dict, Set
from urllib.parse import quote
from color_util import icono_exito, icono_error, icono_info


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
        print(f" {icono_info()} Consultando crt.sh...")
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
                print(f" {icono_exito()} crt.sh: {count} subdominios encontrados")
        except requests.exceptions.RequestException as e:
            print(f" {icono_error()} crt.sh error: {e}")

        return self.subdominios

    def hackertarget(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios via HackerTarget API
        Gratuito, sin API key
        """
        print(f" {icono_info()} Consultando HackerTarget...")
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
                print(f" {icono_exito()} HackerTarget: {count} subdominios encontrados")
        except requests.exceptions.RequestException as e:
            print(f" {icono_error()} HackerTarget error: {e}")

        return self.subdominios

    def rapiddns(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios via RapidDNS
        Gratuito, sin API key
        """
        print(f" {icono_info()} Consultando RapidDNS...")
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
                print(f" {icono_exito()} RapidDNS: {count} subdominios encontrados")
        except (requests.exceptions.RequestException, ValueError) as e:
            print(f" {icono_error()} RapidDNS error: {e}")

        return self.subdominios

    def certspotter(self) -> Dict[str, Dict]:
        """
        Obtiene subdominios de certificados SSL via CertSpotter API
        Gratuito, sin API key
        """
        print(f" {icono_info()} Consultando CertSpotter...")
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
                print(f" {icono_exito()} CertSpotter: {count} subdominios encontrados")
        except (requests.exceptions.RequestException, ValueError) as e:
            print(f" {icono_error()} CertSpotter error: {e}")

        return self.subdominios

    def alienvault(self) -> Dict[str, Dict]:
        print(f" {icono_info()} Consultando AlienVault OTX...")
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.dominio}/passive_dns"

        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get('passive_dns', []):
                    sub = entry.get('hostname', '').lower()
                    ip = entry.get('address', '')
                    if sub and sub.endswith(self.dominio) and sub != self.dominio:
                        self._agregar_subdominio(sub, 'alienvault', ip)

                count = len([s for s in self.subdominios.values() if 'alienvault' in s['fuentes']])
                print(f" {icono_exito()} AlienVault: {count} subdominios encontrados")
        except (requests.exceptions.RequestException, ValueError) as e:
            print(f" {icono_error()} AlienVault error: {e}")

        return self.subdominios

    def threatcrowd(self) -> Dict[str, Dict]:
        print(f" {icono_info()} Consultando ThreatCrowd...")
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.dominio}"

        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get('subdomains', []):
                    sub = sub.lower().strip()
                    if sub.endswith(self.dominio) and sub != self.dominio:
                        self._agregar_subdominio(sub, 'threatcrowd')

                count = len([s for s in self.subdominios.values() if 'threatcrowd' in s['fuentes']])
                print(f" {icono_exito()} ThreatCrowd: {count} subdominios encontrados")
        except (requests.exceptions.RequestException, ValueError) as e:
            print(f" {icono_error()} ThreatCrowd error: {e}")

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
        self.alienvault()
        self.threatcrowd()

        total_antes = len(self.subdominios) if hasattr(self, 'subdominios') else 0
        resultados = []
        for sub, data in self.subdominios.items():
            resultados.append({
                'dominio': sub,
                'ips': list(data['ips']),
                'fuentes': list(data['fuentes']),
            })

        print(f"\n {icono_exito()} Total subdominios unicos: {len(resultados)}")
        return resultados
