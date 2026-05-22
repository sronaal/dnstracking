"""
Consulta WHOIS - informacion de registro de dominios
Usa el comando whois del sistema o consulta RDAP
"""

import subprocess
import re
import requests
from typing import Dict, Optional


class WhoisLookup:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def consultar(self, dominio: str) -> Dict:
        resultado = {
            'dominio': dominio,
            'registrar': None,
            'creacion': None,
            'expiracion': None,
            'name_servers': [],
            'estado': None,
        }
        exitoso = self._consultar_whois_local(dominio, resultado)
        if not exitoso or not resultado.get('registrar'):
            self._consultar_rdap(dominio, resultado)
        return resultado

    def _consultar_whois_local(self, dominio: str, resultado: Dict) -> bool:
        try:
            salida = subprocess.run(
                ['whois', dominio],
                capture_output=True,
                text=True,
                timeout=self.timeout
            ).stdout

            self._parsear_whois(salida, resultado)
            return True

        except FileNotFoundError:
            resultado.setdefault('notas', []).append(
                'whois no instalado en el sistema'
            )
            return False
        except subprocess.TimeoutExpired:
            resultado.setdefault('notas', []).append(
                'Timeout en consulta WHOIS local'
            )
            return False
        except Exception as e:
            resultado.setdefault('notas', []).append(
                f'Error WHOIS local: {e}'
            )
            return False

    def _parsear_whois(self, salida: str, resultado: Dict):
        campos = {
            'registrar': [
                r'Registrar:\s*(.+)',
                r'registrar:\s*(.+)',
                r'Sponsoring Registrar:\s*(.+)',
            ],
            'creacion': [
                r'Creation Date:\s*(.+)',
                r'created:\s*(.+)',
                r'created_date:\s*(.+)',
            ],
            'expiracion': [
                r'Registry Expiry Date:\s*(.+)',
                r'expiration_date:\s*(.+)',
                r'Expiration Date:\s*(.+)',
            ],
        }

        for campo, patrones in campos.items():
            for patron in patrones:
                match = re.search(patron, salida, re.IGNORECASE)
                if match:
                    resultado[campo] = match.group(1).strip()
                    break

        ns_matches = re.findall(
            r'Name Server:\s*(.+)', salida, re.IGNORECASE
        )
        if not ns_matches:
            ns_matches = re.findall(
                r'nserver:\s*(.+)', salida, re.IGNORECASE
            )
        resultado['name_servers'] = [ns.strip().lower() for ns in ns_matches]

        estado = re.search(
            r'Domain Status:\s*(.+)', salida, re.IGNORECASE
        )
        if estado:
            resultado['estado'] = estado.group(1).strip()

    EP_RDAP = {
        'com': 'https://rdap.verisign.com/com/v1/domain/',
        'net': 'https://rdap.verisign.com/net/v1/domain/',
        'org': 'https://rdap.publicinterestregistry.org/rdap/domain/',
        'info': 'https://rdap.afilias.net/rdap/domain/',
        'io': 'https://rdap.nic.io/domain/',
        'co': 'https://rdap.nic.co/domain/',
    }

    def _consultar_rdap(self, dominio: str, resultado: Dict):
        tld = dominio.rsplit('.', 1)[-1].lower()
        base = self.EP_RDAP.get(tld)
        if not base:
            resultado.setdefault('notas', []).append(
                f'RDAP no disponible para TLD .{tld}'
            )
            return

        try:
            resp = requests.get(
                f'{base}{dominio}',
                headers={'Accept': 'application/rdap+json'},
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                resultado.setdefault('notas', []).append(
                    f'RDAP respondio {resp.status_code}'
                )
                return

            data = resp.json()

            if 'events' in data:
                for ev in data['events']:
                    action = ev.get('eventAction', '')
                    date = ev.get('eventDate', '')
                    if action == 'registration' and not resultado.get('creacion'):
                        resultado['creacion'] = date
                    elif action == 'expiration' and not resultado.get('expiracion'):
                        resultado['expiracion'] = date

            if 'entities' in data:
                for ent in data['entities']:
                    if 'vcardArray' in ent:
                        vcard = ent['vcardArray'][1] if len(ent['vcardArray']) > 1 else []
                        for item in vcard:
                            if len(item) >= 3 and item[0] == 'fn' and not resultado.get('registrar'):
                                resultado['registrar'] = item[3]

            if 'nameservers' in data and not resultado.get('name_servers'):
                resultado['name_servers'] = [
                    ns.get('ldhName', '').lower()
                    for ns in data['nameservers']
                ]

        except requests.exceptions.RequestException as e:
            resultado.setdefault('notas', []).append(
                f'Error RDAP: {e}'
            )
