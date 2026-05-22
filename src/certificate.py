"""
Inspeccion de certificados SSL/TLS
Obtiene informacion del certificado de cada subdominio
"""

import ssl
import socket
from datetime import datetime
from typing import Dict, Optional, List


class CertificateInspector:
    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def inspeccionar(self, hostname: str, puerto: int = 443) -> Optional[Dict]:
        contexto = ssl.create_default_context()
        contexto.check_hostname = False
        contexto.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection(
                (hostname, puerto), timeout=self.timeout
            ) as sock:
                with contexto.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    if not cert:
                        return None

                    resultado = {
                        'hostname': hostname,
                        'puerto': puerto,
                        'emisor': dict(cert.get('issuer', [])),
                        'asunto': dict(cert.get('subject', [])),
                        'valido_desde': cert.get('notBefore', ''),
                        'valido_hasta': cert.get('notAfter', ''),
                        'sans': [],
                        'huella': '',
                        'dias_restantes': None,
                        'expirado': False,
                    }

                    sans = []
                    for entry in cert.get('subjectAltName', []):
                        sans.append(entry[1])
                    resultado['sans'] = sans

                    if resultado['valido_hasta']:
                        try:
                        # 'notAfter' tiene formato 'May 22 12:00:00 2026 GMT'
                            expira = datetime.strptime(
                                resultado['valido_hasta'],
                                '%b %d %H:%M:%S %Y %Z'
                            )
                            ahora = datetime.utcnow()
                            dias = (expira - ahora).days
                            resultado['dias_restantes'] = dias
                            resultado['expirado'] = dias < 0
                        except (ValueError, TypeError):
                            pass

                    return resultado

        except socket.timeout:
            return None
        except ConnectionRefusedError:
            return None
        except ssl.SSLError:
            return None
        except OSError:
            return None

    def inspeccionar_subdominios(
        self, subdominios: List[Dict], puerto: int = 443
    ) -> List[Dict]:
        resultados = []
        for sub in subdominios:
            hostname = sub.get('dominio', '')
            if not hostname:
                continue
            cert = self.inspeccionar(hostname, puerto)
            if cert:
                resultados.append(cert)
        return resultados
