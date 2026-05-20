"""
Modulo de deteccion de vulnerabilidades DNS
Analiza la configuracion DNS en busca de problemas de seguridad
"""

import re
import ipaddress
from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class Finding:
    """Representa un hallazgo de vulnerabilidad"""
    id: str
    nombre: str
    severidad: str
    componente: str
    descripcion: str
    evidencia: str
    recomendacion: str
    cvss_estimate: str = "0.0"

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'nombre': self.nombre,
            'severidad': self.severidad,
            'componente': self.componente,
            'descripcion': self.descripcion,
            'evidencia': self.evidencia,
            'recomendacion': self.recomendacion,
            'cvss_estimate': self.cvss_estimate,
        }


SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}


class VulnerabilityScanner:
    """Motor de deteccion de vulnerabilidades DNS"""

    def __init__(self, dominio: str, resolver, resultados: Dict, verbose: bool = False):
        self.dominio = dominio.rstrip('.')
        self.resolver = resolver
        self.resultados = resultados
        self.verbose = verbose
        self.findings: List[Finding] = []
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"VULN-{self._counter:03d}"

    def _add_finding(self, finding: Finding):
        self.findings.append(finding)
        severity_icon = {
            'CRITICAL': '[!!!]',
            'HIGH': '[!!]',
            'MEDIUM': '[!]',
            'LOW': '[~]',
            'INFO': '[i]',
        }.get(finding.severidad, '[?]')
        print(f"  {severity_icon} [{finding.severidad}] {finding.nombre}")
        if self.verbose:
            print(f"      {finding.descripcion}")

    def check_axfr(self) -> Optional[Finding]:
        """Verifica si AXFR fue exitoso (vulnerabilidad critica)"""
        if self.resultados.get('axfr'):
            finding = Finding(
                id=self._next_id(),
                nombre="AXFR Zone Transfer Allowed",
                severidad="CRITICAL",
                componente="AXFR",
                descripcion="El servidor DNS permite transferencia de zona completa. "
                           "Un atacante puede obtener todos los registros DNS incluyendo "
                           "hosts internos, subdominios y estructura de red.",
                evidencia=f"{len(self.resultados.get('axfr_records', []))} registros obtenidos via AXFR",
                recomendacion="Restringir AXFR solo a servidores DNS secundarios autorizados. "
                             "Configurar allow-transfer en BIND o equivalente.",
                cvss_estimate="7.5",
            )
            self._add_finding(finding)
            return finding
        return None

    def check_dnssec(self) -> Optional[Finding]:
        """Verifica si DNSSEC esta configurado correctamente"""
        dnskeys = self.resolver.resolver_registro(self.dominio, 'DNSKEY')
        rrsigs = self.resolver.resolver_registro(self.dominio, 'RRSIG')

        if not dnskeys and not rrsigs:
            finding = Finding(
                id=self._next_id(),
                nombre="DNSSEC Not Configured",
                severidad="MEDIUM",
                componente="DNSSEC",
                descripcion="El dominio no tiene DNSSEC configurado. "
                           "Las respuestas DNS pueden ser manipuladas via cache poisoning "
                           "o ataques de hombre en el medio.",
                evidencia="No se encontraron registros DNSKEY ni RRSIG",
                recomendacion="Habilitar DNSSEC en el registrador del dominio y configurar "
                             "firmas digitales para todos los registros DNS.",
                cvss_estimate="5.0",
            )
            self._add_finding(finding)
            return finding

        if dnskeys and not rrsigs:
            finding = Finding(
                id=self._next_id(),
                nombre="DNSSEC Keys Present but No Signatures",
                severidad="HIGH",
                componente="DNSSEC",
                descripcion="DNSSEC tiene claves configuradas pero no hay firmas RRSIG. "
                           "La configuracion esta incompleta y no protege contra manipulacion.",
                evidencia=f"DNSKEY encontrados: {len(dnskeys)}, RRSIG: 0",
                recomendacion="Completar la configuracion de DNSSEC firmando la zona "
                             "con las claves existentes.",
                cvss_estimate="6.0",
            )
            self._add_finding(finding)
            return finding

        return None

    def _parse_spf(self, spf_record: str) -> Dict:
        """Analiza un registro SPF y retorna su configuracion"""
        result = {
            'raw': spf_record,
            'all_mechanism': None,
            'includes': [],
            'ips': [],
            'is_permissive': False,
            'issues': [],
        }

        match = re.search(r'[+~?-]all', spf_record)
        if match:
            mechanism = match.group(0)
            result['all_mechanism'] = mechanism
            if mechanism in ['+all', '?all', '~all']:
                result['is_permissive'] = True
                if mechanism == '+all':
                    result['issues'].append("SPF permite TODOS los servidores (+all)")
                elif mechanism == '?all':
                    result['issues'].append("SPF tiene politica neutral (?all)")
                elif mechanism == '~all':
                    result['issues'].append("SPF tiene softfail (~all) en lugar de hardfail (-all)")

        result['includes'] = re.findall(r'include:(\S+)', spf_record)
        result['ips'] = re.findall(r'ip[46]:(\S+)', spf_record)

        return result

    def check_spf(self) -> Optional[Finding]:
        """Verifica la configuracion SPF del dominio"""
        txt_records = self.resultados.get('basicos', {}).get('TXT', [])

        spf_records = [r for r in txt_records if 'v=spf1' in r]

        if not spf_records:
            finding = Finding(
                id=self._next_id(),
                nombre="SPF Record Missing",
                severidad="HIGH",
                componente="SPF",
                descripcion="No se encontro registro SPF para el dominio. "
                           "Cualquier servidor puede enviar emails aparentando ser de este dominio, "
                           "facilitando ataques de phishing y spoofing.",
                evidencia="No se encontro registro TXT con v=spf1",
                recomendacion="Crear un registro SPF que liste todos los servidores autorizados "
                             "a enviar emails desde este dominio. Usar -all al final.",
                cvss_estimate="5.3",
            )
            self._add_finding(finding)
            return finding

        for spf in spf_records:
            analysis = self._parse_spf(spf)

            if analysis['is_permissive']:
                severity = "HIGH" if '+all' in spf else "MEDIUM"
                cvss = "7.0" if '+all' in spf else "4.0"
                finding = Finding(
                    id=self._next_id(),
                    nombre=f"SPF Permissive Policy ({analysis['all_mechanism']})",
                    severidad=severity,
                    componente="SPF",
                    descripcion=f"El registro SPF tiene una politica permisiva ({analysis['all_mechanism']}). "
                               f"Esto permite que servidores no autorizados puedan enviar emails.",
                    evidencia=spf[:150],
                    recomendacion="Cambiar a -all para rechazar emails de servidores no autorizados: "
                                 "v=spf1 ... -all",
                    cvss_estimate=cvss,
                )
                self._add_finding(finding)
                return finding

            if len(analysis['includes']) > 5:
                finding = Finding(
                    id=self._next_id(),
                    nombre="SPF Too Many Includes",
                    severidad="LOW",
                    componente="SPF",
                    descripcion=f"El SPF tiene {len(analysis['includes'])} includes. "
                               "Demasiados includes pueden causar que se exceda el limite de "
                               "10 consultas DNS (SPF permerror).",
                    evidencia=f"Includes: {', '.join(analysis['includes'][:5])}...",
                    recomendacion="Consolidar los includes o usar un registro SPF aplanado.",
                    cvss_estimate="2.0",
                )
                self._add_finding(finding)

        return None

    def check_dmarc(self) -> Optional[Finding]:
        """Verifica la configuracion DMARC del dominio"""
        dmarc_domain = f"_dmarc.{self.dominio}"
        dmarc_records = self.resolver.resolver_registro(dmarc_domain, 'TXT')

        dmarc_found = False
        for record in dmarc_records:
            if 'v=DMARC1' in record:
                dmarc_found = True

                if 'p=none' in record.lower():
                    finding = Finding(
                        id=self._next_id(),
                        nombre="DMARC Policy Set to None",
                        severidad="MEDIUM",
                        componente="DMARC",
                        descripcion="DMARC esta configurado pero la politica es 'none'. "
                                   "Esto significa que los emails que fallen SPF/DKIM no seran "
                                   "rechazados ni puestos en cuarentena, solo se genera reporte.",
                        evidencia=record[:150],
                        recomendacion="Cambiar la politica a 'quarantine' o 'reject': "
                                     "v=DMARC1; p=reject; rua=mailto:dmarc@dominio.com",
                        cvss_estimate="4.0",
                    )
                    self._add_finding(finding)
                    return None

                if 'p=quarantine' in record.lower():
                    finding = Finding(
                        id=self._next_id(),
                        nombre="DMARC Policy Set to Quarantine",
                        severidad="LOW",
                        componente="DMARC",
                        descripcion="DMARC tiene politica 'quarantine'. Los emails fallidos van "
                                   "a spam pero no son rechazados completamente.",
                        evidencia=record[:150],
                        recomendacion="Considerar cambiar a p=reject para mayor seguridad.",
                        cvss_estimate="2.0",
                    )
                    self._add_finding(finding)
                    return None

        if not dmarc_found:
            finding = Finding(
                id=self._next_id(),
                nombre="DMARC Record Missing",
                severidad="HIGH",
                componente="DMARC",
                descripcion="No se encontro registro DMARC para el dominio. "
                           "Sin DMARC, los receptores de email no tienen instrucciones sobre "
                           "como manejar emails que fallen SPF/DKIM.",
                evidencia=f"No se encontro registro TXT en {dmarc_domain} con v=DMARC1",
                recomendacion="Crear registro DMARC: v=DMARC1; p=reject; rua=mailto:dmarc@dominio.com; "
                             "ruf=mailto:forensics@dominio.com",
                cvss_estimate="5.3",
            )
            self._add_finding(finding)
            return finding

        return None

    def check_dkim(self) -> Optional[Finding]:
        """Verifica si DKIM esta configurado"""
        selectors = ['default', 'google', 'selector1', 'selector2', 'mail', 'dkim']
        dkim_found = False

        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{self.dominio}"
            records = self.resolver.resolver_registro(dkim_domain, 'TXT')
            for record in records:
                if 'v=DKIM1' in record or 'k=rsa' in record or 'p=' in record:
                    dkim_found = True
                    break
            if dkim_found:
                break

        if not dkim_found:
            finding = Finding(
                id=self._next_id(),
                nombre="DKIM Record Not Found",
                severidad="MEDIUM",
                componente="DKIM",
                descripcion="No se encontraron registros DKIM con los selectores comunes. "
                           "Sin DKIM, los emails no tienen firma criptografica que verifique "
                           "su autenticidad e integridad.",
                evidencia=f"Selectores probados: {', '.join(selectors)}",
                recomendacion="Configurar DKIM generando un par de claves y publicando "
                             "el registro TXT en <selector>._domainkey.dominio.com",
                cvss_estimate="4.0",
            )
            self._add_finding(finding)
            return finding

        return None

    def run_email_security(self):
        """Ejecuta todos los checks de seguridad de email"""
        print(f"\n  [*] Verificando seguridad de email...")
        self.check_spf()
        self.check_dmarc()
        self.check_dkim()

    def run_all(self) -> List[Finding]:
        """Ejecuta todas las verificaciones de vulnerabilidades"""
        print(f"\n[+] Analisis de vulnerabilidades DNS para {self.dominio}")
        print("-" * 60)

        self.check_axfr()
        self.check_dnssec()
        self.run_email_security()

        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severidad, 99))

        if self.findings:
            print(f"\n  [+] Total vulnerabilidades encontradas: {len(self.findings)}")
            counts = {}
            for f in self.findings:
                counts[f.severidad] = counts.get(f.severidad, 0) + 1
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in counts:
                    print(f"      {sev}: {counts[sev]}")
        else:
            print(f"\n  [+] No se encontraron vulnerabilidades")

        return self.findings

    def get_summary(self) -> Dict:
        """Retorna resumen de vulnerabilidades"""
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for f in self.findings:
            if f.severidad in counts:
                counts[f.severidad] += 1
        return {
            'total': len(self.findings),
            'critical': counts['CRITICAL'],
            'high': counts['HIGH'],
            'medium': counts['MEDIUM'],
            'low': counts['LOW'],
            'info': counts['INFO'],
        }
