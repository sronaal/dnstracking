"""
Modulo de deteccion de vulnerabilidades DNS
Analiza la configuracion DNS en busca de problemas de seguridad
"""

import re
import ipaddress
import requests
import dns.resolver
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from color_util import severidad_color


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

    TAKEOVER_FINGERPRINTS = {
        'AWS S3': {
            'pattern': r'\.s3(?:-website)?[.-](?:[a-z0-9-]+\.)?amazonaws\.com',
            'indicators': ['NoSuchBucket', 'The specified bucket does not exist', 'All access to this Amazon S3 will be denied'],
            'risk': 'Un bucket S3 no reclamado puede ser registrado por un atacante',
        },
        'GitHub Pages': {
            'pattern': r'\.github\.io',
            'indicators': ['There isn\'t a GitHub Pages site here', '404 Not Found', 'For more information', 'If you\'re using a custom domain'],
            'risk': 'Una pagina de GitHub no configurada puede ser reclamada',
        },
        'Heroku': {
            'pattern': r'\.herokuapp\.com',
            'indicators': ['no such app', 'There\'s nothing here', 'Application not found', 'herokucdn.com/error-pages/no-such-app.html'],
            'risk': 'Una app de Heroku eliminada puede ser registrada por otro usuario',
        },
        'Azure': {
            'pattern': r'\.azurewebsites\.net',
            'indicators': ['404 Web Site not found', 'The Web App you are attempting to access is not available'],
            'risk': 'Un Azure Web App eliminado puede ser reclamado',
        },
        'Bitbucket': {
            'pattern': r'\.bitbucket\.io',
            'indicators': ['Repository not found', 'The page you have requested does not exist'],
            'risk': 'Un repositorio Bitbucket eliminado puede ser reclamado',
        },
        'Shopify': {
            'pattern': r'\.myshopify\.com',
            'indicators': ['Sorry, this shop is currently unavailable', 'Only one step left!'],
            'risk': 'Una tienda Shopify abandonada puede ser reclamada',
        },
        'Ghost': {
            'pattern': r'\.ghost\.io',
            'indicators': ['The thing you were looking for is no longer here', '404'],
            'risk': 'Un blog Ghost abandonado puede ser reclamado',
        },
        'Zendesk': {
            'pattern': r'\.zendesk\.com',
            'indicators': ['Help Center is not available', 'this help center no longer exists'],
            'risk': 'Un subdominio Zendesk puede ser reclamado',
        },
        'Surge.sh': {
            'pattern': r'\.surge\.sh',
            'indicators': ['project not found', 'You need to sign up or sign in before continuing'],
            'risk': 'Un proyecto Surge abandonado puede ser reclamado',
        },
        'Netlify': {
            'pattern': r'\.netlify\.app',
            'indicators': ['Not Found', 'Page not found', 'The page you are looking for could not be found'],
            'risk': 'Un sitio Netlify eliminado puede ser reclamado',
        },
        'Tumblr': {
            'pattern': r'\.tumblr\.com',
            'indicators': ['There\'s nothing here', 'Whatever you were looking for doesn\'t currently exist'],
            'risk': 'Un blog Tumblr abandonado puede ser reclamado',
        },
        'WordPress.com': {
            'pattern': r'\.wordpress\.com',
            'indicators': ['Do you want to register', 'This domain is not mapped', 'This blog does not exist'],
            'risk': 'Un blog WordPress abandonado puede ser reclamado',
        },
        'Teamwork': {
            'pattern': r'\.teamwork\.com',
            'indicators': ['Oops - We didn\'t find your site', 'This account is no longer available'],
            'risk': 'Un espacio Teamwork abandonado puede ser reclamado',
        },
        'Helpjuice': {
            'pattern': r'\.helpjuice\.com',
            'indicators': ['We could not find what you\'re looking for'],
            'risk': 'Un Help Center Helpjuice abandonado puede ser reclamado',
        },
        'Campaign Monitor': {
            'pattern': r'\.campaignmonitor\.com',
            'indicators': ['Double check the URL', 'Attempting to access a deactivated account'],
            'risk': 'Una cuenta Campaign Monitor puede ser reclamada',
        },
        'Intercom': {
            'pattern': r'\.custom\.intercom\.help',
            'indicators': ['This page is reserved for artistic dogs', 'Uh oh. That page doesn\'t exist'],
            'risk': 'Una pagina Intercom abandonada puede ser reclamada',
        },
        'Webflow': {
            'pattern': r'\.(webflow\.io|webflow\.com)',
            'indicators': ['404 - Page not found', 'The page you are looking for doesn\'t exist'],
            'risk': 'Un sitio Webflow eliminado puede ser reclamado',
        },
        'SmugMug': {
            'pattern': r'\.smugmug\.com',
            'indicators': ['SmugMug is a paid service'],
            'risk': 'Un sitio SmugMug abandonado puede ser reclamado',
        },
        'Strikingly': {
            'pattern': r'\.strikinglydns\.com|\.strikingly\.com',
            'indicators': ['But if you\'re looking to build your own website', 'The site you are looking for no longer exists'],
            'risk': 'Un sitio Strikingly abandonado puede ser reclamado',
        },
        'UptimeRobot': {
            'pattern': r'\.uptimerobot\.com',
            'indicators': ['This public status page is no longer available'],
            'risk': 'Una status page de UptimeRobot puede ser reclamada',
        },
    }

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
        icon = severidad_color(finding.severidad)
        print(f"  {icon} {finding.nombre}")
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

    def _check_subdomain_takeover(self, subdominio: str, cname_chain: List[str]) -> Optional[Finding]:
        """Verifica si un subdominio con CNAME es vulnerable a takeover"""
        for cname in cname_chain:
            cname_lower = cname.lower()
            for service, config in self.TAKEOVER_FINGERPRINTS.items():
                if re.search(config['pattern'], cname_lower):
                    try:
                        resp = requests.get(f"http://{subdominio}", timeout=5, allow_redirects=True)
                        body = resp.text.lower()
                        status = resp.status_code

                        for indicator in config['indicators']:
                            if indicator.lower() in body:
                                return Finding(
                                    id=self._next_id(),
                                    nombre=f"Subdomain Takeover - {service}",
                                    severidad="CRITICAL",
                                    componente="TAKEOVER",
                                    descripcion=f"El subdominio {subdominio} apunta a {cname} "
                                               f"({service}) pero el servicio no esta configurado. "
                                               f"Un atacante puede registrar este servicio y "
                                               f"controlar el subdominio.",
                                    evidencia=f"CNAME: {cname} | HTTP {status} | "
                                             f"Indicator: '{indicator}'",
                                    recomendacion=f"Eliminar el registro DNS o configurar el "
                                                 f"servicio {service} para reclamar {subdominio}.",
                                    cvss_estimate="8.0",
                                )
                    except requests.exceptions.RequestException:
                        pass
        return None

    def check_subdomain_takeover(self) -> List[Finding]:
        """Verifica subdomain takeover en todos los subdominios encontrados"""
        print(f"\n  [*] Verificando subdomain takeover...")
        findings = []
        subdominios = self.resultados.get('subdominios', [])

        vulnerable_count = 0
        checked_count = 0

        for sub in subdominios:
            cname_chain = sub.get('cname_chain', [])
            if not cname_chain:
                continue

            finding = self._check_subdomain_takeover(sub['dominio'], cname_chain)
            checked_count += 1

            if finding:
                self._add_finding(finding)
                findings.append(finding)
                vulnerable_count += 1

        if checked_count > 0:
            print(f"  [+] Takeover check: {checked_count} subdominios con CNAME, "
                  f"{vulnerable_count} vulnerables")
        else:
            print(f"  [+] Takeover check: No se encontraron CNAMEs para verificar")

        return findings

    def check_caa(self) -> Optional[Finding]:
        """Verifica si CAA esta configurado"""
        caa_records = self.resultados.get('basicos', {}).get('CAA', [])

        if not caa_records:
            finding = Finding(
                id=self._next_id(),
                nombre="CAA Record Missing",
                severidad="MEDIUM",
                componente="CAA",
                descripcion="No se encontro registro CAA para el dominio. "
                           "Sin CAA, cualquier autoridad de certificacion puede emitir "
                           "certificados SSL/TLS para este dominio.",
                evidencia="No se encontraron registros CAA",
                recomendacion="Agregar registros CAA para restringir las CAs autorizadas: "
                             "0 issue \"letsencrypt.org\" o 0 issue \"digicert.com\"",
                cvss_estimate="4.0",
            )
            self._add_finding(finding)
            return finding

        return None

    def check_low_ttl(self) -> List[Finding]:
        """Verifica TTLs peligrosamente bajos (riesgo de DNS rebinding)"""
        findings = []
        basicos = self.resultados.get('basicos', {})

        low_ttl_domains = []
        threshold = 300

        for tipo, valores in basicos.items():
            if tipo in ('A', 'AAAA', 'CNAME', 'MX', 'NS'):
                for valor in valores:
                    pass

        ns_servers = basicos.get('NS', [])
        for ns in ns_servers:
            try:
                soa_records = self.resolver.resolver_registro(self.dominio, 'SOA')
                for soa in soa_records:
                    parts = soa.split()
                    if len(parts) >= 5:
                        try:
                            ttl_value = int(parts[3])
                            if ttl_value < threshold:
                                low_ttl_domains.append({
                                    'tipo': 'SOA',
                                    'ttl': ttl_value,
                                    'valor': soa,
                                })
                        except (ValueError, IndexError):
                            pass
            except Exception:
                pass

        for item in low_ttl_domains:
            finding = Finding(
                id=self._next_id(),
                nombre=f"Low TTL Detected ({item['ttl']}s)",
                severidad="LOW",
                componente="TTL",
                descripcion=f"El registro {item['tipo']} tiene un TTL de {item['ttl']} segundos "
                           f"(umbral: {threshold}s). TTLs bajos facilitan ataques de DNS rebinding "
                           f"y aumentan la carga en los servidores DNS.",
                evidencia=f"TTL: {item['ttl']}s | Valor: {item['valor'][:80]}",
                recomendacion="Aumentar el TTL a al menos 300 segundos (5 minutos) para "
                             "registros estaticos. Usar TTLs bajos solo durante migraciones.",
                cvss_estimate="2.0",
            )
            findings.append(finding)
            self._add_finding(finding)

        return findings

    def check_private_ns(self) -> List[Finding]:
        """Verifica si los nameservers apuntan a IPs privadas"""
        findings = []
        ns_records = self.resultados.get('basicos', {}).get('NS', [])

        private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('100.64.0.0/10'),
        ]

        for ns in ns_records:
            ns_clean = ns.rstrip('.')
            try:
                ips = self.resolver.resolver_registro(ns_clean, 'A')
                for ip_str in ips:
                    try:
                        ip = ipaddress.ip_address(ip_str)
                        for network in private_ranges:
                            if ip in network:
                                finding = Finding(
                                    id=self._next_id(),
                                    nombre=f"Private IP in Nameserver ({ns})",
                                    severidad="HIGH",
                                    componente="NS",
                                    descripcion=f"El nameserver {ns} resuelve a una IP privada "
                                               f"({ip_str}). Esto indica una configuracion incorrecta "
                                               f"que puede causar problemas de resolucion externa.",
                                    evidencia=f"NS: {ns} -> {ip_str} (RFC1918/private)",
                                    recomendacion="Usar IPs publicas para los nameservers autoritativos. "
                                                 "Los nameservers deben ser accesibles desde Internet.",
                                    cvss_estimate="5.0",
                                )
                                findings.append(finding)
                                self._add_finding(finding)
                    except ValueError:
                        pass
            except Exception:
                pass

        return findings

    def check_mx_external(self) -> Optional[Finding]:
        """Verifica si los MX apuntan a servicios de email genericos"""
        mx_records = self.resultados.get('basicos', {}).get('MX', [])

        external_services = {
            'google.com': 'Google Workspace',
            'outlook.com': 'Microsoft 365',
            'office365.com': 'Microsoft 365',
            'protection.outlook.com': 'Microsoft 365',
            'mx.hubspot.com': 'HubSpot',
            'zendesk.com': 'Zendesk',
            'freshdesk.com': 'Freshdesk',
            'mail.zoho.com': 'Zoho Mail',
        }

        for mx in mx_records:
            mx_lower = mx.lower()
            for domain, service in external_services.items():
                if domain in mx_lower:
                    finding = Finding(
                        id=self._next_id(),
                        nombre=f"External Email Service ({service})",
                        severidad="INFO",
                        componente="MX",
                        descripcion=f"El dominio usa {service} para el manejo de email "
                                   f"(MX: {mx}). Esto es informativo, no una vulnerabilidad.",
                        evidencia=f"MX: {mx}",
                        recomendacion="Asegurar que SPF, DKIM y DMARC esten correctamente "
                                     "configurados para el servicio de email externo.",
                        cvss_estimate="0.0",
                    )
                    self._add_finding(finding)
                    return finding

        return None

    def check_open_resolver(self) -> List[Finding]:
        """Verifica si los nameservers son resolvers abiertos"""
        findings = []
        ns_records = self.resultados.get('basicos', {}).get('NS', [])

        for ns in ns_records:
            ns_clean = ns.rstrip('.')
            try:
                ips = self.resolver.resolver_registro(ns_clean, 'A')
                for ip_str in ips:
                    try:
                        test_resolver = dns.resolver.Resolver()
                        test_resolver.nameservers = [ip_str]
                        test_resolver.timeout = 3
                        test_resolver.lifetime = 3

                        test_resolver.resolve('google.com', 'A')
                    except Exception:
                        pass
            except Exception:
                pass

        return findings

    def check_amplification(self) -> Optional[Finding]:
        """Verifica el factor de amplificacion DNS"""
        ns_records = self.resultados.get('basicos', {}).get('NS', [])

        if not ns_records:
            return None

        findings = []
        for ns in ns_records:
            ns_clean = ns.rstrip('.')
            try:
                ips = self.resolver.resolver_registro(ns_clean, 'A')
                for ip_str in ips:
                    try:
                        test_resolver = dns.resolver.Resolver()
                        test_resolver.nameservers = [ip_str]
                        test_resolver.timeout = 3
                        test_resolver.lifetime = 3

                        resp = test_resolver.resolve(self.dominio, 'ANY')
                        response_size = sum(len(str(r)) for r in resp)
                        query_size = len(self.dominio) + 4

                        if query_size > 0:
                            amplification_factor = response_size / query_size
                            if amplification_factor > 10:
                                finding = Finding(
                                    id=self._next_id(),
                                    nombre=f"DNS Amplification Risk ({ns})",
                                    severidad="MEDIUM",
                                    componente="AMPLIFICATION",
                                    descripcion=f"El nameserver {ns} responde a consultas ANY con "
                                               f"un factor de amplificacion de {amplification_factor:.1f}x. "
                                               f"Esto puede ser usado para ataques DDoS de amplificacion DNS.",
                                    evidencia=f"NS: {ns} | Query: {query_size} bytes | "
                                             f"Response: {response_size} bytes | "
                                             f"Factor: {amplification_factor:.1f}x",
                                    recomendacion="Deshabilitar respuestas ANY o implementar rate limiting "
                                                 "en el servidor DNS. Usar Response Rate Limiting (RRL).",
                                    cvss_estimate="5.0",
                                )
                                findings.append(finding)
                                self._add_finding(finding)
                    except Exception:
                        pass
            except Exception:
                pass

        return findings if findings else None

    def run_infrastructure(self):
        """Ejecuta todos los checks de infraestructura"""
        print(f"\n  [*] Verificando infraestructura DNS...")
        self.check_caa()
        self.check_low_ttl()
        self.check_private_ns()
        self.check_mx_external()
        self.check_amplification()

    def run_email_security(self):
        """Ejecuta todos los checks de seguridad de email"""
        print(f"\n  [*] Verificando seguridad de email...")
        self.check_spf()
        self.check_dmarc()
        self.check_dkim()

    def run_all(self, check_takeover: bool = True, check_infrastructure: bool = True) -> List[Finding]:
        """Ejecuta todas las verificaciones de vulnerabilidades"""
        print(f"\n[+] Analisis de vulnerabilidades DNS para {self.dominio}")
        print("-" * 60)

        self.check_axfr()
        self.check_dnssec()
        self.run_email_security()

        if check_infrastructure:
            self.run_infrastructure()

        if check_takeover:
            self.check_subdomain_takeover()

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
