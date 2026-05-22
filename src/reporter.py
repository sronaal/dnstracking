"""
Modulo para generar reportes en diferentes formatos
Los resultados se guardan en resultados/<dominio>/ con timestamp
"""

import json
import csv
import os
from typing import Dict, List
from datetime import datetime


class Reporter:
    """Generador de reportes"""

    @staticmethod
    def _crear_dir_dominio(dominio: str, base_dir: str = 'resultados') -> str:
        """Crea la carpeta del dominio dentro de resultados/"""
        dominio_limpio = dominio.rstrip('.').replace('/', '_').replace('\\', '_')
        directorio = os.path.join(base_dir, dominio_limpio)
        os.makedirs(directorio, exist_ok=True)
        return directorio

    @staticmethod
    def guardar_json(resultados: Dict, archivo: str):
        try:
            directorio = os.path.dirname(archivo)
            if directorio:
                os.makedirs(directorio, exist_ok=True)
            with open(archivo, 'w') as f:
                json.dump(resultados, f, indent=2, default=str)
            print(f"[OK] JSON guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar JSON: {e}")

    @staticmethod
    def guardar_txt(resultados: Dict, archivo: str):
        """Genera reporte en texto plano con formato claro"""
        try:
            directorio = os.path.dirname(archivo)
            if directorio:
                os.makedirs(directorio, exist_ok=True)

            dominio = resultados.get('dominio', 'unknown')
            fecha = resultados.get('fecha', datetime.now().isoformat())
            basicos = resultados.get('basicos', {})
            subdominios = resultados.get('subdominios', [])
            subdominios_pasivos = resultados.get('subdominios_pasivos', [])
            axfr = resultados.get('axfr', False)
            axfr_records = resultados.get('axfr_records', [])
            reverse = resultados.get('reverse_lookups', {})
            stats = resultados.get('estadisticas', {})
            vulns = resultados.get('vulnerabilidades', [])
            vuln_summary = resultados.get('resumen_vulnerabilidades', {})
            whois = resultados.get('whois', {})
            geo = resultados.get('geo', [])
            certificados = resultados.get('certificados', [])

            lineas = []
            lineas.append("=" * 70)
            lineas.append(f"  DNSTRACKING - Reporte DNS")
            lineas.append(f"  Dominio: {dominio}")
            lineas.append(f"  Fecha: {fecha}")
            lineas.append("=" * 70)
            lineas.append("")

            lineas.append("-" * 70)
            lineas.append("  REGISTROS DNS")
            lineas.append("-" * 70)
            for tipo, valores in basicos.items():
                if valores:
                    lineas.append(f"\n  [{tipo}]")
                    for valor in valores:
                        lineas.append(f"    {valor}")
            lineas.append("")

            lineas.append("-" * 70)
            lineas.append(f"  SUBDOMINIOS ACTIVOS ({len(subdominios)})")
            lineas.append("-" * 70)
            if subdominios:
                lineas.append("")
                lineas.append(f"  {'Subdominio':<45} {'IPs':<30} {'Fuente'}")
                lineas.append(f"  {'-'*45} {'-'*30} {'-'*10}")
                for sub in subdominios:
                    ips = ', '.join(sub.get('ips', []))
                    fuentes = ', '.join(sub.get('fuentes', ['activo']))
                    lineas.append(f"  {sub['dominio']:<45} {ips:<30} {fuentes}")
            else:
                lineas.append("\n  No se encontraron subdominios")
            lineas.append("")

            if subdominios_pasivos:
                lineas.append("-" * 70)
                lineas.append(f"  SUBDOMINIOS PASIVOS ({len(subdominios_pasivos)})")
                lineas.append("-" * 70)
                lineas.append("")
                lineas.append(f"  {'Subdominio':<45} {'IPs':<30} {'Fuente'}")
                lineas.append(f"  {'-'*45} {'-'*30} {'-'*10}")
                for sub in subdominios_pasivos:
                    ips = ', '.join(sub.get('ips', []))
                    fuentes = ', '.join(sub.get('fuentes', []))
                    lineas.append(f"  {sub['dominio']:<45} {ips:<30} {fuentes}")
                lineas.append("")

            if axfr and axfr_records:
                lineas.append("-" * 70)
                lineas.append(f"  TRANSFERENCIA DE ZONA (AXFR) - EXITOSO")
                lineas.append(f"  {len(axfr_records)} registros obtenidos")
                lineas.append("-" * 70)
                for record in axfr_records:
                    lineas.append(f"  {record}")
                lineas.append("")

            reverse_exitosos = {k: v for k, v in reverse.items() if v}
            if reverse_exitosos:
                lineas.append("-" * 70)
                lineas.append(f"  REVERSE LOOKUP ({len(reverse_exitosos)})")
                lineas.append("-" * 70)
                for ip, dom in reverse_exitosos.items():
                    lineas.append(f"  {ip:<20} -> {dom}")
                lineas.append("")

            if whois and whois.get('registrar'):
                lineas.append("-" * 70)
                lineas.append("  WHOIS")
                lineas.append("-" * 70)
                lineas.append(f"  Registrar: {whois.get('registrar', 'N/A')}")
                if whois.get('creacion'):
                    lineas.append(f"  Creacion:  {whois['creacion']}")
                if whois.get('expiracion'):
                    lineas.append(f"  Expira:    {whois['expiracion']}")
                if whois.get('name_servers'):
                    lineas.append(f"  NS:        {', '.join(whois['name_servers'][:5])}")
                if whois.get('estado'):
                    lineas.append(f"  Estado:    {whois['estado']}")
                lineas.append("")

            if certificados:
                lineas.append("-" * 70)
                lineas.append(f"  CERTIFICADOS SSL/TLS ({len(certificados)})")
                lineas.append("-" * 70)
                lineas.append("")
                lineas.append(f"  {'Host':<40} {'Dias':<10} {'Emisor'}")
                lineas.append(f"  {'-'*40} {'-'*10} {'-'*30}")
                for cert in certificados:
                    dias = cert.get('dias_restantes', '?')
                    estado = 'VENCIDO' if cert.get('expirado') else f'{dias}'
                    emisor = cert.get('emisor', {}).get('organizationName', '?')
                    lineas.append(f"  {cert['hostname']:<40} {estado:<10} {emisor[:30]}")
                lineas.append("")

            if geo:
                lineas.append("-" * 70)
                lineas.append(f"  GEOLOCALIZACION ({len(geo)} IPs)")
                lineas.append("-" * 70)
                lineas.append("")
                lineas.append(f"  {'IP':<18} {'Pais':<20} {'ASN':<20} {'ISP'}")
                lineas.append(f"  {'-'*18} {'-'*20} {'-'*20} {'-'*30}")
                for g in geo:
                    pais = g.get('pais', '?') or '?'
                    asn = g.get('asn', '?') or '?'
                    isp = (g.get('isp', '?') or '?')[:30]
                    lineas.append(f"  {g['ip']:<18} {pais:<20} {asn:<20} {isp}")
                lineas.append("")

            if vulns:
                lineas.append("=" * 70)
                lineas.append("  VULNERABILIDADES")
                lineas.append("=" * 70)
                lineas.append("")
                if vuln_summary:
                    lineas.append(f"  Total: {vuln_summary.get('total', 0)}")
                    lineas.append(f"  Critical: {vuln_summary.get('critical', 0)}")
                    lineas.append(f"  High: {vuln_summary.get('high', 0)}")
                    lineas.append(f"  Medium: {vuln_summary.get('medium', 0)}")
                    lineas.append(f"  Low: {vuln_summary.get('low', 0)}")
                    lineas.append(f"  Info: {vuln_summary.get('info', 0)}")
                    lineas.append("")

                for vuln in vulns:
                    sev = vuln.get('severidad', 'UNKNOWN')
                    icon = {'CRITICAL': '[!!!]', 'HIGH': '[!!]', 'MEDIUM': '[!]', 'LOW': '[~]', 'INFO': '[i]'}.get(sev, '[?]')
                    lineas.append(f"  {icon} [{sev}] {vuln.get('id', '')} - {vuln.get('nombre', '')}")
                    lineas.append(f"      Componente: {vuln.get('componente', '')}")
                    lineas.append(f"      Descripcion: {vuln.get('descripcion', '')}")
                    lineas.append(f"      Evidencia: {vuln.get('evidencia', '')}")
                    lineas.append(f"      Recomendacion: {vuln.get('recomendacion', '')}")
                    lineas.append(f"      CVSS: {vuln.get('cvss_estimate', 'N/A')}")
                    lineas.append("")

            lineas.append("=" * 70)
            lineas.append("  ESTADISTICAS")
            lineas.append("=" * 70)
            lineas.append(f"  Registros DNS encontrados:    {sum(1 for v in basicos.values() if v)} tipos")
            lineas.append(f"  Subdominios activos:          {len(subdominios)}")
            lineas.append(f"  Subdominios pasivos:          {len(subdominios_pasivos)}")
            lineas.append(f"  Total subdominios:            {len(subdominios) + len(subdominios_pasivos)}")
            lineas.append(f"  AXFR:                         {'EXITOSO' if axfr else 'No permitido'}")
            lineas.append(f"  Reverse lookups exitosos:     {len(reverse_exitosos)}")

            ips_unicas = set()
            for sub in subdominios:
                ips_unicas.update(sub.get('ips', []))
            lineas.append(f"  IPs unicas:                   {len(ips_unicas)}")

            if stats.get('permutaciones_generadas', 0) > 0:
                lineas.append(f"  Permutaciones generadas:      {stats['permutaciones_generadas']}")
                lineas.append(f"  Permutaciones nuevas:         {stats.get('permutaciones_nuevas', 0)}")

            if stats.get('tiempos_fases'):
                lineas.append("")
                lineas.append("  Tiempos por fase:")
                for fase, tiempo in stats['tiempos_fases'].items():
                    lineas.append(f"    {fase:<35} {tiempo:.2f}s")

            if stats.get('tiempo_total'):
                lineas.append(f"\n  TIEMPO TOTAL:                 {stats['tiempo_total']:.2f}s")

            if stats.get('wildcard_detectado'):
                lineas.append(f"  Wildcard DNS:                 Detectado y filtrado")

            lineas.append("")
            lineas.append("=" * 70)
            lineas.append(f"  DNSTRACKING - Escaner DNS")
            lineas.append(f"  Reporte generado automaticamente")
            lineas.append("=" * 70)

            with open(archivo, 'w') as f:
                f.write('\n'.join(lineas))
            print(f"[OK] TXT guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar TXT: {e}")

    @staticmethod
    def guardar_csv(subdominios: List[Dict], archivo: str):
        try:
            directorio = os.path.dirname(archivo)
            if directorio:
                os.makedirs(directorio, exist_ok=True)
            with open(archivo, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdominio', 'IP', 'Fuente'])
                for sub in subdominios:
                    for ip in sub.get('ips', []):
                        fuentes = ', '.join(sub.get('fuentes', ['activo']))
                        writer.writerow([sub['dominio'], ip, fuentes])
            print(f"[OK] CSV guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar CSV: {e}")

    @staticmethod
    def guardar_html(resultados: Dict, archivo: str):
        dominio = resultados.get('dominio', 'unknown')
        fecha = resultados.get('fecha', datetime.now().isoformat())
        basicos = resultados.get('basicos', {})
        subdominios = resultados.get('subdominios', [])
        subdominios_pasivos = resultados.get('subdominios_pasivos', [])
        axfr = resultados.get('axfr', False)
        axfr_records = resultados.get('axfr_records', [])
        reverse = resultados.get('reverse_lookups', {})
        stats = resultados.get('estadisticas', {})
        vulns = resultados.get('vulnerabilidades', [])
        vuln_summary = resultados.get('resumen_vulnerabilidades', {})
        whois = resultados.get('whois', {})
        geo = resultados.get('geo', [])
        certificados = resultados.get('certificados', [])

        registros_html = ""
        for tipo, valores in basicos.items():
            if valores:
                registros_html += f"            <h3>{tipo}</h3>\n            <table>\n"
                for valor in valores:
                    display = valor[:120] + "..." if len(valor) > 120 else valor
                    registros_html += f"                <tr><td>{display}</td></tr>\n"
                registros_html += "            </table>\n"

        subdominios_html = ""
        for sub in subdominios:
            ips = ', '.join(sub.get('ips', []))
            fuentes = ', '.join(sub.get('fuentes', ['activo']))
            subdominios_html += f"                <tr><td>{sub['dominio']}</td><td>{ips}</td><td>{fuentes}</td></tr>\n"

        subdominios_pasivos_html = ""
        if subdominios_pasivos:
            for sub in subdominios_pasivos:
                ips = ', '.join(sub.get('ips', []))
                fuentes = ', '.join(sub.get('fuentes', []))
                subdominios_pasivos_html += f"                <tr><td>{sub['dominio']}</td><td>{ips}</td><td>{fuentes}</td></tr>\n"

        reverse_html = ""
        reverse_exitosos = {k: v for k, v in reverse.items() if v}
        if reverse_exitosos:
            for ip, dom in reverse_exitosos.items():
                reverse_html += f"                <tr><td>{ip}</td><td>{dom}</td></tr>\n"

        vulns_html = ""
        if vulns:
            vulns_html += """
        <h2>Vulnerabilidades Encontradas</h2>
        <div class="card">
"""
            if vuln_summary:
                vulns_html += f"""
            <div class="stats">
                <div class="stat">
                    <div class="stat-number">{vuln_summary.get('total', 0)}</div>
                    <div class="stat-label">Total</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #f87171;">{vuln_summary.get('critical', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #fb923c;">{vuln_summary.get('high', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #fbbf24;">{vuln_summary.get('medium', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat">
                    <div class="stat-number" style="color: #34d399;">{vuln_summary.get('low', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
            </div>
"""
            vulns_html += """
            <table>
                <tr><th>ID</th><th>Severidad</th><th>Nombre</th><th>Componente</th><th>CVSS</th></tr>
"""
            for vuln in vulns:
                sev = vuln.get('severidad', 'UNKNOWN')
                badge_class = {
                    'CRITICAL': 'badge-danger',
                    'HIGH': 'badge-high',
                    'MEDIUM': 'badge-medium',
                    'LOW': 'badge-low',
                    'INFO': 'badge-info',
                }.get(sev, 'badge-info')
                vulns_html += f"""                <tr>
                    <td>{vuln.get('id', '')}</td>
                    <td><span class="badge {badge_class}">{sev}</span></td>
                    <td>{vuln.get('nombre', '')}</td>
                    <td>{vuln.get('componente', '')}</td>
                    <td>{vuln.get('cvss_estimate', 'N/A')}</td>
                </tr>
"""
            vulns_html += """            </table>
        </div>

        <h2>Detalle de Vulnerabilidades</h2>
"""
            for vuln in vulns:
                sev = vuln.get('severidad', 'UNKNOWN')
                badge_class = {
                    'CRITICAL': 'badge-danger',
                    'HIGH': 'badge-high',
                    'MEDIUM': 'badge-medium',
                    'LOW': 'badge-low',
                    'INFO': 'badge-info',
                }.get(sev, 'badge-info')
                vulns_html += f"""
        <div class="card">
            <h3><span class="badge {badge_class}">{sev}</span> {vuln.get('id', '')} - {vuln.get('nombre', '')}</h3>
            <p><strong>Componente:</strong> {vuln.get('componente', '')}</p>
            <p><strong>Descripcion:</strong> {vuln.get('descripcion', '')}</p>
            <p><strong>Evidencia:</strong> <code>{vuln.get('evidencia', '')}</code></p>
            <p><strong>Recomendacion:</strong> {vuln.get('recomendacion', '')}</p>
            <p><strong>CVSS Estimate:</strong> {vuln.get('cvss_estimate', 'N/A')}</p>
        </div>
"""

        axfr_html = ""
        if axfr and axfr_records:
            axfr_rows = ""
            for record in axfr_records[:100]:
                axfr_rows += f"                <tr><td><code>{record}</code></td></tr>\n"
            extra = f" y {len(axfr_records) - 100} mas" if len(axfr_records) > 100 else ""
            axfr_html = f"""
        <h2>Transferencia de Zona (AXFR) <span class="badge badge-success">EXITOSO</span></h2>
        <div class="card">
            <p>{len(axfr_records)} registros obtenidos</p>
            <table>
                <tr><th>Registro</th></tr>
{axfr_rows}                <tr><td>...{extra}</td></tr>
            </table>
        </div>
"""

        num_registros = len([t for t, v in basicos.items() if v])
        total_subdominios = len(subdominios) + len(subdominios_pasivos)
        tiempo_total = stats.get('tiempo_total', 0)

        ips_unicas = set()
        for sub in subdominios:
            ips_unicas.update(sub.get('ips', []))

        tiempos_html = ""
        if stats.get('tiempos_fases'):
            for fase, tiempo in stats['tiempos_fases'].items():
                tiempos_html += f"                <tr><td>{fase}</td><td>{tiempo:.2f}s</td></tr>\n"

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNSTRACKING - Reporte DNS: {dominio}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #38bdf8; font-size: 2rem; margin-bottom: 0.5rem; }}
        h2 {{ color: #38bdf8; font-size: 1.5rem; margin: 2rem 0 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }}
        h3 {{ color: #94a3b8; font-size: 1.1rem; margin: 1rem 0 0.5rem; }}
        .header {{ background: #1e293b; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }}
        .header p {{ color: #94a3b8; margin-top: 0.5rem; }}
        .card {{ background: #1e293b; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th {{ background: #334155; color: #38bdf8; padding: 0.75rem; text-align: left; font-weight: 600; }}
        td {{ padding: 0.75rem; border-bottom: 1px solid #334155; word-break: break-all; }}
        tr:hover {{ background: #334155; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
        .badge-success {{ background: #065f46; color: #6ee7b7; }}
        .badge-danger {{ background: #7f1d1d; color: #fca5a5; }}
        .badge-high {{ background: #7c2d12; color: #fdba74; }}
        .badge-medium {{ background: #713f12; color: #fde047; }}
        .badge-low {{ background: #14532d; color: #86efac; }}
        .badge-info {{ background: #1e3a5f; color: #93c5fd; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
        .stat-label {{ color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }}
        code {{ background: #334155; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.875rem; }}
        .footer {{ text-align: center; color: #64748b; margin-top: 3rem; padding: 1rem; font-size: 0.875rem; }}
        .source-badge {{ background: #1e3a5f; color: #93c5fd; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>DNS Report: {dominio}</h1>
            <p>Generado por DNSTRACKING el {fecha}</p>
        </div>

        <div class="stats">
            <div class="stat">
                <div class="stat-number">{num_registros}</div>
                <div class="stat-label">Tipos de Registro</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(subdominios)}</div>
                <div class="stat-label">Subdominios Activos</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(subdominios_pasivos)}</div>
                <div class="stat-label">Subdominios Pasivos</div>
            </div>
            <div class="stat">
                <div class="stat-number">{len(ips_unicas)}</div>
                <div class="stat-label">IPs Unicas</div>
            </div>
            <div class="stat">
                <div class="stat-number">{'SI' if axfr else 'NO'}</div>
                <div class="stat-label">AXFR Exitoso</div>
            </div>
            <div class="stat">
                <div class="stat-number">{tiempo_total:.1f}s</div>
                <div class="stat-label">Tiempo Total</div>
            </div>
        </div>

        <h2>Registros DNS</h2>
        <div class="card">
{registros_html}        </div>

        <h2>Subdominios Activos</h2>
        <div class="card">
            <table>
                <tr><th>#</th><th>Subdominio</th><th>Direcciones IP</th><th>Fuente</th></tr>
"""

        for i, sub in enumerate(subdominios, 1):
            ips = ', '.join(sub.get('ips', []))
            fuentes = ', '.join(sub.get('fuentes', ['activo']))
            html += f"                <tr><td>{i}</td><td>{sub['dominio']}</td><td>{ips}</td><td><span class='source-badge'>{fuentes}</span></td></tr>\n"

        html += """            </table>
        </div>
"""

        if subdominios_pasivos:
            html += f"""
        <h2>Subdominios Pasivos (APIs externas)</h2>
        <div class="card">
            <table>
                <tr><th>#</th><th>Subdominio</th><th>Direcciones IP</th><th>Fuente</th></tr>
"""
            for i, sub in enumerate(subdominios_pasivos, 1):
                ips = ', '.join(sub.get('ips', []))
                fuentes = ', '.join(sub.get('fuentes', []))
                html += f"                <tr><td>{i}</td><td>{sub['dominio']}</td><td>{ips}</td><td><span class='source-badge'>{fuentes}</span></td></tr>\n"

            html += """            </table>
        </div>
"""

        if reverse_exitosos:
            html += """
        <h2>Reverse Lookup</h2>
        <div class="card">
            <table>
                <tr><th>IP</th><th>Dominio</th></tr>
"""
            for ip, dom in reverse_exitosos.items():
                html += f"                <tr><td>{ip}</td><td>{dom}</td></tr>\n"
            html += """            </table>
        </div>
"""

        whois_html = ""
        if whois and whois.get('registrar'):
            whois_html = f"""
        <h2>WHOIS</h2>
        <div class="card">
            <table>
                <tr><th>Campo</th><th>Valor</th></tr>
                <tr><td>Registrar</td><td>{whois.get('registrar', 'N/A')}</td></tr>
"""
            if whois.get('creacion'):
                whois_html += f"                <tr><td>Creacion</td><td>{whois['creacion']}</td></tr>\n"
            if whois.get('expiracion'):
                whois_html += f"                <tr><td>Expira</td><td>{whois['expiracion']}</td></tr>\n"
            if whois.get('name_servers'):
                whois_html += f"                <tr><td>Name Servers</td><td>{', '.join(whois['name_servers'][:5])}</td></tr>\n"
            if whois.get('estado'):
                whois_html += f"                <tr><td>Estado</td><td>{whois['estado']}</td></tr>\n"
            whois_html += """            </table>
        </div>
"""

        cert_html = ""
        if certificados:
            cert_html = """
        <h2>Certificados SSL/TLS</h2>
        <div class="card">
            <table>
                <tr><th>Host</th><th>Dias</th><th>Emisor</th><th>SANs</th></tr>
"""
            for cert in certificados[:50]:
                dias = cert.get('dias_restantes', '?')
                if cert.get('expirado'):
                    badge = '<span class="badge badge-danger">VENCIDO</span>'
                elif dias is not None and dias < 7:
                    badge = f'<span class="badge badge-danger">{dias}</span>'
                elif dias is not None and dias < 30:
                    badge = f'<span class="badge badge-high">{dias}</span>'
                else:
                    badge = f'<span class="badge badge-low">{dias}</span>'
                emisor = cert.get('emisor', {}).get('organizationName', '')
                sans = ', '.join(cert.get('sans', [])[:3])
                sans += '...' if len(cert.get('sans', [])) > 3 else ''
                cert_html += f"""                <tr>
                    <td>{cert['hostname']}</td>
                    <td>{badge}</td>
                    <td>{emisor}</td>
                    <td>{sans}</td>
                </tr>
"""
            cert_html += """            </table>
        </div>
"""

        geo_html = ""
        if geo:
            geo_rows = ""
            for g in geo[:30]:
                geo_rows += f"""                <tr>
                    <td>{g['ip']}</td>
                    <td>{g.get('pais', '?')}</td>
                    <td>{g.get('asn', '?')}</td>
                    <td>{g.get('isp', '?')}</td>
                </tr>
"""
            geo_html = f"""
        <h2>Geolocalizacion</h2>
        <div class="card">
            <table>
                <tr><th>IP</th><th>Pais</th><th>ASN</th><th>ISP</th></tr>
{geo_rows}            </table>
        </div>
"""

        html += f"""
{whois_html}
{cert_html}
{geo_html}
{vulns_html}
{axfr_html}
"""

        if tiempos_html:
            html += f"""
        <h2>Estadisticas de Ejecucion</h2>
        <div class="card">
            <table>
                <tr><th>Fase</th><th>Tiempo</th></tr>
{tiempos_html}            </table>
        </div>
"""

        html += f"""
        <div class="footer">
            <p>DNSTRACKING - Escaner DNS | Reporte generado automaticamente</p>
        </div>
    </div>
</body>
</html>"""

        try:
            directorio = os.path.dirname(archivo)
            if directorio:
                os.makedirs(directorio, exist_ok=True)
            with open(archivo, 'w') as f:
                f.write(html)
            print(f"[OK] HTML guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar HTML: {e}")

    @staticmethod
    def guardar_todos(resultados: Dict, dominio: str, base_dir: str = 'resultados'):
        """Guarda todos los formatos en resultados/<dominio>/"""
        directorio = Reporter._crear_dir_dominio(dominio, base_dir)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        json_path = os.path.join(directorio, f"scan_{timestamp}.json")
        txt_path = os.path.join(directorio, f"scan_{timestamp}.txt")
        csv_path = os.path.join(directorio, f"subdominios_{timestamp}.csv")
        html_path = os.path.join(directorio, f"reporte_{timestamp}.html")

        Reporter.guardar_json(resultados, json_path)
        Reporter.guardar_txt(resultados, txt_path)
        Reporter.guardar_html(resultados, html_path)

        subdominios = resultados.get('subdominios', [])
        subdominios_pasivos = resultados.get('subdominios_pasivos', [])
        todos_subs = subdominios + subdominios_pasivos
        if todos_subs:
            Reporter.guardar_csv(todos_subs, csv_path)

        print(f"\n[OK] Resultados guardados en: {directorio}/")
        return directorio
