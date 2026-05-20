"""
Módulo para generar reportes en diferentes formatos
"""

import json
import csv
import os
from typing import Dict, List
from datetime import datetime


class Reporter:
    """Generador de reportes"""

    @staticmethod
    def guardar_json(resultados: Dict, archivo: str):
        try:
            with open(archivo, 'w') as f:
                json.dump(resultados, f, indent=2, default=str)
            print(f"[OK] JSON guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar JSON: {e}")

    @staticmethod
    def guardar_csv(subdominios: List[Dict], archivo: str):
        try:
            with open(archivo, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Subdominio', 'IP'])
                for sub in subdominios:
                    for ip in sub['ips']:
                        writer.writerow([sub['dominio'], ip])
            print(f"[OK] CSV guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar CSV: {e}")

    @staticmethod
    def guardar_html(resultados: Dict, archivo: str):
        dominio = resultados.get('dominio', 'unknown')
        fecha = resultados.get('fecha', datetime.now().isoformat())
        basicos = resultados.get('basicos', {})
        subdominios = resultados.get('subdominios', [])
        axfr = resultados.get('axfr', False)
        axfr_records = resultados.get('axfr_records', [])

        registros_html = ""
        for tipo, valores in basicos.items():
            if valores:
                registros_html += f"            <h3>{tipo}</h3>\n            <table>\n"
                for valor in valores:
                    registros_html += f"                <tr><td>{valor}</td></tr>\n"
                registros_html += "            </table>\n"

        subdominios_html = ""
        for sub in subdominios:
            ips = ', '.join(sub['ips'])
            subdominios_html += f"                <tr><td>{sub['dominio']}</td><td>{ips}</td></tr>\n"

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
        td {{ padding: 0.75rem; border-bottom: 1px solid #334155; }}
        tr:hover {{ background: #334155; }}
        .badge {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }}
        .badge-success {{ background: #065f46; color: #6ee7b7; }}
        .badge-danger {{ background: #7f1d1d; color: #fca5a5; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
        .stat {{ background: #1e293b; padding: 1.5rem; border-radius: 8px; text-align: center; }}
        .stat-number {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
        .stat-label {{ color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }}
        code {{ background: #334155; padding: 0.125rem 0.5rem; border-radius: 4px; font-size: 0.875rem; }}
        .footer {{ text-align: center; color: #64748b; margin-top: 3rem; padding: 1rem; font-size: 0.875rem; }}
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
                <div class="stat-label">Subdominios</div>
            </div>
            <div class="stat">
                <div class="stat-number">{'SI' if axfr else 'NO'}</div>
                <div class="stat-label">AXFR Exitoso</div>
            </div>
        </div>

        <h2>Registros DNS</h2>
        <div class="card">
{registros_html}        </div>

        <h2>Subdominios Encontrados</h2>
        <div class="card">
            <table>
                <tr><th>Subdominio</th><th>Direcciones IP</th></tr>
{subdominios_html}            </table>
        </div>
{axfr_html}
        <div class="footer">
            <p>DNSTRACKING - Escaner DNS | Reporte generado automaticamente</p>
        </div>
    </div>
</body>
</html>"""

        try:
            with open(archivo, 'w') as f:
                f.write(html)
            print(f"[OK] HTML guardado: {archivo}")
        except Exception as e:
            print(f"[-] Error al guardar HTML: {e}")

    @staticmethod
    def guardar_todos(resultados: Dict, dominio: str, output_dir: str = 'output'):
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        json_path = os.path.join(output_dir, f"{dominio}_{timestamp}.json")
        csv_path = os.path.join(output_dir, f"{dominio}_{timestamp}.csv")
        html_path = os.path.join(output_dir, f"{dominio}_{timestamp}.html")

        Reporter.guardar_json(resultados, json_path)

        subdominios = resultados.get('subdominios', [])
        if subdominios:
            Reporter.guardar_csv(subdominios, csv_path)

        Reporter.guardar_html(resultados, html_path)
