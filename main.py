#!/usr/bin/env python3
"""
DNSTRACKING - Escaner DNS de Reconocimiento
Herramienta para auditoria y analisis de infraestructura DNS
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

import click
from colorama import init as colorama_init
from scanner import DNSScanner
from doh_resolver import DohResolver
from reporter import Reporter


@click.command()
@click.argument('dominio')
@click.option('-w', '--wordlist', default=None, help='Archivo con palabras para enumeracion de subdominios')
@click.option('--no-axfr', is_flag=True, help='No intentar transferencia de zona')
@click.option('--no-reverse', is_flag=True, help='No realizar busquedas inversas')
@click.option('-v', '--verbose', is_flag=True, help='Modo verbose')
@click.option('-o', '--output', default='all', type=click.Choice(['txt', 'json', 'csv', 'html', 'ndjson', 'yaml', 'all']), help='Formato de salida (default: all)')
@click.option('--timeout', default=5, type=int, help='Timeout en segundos para consultas DNS')
@click.option('--max-sub', default=None, type=int, help='Limitar numero de subdominios encontrados')
@click.option('--delay', default=0.0, type=float, help='Delay en segundos entre lotes de consultas')
@click.option('--dns-server', default=None, help='Servidor DNS personalizado')
@click.option('-t', '--threads', default=20, type=int, help='Numero de hilos concurrentes (default: 20)')
@click.option('--tipos-dns', default='A', help='Tipos DNS a consultar separados por coma (A,AAAA,CNAME)')
@click.option('--no-wildcard', is_flag=True, help='Desactivar deteccion de wildcards')
@click.option('-p', '--permutations', is_flag=True, help='Generar permutaciones de subdominios encontrados')
@click.option('--passive', is_flag=True, help='Incluir fuentes pasivas (crt.sh, HackerTarget, etc)')
@click.option('--passive-only', is_flag=True, help='Solo fuentes pasivas, sin consultas DNS directas')
@click.option('-d', '--output-dir', default='resultados', help='Directorio base para guardar resultados (default: resultados)')
@click.option('--vulns', is_flag=True, help='Ejecutar analisis de vulnerabilidades DNS')
@click.option('--vulns-only', is_flag=True, help='Solo analisis de vulnerabilidades (sin enumeracion completa)')
@click.option('--no-takeover', is_flag=True, help='Saltar check de subdomain takeover')
@click.option('--no-infra', is_flag=True, help='Saltar checks de infraestructura')
@click.option('--whois', is_flag=True, help='Consultar WHOIS del dominio')
@click.option('--ssl', is_flag=True, help='Inspeccionar certificados SSL/TLS')
@click.option('--geo', is_flag=True, help='Geolocalizar IPs encontradas')
@click.option('--doh', is_flag=True, help='Usar DNS-over-HTTPS (Cloudflare)')
@click.option('--ports', is_flag=True, help='Escanear puertos comunes en IPs')
@click.option('--diff', default=None, help='Comparar con resultado JSON anterior (ruta)')
def main(dominio, wordlist, no_axfr, no_reverse, verbose, output, timeout, max_sub, delay, dns_server, threads, tipos_dns, no_wildcard, permutations, passive, passive_only, output_dir, vulns, vulns_only, no_takeover, no_infra, whois, ssl, geo, doh, ports, diff):
    """
    DNSTRACKING - Escaner DNS de Reconocimiento

    Los resultados se guardan en resultados/<dominio>/ con timestamp.

    Ejemplos:
        python main.py google.com
        python main.py google.com -w wordlists/subdomains-medium.txt
        python main.py google.com -w wordlists/subdomains-medium.txt -t 30
        python main.py google.com -w wordlists/subdomains-medium.txt -p --tipos-dns A,AAAA,CNAME
        python main.py google.com --passive
        python main.py google.com --passive-only
        python main.py google.com --no-axfr --no-reverse -v
        python main.py google.com -o json
        python main.py google.com -d /ruta/personalizada
        python main.py google.com --vulns
        python main.py google.com --vulns-only
        python main.py google.com --vulns --no-takeover
    """

    colorama_init()
    tipos_dns_list = [t.strip().upper() for t in tipos_dns.split(',')] if tipos_dns else ['A']

    try:
        dns_resolver = None
        if doh:
            print("[*] Usando DNS-over-HTTPS (Cloudflare)")
            dns_resolver = DohResolver(proveedor='cloudflare', timeout=timeout)
        scanner = DNSScanner(dominio, verbose=verbose, timeout=timeout, resolver=dns_resolver)

        if dns_server:
            scanner.resolver.resolver.nameservers = [dns_server]

        resultados = scanner.escanear_completo(
            wordlist=wordlist,
            intentar_axfr=not no_axfr,
            reverse_lookup=not no_reverse,
            max_subdominios=max_sub,
            delay=delay,
            threads=threads,
            tipos_dns=tipos_dns_list,
            detectar_wildcards=not no_wildcard,
            con_permutaciones=permutations,
            solo_pasivo=passive_only,
            con_pasivo=passive,
            con_vulnerabilidades=vulns,
            solo_vulnerabilidades=vulns_only,
            check_takeover=not no_takeover,
            check_infrastructure=not no_infra,
            con_whois=whois,
            con_ssl=ssl,
            con_geo=geo,
            con_puertos=ports,
        )

        if diff:
            _mostrar_diff(resultados, diff)

        if output == 'all':
            Reporter.guardar_todos(resultados, dominio, base_dir=output_dir)
        else:
            directorio = Reporter._crear_dir_dominio(dominio, output_dir)
            timestamp = __import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')

            if output == 'json':
                Reporter.guardar_json(resultados, os.path.join(directorio, f"scan_{timestamp}.json"))
            elif output == 'txt':
                Reporter.guardar_txt(resultados, os.path.join(directorio, f"scan_{timestamp}.txt"))
            elif output == 'html':
                Reporter.guardar_html(resultados, os.path.join(directorio, f"reporte_{timestamp}.html"))
            elif output == 'csv':
                subs = resultados.get('subdominios', []) + resultados.get('subdominios_pasivos', [])
                if subs:
                    Reporter.guardar_csv(subs, os.path.join(directorio, f"subdominios_{timestamp}.csv"))
            elif output == 'ndjson':
                Reporter.guardar_ndjson(resultados, os.path.join(directorio, f"subdominios_{timestamp}.ndjson"))
            elif output == 'yaml':
                Reporter.guardar_yaml(resultados, os.path.join(directorio, f"scan_{timestamp}.yaml"))

    except KeyboardInterrupt:
        print("\n[-] Escaneo cancelado por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"[-] Error fatal: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def _mostrar_diff(actuales: Dict, ruta_anterior: str):
    from color_util import verde, rojo, icono_info
    try:
        with open(ruta_anterior) as f:
            anteriores = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f" {icono_error()} Error al cargar archivo diff: {e}")
        return

    subs_prev = set()
    for sub in anteriores.get('subdominios', []):
        subs_prev.add(sub['dominio'])
    for sub in anteriores.get('subdominios_pasivos', []):
        subs_prev.add(sub['dominio'])

    subs_act = set()
    for sub in actuales.get('subdominios', []):
        subs_act.add(sub['dominio'])
    for sub in actuales.get('subdominios_pasivos', []):
        subs_act.add(sub['dominio'])

    nuevos = subs_act - subs_prev
    desaparecidos = subs_prev - subs_act

    print(f"\n{'='*60}")
    print(f"  DIFF vs escaneo anterior")
    print(f"{'='*60}")

    if nuevos:
        print(f"\n {verde('NUEVOS:')} {len(nuevos)}")
        for sub in sorted(nuevos)[:20]:
            print(f"    + {sub}")
        if len(nuevos) > 20:
            print(f"    ... y {len(nuevos) - 20} mas")

    if desaparecidos:
        print(f"\n {rojo('DESAPARECIDOS:')} {len(desaparecidos)}")
        for sub in sorted(desaparecidos)[:20]:
            print(f"    - {sub}")
        if len(desaparecidos) > 20:
            print(f"    ... y {len(desaparecidos) - 20} mas")

    if not nuevos and not desaparecidos:
        print(f"\n {icono_info()} Sin cambios respecto al escaneo anterior")
    print()


if __name__ == '__main__':
    main()
