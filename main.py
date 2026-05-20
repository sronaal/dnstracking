#!/usr/bin/env python3
"""
DNSTRACKING - Escaner DNS de Reconocimiento
Herramienta para auditoria y analisis de infraestructura DNS
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import click
from scanner import DNSScanner
from reporter import Reporter


@click.command()
@click.argument('dominio')
@click.option('-w', '--wordlist', default=None, help='Archivo con palabras para enumeracion de subdominios')
@click.option('--no-axfr', is_flag=True, help='No intentar transferencia de zona')
@click.option('--no-reverse', is_flag=True, help='No realizar busquedas inversas')
@click.option('-v', '--verbose', is_flag=True, help='Modo verbose')
@click.option('-o', '--output', default='txt', type=click.Choice(['txt', 'json', 'csv', 'html', 'all']), help='Formato de salida')
@click.option('--timeout', default=5, type=int, help='Timeout en segundos para consultas DNS')
@click.option('--max-sub', default=None, type=int, help='Limitar numero de subdominios encontrados')
@click.option('--delay', default=0.0, type=float, help='Delay en segundos entre consultas de subdominios')
@click.option('--dns-server', default=None, help='Servidor DNS personalizado')
def main(dominio, wordlist, no_axfr, no_reverse, verbose, output, timeout, max_sub, delay, dns_server):
    """
    DNSTRACKING - Escaner DNS de Reconocimiento

    Ejemplos:
        python main.py google.com
        python main.py example.com -w wordlists/subdomains-small.txt
        python main.py example.com -w wordlists/subdomains-small.txt -o json
        python main.py example.com --no-axfr --no-reverse -v
    """

    try:
        scanner = DNSScanner(dominio, verbose=verbose, timeout=timeout)

        if dns_server:
            scanner.resolver.resolver.nameservers = [dns_server]

        resultados = scanner.escanear_completo(
            wordlist=wordlist,
            intentar_axfr=not no_axfr,
            reverse_lookup=not no_reverse,
            max_subdominios=max_sub,
            delay=delay,
        )

        if output in ['json', 'all']:
            Reporter.guardar_json(resultados, f"{dominio}.json")

        if output in ['csv', 'all'] and resultados.get('subdominios'):
            Reporter.guardar_csv(resultados['subdominios'], f"{dominio}.csv")

        if output in ['html', 'all']:
            Reporter.guardar_html(resultados, f"{dominio}.html")

        if output == 'all':
            print(f"\n[OK] Reportes generados en formato JSON, CSV y HTML")

    except KeyboardInterrupt:
        print("\n[-] Escaneo cancelado por el usuario")
        sys.exit(130)
    except Exception as e:
        print(f"[-] Error fatal: {e}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
