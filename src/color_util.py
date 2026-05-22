"""
Utilidades de color para la salida en consola
Usa colorama para terminales Windows y *nix
"""

from colorama import Fore, Back, Style, init

init(autoreset=True)


def rojo(texto):
    return f"{Fore.RED}{texto}{Style.RESET_ALL}"


def verde(texto):
    return f"{Fore.GREEN}{texto}{Style.RESET_ALL}"


def amarillo(texto):
    return f"{Fore.YELLOW}{texto}{Style.RESET_ALL}"


def cian(texto):
    return f"{Fore.CYAN}{texto}{Style.RESET_ALL}"


def magenta(texto):
    return f"{Fore.MAGENTA}{texto}{Style.RESET_ALL}"


def azul(texto):
    return f"{Fore.BLUE}{texto}{Style.RESET_ALL}"


def negrita(texto):
    return f"{Style.BRIGHT}{texto}{Style.RESET_ALL}"


def icono_ok():
    return f"{Fore.GREEN}[OK]{Style.RESET_ALL}"


def icono_error():
    return f"{Fore.RED}[-]{Style.RESET_ALL}"


def icono_exito():
    return f"{Fore.GREEN}[+]{Style.RESET_ALL}"


def icono_info():
    return f"{Fore.CYAN}[*]{Style.RESET_ALL}"


def icono_encontrado():
    return f"{Fore.GREEN}[FOUND]{Style.RESET_ALL}"


def icono_critico():
    return f"{Fore.RED}{Back.YELLOW}[!!!]{Style.RESET_ALL}"


def icono_alto():
    return f"{Fore.YELLOW}[!!]{Style.RESET_ALL}"


def icono_medio():
    return f"{Fore.YELLOW}[!]{Style.RESET_ALL}"


def icono_bajo():
    return f"{Fore.GREEN}[~]{Style.RESET_ALL}"


def icono_info_vuln():
    return f"{Fore.CYAN}[i]{Style.RESET_ALL}"


def severidad_color(severidad: str) -> str:
    mapa = {
        'CRITICAL': icono_critico(),
        'HIGH': icono_alto(),
        'MEDIUM': icono_medio(),
        'LOW': icono_bajo(),
        'INFO': icono_info_vuln(),
    }
    return mapa.get(severidad, f"[{severidad}]")
