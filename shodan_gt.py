#!/usr/bin/env python3
import os
import sys
import argparse
from collections import defaultdict
from datetime import datetime

try:
    import shodan
except ImportError:
    print("Falta el paquete 'shodan'. Instálalo con: pip install shodan", file=sys.stderr)
    sys.exit(1)


def validate_filter(user_filter: str):
    f = (user_filter or "").strip()
    if "org:" in f.lower():
        raise ValueError("El uso de filtros por organización (org:) está prohibido para este proyecto.")
    return f


def build_query(user_filter: str) -> str:
    base = 'country:"GT"'
    return f'{base} {user_filter}' if user_filter else base


def human(v):
    return v if v is not None else "-"


def print_match(m):
    ip = m.get("ip_str") or m.get("ip")
    port = m.get("port")
    transport = m.get("transport")
    hostnames = ",".join(m.get("hostnames", []) or []) or "-"
    product = m.get("product") or m.get("_shodan", {}).get("module") or "-"
    org = m.get("org") or "-"
    city = m.get("location", {}).get("city") or m.get("city") or "-"
    region = m.get("location", {}).get("region_code") or "-"
    ts = m.get("timestamp") or m.get("last_update") or "-"
    asn = m.get("asn") or "-"
    vulns = m.get("vulns")
    cves = ", ".join(sorted(vulns.keys())) if isinstance(vulns, dict) else "-"

    print(f"[{ip}:{port}]  proto={human(transport)}  hostnames={hostnames}  svc={product}  "
          f"org={org}  loc={city}/{region}/GT  asn={asn}  time={ts}  cves={cves}")


def main():
    parser = argparse.ArgumentParser(
        description="Búsqueda Shodan enfocada en Guatemala con resumen por puerto (sin org:)."
    )
    parser.add_argument("--filter", "-f",
                        help='Filtro Shodan adicional, p.ej.: city:"Jalapa"  (NO se permite org:)',
                        default="")
    parser.add_argument("--max-results", "-n", type=int, default=200,
                        help="Máximo de resultados a recuperar. Default: 200.")
    parser.add_argument("--all", action="store_true",
                        help="Recorrer todos los resultados (search_cursor). Ojo con rate limits.")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Timeout de la librería Shodan en segundos. Default: 60.")
    # Identificación del estudiante
    parser.add_argument("--carne", required=True, help="Número de carné.")
    parser.add_argument("--nombre", required=True, help="Nombre completo.")
    parser.add_argument("--curso", required=True, help="Curso.")
    parser.add_argument("--seccion", required=True, help="Sección.")
    args = parser.parse_args()

    try:
        uf = validate_filter(args.filter)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

    query = build_query(uf)

    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print("No se encontró SHODAN_API_KEY en variables de entorno.", file=sys.stderr)
        sys.exit(3)

    api = shodan.Shodan(api_key)
    api.timeout = args.timeout

    ip_set = set()
    port_to_ips = defaultdict(set)
    total_matches = 0

    print("#" * 80)
    print("BÚSQUEDA SHODAN PARA GUATEMALA")
    print(f"Query: {query}")
    print("#" * 80)

    try:
        if args.all:
            for m in api.search_cursor(query):
                total_matches += 1
                print_match(m)
                ip = m.get("ip_str") or m.get("ip")
                port = m.get("port")
                if ip:
                    ip_set.add(ip)
                    if port is not None:
                        port_to_ips[int(port)].add(ip)
        else:
            page = 1
            fetched = 0
            while fetched < args.max_results:
                res = api.search(query, page=page)
                matches = res.get("matches", [])
                if not matches:
                    break
                for m in matches:
                    total_matches += 1
                    fetched += 1
                    print_match(m)
                    ip = m.get("ip_str") or m.get("ip")
                    port = m.get("port")
                    if ip:
                        ip_set.add(ip)
                        if port is not None:
                            port_to_ips[int(port)].add(ip)
                    if fetched >= args.max_results:
                        break
                page += 1

    except shodan.APIError as e:
        print(f"Shodan API error: {e}", file=sys.stderr)
        sys.exit(4)
    except Exception as e:
        print(f"Error inesperado: {e}", file=sys.stderr)
        sys.exit(5)

    # --- Resumen ---
    print("\n" + "=" * 80)
    print("RESUMEN")
    print(f"Fecha de ejecución: {datetime.utcnow().isoformat()}Z")
    print(f"Filtro usado     : {query}")
    print(f"Total resultados : {total_matches}")
    print(f"IPs únicas       : {len(ip_set)}")
    print("\nIPs por puerto abierto (únicas por puerto):")
    if port_to_ips:
        for port in sorted(port_to_ips.keys()):
            print(f"  - puerto {port:<5} -> {len(port_to_ips[port])} IPs")
    else:
        print("  (sin datos)")

    # --- Datos del estudiante ---
    print("\n" + "-" * 80)
    print("DATOS DEL ESTUDIANTE")
    print(f"Carne   : {args.carne}")
    print(f"Nombre  : {args.nombre}")
    print(f"Curso   : {args.curso}")
    print(f"Sección : {args.seccion}")
    print("-" * 80)


if __name__ == "__main__":
    main()
