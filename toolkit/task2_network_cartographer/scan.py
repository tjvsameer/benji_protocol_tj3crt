import argparse
import json
import socket
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any


# Arguments
def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing."
    )

    parser.add_argument("target", help="Target IP Address")

    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Port range or list",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection timeout per port",
    )

    parser.add_argument(
        "--output",
        default="cartographer_results.json",
        help="Output JSON file",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Thread pool size",
    )

    return parser.parse_args()


# Port parsing
#
def parse_port_input(port_str: str) -> list[int]:
    ports = []

    for part in port_str.split(","):
        part = part.strip()

        if "-" in part:
            start, end = map(int, part.split("-", 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))

    return sorted(set(ports))


# Port check
def check_port(target: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((target, port)) == 0
    except socket.timeout:
        return False


# Banner grab


def grab_banner(target: str, port: int, timeout: float = 0.5) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect_ex((target, port))

            time.sleep(0.2)

            try:
                return sock.recv(1024).decode("utf-8", errors="ignore").strip()
            except Exception:
                return ""

    except Exception:
        return ""


# Main


def main() -> None:
    args = parse_arguments()
    ports = parse_port_input(args.ports)

    open_ports: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:

        futures = {
            executor.submit(check_port, args.target, p, args.timeout): p for p in ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                if future.result():
                    banner = grab_banner(args.target, port, args.timeout)
                    open_ports.append({"port": port, "banner": banner})
            except Exception:
                pass

    open_ports.sort(key=lambda x: x["port"])

    output = {
        "target": args.target,
        "open_ports": open_ports,
        "count": len(open_ports),
    }

    # Print JSON
    data = json.dumps(output, indent=2)
    print(data)

    #  Writes JSON file###
    Path(args.output).write_text(data)

    print(f"[*] {len(open_ports)} port(s) found.", file=sys.stderr)


if __name__ == "__main__":
    main()
