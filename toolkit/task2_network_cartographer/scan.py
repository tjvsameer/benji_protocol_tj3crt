import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from ssl import PROTOCOL_TLS_SERVER


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TCP connect scanner with banner grabbing."
    )

    parser.add_argument("target", help="Target IP Address")
    parser.add_argument("--ports", default="1-1024", help="Port range or list. Default")
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.5,
        help="Connection time out per port in seconds. Default: 0.5",
    )
    parser.add_argument(
        "--output", default="cartographer_results.json", help="Output JSON"
    )
    parser.add_argument(
        "--threads", type=int, default=50, help="Thread pool size. Default"
    )
    return parser.parse_args()


def parse_port_input(port_str: str) -> list[int]:
    ports = []
    for part in port_str.split(","):
        part.strip()
        if "-" in part:
            pieces: list[str] = part.split("-", 1)
            start, end = [int(x.strip()) for x in pieces]
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def check_port(target: str, port: int, timeout: float = 0.5) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        result: int = sock.connect_ex((target, port))
        return result == 0
    except socket.timeout:
        return False
    finally:
        sock.close()
    pass


def grab_banner(target: str, port: int, timeout: float = 0.5) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:

        sock.settimeout(timeout)
        try:

            sock.connect_ex((target, port))
            time.sleep(0.5)
            return sock.recv(1024).decode("utf-8", errors="ignore")
        except:
            (socket.timeout, ConnectionRefusedError, OSError)
            return ""


def main():
    args: Namespace = parse_arguments()
    ports: list[int] = parse_port_input(args.ports)
    open_ports: list[any] = []
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures: dict[Future[bool], int] = {
            executor.submit(check_port, args.target, p, args.timeout): p for p in ports
        }
        for future, port in futures.items():
            if future.result():
                banner: str = grab_banner(args.target, port, args.timeout)
                open_ports.append({"port": port, "banner": banner})
    open_ports.sort(key=lambda x: x["port"])

    output: dict[str, Any] = {
        "target": args.target,
        "open_ports": open_ports,
    }
    print(json.dumps(output, indent=2))
    Path(args.output).write_text(json.dumps(output, indent=2))
    print(f"[*] {len(open_ports)}  port(s) found.", file=sys.stderr)


if __name__ == "__main__":
    main()
