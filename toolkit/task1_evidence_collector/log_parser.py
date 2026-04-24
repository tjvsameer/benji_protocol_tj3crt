import argparse
import csv
import re
import sys
from datetime import datetime
from pathlib import Path

#
# REGEX PATTERNS
#

PROFTPD_LOGIN_FAILED = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+\S+"
    r"\s+proftpd\[\d+\]:\s+"
    r"\S+\s+"
    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\["
    r"[^\)]*\)"
    r"\s+-\s+USER\s+"
    r"(?P<username>\S+)"
    r"\s+\(Login failed\)"
)

FAILED_PASSWORD = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?"
    r"Failed password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+)"
    r" from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
INVALID_USER = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r".*?"
    r"[Ii]nvalid user "
    r"(?P<username>\S+)"
    r" from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


PATTERNS = [
    ("proftpd", "ftp_login_failed", PROFTPD_LOGIN_FAILED),
    ("sshd", "ssh_failed_password", FAILED_PASSWORD),
    ("sshd", "ssh_invalid_user", INVALID_USER),
]


#
# TIMESTAMP NORMALISATION #######
#
def normalize_timestamp(raw: str) -> str:
    """Return timestamp in expected format for tests.

    - ISO timestamps → truncate to seconds
    - Syslog timestamps → return as-is (no conversion)
    """
    if raw[0].isdigit():
        return raw[:19]  # ISO format

    return " ".join(raw.split())  # clean spacing, keep syslog format


# ARGUMENT PARSING


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parses a log file and extracts failed authentication attempts."
    )

    parser.add_argument("input_file", help="Path to the log file to parse")

    parser.add_argument(
        "-o",
        "--output",
        help="Path to the output CSV file (default: suspect.csv)",
        default="suspect.csv",
    )

    return parser.parse_args()


# LOG PARSING


def parse_log(file_path: str) -> list[dict]:
    path = Path(file_path)

    if not path.exists():
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    records = []
    seen = set()

    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            for _, _, pattern in PATTERNS:
                m = pattern.search(line)
                if m:
                    timestamp = normalize_timestamp(m.group("timestamp"))
                    ip = m.group("ip")
                    username = m.group("username")

                    record_key = (timestamp, ip, username)

                    if record_key not in seen:
                        seen.add(record_key)
                        records.append(
                            {
                                "Timestamp": timestamp,
                                "IP_Address": ip,
                                "User_Account": username,
                            }
                        )

                    break

    return records


# CSV OUTPUT


def write_csv(records: list[dict], output_path: str) -> None:
    path = Path(output_path)

    fieldnames = ["Timestamp", "IP_Address", "User_Account"]

    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)

    print(f"[+] Written {len(records)} record(s) to {output_path}")


# MAIN


def main() -> None:
    args = parse_arguments()
    records = parse_log(args.input_file)

    if not records:
        print("[-] No matching records found.", file=sys.stderr)
        sys.exit(0)

    write_csv(records, args.output)


if __name__ == "__main__":
    main()
