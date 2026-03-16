import argparse
import csv
import re
import sys
from pathlib import Path

FAILED_PASSWORD = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r".*?"
    r"Failed password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+)"
    r" from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


INVALID_USER = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r".*?"
    r"(?:Connection closed by )?"
    r"[Ii]nvalid user "
    r"(?P<username>\S+)"
    r" from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
FAILED_PASSWORD_AUTH = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"Failed password for (?:invalid user )?"
    r"(?P<username>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

INVALID_USER_AUTH = re.compile(
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?"
    r"[Ii]nvalid user "
    r"(?P<username>\S+) from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Parse agateay auth log and extract stuff"
    )

    parser.add_argument("input_file", help="path to the log file to be parsed")

    parser.add_argument(
        "-o", "--output", help="path to the output csv file", default="suspects.csv"
    )
    return parser.parse_args()


def parse_log(input_file) -> None:
    path = Path(input_file)
    if not path.exists():
        print(f"Error: File {input_file} does not exist.", file=sys.stderr)
        sys.exit(1)

    records = []

    seen = set()
    patterns = (
        FAILED_PASSWORD,
        INVALID_USER,
        FAILED_PASSWORD_AUTH,
        INVALID_USER_AUTH,
    )
    with path.open(encoding="utf-8", errors="ignore") as f:
        for line in f:
            for pattern in patterns:
                m = pattern.search(line)

                if m:
                    record_key = (
                        m.group("timestamp"),
                        m.group("ip"),
                        m.group("username"),
                    )
                    if record_key not in seen:
                        seen.add(record_key)
                        records.append(
                            {
                                "timestamp": record_key[0],
                                "ip_address": record_key[1],
                                "username": record_key[2],
                            }
                        )
                    break
    return records


def write_csv(records, output_path):
    path = Path(output_path)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["Timestamp", "IP_Address", "User_Account"]
        )
        writer.writeheader()
        writer.writerows(records)
    print(f"[+] Wrote {len(records)} record(s) to {output_path}")


def main():
    args = parse_arguments()
    records = parse_log(args.input_file)
    write_csv(records, args.output)


if __name__ == "__main__":
    main()
