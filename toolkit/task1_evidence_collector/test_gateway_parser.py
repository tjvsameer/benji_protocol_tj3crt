from pathlib import Path

from gateway_parser import parse_log, write_csv

KNOWN_ATTACK_LINE = (
    "2024-05-27T12:30:45 sshd[1024]: Failed password for invalid user admin "
    "from 192.168.1.5 port 50214 ssh2"
)

CORRUPTED_LINE = "2024-05-27T12:30:45 sshd: Failed password for invalid user admin from"

DUPLICATE_LINES = (
    "2024-05-27T12:31:05 sshd[1024]: Failed password for invalid user mysql "
    "from 192.168.1.5 port 50214 ssh2\n"
    "2024-05-27T12:31:05 sshd[1024]: Failed password for invalid user mysql "
    "from 192.168.1.5 port 50214 ssh2\n"
)


def test_failed_password_extracted(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(KNOWN_ATTACK_LINE)

    records = parse_log(str(log_file))

    assert len(records) == 1
    record = records[0]
    assert record["Timestamp"] == "2024-05-27T12:30:45"
    assert record["User_Account"] == "admin"
    assert record["IP_Address"] == "192.168.1.5"


def test_corrupted_password_extracted(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(CORRUPTED_LINE)

    records = parse_log(str(log_file))

    assert len(records) == 0


def test_duplicate_lines(tmp_path):
    log_file = tmp_path / "test.log"
    log_file.write_text(DUPLICATE_LINES)

    records = parse_log(str(log_file))

    assert len(records) == 1
