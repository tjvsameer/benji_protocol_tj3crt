# AI Transparency Log — The Benji Protocol

**Student Name:** Tariq Javaid
**Student ID:** 1909712

---

## Policy Summary

You may use GenAI tools (ChatGPT, GitHub Copilot, etc.) to debug, explain,
or refactor code. You must document every substantive use in this log.

You may NOT paste the Vulnerability Hunt scenario into an AI tool and ask
for the solution. Code you cannot explain during the session will be flagged.

---

## Log Format

| Week | Task | Prompt Used | AI Output Summary | My Verification / Changes Made |
|------|------|-------------|-------------------|-------------------------------|

---

## Entries

| Week | Task | Prompt Used | AI Output Summary | My Verification / Changes Made |
|------|------|-------------|-------------------|-------------------------------|
| Week 1 | Task 1 — Evidence Collector | "Write regex to extract failed SSH and FTP login attempts from logs" | Provided regex patterns for SSH failed password, invalid users, and FTP login failures. | Tested against Metasploitable logs. Fixed timestamp inconsistencies by adding `normalize_timestamp()`. Improved regex to correctly capture duplicate entries. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 1 | Task 1 — Evidence Collector | "How to handle duplicate log entries in Python parsing" | Suggested using a `set()` to track unique records. | Implemented `seen` set using `(timestamp, IP, username)` tuple. Verified duplicates removed. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 2 | Task 2 — Network Cartographer | "How to build a multithreaded port scanner in Python" | Suggested `ThreadPoolExecutor` with futures. | Implemented threading and fixed race condition by mapping futures to ports. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 2 | Task 2 — Network Cartographer | "How to grab banners from open ports using sockets" | Provided socket `recv()` logic. | Added timeout, delay, and exception handling. Verified FTP and SSH banners captured. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 2 | Task 2 — Network Cartographer | "How to parse ports from range and comma-separated input" | Provided parsing logic. | Implemented `parse_port_input()` and tested multiple formats. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 3 | Task 3 — Access Validator | "How to safely brute force SSH using Paramiko" | Suggested timeouts and exception handling. | Added `timeout` and `auth_timeout`. Prevented hanging connections. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 3 | Task 3 — Access Validator | "Fix FTP quit error when connection fails" | Suggested safe cleanup logic. | Implemented try/except around `ftp.quit()`. Prevented crashes. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 3 | Task 3 — Access Validator | "How to implement safe brute force to avoid detection" | Recommended delay and single-threading. | Added `time.sleep(0.1)` and sequential execution. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 4 | Task 4 — Web Enumerator | "How to extract HTML comments using BeautifulSoup" | Provided method using `Comment`. | Implemented with cleaning logic. Verified proper extraction. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 4 | Task 4 — Web Enumerator | "How to validate URL input in Python argparse" | Suggested `urlparse`. | Enforced http/https validation. Prevented invalid input. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 4 | Task 4 — Web Enumerator | "How to detect sensitive paths via HTTP requests" | Suggested path probing. | Implemented list + redirect handling. Verified results. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 4 | Task 4 — Web Enumerator | "How to analyse HTTP headers for fingerprinting" | Suggested checking common headers. | Implemented structured + dynamic header detection. |
|      |      |             |                   |                               |
|      |      |             |                   |                               |

|      |      |             |                   |                               |
|      |      |             |                   |                               |
| Week 5 | |
|      |      |             |                   |                               |
|      |      |             |                   |                               |

---

## Notes

- All AI-assisted code was reviewed, tested, and modified before use.
- I understand and can explain all implemented logic.
- No AI was used to directly solve the Vulnerability Hunt scenario.

---
