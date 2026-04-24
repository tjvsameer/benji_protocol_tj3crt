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
