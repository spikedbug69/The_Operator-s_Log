#!/usr/bin/env python3

import argparse
import json
import re
import time
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


USER_AGENT = "UniversalReconCrawler/1.0"
TIMEOUT = 10

INTERESTING_EXTENSIONS = {
    ".js", ".json", ".xml", ".txt", ".map",
    ".env", ".bak", ".old", ".zip", ".log",
    ".sql", ".config", ".conf"
}

INTERESTING_PATTERNS = {
    "API endpoint": r"""(?i)(/api/|/v[0-9]+/|graphql|rest/)""",
    "Possible secret": r"""(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)""",
    "AWS key": r"""AKIA[0-9A-Z]{16}""",
    "JWT": r"""eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+""",
    "Private key": r"""-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----""",
    "Email": r"""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""",
    "IP address": r"""\b(?:\d{1,3}\.){3}\d{1,3}\b""",
}


class UniversalCrawler:

    def __init__(self, target, max_pages=100, delay=0.5):
        self.target = target.rstrip("/")
        self.domain = urlparse(target).netloc

        self.max_pages = max_pages
        self.delay = delay

        self.queue = deque([self.target])
        self.visited = set()

        self.results = {
            "target": self.target,
            "pages": [],
            "javascript": [],
            "comments": [],
            "forms": [],
            "interesting_urls": [],
            "findings": []
        }

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": USER_AGENT
        })

    # --------------------------------------------------
    # URL handling
    # --------------------------------------------------

    def normalize_url(self, url):
        url, _ = urldefrag(url)

        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return None

        return url.rstrip("/")

    def is_same_domain(self, url):
        return urlparse(url).netloc == self.domain

    # --------------------------------------------------
    # Pattern detection
    # --------------------------------------------------

    def analyze_text(self, url, text):
        for name, pattern in INTERESTING_PATTERNS.items():

            matches = re.findall(pattern, text)

            if matches:
                unique = list(set(matches))

                self.results["findings"].append({
                    "type": name,
                    "url": url,
                    "matches": unique[:20]
                })

    # --------------------------------------------------
    # HTML analysis
    # --------------------------------------------------

    def analyze_html(self, url, html):

        soup = BeautifulSoup(html, "html.parser")

        # ----------------------------------------------
        # Comments
        # ----------------------------------------------

        for comment in soup.find_all(
            string=lambda text: isinstance(text, type(soup.string))
        ):
            pass

        comments = re.findall(
            r"<!--(.*?)-->",
            html,
            re.DOTALL
        )

        for comment in comments:

            cleaned = comment.strip()

            if cleaned:
                self.results["comments"].append({
                    "url": url,
                    "comment": cleaned
                })

        # ----------------------------------------------
        # Links
        # ----------------------------------------------

        for tag in soup.find_all("a", href=True):

            link = self.normalize_url(
                urljoin(url, tag["href"])
            )

            if not link:
                continue

            if self.is_same_domain(link):
                self.queue.append(link)

            self.check_interesting_url(link)

        # ----------------------------------------------
        # JavaScript
        # ----------------------------------------------

        for script in soup.find_all("script", src=True):

            js_url = self.normalize_url(
                urljoin(url, script["src"])
            )

            if js_url:

                self.results["javascript"].append({
                    "page": url,
                    "url": js_url
                })

                if self.is_same_domain(js_url):
                    self.queue.append(js_url)

        # ----------------------------------------------
        # Forms
        # ----------------------------------------------

        for form in soup.find_all("form"):

            action = form.get("action", "")

            method = form.get(
                "method",
                "GET"
            ).upper()

            inputs = []

            for field in form.find_all(
                ["input", "textarea", "select"]
            ):

                inputs.append({
                    "name": field.get("name"),
                    "type": field.get("type"),
                    "value": field.get("value")
                })

            self.results["forms"].append({
                "url": url,
                "action": urljoin(url, action),
                "method": method,
                "inputs": inputs
            })

        # ----------------------------------------------
        # Text analysis
        # ----------------------------------------------

        self.analyze_text(url, html)

    # --------------------------------------------------
    # Interesting files / URLs
    # --------------------------------------------------

    def check_interesting_url(self, url):

        parsed = urlparse(url)
        path = parsed.path.lower()

        for extension in INTERESTING_EXTENSIONS:

            if path.endswith(extension):

                if url not in self.results["interesting_urls"]:

                    self.results["interesting_urls"].append(url)

                break

    # --------------------------------------------------
    # Crawl page
    # --------------------------------------------------

    def crawl_page(self, url):

        try:

            print(f"[+] Crawling {url}")

            response = self.session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True
            )

            content_type = response.headers.get(
                "Content-Type",
                ""
            )

            page_info = {
                "url": url,
                "final_url": response.url,
                "status": response.status_code,
                "content_type": content_type,
                "size": len(response.content)
            }

            self.results["pages"].append(page_info)

            # Only parse textual responses
            if (
                "text" in content_type
                or "json" in content_type
                or "javascript" in content_type
            ):

                text = response.text

                self.analyze_text(
                    response.url,
                    text
                )

                if "html" in content_type:

                    self.analyze_html(
                        response.url,
                        text
                    )

        except requests.RequestException as e:

            print(f"[-] Error: {url} -> {e}")

    # --------------------------------------------------
    # Special files
    # --------------------------------------------------

    def check_special_files(self):

        files = [
            "/robots.txt",
            "/sitemap.xml",
            "/security.txt",
            "/.well-known/security.txt"
        ]

        for path in files:

            url = self.target + path

            print(f"[+] Checking {url}")

            try:

                response = self.session.get(
                    url,
                    timeout=TIMEOUT
                )

                self.results.setdefault(
                    "special_files",
                    []
                ).append({
                    "url": url,
                    "status": response.status_code,
                    "content": response.text[:10000]
                })

            except requests.RequestException:
                pass

    # --------------------------------------------------
    # Run crawler
    # --------------------------------------------------

    def run(self):

        self.check_special_files()

        while self.queue and len(self.visited) < self.max_pages:

            url = self.queue.popleft()

            if url in self.visited:
                continue

            if not self.is_same_domain(url):
                continue

            self.visited.add(url)

            self.crawl_page(url)

            time.sleep(self.delay)

        return self.results


def main():

    parser = argparse.ArgumentParser(
        description="Universal passive web reconnaissance crawler"
    )

    parser.add_argument(
        "target",
        help="Target URL"
    )

    parser.add_argument(
        "-m",
        "--max-pages",
        type=int,
        default=100,
        help="Maximum pages to crawl"
    )

    parser.add_argument(
        "-d",
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="crawl_results.json",
        help="Output JSON file"
    )

    args = parser.parse_args()

    target = args.target

    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    crawler = UniversalCrawler(
        target,
        max_pages=args.max_pages,
        delay=args.delay
    )

    results = crawler.run()

    with open(args.output, "w", encoding="utf-8") as f:

        json.dump(
            results,
            f,
            indent=4
        )

    print("\n========== RESULTS ==========")

    print(
        f"Pages       : {len(results['pages'])}"
    )

    print(
        f"JS files    : {len(results['javascript'])}"
    )

    print(
        f"Comments    : {len(results['comments'])}"
    )

    print(
        f"Forms       : {len(results['forms'])}"
    )

    print(
        f"Interesting : {len(results['interesting_urls'])}"
    )

    print(
        f"Findings    : {len(results['findings'])}"
    )

    print(
        f"\n[+] Results saved to {args.output}"
    )


if __name__ == "__main__":
    main()