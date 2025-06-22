import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import argparse
import threading
from queue import Queue

visited_urls = set()
lock = threading.Lock()

headers = {
    'User-Agent': 'Mozilla/5.0 (AutoReconX)'
}

def is_valid_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def extract_forms(soup, base_url):
    forms = soup.find_all("form")
    endpoints = []

    for form in forms:
        action = form.get("action")
        method = form.get("method", "GET").upper()
        if action:
            full_url = urljoin(base_url, action)
            endpoints.append((full_url, method))

    return endpoints

def extract_links(soup, base_url):
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        full_url = urljoin(base_url, href)
        if is_valid_url(full_url) and urlparse(full_url).netloc == urlparse(base_url).netloc:
            links.add(full_url)
    return links

def scan_url(url, queue, depth):
    with lock:
        if url in visited_urls or depth <= 0:
            return
        visited_urls.add(url)

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(resp.text, "html.parser")

        print(f"[+] Scanning: {url} ({resp.status_code})")

        # Extract and print forms (GET/POST)
        forms = extract_forms(soup, url)
        for endpoint, method in forms:
            print(f"    └─ [{method}] {endpoint}")

        # Traverse other internal links
        if depth > 0:
            links = extract_links(soup, url)
            for link in links:
                queue.put((link, depth - 1))

    except Exception as e:
        print(f"[!] Error on {url}: {e}")

def directory_bruteforce(base_url, wordlist_file, queue):
    try:
        with open(wordlist_file, "r") as f:
            for line in f:
                path = line.strip()
                url = urljoin(base_url, path)
                try:
                    r = requests.get(url, headers=headers, timeout=5)
                    if r.status_code in [200, 301, 302]:
                        print(f"[FOUND] {url} ({r.status_code})")
                        queue.put((url, 1))  # Queue for crawling
                except:
                    continue
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_file}")

def start_recon(base_url, wordlist_file, max_depth):
    queue = Queue()
    queue.put((base_url, max_depth))

    # Start directory brute-force
    print("\n--- Directory Brute-Forcing ---")
    directory_bruteforce(base_url, wordlist_file, queue)

    print("\n--- Crawling and Endpoint Detection ---")
    threads = []

    def worker():
        while not queue.empty():
            url, depth = queue.get()
            scan_url(url, queue, depth)
            queue.task_done()

    # Launch multiple threads
    for _ in range(10):
        t = threading.Thread(target=worker)
        t.daemon = True
        threads.append(t)
        t.start()

    queue.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoReconX - Directory and Endpoint Scanner")
    parser.add_argument("--domain", required=True, help="Target domain (e.g., https://example.com)")
    parser.add_argument("--wordlist", default="common.txt", help="Path to wordlist for brute force")
    parser.add_argument("--depth", type=int, default=2, help="Crawling depth")

    args = parser.parse_args()

    start_recon(args.domain, args.wordlist, args.depth)
