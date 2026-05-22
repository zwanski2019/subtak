#!/usr/bin/env python3
"""
subtak — Subdomain Takeover Verification Scanner
Author: zwanski (Zwanski Tech / Tinosoft Informatique)
Usage:  python3 subtak.py --list subs.txt
        python3 subtak.py --domain target.com --threads 30
Deps:   pip install dnspython httpx
"""

import sys
import re
import json
import ipaddress
import argparse
from typing import Any, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx
import dns.resolver
import dns.exception

# ─── Terminal helpers ────────────────────────────────────────────────────────

_ANSI_RE = re.compile(r'\033\[[0-9;]*m')

COLORS = {
    "red":     "\033[91m", "green":   "\033[92m", "yellow":  "\033[93m",
    "blue":    "\033[94m", "magenta": "\033[95m", "cyan":    "\033[96m",
    "white":   "\033[97m", "reset":   "\033[0m",
}

def c(text: str, color: str = "white", bold: bool = False) -> str:
    b = "\033[1m" if bold else ""
    return f"{b}{COLORS.get(color, '')}{text}{COLORS['reset']}"

def vlen(s: str) -> int:
    return len(_ANSI_RE.sub("", s))

def render_table(headers: List[str], rows: List[List[str]]) -> None:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], vlen(cell))
    sep = "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    def fmt(cells):
        return "| " + " | ".join(
            cell + " " * (col_widths[i] - vlen(cell)) for i, cell in enumerate(cells)
        ) + " |"
    print(sep); print(fmt(headers)); print(sep)
    for row in rows:
        print(fmt(row))
    print(sep)

# ─── Cloud IP ranges (representative — update periodically) ──────────────────
# Source: AWS ip-ranges.json, Azure Public IPs, GCP goog.json

_CLOUD_NETS = [
    # AWS
    "13.32.0.0/15", "13.35.0.0/16", "52.0.0.0/6", "54.0.0.0/8",
    "18.0.0.0/8", "3.0.0.0/8", "34.192.0.0/10", "35.0.0.0/8",
    # Azure
    "13.64.0.0/11", "13.96.0.0/13", "20.0.0.0/8", "40.64.0.0/10",
    "51.0.0.0/8", "104.40.0.0/13",
    # GCP
    "34.64.0.0/10", "34.128.0.0/10", "35.184.0.0/13", "35.192.0.0/11",
    "104.154.0.0/15", "104.196.0.0/14",
]
_CLOUD_NETS_PARSED = [ipaddress.ip_network(n, strict=False) for n in _CLOUD_NETS]

def is_cloud_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _CLOUD_NETS_PARSED)
    except ValueError:
        return False

# ─── Fingerprint database ─────────────────────────────────────────────────────

FINGERPRINTS: List[Dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname": [r"github\.io", r"github\.map\.fastly\.net"],
        "fingerprint": "There isn't a GitHub Pages site here",
        "verified": True, "confidence": "HIGH",
        "guide": "Create a GitHub repo, add a CNAME file with this subdomain, enable Pages under Settings > Pages.",
    },
    {
        "service": "Heroku",
        "cname": [r"herokudns\.com", r"herokussl\.com", r"herokuapp\.com"],
        "fingerprint": "There's nothing here, yet.",
        "verified": True, "confidence": "HIGH",
        "guide": "Deploy an app to Heroku and bind this domain via `heroku domains:add <subdomain>`.",
    },
    {
        "service": "Fastly",
        "cname": [r"fastly\.net"],
        "fingerprint": "Fastly error: unknown domain",
        "verified": True, "confidence": "HIGH",
        "guide": "Register a Fastly service and add this domain under Domains in your service config.",
    },
    {
        "service": "Shopify",
        "cname": [r"myshopify\.com", r"shopify\.com"],
        "fingerprint": "Sorry, this shop is currently unavailable",
        "verified": True, "confidence": "HIGH",
        "guide": "Create a Shopify store → Online Store → Domains → Connect existing domain.",
    },
    {
        "service": "Tumblr",
        "cname": [r"tumblr\.com", r"domains\.tumblr\.com"],
        "fingerprint": "There's no Tumblr blog here",          # Fix: accurate string
        "verified": True, "confidence": "MEDIUM",
        "guide": "Register a Tumblr blog and map this custom domain under Blog Settings.",
    },
    {
        "service": "WordPress.com",
        "cname": [r"wordpress\.com"],
        "fingerprint": "Do you want to register",
        "verified": True, "confidence": "MEDIUM",
        "guide": "Create a WordPress.com site and add domain mapping via Upgrades > Domains.",
    },
    {
        "service": "Surge.sh",
        "cname": [r"surge\.sh"],
        "fingerprint": "project not found",
        "verified": True, "confidence": "HIGH",
        "guide": "Run `surge` and set this as the domain during deployment.",
    },
    {
        "service": "Pantheon",
        "cname": [r"pantheonsite\.io", r"getpantheon\.com"],
        # Fix: correct real-world fingerprint string
        "fingerprint": "The gods are wise, but do not know of the site which you seek",
        "verified": True, "confidence": "HIGH",
        "guide": "Add this domain in your Pantheon dashboard under Domains / HTTPS.",
    },
    {
        "service": "Ghost.io",
        "cname": [r"ghost\.io"],
        "fingerprint": "The thing you were looking for is no longer here",
        "verified": True, "confidence": "HIGH",
        "guide": "Claim this domain inside your Ghost(Pro) publication under Settings > Domain.",
    },
    {
        "service": "Readme.io",
        "cname": [r"readme\.io", r"readmessl\.com"],
        "fingerprint": "Project not found",
        "verified": True, "confidence": "HIGH",
        "guide": "Create a ReadMe project and add this as a custom domain under Project Settings.",
    },
    {
        "service": "HubSpot",
        "cname": [r"hubspot\.net", r"hs-sites\.com"],
        "fingerprint": "DomainNotMappedException",
        "verified": True, "confidence": "HIGH",
        "guide": "Add this domain in HubSpot under Settings > Website > Domains & URLs.",
    },
    {
        "service": "Zendesk",
        "cname": [r"zendesk\.com"],
        "fingerprint": "Help Center Closed",
        "verified": True, "confidence": "HIGH",
        "guide": "Configure custom host mapping in Zendesk Admin > Account > Brands.",
    },
    {
        "service": "Cargo",
        "cname": [r"cargo\.site", r"cargocollective\.com"],
        # Fix: "404 Not Found" is far too generic — use service-specific string
        "fingerprint": "If you're moving your domain away from Cargo",
        "verified": False, "confidence": "LOW",
        "guide": "Verify Cargo dashboard for custom domain assignment options.",
    },
    {
        "service": "Feedpress",
        "cname": [r"feedpress\.me"],
        "fingerprint": "The feed you are looking for does not exist",
        "verified": True, "confidence": "HIGH",
        "guide": "Link this domain in your Feedpress account under Custom Domain settings.",
    },
    {
        "service": "Bitbucket Pages",
        "cname": [r"bitbucket\.io"],
        "fingerprint": "Repository not found",
        "verified": True, "confidence": "HIGH",
        "guide": "Deploy a static site via Bitbucket Pages and define this domain in repo settings.",
    },
    {
        "service": "AWS S3 / Elastic Beanstalk",
        "cname": [r"s3\.amazonaws\.com", r"s3-website", r"elasticbeanstalk\.com"],
        "fingerprint": "NoSuchBucket",
        "verified": True, "confidence": "HIGH",
        "guide": "Create an S3 bucket with this exact subdomain name and configure static hosting.",
    },
    {
        "service": "Azure",
        "cname": [r"azurewebsites\.net", r"cloudapp\.net", r"trafficmanager\.net"],
        "fingerprint": "404 Web Site not found",
        "verified": True, "confidence": "HIGH",
        "guide": "Register the Azure resource matching this subdomain in your Azure subscription.",
    },
]

# ─── DNS resolution engine ────────────────────────────────────────────────────

def resolve_cname_chain(
    subdomain: str, timeout: float = 3.0, max_hops: int = 10
) -> Tuple[List[str], str, List[str]]:
    """
    Returns (cname_chain, status, a_records).
    Status: RESOLVED | NXDOMAIN | DNS_ERROR | DANGLING
    Fix: per-call Resolver() = thread-safe; visited set = cycle detection.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    chain: List[str] = []
    visited = {subdomain.lower()}        # Fix: cycle detection
    current = subdomain
    status = "RESOLVED"

    for _ in range(max_hops):
        try:
            answers = resolver.resolve(current, "CNAME")
            next_hop = str(answers[0].target).rstrip(".")
            if next_hop.lower() in visited:   # cycle detected
                status = "DNS_ERROR"
                break
            visited.add(next_hop.lower())
            chain.append(next_hop)
            current = next_hop
        except dns.resolver.NoAnswer:
            break
        except dns.resolver.NXDOMAIN:
            status = "NXDOMAIN"
            break
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            status = "DNS_ERROR"
            break

    # Resolve A/AAAA on final hop — check cloud IP ranges
    a_records: List[str] = []
    if status == "RESOLVED":
        for qtype in ("A", "AAAA"):
            try:
                for rdata in resolver.resolve(current, qtype):
                    a_records.append(str(rdata))
            except dns.resolver.NXDOMAIN:
                status = "NXDOMAIN"
                break
            except Exception:
                pass

    return chain, status, a_records

# ─── Fingerprint matcher ──────────────────────────────────────────────────────

def match_fingerprint(chain: List[str]) -> Optional[Dict[str, Any]]:
    if not chain:
        return None
    final = chain[-1]
    for fp in FINGERPRINTS:
        for pattern in fp["cname"]:
            if re.search(pattern, final, re.IGNORECASE):
                return fp
    return None

# ─── Per-subdomain scan ───────────────────────────────────────────────────────

def scan(subdomain: str, client: httpx.Client) -> Dict[str, Any]:
    chain, dns_status, a_records = resolve_cname_chain(subdomain)

    result: Dict[str, Any] = {
        "subdomain":       subdomain,
        "cname_chain":     chain,
        "dns_status":      dns_status,
        "a_records":       a_records,
        "cloud_ip":        any(is_cloud_ip(ip) for ip in a_records),
        "matched_service": None,
        "http_status":     0,
        "fingerprint_hit": False,
        "verdict":         "SAFE",
        "confidence":      "LOW",
        "snippet":         "",
        "guide":           "",
    }

    fp = match_fingerprint(chain)

    # Dangling CNAME → NXDOMAIN on final hop
    if dns_status == "NXDOMAIN" and chain:
        result["verdict"] = "POTENTIAL"
        result["confidence"] = "HIGH" if fp else "MEDIUM"
        if fp:
            result["matched_service"] = f"{fp['service']} (Dangling)"
            result["guide"] = fp["guide"]
        else:
            result["matched_service"] = "Dangling CNAME"
            result["guide"] = "Final CNAME target is NXDOMAIN — check if destination domain is registerable."
        # Still attempt HTTP probe to see what comes back
    elif not fp:
        return result
    else:
        result["matched_service"] = fp["service"]
        result["confidence"] = fp["confidence"]

    # HTTP verification
    for proto in ("https://", "http://"):
        try:
            r = client.get(f"{proto}{subdomain}", follow_redirects=True)
            result["http_status"] = r.status_code
            body = r.text
            result["snippet"] = body[:100].replace("\n", " ").replace("\r", "")
            if fp and fp["fingerprint"].lower() in body.lower():
                result["fingerprint_hit"] = True
                result["verdict"] = "VULNERABLE" if fp["verified"] else "POTENTIAL"
                result["guide"] = fp["guide"]
            break
        except httpx.RequestError:
            continue

    return result

# ─── Main ─────────────────────────────────────────────────────────────────────

# Common subdomain prefixes for --domain mode
_PREFIXES = [
    "www", "blog", "dev", "staging", "api", "docs", "help", "shop",
    "status", "support", "test", "demo", "mail", "cdn", "assets",
    "static", "media", "portal", "app", "admin", "dashboard", "beta",
    "preview", "careers", "jobs", "forum", "community", "wiki", "git",
]

def main() -> None:
    pa = argparse.ArgumentParser(description="subtak — Subdomain Takeover Verification Scanner")
    grp = pa.add_mutually_exclusive_group(required=True)
    grp.add_argument("--domain", help="Apex domain — scans common prefixes (e.g. target.com)")
    grp.add_argument("--list",   help="File of subdomains, one per line")
    pa.add_argument("--threads", type=int, default=20)
    pa.add_argument("--proxy",   help="HTTP proxy e.g. http://127.0.0.1:8080")
    pa.add_argument("--output",  default="subtak_results.json")
    args = pa.parse_args()

    if args.list:
        try:
            with open(args.list) as f:
                subdomains = [l.strip() for l in f if l.strip()]
        except Exception as e:
            print(c(f"[-] Cannot read list: {e}", "red")); sys.exit(1)
    else:
        subdomains = [f"{p}.{args.domain.strip()}" for p in _PREFIXES]

    proxies = {"all://": args.proxy} if args.proxy else None
    client = httpx.Client(
        proxies=proxies,
        transport=httpx.HTTPTransport(retries=0, verify=False),
        timeout=5.0,
        limits=httpx.Limits(max_connections=args.threads, max_keepalive_connections=10),
        headers={"User-Agent": "subtak/1.0"},
        http1=True, http2=False,
    )

    print(f"\n{c('subtak', 'cyan', bold=True)} — Subdomain Takeover Scanner")
    print(f"Targets  : {len(subdomains)}")
    print(f"Threads  : {args.threads}\n")

    all_results: List[Dict[str, Any]] = []
    table_rows:  List[List[str]]      = []

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(scan, sub, client): sub for sub in subdomains}
        done = 0
        for fut in as_completed(futures):
            done += 1
            res = fut.result()
            all_results.append(res)
            sys.stdout.write(f"  [{done}/{len(subdomains)}] {res['subdomain']:<50}\r")
            sys.stdout.flush()

            cname_disp = (res["cname_chain"][-1][:28] + "…") \
                         if res["cname_chain"] and len(res["cname_chain"][-1]) > 29 \
                         else (res["cname_chain"][-1] if res["cname_chain"] else "-")

            v = res["verdict"]
            vc = "red" if v == "VULNERABLE" else "yellow" if v == "POTENTIAL" else "green"
            cc = res["confidence"]
            ccc = "red" if cc == "HIGH" else "yellow" if cc == "MEDIUM" else "white"

            cloud_tag = c(" ☁", "cyan") if res["cloud_ip"] else ""

            table_rows.append([
                c(res["subdomain"], "white", bold=True),
                cname_disp + cloud_tag,
                res["matched_service"] or "-",
                str(res["http_status"]) if res["http_status"] else "-",
                c("YES", "red", bold=True) if res["fingerprint_hit"] else "no",
                c(v, vc, bold=(v != "SAFE")),
                c(cc, ccc),
            ])

    print(" " * 70)
    print(f"\n{'=' * 15} SUBDOMAIN TAKEOVER MATRIX {'=' * 15}")
    render_table(
        ["Subdomain", "Final CNAME", "Service", "HTTP", "FP Hit", "Verdict", "Conf"],
        table_rows,
    )

    with open(args.output, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n[+] Report → {c(args.output, 'cyan')}")

    hits = [r for r in all_results if r["verdict"] in ("VULNERABLE", "POTENTIAL")]
    if hits:
        print(f"\n{c('!!! TAKEOVER TARGETS !!!', 'red', bold=True)}\n")
        for r in hits:
            tag = c("VULNERABLE", "red", bold=True) if r["verdict"] == "VULNERABLE" \
                  else c("POTENTIAL", "yellow", bold=True)
            print(f"  {tag}  {c(r['subdomain'], 'white', bold=True)}")
            print(f"    Service    : {r['matched_service']}")
            print(f"    CNAME chain: {' → '.join(r['cname_chain']) if r['cname_chain'] else 'N/A'}")
            print(f"    DNS status : {r['dns_status']}")
            print(f"    FP hit     : {'YES' if r['fingerprint_hit'] else 'NO'}")
            print(f"    Guide      : {c(r['guide'], 'magenta')}\n")
    else:
        print(c("\n[*] No takeover candidates found.", "green"))

    client.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\n[-] Aborted.", "red"))
        sys.exit(1)
