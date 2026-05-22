# subtak

Subdomain takeover verification scanner for bug bounty and penetration testing.

## Features

- Full recursive CNAME chain resolution with **cycle detection**
- **17 service fingerprints** with accurate real-world 404 strings
- HTTP body verification to confirm vs false positive
- Cloud IP detection (AWS / Azure / GCP CIDR matching)
- ThreadPoolExecutor with thread-safe per-call DNS resolver
- Color-coded terminal table + per-target takeover instructions
- JSON report output

## Install

```bash
pip install dnspython httpx
```

## Usage

```bash
# Scan from subdomain list
python3 subtak.py --list subs.txt

# Scan common prefixes on apex domain
python3 subtak.py --domain target.com

# Full options
python3 subtak.py --list subs.txt --threads 30 --proxy http://127.0.0.1:8080 --output report.json
```

## Verdicts

|Verdict     |Meaning                                                              |
|------------|---------------------------------------------------------------------|
|`VULNERABLE`|CNAME match + HTTP fingerprint confirmed — verified claimable service|
|`POTENTIAL` |Dangling CNAME (NXDOMAIN) or unverified service match                |
|`SAFE`      |No indicators found                                                  |

## Fingerprint Coverage

GitHub Pages, Heroku, Fastly, Shopify, Tumblr, WordPress.com, Surge.sh,
Pantheon, Ghost.io, Readme.io, HubSpot, Zendesk, Cargo, Feedpress,
Bitbucket Pages, AWS S3/Elastic Beanstalk, Azure

## Notes

- `☁` tag in CNAME column = final A record resolves to cloud provider IP range
- For best results, pipe subdomains from `subfinder`, `amass`, or `assetfinder` into `--list`
- DNS timeout: 3s/hop, max 10 hops. HTTP timeout: 5s.

```bash
subfinder -d target.com -silent | python3 subtak.py --list /dev/stdin
```

## Author

[zwanski](https://zwanski.bio) — Zwanski Tech / Tinosoft Informatique
