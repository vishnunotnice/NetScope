# NetScope

NetScope is an authorized network discovery, asset inventory, vulnerability intelligence, risk scoring, and topology platform.

Only scan systems and ranges for which you have explicit authorization. NetScope does not exploit systems or perform credential attacks.

## NetScope website

Visit the [NetScope website](http://netscope.vishnumoguluri.com/) for the project overview, product information, and additional resources.

## Phase 1 — Network Discovery and Core Scanning

Implemented:

- Nmap host discovery
- Quick, service, full TCP, and OS-detection profiles
- Hostnames, MAC addresses, vendors, ports, products, versions, and CPEs
- Target validation, allowlists, and CIDR size limits
- Shell-safe Nmap execution
- JSON scan output
- CLI scan command

## Phase 2 — Vulnerability Intelligence, Risk, and Topology

Implemented:

- CVE data model
- Explainable 0–100 risk scoring
- CVSS, EPSS, KEV, exposure, criticality, and confidence factors
- NVD live lookup client
- CISA KEV feed caching
- EPSS feed caching
- SQLite asset inventory and findings
- Audit logging
- Multi-host topology nodes
- React Flow-compatible graph output
- Nmap traceroute relationship collection with `--traceroute`
- Verified traceroute hop nodes and edges
- Local visual topology dashboard

## Phase 3 — Dashboard, API, Automation, and Deployment

Implemented:

- Local dashboard at `http://localhost:8080`
- Backend API server
- `/api/health`, `/api/assets`, `/api/findings`, and `/api/topology`
- Persistent SQLite schedules
- Schedule creation, listing, deletion, enable/disable, and daemon mode
- React Flow frontend foundation under `frontend/`
- Dockerfile and Docker Compose configuration
- Safety and installation documentation

## Phase 4 — Advanced Reconnaissance and Passive Intelligence

Planned:

- Passive subdomain and DNS discovery
- Amass and Subfinder integrations
- CRT.sh and optional SecurityTrails integration
- AWS, GCP, and Azure read-only connectors
- Cloud instance, public-IP, and security-group correlation
- HTTP header and TLS certificate analysis
- Wappalyzer-style technology detection
- Web-server, framework, and CMS fingerprinting
- Security-header, exposed-admin-panel, directory-listing, and weak-TLS checks
- Passive reconnaissance evidence tracking

## macOS installation

```bash
cd "/Users/vishnumoguluri/.codex/.chatgpt-projects/g-p-6acfcb1be4ac8191931bfc5de7db465d"
brew install nmap
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip setuptools
python3 -m pip install -e .
```

Verify the installed CLI:

```bash
python3 -m netscope.cli --help
```

Available commands:

```text
scan inventory topology risk cve feeds api schedule
```

## Scan and topology workflow

Replace the example range with an explicitly authorized target:

```bash
python3 -m netscope.cli scan 192.168.1.0/24 --profile quick --traceroute --output scan.json
python3 -m netscope.cli inventory scan.json --db netscope.db
python3 -m netscope.cli topology scan.json > site/topology.json
python3 -m http.server 8080 --directory site
```

The `--traceroute` option adds only route hops observed by Nmap. Without it, topology edges remain empty by design.

Available scan profiles:

```text
discovery  quick  service  full  os
```

## Vulnerability feeds

```bash
python3 -m netscope.cli feeds update-kev
python3 -m netscope.cli feeds update-epss
python3 -m netscope.cli cve CVE-2025-0001
```

Feeds are cached under `.netscope/feeds`.

## API and scheduling

```bash
python3 -m netscope.cli api --host 127.0.0.1 --port 8000 --db netscope.db
python3 -m netscope.cli schedule add --target 192.168.1.0/24 --profile quick --every 60
python3 -m netscope.cli schedule list
python3 -m netscope.cli schedule daemon
```

## React frontend

```bash
cd frontend
npm install
npm run dev
```

## Docker

```bash
docker compose up --build
```

## Tests

```bash
python3 -m unittest discover -v
```
