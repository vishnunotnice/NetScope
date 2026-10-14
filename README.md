# NetScope

NetScope is an authorized network discovery, asset inventory, vulnerability intelligence, risk scoring, and topology platform.

## Quick start on macOS

```bash
brew install nmap
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Only scan IPs and networks for which you have explicit authorization.

## Scanning

```bash
# Discover live hosts
python3 -m netscope.cli scan 192.168.1.0/24 --profile discovery --output scan.json

# Quick service scan
python3 -m netscope.cli scan 192.168.1.0/24 --profile quick --output scan.json

# Services on ports 1–1024
python3 -m netscope.cli scan 192.168.1.0/24 --profile service --output scan.json

# Full TCP port scan
python3 -m netscope.cli scan 192.168.1.0/24 --profile full --output scan.json

# OS and service detection
python3 -m netscope.cli scan 192.168.1.10 --profile os --output scan.json
```

Use `--allow 192.168.1.0/24` to enforce an allowlist and `--max-addresses` to bound CIDR size.

## Inventory, topology, and risk

```bash
python3 -m netscope.cli inventory scan.json --db netscope.db
python3 -m netscope.cli topology scan.json > site/topology.json
python3 -m netscope.cli risk CVE-2025-0001 --cvss 9.8 --epss 0.9 --kev
python3 -m netscope.cli cve CVE-2025-0001
```

The topology output contains `nodes` and `edges` in React Flow format. Edges are intentionally not invented when no verified relationship exists.

## Vulnerability feeds

```bash
python3 -m netscope.cli feeds update-kev
python3 -m netscope.cli feeds update-epss
```

Feeds are cached under `.netscope/feeds`.

## API and scheduling

```bash
python3 -m netscope.cli api --host 127.0.0.1 --port 8000 --db netscope.db
python3 -m netscope.cli schedule add --target 192.168.1.0/24 --profile quick --every 60
python3 -m netscope.cli schedule list
python3 -m netscope.cli schedule daemon
```

API endpoints include `/api/health`, `/api/assets`, `/api/findings`, and `/api/topology`.

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
