# NetScope

NetScope is an authorized network discovery and asset-inventory tool.

## Phase 1

- Host discovery with Nmap
- Quick, service, full-TCP, and OS-detection profiles
- Hostnames, MAC addresses, vendors, ports, services, products, versions, and CPEs
- Optional OS fingerprinting with accuracy and evidence
- IP/CIDR validation, configurable address limits, and optional allowlists
- Argument-safe Nmap execution (no shell interpolation)
- JSON output for automation

Only scan systems and ranges for which you have explicit authorization.

## Local usage

Install the package in editable mode:

```bash
python3 -m pip install -e .
```

Examples:

```bash
netscope discover 192.168.1.0/24 --json
netscope scan 192.168.1.10 --profile quick --json
netscope services 10.0.0.10
netscope os 10.0.0.10 --allow 10.0.0.0/24
```

The host running NetScope must have Nmap installed and the appropriate privileges for the selected scan profile. No real scan is performed by the test suite.

## Tests

```bash
python3 -m unittest discover -v
```
