# SentinelScan

Professional web security testing and reconnaissance tool.

## Features

- **HTTP Security Headers Analysis** - Evaluates security header configuration
- **Port Scanner** - Multi-threaded TCP port scanning with service detection
- **XSS Scanner** - Detects reflected Cross-Site Scripting vulnerabilities
- **SQL Injection Scanner** - Error-based SQL injection detection
- **Subdomain Finder** - DNS-based subdomain enumeration

## Requirements

- Python 3.8 or higher
- pip (Python package manager)
- Network access to target systems

## Installation

### 1. Clone Repository

```bash
git clone <repository-url>
cd sentinel_scan
```

### 2. Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Usage

### HTTP Security Headers

Check security headers configuration:

```bash
python main.py headers --url https://example.com
```

### Port Scanning

Scan for open ports:

```bash
# Scan default range (1-1000)
python main.py portscan --target example.com

# Scan specific ports
python main.py portscan --target 192.168.1.1 --ports 80,443,8080

# Scan port range
python main.py portscan --target localhost --ports 1-65535
```

### XSS Vulnerability Scan

Test for Cross-Site Scripting vulnerabilities:

```bash
python main.py xss --url https://example.com/search?q=test
```

### SQL Injection Scan

Test for SQL injection vulnerabilities:

```bash
python main.py sqli --url https://example.com/login
```

### Subdomain Enumeration

Discover subdomains:

```bash
# Basic scan
python main.py subdomain --domain example.com

# Custom wordlist
python main.py subdomain --domain example.com --wordlist subdomains.txt

# Adjust threads
python main.py subdomain --domain example.com --threads 20

# Export results
python main.py subdomain --domain example.com --output results.txt
```

## Command Reference

| Command | Description | Required Args | Optional Args |
|---------|-------------|---------------|---------------|
| `headers` | Security header analysis | `--url` | - |
| `portscan` | Port scanning | `--target` | `--ports` |
| `xss` | XSS vulnerability scan | `--url` | - |
| `sqli` | SQL injection scan | `--url` | - |
| `subdomain` | Subdomain enumeration | `--domain` | `--wordlist`, `--threads`, `--output` |

## Logging

All scan activities are logged to `logs/` directory with timestamps.

## Disclaimer

**IMPORTANT:** This tool is for educational and authorized security testing only.

- Only use on systems you own or have explicit permission to test
- Unauthorized testing is illegal and unethical
- The authors are not responsible for misuse

## License

See LICENSE file for details.

## Contributing

Contributions welcome. Please follow standard Python conventions and include tests.

For detailed usage, see `USAGE.md`.

## Basic Usage

```bash
python main.py --help
```

## Reporting & Logs

Test results are shown directly in the terminal with colored output.

- Logs are stored in the `logs/` folder.

## Legal Notice

This tool is developed for **legal and ethical** penetration testing only.
Use it **only** on systems you own or have explicit permission to test.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push the branch (`git push origin feature/new-feature`)
5. Open a Pull Request

## License

MIT License

## Author

Ulku Bayraktar - [@bayraktarulku](https://github.com/bayraktarulku)
