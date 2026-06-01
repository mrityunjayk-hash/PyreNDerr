# PortForge

Advanced Python port scanner with SYN, UDP, NULL, FIN, XMAS, and ACK scans, service fingerprinting, OS detection, vulnerability checks, and multi-threaded network reconnaissance.

```text
    ____             __  ______                    
   / __ \____  _____/ /_/ ____/___  _________ ____ 
  / /_/ / __ \/ ___/ __/ /_  / __ \/ ___/ __ `/ _ \
 / ____/ /_/ / /  / /_/ __/ / /_/ / /  / /_/ /  __/
/_/    \____/_/   \__/_/    \____/_/   \__, /\___/
                                      /____/
                     Advanced Port Scanner v1.0
```

---

## Overview

PortForge is an advanced Python-based port scanner inspired by professional network reconnaissance tools. It supports multiple scanning techniques, service detection, banner grabbing, host discovery, OS fingerprinting, and basic vulnerability checks without relying on external dependencies.

Designed for cybersecurity students, penetration testers, CTF players, and security researchers, PortForge provides a lightweight alternative for understanding how network scanners operate internally.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/PortForge.git
cd PortForge
```

Verify installation:

```bash
python3 portforge.py --help
```

No pip installs required.

---

## Project Structure

```text
PortForge/
├── portforge.py
├── README.md
├── LICENSE
└── examples/
```

---

## Usage

### Basic Scan

```bash
python3 portforge.py 192.168.1.1
```

### Scan Specific Ports

```bash
python3 portforge.py 192.168.1.1 -p 22,80,443
```

### Scan Port Range

```bash
python3 portforge.py 192.168.1.1 -p 1-1000
```

### Full Port Scan

```bash
python3 portforge.py 192.168.1.1 -p -
```

### SYN Scan

```bash
sudo python3 portforge.py 192.168.1.1 -sS
```

### UDP Scan

```bash
sudo python3 portforge.py 192.168.1.1 -sU
```

### Vulnerability Detection

```bash
python3 portforge.py 192.168.1.1 --script
```

### Skip Host Discovery

```bash
python3 portforge.py 192.168.1.1 -Pn
```

### Save Results

```bash
python3 portforge.py 192.168.1.1 -o results.json
```

---

## Service Detection

PortForge includes built-in fingerprinting support for:

```text
SSH
FTP
SMTP
HTTP
HTTPS
Apache
Nginx
Microsoft IIS
MySQL
MariaDB
Redis
MongoDB
Postfix
Exim
ProFTPD
vsFTPd
```

---

## Vulnerability Checks

When using:

```bash
--script
```

PortForge performs basic NSE-style checks against detected services.

---

## Architecture

```text
portforge.py
│
├── RawScanner
│   ├── ICMP Discovery
│   ├── SYN Scanner
│   ├── ACK Scanner
│   └── Flag Scans
│
├── PortScanner
│   ├── Host Discovery
│   ├── Port Enumeration
│   ├── Banner Grabbing
│   ├── Version Detection
│   ├── Vulnerability Checks
│   └── Reporting
│
└── CLI Interface
```

---

## Performance

PortForge uses:

- ThreadPoolExecutor
- Parallel Port Enumeration
- Configurable Timing Profiles
- Randomized Scanning
- Adjustable Thread Counts

Making it suitable for scanning individual hosts as well as larger network ranges.
