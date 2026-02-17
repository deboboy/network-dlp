# Network DLP

A network-level Data Loss Prevention (DLP) proof-of-concept that captures and inspects network traffic to detect sensitive data leakage.

## Overview

Network DLP operates at OSI layers 1-7 to monitor traffic flowing through a network interface. This POC is designed for deployment on VPS instances hosting AI agents or other services.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Network DLP Service                      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Packet     │───▶│   Protocol   │───▶│  Content     │  │
│  │  Capture     │    │   Parser     │    │  Inspector   │  │
│  │  (L1-L3)     │    │  (L4-L7)     │    │  (Patterns)  │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│         │                                        │          │
│         ▼                                        ▼          │
│  ┌──────────────┐                        ┌──────────────┐  │
│  │   libpcap    │                        │   Policy     │  │
│  │  / Scapy    │                        │   Engine     │  │
│  └──────────────┘                        └──────────────┘  │
│                                                │            │
│                                                ▼            │
│                                       ┌──────────────┐      │
│                                       │   Alerting   │      │
│                                       │   & Logging  │      │
│                                       └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | File | Description |
|-----------|------|-------------|
| Packet Capture | `packet_capture.py` | Captures raw packets from network interface using libpcap |
| Protocol Parser | `protocol_parser.py` | Identifies application protocols (HTTP, DNS, SMTP, etc.) |
| Content Inspector | `content_inspector.py` | Pattern matching for sensitive data detection |
| Policy Engine | `policy_engine.py` | Evaluates findings against policies, triggers alerts |
| Service | `dlp_service.py` | Main daemon that ties all components together |

## Detection Capabilities

The content inspector detects the following sensitive data types:

### Credentials & Secrets
- Credit card numbers (Visa, MasterCard, Amex, Discover)
- US Social Security Numbers (SSN)
- API keys (generic)
- AWS Access Key IDs
- AWS Secret Access Keys
- GitHub tokens
- Slack tokens
- Private keys (RSA, EC, DSA, OpenSSH)

### Authentication
- JWT tokens
- Bearer tokens
- Basic authentication headers
- Authorization headers
- Passwords in URLs

### Security Threats
- SQL injection attempts
- XSS attempts
- Sensitive file path references

### PII
- Email addresses
- Phone numbers
- Private IP addresses

## Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3-pip python3-scapy libpcap-dev

# CentOS/RHEL
sudo yum install -y python3-pip python3-scapy libpcap-devel
```

### Setup

1. Clone the repository:
```bash
git clone https://github.com/deboboy/network-dlp.git
cd network-dlp
```

2. Install dependencies (if not using system packages):
```bash
pip3 install scapy
```

3. Test the installation:
```bash
# Test individual components
python3 content_inspector.py
python3 policy_engine.py

# Test packet capture (requires root)
sudo python3 packet_capture.py --count 10
```

## Usage

### Quick Start

Capture 100 packets and analyze:
```bash
sudo python3 dlp_service.py --count 100
```

Run continuously:
```bash
sudo python3 dlp_service.py
```

### Command Options

```bash
python3 dlp_service.py [OPTIONS]

Options:
  -i, --interface TEXT   Network interface to capture (default: eth0)
  -c, --config TEXT     Configuration directory (default: config)
  -l, --logs TEXT       Log directory (default: logs)
  --count INTEGER       Number of packets to capture (0 = unlimited)
  --timeout INTEGER    Timeout in seconds
```

### Install as System Service

1. Copy the service file:
```bash
sudo cp config/network-dlp.service /etc/systemd/system/
```

2. Edit the service file to match your installation path:
```bash
sudo nano /etc/systemd/system/network-dlp.service
```

3. Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable network-dlp
sudo systemctl start network-dlp
```

4. Check status:
```bash
sudo systemctl status network-dlp
```

## Deployment Modes

### Passive Mode (Recommended for POC)

The service runs in passive mode using a network tap or span port. It can only detect and alert - it cannot block traffic.

```
Internet <---> [eth0] <---> DLP Service <---> Host
                    (mirror port)
```

### Inline Mode (Production)

For blocking capability, deploy in inline mode with iptables integration. This requires additional configuration.

## Configuration

### Adding Custom Patterns

Edit `content_inspector.py` and add to the `DEFAULT_PATTERNS` dictionary:

```python
'custom_pattern': {
    'pattern': r'your-regex-here',
    'description': 'Description of what this detects',
    'severity': 'high',  # critical, high, medium, low, info
    'regex': True
}
```

### Custom Policies

Edit `policy_engine.py` and add to `DEFAULT_POLICIES`:

```python
Policy(
    name='your_policy_name',
    conditions=[
        {'field': 'type', 'operator': 'equals', 'value': 'pattern_name'}
    ],
    action=Action.ALERT  # or Action.BLOCK
)
```

## Log Output

Alerts are written to:
- `logs/dlp_alerts_YYYYMMDD.jsonl` - JSON Lines format
- Console output - human-readable alerts

### Alert Format

```json
{
  "id": "alert-1234567890.123",
  "timestamp": "2026-02-17T12:00:00.000000",
  "policy": "api_key_leak",
  "action": "alert",
  "severity": "HIGH",
  "source_ip": "192.168.1.100",
  "dest_ip": "203.0.113.1",
  "source_port": 54321,
  "dest_port": 443,
  "app_protocol": "https",
  "findings": [...],
  "matched_count": 1
}
```

## Limitations

- **Encrypted Traffic**: Cannot inspect TLS/SSL-encrypted traffic without SSL interception
- **Performance**: Python-based; may not handle 10Gbps+ traffic without optimization
- **Passive Only**: Cannot block traffic in default configuration
- **Root Required**: Needs root privileges for packet capture

## Future Enhancements

- [ ] SSL/TLS interception for encrypted traffic inspection
- [ ] eBPF-based capture for higher performance
- [ ] Integration with SIEM systems (Splunk, ELK, QRadar)
- [ ] Real-time blocking via iptables/nftables
- [ ] Machine learning-based classification
- [ ] File fingerprinting for known sensitive documents

## License

MIT License

## Author

deboboy
