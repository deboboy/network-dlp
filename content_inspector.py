#!/usr/bin/env python3
"""
Network DLP - Content Inspector
Pattern matching for sensitive data detection
"""

import re
import hashlib
from datetime import datetime


class ContentInspector:
    DEFAULT_PATTERNS = {
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'description': 'Credit card number (Visa, MasterCard, Amex, Discover)',
            'severity': 'critical',
            'regex': True
        },
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'description': 'US Social Security Number',
            'severity': 'critical',
            'regex': True
        },
        'ssn_nodash': {
            'pattern': r'\b\d{9}\b',
            'description': 'US Social Security Number (no dashes)',
            'severity': 'medium',
            'regex': True,
            'min_length': 9
        },
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email address',
            'severity': 'low',
            'regex': True
        },
        'phone_us': {
            'pattern': r'\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b',
            'description': 'US phone number',
            'severity': 'low',
            'regex': True
        },
        'ipv4_private': {
            'pattern': r'\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3}\b',
            'description': 'Private IPv4 address',
            'severity': 'low',
            'regex': True
        },
        'aws_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'description': 'AWS Access Key ID',
            'severity': 'critical',
            'regex': True
        },
        'aws_secret': {
            'pattern': r'(?i)aws_secret_access_key["\s:=]+[A-Za-z0-9/+=]{40}',
            'description': 'AWS Secret Access Key',
            'severity': 'critical',
            'regex': True
        },
        'api_key': {
            'pattern': r'(?i)(api[_-]?key|apikey|api_secret)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
            'description': 'Generic API Key',
            'severity': 'high',
            'regex': True
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'description': 'Private key header',
            'severity': 'critical',
            'regex': True
        },
        'password_in_url': {
            'pattern': r'[a-zA-Z]+://[^/\s:]+:[^/\s@]+@[^/\s]+',
            'description': 'Password in URL',
            'severity': 'high',
            'regex': True
        },
        'jwt': {
            'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'description': 'JSON Web Token',
            'severity': 'medium',
            'regex': True
        },
        'bearer_token': {
            'pattern': r'(?i)bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
            'description': 'Bearer token in Authorization header',
            'severity': 'high',
            'regex': True
        },
        'authorization': {
            'pattern': r'(?i)authorization:\s*[^\r\n]+',
            'description': 'Authorization header',
            'severity': 'high',
            'regex': True
        },
        'basic_auth': {
            'pattern': r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]+',
            'description': 'Basic Authentication header',
            'severity': 'high',
            'regex': True
        },
        'github_token': {
            'pattern': r'(?:gh[pousr]_[A-Za-z0-9_]{36,})',
            'description': 'GitHub Token',
            'severity': 'critical',
            'regex': True
        },
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*',
            'description': 'Slack Token',
            'severity': 'critical',
            'regex': True
        },
        'sql_injection': {
            'pattern': r'(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|delete\s+from|update\s+.*\s+set|exec\s*\(|execute\s*\()',
            'description': 'SQL Injection attempt',
            'severity': 'high',
            'regex': True
        },
        'xss_attempt': {
            'pattern': r'(?i)(<script|javascript:|on\w+\s*=|<iframe|<object|<embed)',
            'description': 'XSS attempt',
            'severity': 'high',
            'regex': True
        },
        'file_path': {
            'pattern': r'(?i)(/etc/passwd|/etc/shadow|/windows/system32|\.ssh/|\.aws/|\.env)',
            'description': 'Sensitive file path',
            'severity': 'medium',
            'regex': True
        }
    }

    def __init__(self, patterns=None):
        self.patterns = patterns or self.DEFAULT_PATTERNS
        self.compiled_patterns = {}
        self._compile_patterns()
        self.stats = {
            'packets_scanned': 0,
            'matches_found': 0
        }

    def _compile_patterns(self):
        for name, config in self.patterns.items():
            if config.get('regex', False):
                try:
                    self.compiled_patterns[name] = re.compile(config['pattern'])
                except re.error as e:
                    print(f"[!] Invalid regex for {name}: {e}")

    def inspect(self, packet_info):
        findings = []

        payload_str = packet_info.get('payload_str', '')
        if not payload_str:
            return findings

        self.stats['packets_scanned'] += 1

        for name, config in self.patterns.items():
            matches = self._check_pattern(name, config, payload_str)
            if matches:
                for match in matches:
                    finding = {
                        'type': name,
                        'description': config['description'],
                        'severity': config['severity'],
                        'matched': match,
                        'timestamp': packet_info.get('timestamp'),
                        'source_ip': packet_info.get('src_ip'),
                        'dest_ip': packet_info.get('dst_ip'),
                        'app_protocol': packet_info.get('app_protocol', 'unknown'),
                        'context': self._extract_context(payload_str, match)
                    }
                    findings.append(finding)
                    self.stats['matches_found'] += 1

        if findings:
            packet_info['dlp_findings'] = findings

        return findings

    def _check_pattern(self, name, config, content):
        matches = []

        if config.get('regex', False):
            compiled = self.compiled_patterns.get(name)
            if compiled:
                for match in compiled.finditer(content):
                    match_str = match.group(0)
                    min_len = config.get('min_length', 0)
                    if len(match_str) >= min_len:
                        matches.append(match_str[:50])
        else:
            if config['pattern'] in content:
                matches.append(config['pattern'][:50])

        return matches

    def _extract_context(self, content, matched, context_size=50):
        idx = content.find(matched)
        if idx == -1:
            return ''

        start = max(0, idx - context_size)
        end = min(len(content), idx + len(matched) + context_size)

        context = content[start:end]
        return context.replace('\n', '\\n').replace('\r', '')

    def get_stats(self):
        return self.stats


def main():
    inspector = ContentInspector()

    test_packets = [
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '10.0.0.1',
            'app_protocol': 'http',
            'payload_str': 'POST /api/login HTTP/1.1\nHost: example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\nContent-Type: application/json\n\n{"email": "user@example.com", "password": "secret123"}'
        },
        {
            'timestamp': datetime.now().isoformat(),
            'src_ip': '192.168.1.100',
            'dst_ip': '203.0.113.1',
            'app_protocol': 'smtp',
            'payload_str': 'MAIL FROM:<sender@example.com>\r\nRCPT TO:<receiver@target.org>\r\nDATA\r\nHere is my credit card: 4532015112830366 exp 12/25'
        }
    ]

    for pkt in test_packets:
        findings = inspector.inspect(pkt)
        if findings:
            print(f"\n[ALERT] {len(findings)} findings in packet from {pkt['src_ip']}")
            for f in findings:
                print(f"  - [{f['severity'].upper()}] {f['type']}: {f['description']}")
                print(f"    Matched: {f['matched']}")

    print(f"\nStats: {inspector.get_stats()}")


if __name__ == '__main__':
    main()
