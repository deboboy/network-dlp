#!/usr/bin/env python3
"""
Network DLP - HTTP Interceptor for AI Agents
Intercepts outbound HTTP/HTTPS requests from AI agents for DLP inspection
"""

import json
import re
import os
import sys
import time
import threading
from datetime import datetime
from collections import defaultdict
from functools import wraps

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False


class HTTPInterceptor:
    DEFAULT_PATTERNS = {
        'api_key': {
            'pattern': r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
            'severity': 'high'
        },
        'auth_token': {
            'pattern': r'(?i)(authorization|bearer|token)["\s:=]+["\']?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)',
            'severity': 'high'
        },
        'password': {
            'pattern': r'(?i)(password|passwd|pwd)["\s:=]+["\']?([^\s"\'<>]+)',
            'severity': 'high'
        },
        'private_key': {
            'pattern': r'-----BEGIN\s+(RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----',
            'severity': 'critical'
        },
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            'severity': 'critical'
        },
        'aws_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'severity': 'critical'
        },
        'github_token': {
            'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'severity': 'critical'
        },
    }

    def __init__(self, log_file='logs/agent_requests.jsonl', patterns=None, alert_callback=None):
        self.log_file = log_file
        self.patterns = patterns or self.DEFAULT_PATTERNS
        self.alert_callback = alert_callback
        self.compiled_patterns = {}
        self.stats = {
            'requests_intercepted': 0,
            'sensitive_data_found': 0,
            'alerts_generated': 0
        }
        
        os.makedirs(os.path.dirname(log_file) if os.path.dirname(log_file) else 'logs', exist_ok=True)
        
        self._compile_patterns()
        
    def _compile_patterns(self):
        for name, config in self.patterns.items():
            try:
                self.compiled_patterns[name] = re.compile(config['pattern'])
            except re.error:
                pass
                
    def _scan_content(self, content):
        findings = []
        if not content:
            return findings
            
        content_str = str(content)[:10000]
        
        for name, config in self.patterns.items():
            compiled = self.compiled_patterns.get(name)
            if compiled:
                for match in compiled.finditer(content_str):
                    findings.append({
                        'type': name,
                        'severity': config['severity'],
                        'matched': match.group(0)[:100]
                    })
                    
        return findings
        
    def _log_request(self, method, url, headers, body, findings):
        entry = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'url': url,
            'headers': {k: v for k, v in headers.items() if k.lower() not in ['authorization', 'cookie']},
            'findings': findings,
            'has_sensitive_data': len(findings) > 0
        }
        
        if body:
            entry['body_size'] = len(body)
            
        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
            
        self.stats['requests_intercepted'] += 1
        
        if findings:
            self.stats['sensitive_data_found'] += len(findings)
            self.stats['alerts_generated'] += 1
            
            if self.alert_callback:
                self.alert_callback(entry, findings)
                
    def wrap_requests_session(self):
        if not REQUESTS_AVAILABLE:
            return None
            
        import requests
        interceptor = self
        
        original_request = requests.Session.request
        
        @wraps(original_request)
        def intercepted_request(self, method, url, **kwargs):
            headers = kwargs.get('headers', {}) or {}
            body = kwargs.get('data') or kwargs.get('json')
            
            findings = []
            
            body_str = json.dumps(body) if body else ''
            scan_content = str(url) + str(headers) + body_str
            findings = interceptor._scan_content(scan_content)
            
            interceptor._log_request(method, url, headers, body, findings)
            
            return original_request(self, method, url, **kwargs)
            
        requests.Session.request = intercepted_request
        return True
        
    def wrap_httpx_client(self):
        if not HTTPX_AVAILABLE:
            return None
            
        import httpx
        interceptor = self
        
        original_request = httpx.Client.request
        
        @wraps(original_request)
        def intercepted_request(self, method, url, **kwargs):
            headers = kwargs.get('headers', {}) or {}
            body = kwargs.get('content') or kwargs.get('json')
            
            findings = []
            
            scan_content = str(url) + str(headers) + str(body)
            findings = interceptor._scan_content(scan_content)
            
            interceptor._log_request(method, url, headers, body, findings)
            
            return original_request(method, url, **kwargs)
            
        httpx.Client.request = intercepted_request
        return True
        
    def wrap_urlopen(self):
        import urllib.request
        interceptor = self
        
        original_urlopen = urllib.request.urlopen
        
        @wraps(original_urlopen)
        def intercepted_urlopen(url, **kwargs):
            findings = interceptor._scan_content(str(url))
            interceptor._log_request('GET', str(url), {}, None, findings)
            
            return original_urlopen(url, **kwargs)
            
        urllib.request.urlopen = intercepted_urlopen
        return True
        
    def install(self):
        installed = []
        
        if self.wrap_requests_session():
            installed.append('requests')
        if self.wrap_httpx_client():
            installed.append('httpx')
        if self.wrap_urlopen():
            installed.append('urllib')
            
        return installed
        
    def get_stats(self):
        return self.stats
        
    def get_recent_logs(self, count=10):
        if not os.path.exists(self.log_file):
            return []
            
        with open(self.log_file, 'r') as f:
            lines = f.readlines()
            
        return [json.loads(line) for line in lines[-count:]]


def alert_handler(entry, findings):
    print(f"\n{'='*60}")
    print(f"[AGENT DLP ALERT] {len(findings)} sensitive item(s) found")
    print(f"{'='*60}")
    print(f"Method: {entry['method']}")
    print(f"URL: {entry['url']}")
    print(f"Findings:")
    for f in findings:
        print(f"  - [{f['severity'].upper()}] {f['type']}: {f['matched'][:50]}")
    print(f"{'='*60}\n")


def test_interceptor():
    interceptor = HTTPInterceptor(log_file='logs/test_agent_requests.jsonl', alert_callback=alert_handler)
    
    installed = interceptor.install()
    print(f"[*] Installed interceptor for: {', '.join(installed) if installed else 'none'}")
    
    if not REQUESTS_AVAILABLE:
        print("[!] requests library not available")
        return
        
    print("\n[*] Making test requests...")
    
    import requests
    
    test_requests = [
        ('GET', 'https://api.github.com/users/octocat', None),
        ('POST', 'https://httpbin.org/post', {'api_key': 'sk_live_abc123defghijklmnop', 'password': 'secret123'}),
    ]
    
    for method, url, data in test_requests:
        print(f"  {method} {url}")
        try:
            if method == 'GET':
                requests.get(url, timeout=5)
            else:
                requests.post(url, json=data, timeout=5)
        except Exception as e:
            print(f"    Error: {e}")
            
    print(f"\n--- Stats ---")
    print(interceptor.get_stats())
    
    print(f"\n--- Recent Logs ---")
    for log in interceptor.get_recent_logs(3):
        print(f"{log['timestamp']} | {log['method']} {log['url'][:50]} | findings: {len(log['findings'])}")


if __name__ == '__main__':
    test_interceptor()
