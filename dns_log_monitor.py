#!/usr/bin/env python3
"""
Network DLP - DNS Log Monitor
Monitors DNS queries via systemd-resolved journal logs
"""

import subprocess
import re
import time
from datetime import datetime
from collections import defaultdict


class DNSLogMonitor:
    def __init__(self):
        self.stats = {
            'queries_processed': 0,
            'tunneling_suspected': 0,
            'suspicious_domains': 0,
            'data_exfiltration': 0
        }
        
        self.recent_queries = defaultdict(list)
        self.tld_stats = defaultdict(int)
        
    def _calculate_entropy(self, s):
        if not s:
            return 0
        from collections import Counter
        counts = Counter(s)
        length = len(s)
        entropy = 0
        for count in counts.values():
            p = count / length
            entropy -= p * (p.bit_length() - 1 if p > 0 else 0)
            entropy -= p * (1 / p if p > 0 else 0)
        return entropy
        
    def _calculate_shannon_entropy(self, s):
        if not s:
            return 0
        from collections import Counter
        counts = Counter(s)
        length = len(s)
        entropy = 0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        import math
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy += p * math.log2(p)
        return abs(entropy)
        
    def _is_suspicious(self, query):
        findings = []
        
        # Suspicious TLDs
        suspicious_tlds = ['xyz', 'top', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link']
        tld = query.split('.')[-1] if '.' in query else ''
        if tld in suspicious_tlds:
            findings.append(('suspicious_tld', 'high', f'suspicious TLD: {tld}'))
            
        # Long subdomains (potential tunneling)
        parts = query.split('.')
        if len(parts) > 1:
            subdomain = parts[0]
            if len(subdomain) > 40:
                findings.append(('long_subdomain', 'high', f'very long subdomain: {len(subdomain)} chars'))
            elif len(subdomain) > 25:
                entropy = self._calculate_shannon_entropy(subdomain)
                if entropy > 4.0:
                    findings.append(('high_entropy', 'medium', f'high entropy: {entropy:.2f}'))
                    
        # Data exfiltration patterns (long alphanumeric strings)
        if len(parts) > 1:
            subdomain = parts[0]
            if subdomain.isalnum() and len(subdomain) > 30:
                findings.append(('data_exfil', 'critical', 'potential data exfiltration'))
            elif subdomain.isdigit() and len(subdomain) > 20:
                findings.append(('data_exfil', 'critical', 'numeric data in query'))
                
        # Suspicious keywords
        suspicious_keywords = ['update', 'secure', 'login', 'verify', 'auth', 'token', 'api', 'cloud']
        for keyword in suspicious_keywords:
            if keyword in query and len(query) > 25:
                findings.append(('suspicious_keyword', 'medium', f'keyword: {keyword}'))
                break
                
        return findings
        
    def parse_log_line(self, line):
        query = None
        result = None
        
        # Match query patterns
        # Example: "query A example.com. IN 1.2.3.4"
        query_match = re.search(r'query:\s+(A|AAAA|CNAME|MX|TXT)?\s*(\S+)\.', line)
        if query_match:
            query = query_match.group(2)
            
        # Match result patterns  
        # Example: "example.com: 1.2.3.4"
        result_match = re.search(r'(\S+):\s+(\d+\.\d+\.\d+\.\d+)', line)
        if result_match:
            result = result_match.group(1)
            
        return query, result
        
    def monitor(self, duration=60):
        print(f"[*] Monitoring DNS logs for {duration} seconds...")
        
        last_position = 0
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                # Get recent journal entries
                result = subprocess.run(
                    ['journalctl', '-u', 'systemd-resolved', '-n', '50', '--no-pager'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                lines = result.stdout.split('\n')
                
                for line in lines[last_position:]:
                    if 'query:' in line.lower() or 'GOT' in line.upper():
                        query, result_ip = self.parse_log_line(line)
                        
                        if query and query not in ['[zero]']:
                            self.stats['queries_processed'] += 1
                            
                            findings = self._is_suspicious(query)
                            
                            if findings:
                                for ftype, severity, desc in findings:
                                    print(f"\n[DNS ALERT] {query}")
                                    print(f"  [{severity.upper()}] {ftype}: {desc}")
                                    
                                    if ftype in ['tunneling_suspected', 'data_exfil', 'long_subdomain']:
                                        self.stats['tunneling_suspected'] += 1
                                    elif ftype == 'suspicious_tld':
                                        self.stats['suspicious_domains'] += 1
                                    elif ftype == 'data_exfil':
                                        self.stats['data_exfiltration'] += 1
                                    
                                    # Track TLD
                                    if '.' in query:
                                        tld = query.split('.')[-1]
                                        self.tld_stats[tld] += 1
                                        
                last_position = len(lines)
                
            except Exception as e:
                print(f"  Note: {e}")
                
            time.sleep(2)
            
        return self.stats
        
    def get_stats(self):
        return self.stats
        
    def get_top_tlds(self, limit=10):
        return sorted(self.tld_stats.items(), key=lambda x: x[1], reverse=True)[:limit]


def main():
    monitor = DNSLogMonitor()
    stats = monitor.monitor(duration=30)
    
    print(f"\n--- DNS Log Monitor Stats ---")
    print(f"Queries: {stats['queries_processed']}")
    print(f"Tunneling suspected: {stats['tunneling_suspected']}")
    print(f"Suspicious domains: {stats['suspicious_domains']}")
    print(f"Data exfiltration: {stats['data_exfiltration']}")
    print(f"Top TLDs: {monitor.get_top_tlds(5)}")


if __name__ == '__main__':
    main()
