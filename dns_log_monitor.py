#!/usr/bin/env python3
"""
Network DLP - DNS Log Monitor
Monitors DNS queries via dnsmasq log file
"""

import os
import re
import time
from datetime import datetime
from collections import defaultdict


class DNSLogMonitor:
    def __init__(self, log_file='/var/log/dnsmasq.log'):
        self.log_file = log_file
        self.stats = {
            'queries_processed': 0,
            'tunneling_suspected': 0,
            'suspicious_domains': 0,
            'data_exfiltration': 0
        }
        
        self.recent_queries = defaultdict(list)
        self.tld_stats = defaultdict(int)
        self.last_position = 0
        self._ensure_file_exists()
        
    def _ensure_file_exists(self):
        if not os.path.exists(self.log_file):
            open(self.log_file, 'a').close()
            
    def _calculate_shannon_entropy(self, s):
        if not s:
            return 0
        from collections import Counter
        import math
        counts = Counter(s)
        length = len(s)
        entropy = 0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy += p * math.log2(p)
        return abs(entropy)
        
    def _is_suspicious(self, query):
        findings = []
        
        if not query:
            return findings
            
        query = query.strip().lower()
        
        # Suspicious TLDs
        suspicious_tlds = ['xyz', 'top', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link', 'buzz']
        tld = query.split('.')[-1] if '.' in query else ''
        if tld in suspicious_tlds:
            findings.append(('suspicious_tld', 'high', f'suspicious TLD: {tld}'))
            
        # Long subdomains (potential tunneling)
        parts = query.split('.')
        if len(parts) > 1:
            subdomain = parts[0]
            if len(subdomain) > 50:
                findings.append(('long_subdomain', 'high', f'very long subdomain: {len(subdomain)} chars'))
            elif len(subdomain) > 30:
                entropy = self._calculate_shannon_entropy(subdomain)
                if entropy > 4.0:
                    findings.append(('high_entropy', 'medium', f'high entropy: {entropy:.2f}'))
                    
        # Data exfiltration patterns
        if len(parts) > 1:
            subdomain = parts[0]
            if subdomain.isalnum() and len(subdomain) > 30:
                findings.append(('data_exfil', 'critical', 'potential data exfiltration'))
            elif subdomain.isdigit() and len(subdomain) > 25:
                findings.append(('data_exfil', 'critical', 'numeric data in query'))
                
        # Suspicious keywords in long domains
        suspicious_keywords = ['update', 'secure', 'login', 'verify', 'auth', 'token', 'api', 'cloud', 'service']
        for keyword in suspicious_keywords:
            if keyword in query and len(query) > 25:
                findings.append(('suspicious_keyword', 'low', f'keyword: {keyword}'))
                break
                
        return findings
        
    def parse_log_line(self, line):
        query = None
        
        # Match: query[A] domain.com from IP
        match = re.search(r'query\[(\w+)\]\s+(\S+)\s+from', line)
        if match:
            query = match.group(2)
            
        return query
    
    def check_new_queries(self):
        findings = []
        
        try:
            with open(self.log_file, 'r') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                self.last_position = f.tell()
                
            for line in new_lines:
                query = self.parse_log_line(line)
                
                if query:
                    self.stats['queries_processed'] += 1
                    self.tld_stats[query.split('.')[-1] if '.' in query else ''] += 1
                    
                    findings = self._is_suspicious(query)
                    
                    if findings:
                        for ftype, severity, desc in findings:
                            alert = {
                                'type': f'dns_{ftype}',
                                'description': desc,
                                'severity': severity,
                                'matched': query,
                                'timestamp': datetime.now().isoformat(),
                                'source': 'dnsmasq'
                            }
                            findings.append(alert)
                            
                            if ftype in ['tunneling_suspected', 'long_subdomain', 'high_entropy']:
                                self.stats['tunneling_suspected'] += 1
                            elif ftype == 'suspicious_tld':
                                self.stats['suspicious_domains'] += 1
                            elif ftype == 'data_exfil':
                                self.stats['data_exfiltration'] += 1
                                
                            print(f"\n[DNS ALERT] {query}")
                            print(f"  [{severity.upper()}] {ftype}: {desc}")
                            
        except Exception as e:
            print(f"Error reading log: {e}")
            
        return findings
        
    def monitor(self, duration=60, poll_interval=2):
        print(f"[*] Monitoring DNS log ({self.log_file}) for {duration} seconds...")
        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            self.check_new_queries()
            time.sleep(poll_interval)
            
        return self.stats
        
    def get_stats(self):
        return self.stats
        
    def get_top_tlds(self, limit=10):
        return sorted(self.tld_stats.items(), key=lambda x: x[1], reverse=True)[:limit]


def main():
    monitor = DNSLogMonitor()
    
    # Initial check
    monitor.check_new_queries()
    
    print("=== Testing DNS monitoring ===")
    print("Making some DNS queries...\n")
    
    # Make some test queries
    import subprocess
    for domain in ['google.com', 'github.com', 'openai.com']:
        subprocess.run(['nslookup', domain], capture_output=True)
        
    time.sleep(2)
    
    # Check for new queries
    print("\n=== Checking for queries ===")
    stats = monitor.check_new_queries()
    
    print(f"\n--- DNS Log Monitor Stats ---")
    print(f"Queries: {monitor.stats['queries_processed']}")
    print(f"Tunneling suspected: {monitor.stats['tunneling_suspected']}")
    print(f"Suspicious domains: {monitor.stats['suspicious_domains']}")
    print(f"Data exfiltration: {monitor.stats['data_exfiltration']}")
    print(f"Top TLDs: {monitor.get_top_tlds(5)}")


if __name__ == '__main__':
    main()
