#!/usr/bin/env python3
"""
Network DLP - DNS Monitor
Monitors DNS queries and responses for suspicious activity
"""

import struct
import math
from collections import defaultdict
from datetime import datetime


class DNSMonitor:
    def __init__(self):
        self.stats = {
            'queries_seen': 0,
            'responses_seen': 0,
            'tunneling_suspected': 0,
            'suspicious_domains': 0
        }
        
        self.recent_queries = defaultdict(list)
        self.suspicious_patterns = []
        
        self.tld_stats = defaultdict(int)
        
    def analyze(self, packet_info):
        if not packet_info:
            return []
            
        findings = []
        
        if packet_info.get('app_protocol') != 'dns':
            return findings
            
        payload = packet_info.get('payload')
        if not payload or len(payload) < 12:
            return findings
            
        try:
            if packet_info.get('dst_port') == 53:
                findings = self._analyze_query(packet_info, payload)
            elif packet_info.get('src_port') == 53:
                findings = self._analyze_response(packet_info, payload)
        except Exception as e:
            pass
            
        return findings
        
    def _analyze_query(self, packet_info, payload):
        findings = []
        self.stats['queries_seen'] += 1
        
        try:
            transaction_id = struct.unpack('!H', payload[0:2])[0]
            flags = struct.unpack('!H', payload[2:4])[0]
            questions = struct.unpack('!H', payload[4:6])[0]
            
            qr = (flags >> 15) & 0x1
            opcode = (flags >> 11) & 0xF
            
            if qr != 0:
                return findings
                
            query_name = self._parse_dns_name(payload, 12)
            if not query_name:
                return findings
                
            query_name = query_name.lower()
            src_ip = packet_info.get('src_ip', '')
            
            self.recent_queries[src_ip].append({
                'name': query_name,
                'timestamp': datetime.now(),
                'size': len(payload)
            })
            
            if len(self.recent_queries[src_ip]) > 100:
                self.recent_queries[src_ip] = self.recent_queries[src_ip][-50:]
            
            if '.' in query_name:
                tld = query_name.split('.')[-1]
                self.tld_stats[tld] += 1
            
            if self._is_dns_tunneling(query_name, payload):
                findings.append({
                    'type': 'dns_tunneling_suspected',
                    'description': 'Potential DNS tunneling - unusual domain characteristics',
                    'severity': 'high',
                    'matched': query_name[:100],
                    'timestamp': packet_info.get('timestamp'),
                    'source_ip': src_ip,
                    'dest_ip': packet_info.get('dst_ip'),
                    'context': f'query_size={len(payload)},subdomains={query_name.count(".")}'
                })
                self.stats['tunneling_suspected'] += 1
                
            if self._is_suspicious_domain(query_name):
                findings.append({
                    'type': 'suspicious_domain',
                    'description': 'Suspicious domain pattern detected',
                    'severity': 'medium',
                    'matched': query_name[:100],
                    'timestamp': packet_info.get('timestamp'),
                    'source_ip': src_ip,
                    'dest_ip': packet_info.get('dst_ip'),
                    'context': f'tld={query_name.split(".")[-1]}'
                })
                self.stats['suspicious_domains'] += 1
                
            if self._is_data_exfiltration(query_name):
                findings.append({
                    'type': 'potential_data_exfiltration',
                    'description': 'Potential data exfiltration via DNS',
                    'severity': 'high',
                    'matched': query_name[:100],
                    'timestamp': packet_info.get('timestamp'),
                    'source_ip': src_ip,
                    'dest_ip': packet_info.get('dst_ip'),
                    'context': 'unusual_dns_query_pattern'
                })
                
        except Exception as e:
            pass
            
        return findings
        
    def _analyze_response(self, packet_info, payload):
        findings = []
        self.stats['responses_seen'] += 1
        
        try:
            if len(payload) > 512:
                findings.append({
                    'type': 'large_dns_response',
                    'description': 'Unusually large DNS response (potential DNS amplification)',
                    'severity': 'medium',
                    'matched': f'size={len(payload)}',
                    'timestamp': packet_info.get('timestamp'),
                    'source_ip': packet_info.get('src_ip'),
                    'dest_ip': packet_info.get('dst_ip'),
                    'context': f'response_size={len(payload)}'
                })
        except:
            pass
            
        return findings
        
    def _parse_dns_name(self, payload, offset):
        name = b''
        jumped = False
        jump_offset = 0
        
        i = offset
        jumps = 0
        
        while i < len(payload) and jumps < 10:
            length = payload[i]
            
            if length == 0:
                if not jumped:
                    i += 1
                break
                
            if (length & 0xC0) == 0xC0:
                if not jumped:
                    jump_offset = i + 2
                    jumped = True
                offset = struct.unpack('!H', payload[i:i+2])[0] & 0x3FFF
                i = offset
                jumps += 1
                continue
                
            i += 1
            name += payload[i:i+length] + b'.'
            i += length
            
        try:
            if jump_offset > 0:
                return name.decode('utf-8', errors='replace')
            return name.decode('utf-8', errors='replace')
        except:
            return ''
            
    def _is_dns_tunneling(self, domain, payload):
        subdomain = domain.split('.')[0] if '.' in domain else domain
        
        if len(subdomain) > 50:
            return True
            
        entropy = self._calculate_entropy(subdomain)
        if entropy > 4.0 and len(subdomain) > 20:
            return True
            
        if len(payload) > 100 and '[' not in domain and '{' not in domain:
            parts = subdomain.split('-')
            if len(parts) > 5:
                return True
                
        return False
        
    def _calculate_entropy(self, s):
        if not s:
            return 0
        from collections import Counter
        counts = Counter(s)
        length = len(s)
        entropy = 0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy
        
    def _is_suspicious_domain(self, domain):
        suspicious_tlds = ['xyz', 'top', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'work']
        suspicious_keywords = ['free', 'download', 'update', 'secure', 'login', 'verify', 'cdn']
        
        domain = domain.lower()
        
        if '.' in domain:
            tld = domain.split('.')[-1]
            if tld in suspicious_tlds:
                return True
                
        for keyword in suspicious_keywords:
            if keyword in domain and len(domain) > 20:
                return True
                
        return False
        
    def _is_data_exfiltration(self, domain):
        subdomain = domain.split('.')[0] if '.' in domain else domain
        
        if subdomain.isalnum() and len(subdomain) > 30:
            return True
            
        if subdomain.isdigit() and len(subdomain) > 20:
            return True
            
        return False
        
    def get_stats(self):
        return self.stats
        
    def get_top_tlds(self, limit=10):
        return sorted(self.tld_stats.items(), key=lambda x: x[1], reverse=True)[:limit]


def main():
    import time
    from packet_capture import PacketCapture
    from protocol_parser import ProtocolParser
    
    capture = PacketCapture(interface='eth0', bpf_filter='udp port 53')
    parser = ProtocolParser()
    dns_monitor = DNSMonitor()
    
    def process(pkt):
        parsed = parser.parse(pkt)
        findings = dns_monitor.analyze(parsed)
        if findings:
            print(f"\n[DNS ALERT] {pkt.get('src_ip')} -> {pkt.get('dst_ip')}")
            for f in findings:
                print(f"  [{f['severity']}] {f['type']}: {f['matched']}")
    
    capture.add_callback(process)
    
    print("[*] DNS Monitor - capturing DNS queries for 30 seconds")
    t = __import__('threading').Thread(target=capture.start, args=(0, 30))
    t.daemon = True
    t.start()
    
    time.sleep(32)
    
    print(f"\n--- DNS Stats ---")
    print(dns_monitor.get_stats())
    print(f"\nTop TLDs: {dns_monitor.get_top_tlds(5)}")


if __name__ == '__main__':
    main()
