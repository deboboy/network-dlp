#!/usr/bin/env python3
"""
Network DLP - Protocol Parser (L4-L7)
Identifies and parses application-layer protocols
"""

import re
from urllib.parse import urlparse
import struct


class ProtocolParser:
    KNOWN_PORTS = {
        20: 'ftp-data',
        21: 'ftp',
        22: 'ssh',
        23: 'telnet',
        25: 'smtp',
        53: 'dns',
        80: 'http',
        110: 'pop3',
        143: 'imap',
        443: 'https',
        465: 'smtps',
        587: 'smtp',
        993: 'imaps',
        995: 'pop3s',
        3306: 'mysql',
        5432: 'postgresql',
        6379: 'redis',
        8080: 'http-proxy',
        8443: 'https-alt',
        9200: 'elasticsearch',
        27017: 'mongodb',
    }

    def __init__(self):
        self.http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'CONNECT']
        self.dns_opcodes = {0: 'query', 1: 'inverse', 2: 'status'}

    def parse(self, packet_info):
        if not packet_info:
            return packet_info

        protocol = packet_info.get('protocol', '').lower()
        src_port = packet_info.get('src_port')
        dst_port = packet_info.get('dst_port')
        payload = packet_info.get('payload')

        inferred = self._infer_protocol(protocol, src_port, dst_port, payload)
        packet_info['app_protocol'] = inferred

        if inferred == 'http':
            self._parse_http(packet_info, payload)
        elif inferred == 'dns':
            self._parse_dns(packet_info, payload)
        elif inferred == 'smtp':
            self._parse_smtp(packet_info, payload)

        return packet_info

    def _infer_protocol(self, protocol, src_port, dst_port, payload):
        if protocol != 'tcp' and protocol != 'udp':
            return 'unknown'

        port = dst_port or src_port

        if port in self.KNOWN_PORTS:
            return self.KNOWN_PORTS[port]

        if payload and len(payload) > 4:
            if payload[:4] in self.http_methods:
                return 'http'

        return 'unknown'

    def _parse_http(self, packet_info, payload):
        if not payload:
            return

        packet_info['http'] = {}

        try:
            payload_str = payload.decode('utf-8', errors='replace')
            lines = payload_str.split('\r\n')

            if not lines:
                return

            first_line = lines[0].strip()
            parts = first_line.split(' ')

            if len(parts) >= 2:
                if parts[0] in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT']:
                    packet_info['http']['method'] = parts[0]
                    packet_info['http']['uri'] = parts[1] if len(parts) > 1 else ''
                    if parts[1].startswith('http'):
                        parsed = urlparse(parts[1])
                        packet_info['http']['host'] = parsed.netloc
                        packet_info['http']['path'] = parsed.path
                elif parts[0].startswith('HTTP/'):
                    packet_info['http']['status_code'] = int(parts[1]) if len(parts) > 1 else 0
                    packet_info['http']['status_text'] = parts[2] if len(parts) > 2 else ''

            headers = {}
            for line in lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()

            if 'host' in headers:
                packet_info['http']['host'] = headers['host']
            if 'user-agent' in headers:
                packet_info['http']['user_agent'] = headers['user-agent']
            if 'content-type' in headers:
                packet_info['http']['content_type'] = headers['content-type']

            packet_info['http']['headers'] = headers

            if 'uri' in packet_info['http']:
                packet_info['url'] = packet_info['http'].get('host', '') + packet_info['http']['uri']

        except Exception as e:
            packet_info['http']['parse_error'] = str(e)

    def _parse_dns(self, packet_info, payload):
        if not payload or len(payload) < 12:
            return

        packet_info['dns'] = {}

        try:
            transaction_id = struct.unpack('!H', payload[0:2])[0]
            flags = struct.unpack('!H', payload[2:4])[0]
            questions = struct.unpack('!H', payload[4:6])[0]
            answers = struct.unpack('!H', payload[6:8])[0]

            opcode = (flags >> 11) & 0xF
            qr = (flags >> 15) & 0x1

            packet_info['dns']['transaction_id'] = transaction_id
            packet_info['dns']['opcode'] = self.dns_opcodes.get(opcode, 'unknown')
            packet_info['dns']['qr'] = 'response' if qr == 1 else 'query'
            packet_info['dns']['questions'] = questions
            packet_info['dns']['answers'] = answers

            query_name = self._parse_dns_name(payload, 12)
            if query_name:
                packet_info['dns']['query_name'] = query_name

            qtype_offset = 12 + len(query_name) + 1
            if len(payload) >= qtype_offset + 2:
                qtype = struct.unpack('!H', payload[qtype_offset:qtype_offset+2])[0]
                packet_info['dns']['query_type'] = self._dns_qtype_str(qtype)

        except Exception as e:
            packet_info['dns']['parse_error'] = str(e)

    def _parse_dns_name(self, payload, offset):
        name = b''
        original_offset = offset

        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                break
            if (length & 0xC0) == 0xC0:
                break
            offset += 1
            name += payload[offset:offset+length] + b'.'
            offset += length

        try:
            return name.decode('utf-8', errors='replace')
        except:
            return ''

    def _dns_qtype_str(self, qtype):
        qtypes = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV'
        }
        return qtypes.get(qtype, f'未知({qtype})')

    def _parse_smtp(self, packet_info, payload):
        if not payload:
            return

        packet_info['smtp'] = {}

        try:
            payload_str = payload.decode('utf-8', errors='replace')
            lines = payload_str.split('\r\n')

            for line in lines[:10]:
                line = line.strip()
                if line.startswith('MAIL FROM:'):
                    packet_info['smtp']['mail_from'] = line[10:].strip().strip('<>')
                elif line.startswith('RCPT TO:'):
                    if 'rcpt_to' not in packet_info['smtp']:
                        packet_info['smtp']['rcpt_to'] = []
                    packet_info['smtp']['rcpt_to'].append(line[8:].strip().strip('<'))
                elif line.startswith('AUTH '):
                    packet_info['smtp']['auth'] = line[5:].strip()
                elif line.startswith('220'):
                    packet_info['smtp']['banner'] = line[4:].strip()
                elif line.startswith('530'):
                    packet_info['smtp']['auth_required'] = True

        except Exception as e:
            packet_info['smtp']['parse_error'] = str(e)


def main():
    from packet_capture import PacketCapture

    parser = ProtocolParser()

    def process(pkt):
        parsed = parser.parse(pkt)
        if parsed.get('app_protocol') != 'unknown':
            print(f"[{parsed['timestamp']}] {parsed.get('src_ip')} -> {parsed.get('dst_ip')} | "
                  f"{parsed['app_protocol']}")

    capture = PacketCapture(interface='eth0', bpf_filter='tcp or udp')
    capture.add_callback(process)

    print("[*] Protocol parser - capturing 50 packets")
    capture.start(count=50, timeout=30)


if __name__ == '__main__':
    main()
