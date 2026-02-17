#!/usr/bin/env python3
"""
Network DLP - Packet Capture Layer (L1-L3)
Captures raw packets from network interface
"""

import sys
from scapy.all import sniff, Packet, IP, Ether, IPv6, TCP, UDP, Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
import threading
import time
from datetime import datetime


class PacketCapture:
    def __init__(self, interface='eth0', bpf_filter=''):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.running = False
        self.packet_queue = []
        self.queue_lock = threading.Lock()
        self.callbacks = []
        self.stats = {
            'packets_captured': 0,
            'bytes_captured': 0,
            'start_time': None,
            'errors': 0
        }

    def add_callback(self, callback):
        self.callbacks.append(callback)

    def _process_packet(self, packet):
        with self.queue_lock:
            self.stats['packets_captured'] += 1
            try:
                if packet.haslayer(Raw):
                    self.stats['bytes_captured'] += len(packet[Raw].load)
            except:
                pass

            parsed = self._parse_packet(packet)
            for callback in self.callbacks:
                try:
                    callback(parsed)
                except Exception as e:
                    self.stats['errors'] += 1

    def _parse_packet(self, packet):
        parsed = {
            'timestamp': datetime.now().isoformat(),
            'length': len(packet),
            'layers': []
        }

        if packet.haslayer(Ether):
            eth = packet[Ether]
            parsed['layers'].append('ethernet')
            parsed['ether'] = {
                'src': eth.src,
                'dst': eth.dst,
                'type': eth.type
            }

        if packet.haslayer(IP):
            ip = packet[IP]
            parsed['layers'].append('ipv4')
            parsed['ipv4'] = {
                'src': ip.src,
                'dst': ip.dst,
                'proto': ip.proto,
                'ttl': ip.ttl,
                'len': ip.len
            }
            parsed['src_ip'] = ip.src
            parsed['dst_ip'] = ip.dst

        if packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            parsed['layers'].append('ipv6')
            parsed['ipv6'] = {
                'src': ipv6.src,
                'dst': ipv6.dst,
                'nh': ipv6.nh
            }

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            parsed['layers'].append('tcp')
            parsed['tcp'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'flags': tcp.flags,
                'seq': tcp.seq,
                'ack': tcp.ack
            }
            parsed['src_port'] = tcp.sport
            parsed['dst_port'] = tcp.dport
            parsed['protocol'] = 'tcp'

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            parsed['layers'].append('udp')
            parsed['udp'] = {
                'sport': udp.sport,
                'dport': udp.dport
            }
            parsed['src_port'] = udp.sport
            parsed['dst_port'] = udp.dport
            parsed['protocol'] = 'udp'

        if packet.haslayer(Raw):
            raw = packet[Raw]
            parsed['layers'].append('raw')
            try:
                payload = raw.load
                if isinstance(payload, bytes):
                    parsed['payload'] = payload
                    parsed['payload_str'] = payload.decode('utf-8', errors='replace')
                    parsed['payload_size'] = len(payload)
            except:
                pass

        return parsed

    def start(self, count=None, timeout=None):
        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()
        print(f"[*] Starting packet capture on {self.interface}")
        if self.bpf_filter:
            print(f"[*] BPF filter: {self.bpf_filter}")

        sniff(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=self._process_packet,
            count=count,
            timeout=timeout,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        self.running = False
        print(f"[*] Stopped packet capture")
        print(f"[*] Stats: {self.stats}")

    def get_stats(self):
        return self.stats


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network DLP Packet Capture')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-f', '--filter', default='', help='BPF filter')
    parser.add_argument('-c', '--count', type=int, help='Number of packets')
    parser.add_argument('-t', '--timeout', type=int, help='Timeout in seconds')

    args = parser.parse_args()

    capture = PacketCapture(interface=args.interface, bpf_filter=args.filter)

    def print_packet(pkt):
        print(f"{pkt['timestamp']} | {pkt.get('src_ip', '?')} -> {pkt.get('dst_ip', '?')} | "
              f"{pkt.get('protocol', '?')}:{pkt.get('src_port', '?')} -> {pkt.get('dst_port', '?')} | "
              f"len={pkt['length']}")

    capture.add_callback(print_packet)

    try:
        capture.start(count=args.count, timeout=args.timeout)
    except KeyboardInterrupt:
        capture.stop()


if __name__ == '__main__':
    main()
