#!/usr/bin/env python3
"""
Network DLP - Main Service Daemon
Ties together packet capture, protocol parsing, content inspection, and policy engine
"""

import os
import sys
import signal
import time
import json
import threading
from datetime import datetime
from collections import deque

from packet_capture import PacketCapture
from protocol_parser import ProtocolParser
from content_inspector import ContentInspector
from policy_engine import PolicyEngine


class DLPService:
    def __init__(self, interface='eth0', config_dir='config', log_dir='logs'):
        self.interface = interface
        self.config_dir = config_dir
        self.log_dir = log_dir

        os.makedirs(config_dir, exist_ok=True)
        os.makedirs(log_dir, exist_ok=True)

        self.capture = PacketCapture(interface=interface, bpf_filter='tcp or udp')
        self.parser = ProtocolParser()
        self.inspector = ContentInspector()
        self.engine = PolicyEngine(config_dir=config_dir)

        self.running = False
        self.start_time = None
        self.alert_queue = deque(maxlen=1000)
        self.stats = {
            'packets_processed': 0,
            'bytes_processed': 0,
            'alerts_generated': 0,
            'errors': 0
        }

        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        print("\n[*] Shutting down DLP service...")
        self.running = False

    def _process_packet(self, packet_info):
        try:
            self.stats['packets_processed'] += 1
            if packet_info.get('payload_size'):
                self.stats['bytes_processed'] += packet_info['payload_size']

            parsed = self.parser.parse(packet_info)
            findings = self.inspector.inspect(parsed)

            if findings:
                self.engine.evaluate(parsed, findings)
                self.stats['alerts_generated'] += len(self.engine.alerts)

                for alert in self.engine.alerts:
                    self.alert_queue.append(alert)
                    self.engine.process_alert(alert)
                    self._log_alert(alert)

        except Exception as e:
            self.stats['errors'] += 1
            print(f"[!] Error processing packet: {e}")

    def _log_alert(self, alert):
        log_file = os.path.join(self.log_dir, f"dlp_alerts_{datetime.now().strftime('%Y%m%d')}.jsonl")
        with open(log_file, 'a') as f:
            f.write(json.dumps(alert) + '\n')

    def start(self, count=None, timeout=None):
        print(f"""
{'='*60}
  Network DLP Service - Starting
{'='*60}
Interface: {self.interface}
Config: {self.config_dir}
Logs: {self.log_dir}
Protocols: TCP, UDP
Detection: Pattern matching + Policy engine
{'='*60}
""")

        self.running = True
        self.start_time = datetime.now()
        self.capture.add_callback(self._process_packet)

        print(f"[*] Starting packet capture on {self.interface}")
        print(f"[*] Press Ctrl+C to stop\n")

        try:
            self.capture.start(count=count, timeout=timeout)
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            print(f"[!] Capture error: {e}")
            self.stop()

    def stop(self):
        self.running = False
        self.capture.stop()
        self._print_stats()

    def _print_stats(self):
        duration = datetime.now() - self.start_time if self.start_time else 0

        print(f"""
{'='*60}
  Network DLP Service - Statistics
{'='*60}
Uptime: {duration}
Packets Processed: {self.stats['packets_processed']}
Bytes Processed: {self.stats['bytes_processed']:,}
Alerts Generated: {self.stats['alerts_generated']}
Errors: {self.stats['errors']}

Capture Stats:
{json.dumps(self.capture.get_stats(), indent=2)}

Inspector Stats:
{json.dumps(self.inspector.get_stats(), indent=2)}

Engine Stats:
{json.dumps(self.engine.get_stats(), indent=2)}
{'='*60}
""")

        if self.engine.alerts:
            self.engine.save_alerts(os.path.join(self.log_dir, 'alerts.json'))


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Network DLP Service')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface to capture')
    parser.add_argument('-c', '--config', default='config', help='Configuration directory')
    parser.add_argument('-l', '--logs', default='logs', help='Log directory')
    parser.add_argument('--count', type=int, help='Number of packets to capture (0 = unlimited)')
    parser.add_argument('--timeout', type=int, help='Timeout in seconds')

    args = parser.parse_args()

    service = DLPService(
        interface=args.interface,
        config_dir=args.config,
        log_dir=args.logs
    )

    service.start(count=args.count, timeout=args.timeout)


if __name__ == '__main__':
    main()
