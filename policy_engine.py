#!/usr/bin/env python3
"""
Network DLP - Policy Engine and Alerting
Evaluates findings against policies and triggers actions
"""

import json
import os
import sys
from datetime import datetime
from enum import Enum


class Severity(Enum):
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


class Action(Enum):
    ALERT = 'alert'
    BLOCK = 'block'
    LOG = 'log'
    QUARANTINE = 'quarantine'


class Policy:
    def __init__(self, name, conditions, action=Action.ALERT, enabled=True):
        self.name = name
        self.conditions = conditions
        self.action = action
        self.enabled = enabled
        self.stats = {'triggered': 0}

    def evaluate(self, findings):
        if not self.enabled:
            return False

        for finding in findings:
            for condition in self.conditions:
                if self._match_condition(finding, condition):
                    self.stats['triggered'] += 1
                    return True
        return False

    def _match_condition(self, finding, condition):
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')

        finding_value = finding.get(field)
        if finding_value is None:
            return False

        if operator == 'equals':
            return finding_value == value
        elif operator == 'contains':
            return value in finding_value
        elif operator == 'regex':
            import re
            return re.search(value, str(finding_value)) is not None
        elif operator == 'in':
            return finding_value in value
        elif operator == 'gt':
            return finding_value > value
        elif operator == 'lt':
            return finding_value < value

        return False


class PolicyEngine:
    DEFAULT_POLICIES = [
        Policy(
            name='critical_data_exfiltration',
            conditions=[
                {'field': 'severity', 'operator': 'equals', 'value': 'critical'}
            ],
            action=Action.ALERT
        ),
        Policy(
            name='api_key_leak',
            conditions=[
                {'field': 'type', 'operator': 'in', 'value': ['api_key', 'aws_key', 'aws_secret', 'github_token', 'slack_token']}
            ],
            action=Action.ALERT
        ),
        Policy(
            name='auth_token_exposure',
            conditions=[
                {'field': 'type', 'operator': 'in', 'value': ['jwt', 'bearer_token', 'basic_auth', 'authorization']}
            ],
            action=Action.ALERT
        ),
        Policy(
            name='credential_leak',
            conditions=[
                {'field': 'type', 'operator': 'in', 'value': ['credit_card', 'ssn', 'password_in_url', 'private_key']}
            ],
            action=Action.ALERT
        ),
        Policy(
            name='sql_injection_detected',
            conditions=[
                {'field': 'type', 'operator': 'equals', 'value': 'sql_injection'}
            ],
            action=Action.ALERT
        ),
        Policy(
            name='xss_attempt_detected',
            conditions=[
                {'field': 'type', 'operator': 'equals', 'value': 'xss_attempt'}
            ],
            action=Action.ALERT
        ),
    ]

    def __init__(self, policies=None, config_dir='config'):
        self.policies = policies or self.DEFAULT_POLICIES
        self.config_dir = config_dir
        self.alerts = []
        self.stats = {
            'packets_evaluated': 0,
            'policies_triggered': 0,
            'alerts_generated': 0
        }

    def evaluate(self, packet_info, findings):
        self.stats['packets_evaluated'] += 1

        if not findings:
            return []

        triggered = []

        for policy in self.policies:
            if policy.evaluate(findings):
                triggered.append(policy)
                self.stats['policies_triggered'] += 1

                alert = self._create_alert(packet_info, findings, policy)
                self.alerts.append(alert)
                self.stats['alerts_generated'] += 1

        return triggered

    def _create_alert(self, packet_info, findings, policy):
        severity_values = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        max_severity = min([severity_values.get(f['severity'], 5) for f in findings])
        max_severity_name = [k for k, v in severity_values.items() if v == max_severity][0]

        alert = {
            'id': f"alert-{datetime.now().timestamp()}",
            'timestamp': datetime.now().isoformat(),
            'policy': policy.name,
            'action': policy.action.value,
            'severity': max_severity_name.upper(),
            'source_ip': packet_info.get('src_ip'),
            'dest_ip': packet_info.get('dst_ip'),
            'source_port': packet_info.get('src_port'),
            'dest_port': packet_info.get('dst_port'),
            'app_protocol': packet_info.get('app_protocol', 'unknown'),
            'findings': findings,
            'matched_count': len(findings)
        }

        return alert

    def process_alert(self, alert):
        print(f"\n{'='*60}")
        print(f"[ALERT] {alert['severity']} - {alert['policy']}")
        print(f"{'='*60}")
        print(f"Time: {alert['timestamp']}")
        print(f"Source: {alert['source_ip']}:{alert['source_port']} -> {alert['dest_ip']}:{alert['dest_port']}")
        print(f"Protocol: {alert['app_protocol']}")
        print(f"Action: {alert['action']}")
        print(f"Matches: {alert['matched_count']}")
        print(f"Findings:")
        for f in alert['findings']:
            print(f"  - [{f['severity']}] {f['type']}: {f['description']}")
            print(f"    Matched: {f['matched']}")
        print(f"{'='*60}\n")

    def get_stats(self):
        return {
            **self.stats,
            'policy_stats': {p.name: p.stats for p in self.policies}
        }

    def save_alerts(self, filepath=None):
        if filepath is None:
            filepath = os.path.join(self.config_dir, 'alerts.json')

        with open(filepath, 'a') as f:
            for alert in self.alerts:
                f.write(json.dumps(alert) + '\n')

        print(f"[*] Saved {len(self.alerts)} alerts to {filepath}")
        self.alerts = []


def main():
    from content_inspector import ContentInspector

    inspector = ContentInspector()
    engine = PolicyEngine()

    test_packet = {
        'timestamp': datetime.now().isoformat(),
        'src_ip': '192.168.1.100',
        'dst_ip': '203.0.113.1',
        'src_port': 54321,
        'dst_port': 443,
        'app_protocol': 'https',
        'payload_str': 'POST /api/v1/data HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n\n{"api_key": "sk_live_abc123xyz789", "data": "sensitive info"}'
    }

    findings = inspector.inspect(test_packet)
    triggered = engine.evaluate(test_packet, findings)

    print(f"Findings: {len(findings)}")
    print(f"Policies triggered: {len(triggered)}")

    for alert in engine.alerts:
        engine.process_alert(alert)

    print(f"\nStats: {engine.get_stats()}")


if __name__ == '__main__':
    main()
