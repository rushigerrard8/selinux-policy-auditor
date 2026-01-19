"""
Debug logging utilities
"""

import json
from datetime import datetime


class DebugLogger:
    def __init__(self, log_file="/tmp/selinux_prober_debug.log"):
        self.log_file = log_file
        self.enabled = True

    def log(self, message, data=None):
        """Log a debug message with optional data"""
        if not self.enabled:
            return

        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        log_entry = {
            'timestamp': timestamp,
            'message': message,
        }

        if data:
            log_entry['data'] = data

        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Failed to write log: {e}")

    def log_event(self, event, context=""):
        """Log a captured event"""
        self.log(f"Event captured: {context}", {
            'pid': event.get('pid'),
            'comm': event.get('comm'),
            'tclass': event.get('tclass'),
            'requested': hex(event.get('requested', 0)),
        })

    def log_policy_rule(self, rule):
        """Log a policy rule"""
        self.log("Policy rule", {
            'source': rule['source'],
            'target': rule['target'],
            'class': rule['class'],
            'permissions': rule['permissions']
        })

    def clear(self):
        """Clear the log file"""
        try:
            open(self.log_file, 'w').close()
        except:
            pass

    def dump_summary(self):
        """Print summary of what was logged"""
        try:
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            print(f"\nDebug log written to: {self.log_file}")
            print(f"Total log entries: {len(lines)}")
            print(f"\nTo view: cat {self.log_file} | jq")
        except:
            pass
