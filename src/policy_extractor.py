"""
SELinux policy rule extraction
Uses sesearch to extract allow rules from the active policy
"""

import re
import subprocess
import sys


def extract_policy_rules(context):
    """Extract SELinux policy rules using sesearch"""
    print(f"Extracting policy rules for context: {context}")
    try:
        result = subprocess.run(
            ['sesearch', '--allow', '-s', context],
            capture_output=True,
            text=True,
            check=True
        )

        # Parse sesearch output
        rules = []
        for line in result.stdout.split('\n'):
            line = line.strip()
            if line.startswith('allow') and context in line:
                rule = parse_rule(line)
                if rule:
                    rules.append(rule)

        print(f"Found {len(rules)} allow rules")
        return rules

    except subprocess.CalledProcessError as e:
        print(f"Error running sesearch: {e}")
        print("Make sure setools is installed: sudo dnf install setools-console")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: sesearch not found")
        print("Install with: sudo dnf install setools-console")
        sys.exit(1)


def parse_rule(line):
    """Parse a single allow rule line"""
    # Example: allow httpd_t httpd_log_t:file { read write };
    match = re.match(r'allow\s+(\S+)\s+(\S+):(\S+)\s+\{\s*([^)]+)\s*\}', line)
    if match:
        source, target, obj_class, perms = match.groups()
        permissions = [p.strip() for p in perms.split()]
        return {
            'source': source,
            'target': target,
            'class': obj_class,
            'permissions': permissions,
            'raw': line
        }
    return None
