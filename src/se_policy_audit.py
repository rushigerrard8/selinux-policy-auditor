#!/usr/bin/env python3
"""
AVC Prober - Direct Access Vector Cache Monitoring

This is a clean, focused tool that directly probes the SELinux AVC
to understand what permissions are actually being granted.

Usage:
    python3 avc_prober.py analyze <context>
"""

import sys
import subprocess
from ebpf_avc_probe import EBPFAVCProbe
from policy_extractor import extract_policy_rules
from selinux_mappings import get_class_name, decode_permissions
from debug_logger import DebugLogger


def get_pids_for_context(context):
    """Get all PIDs running with the specified SELinux context"""
    try:
        result = subprocess.run(['ps', '-eZ'], capture_output=True, text=True, check=True)
        pids = set()
        for line in result.stdout.splitlines():
            if context in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        pid = int(parts[1])
                        pids.add(pid)
                    except ValueError:
                        continue
        return pids
    except subprocess.CalledProcessError:
        return set()


def analyze_avc_events(events, rules, context, logger):
    """Analyze captured AVC events against policy rules"""

    print("\n" + "="*70)
    print("SELinux AVC Analysis Report")
    print("="*70)
    print(f"Context:        {context}")
    print(f"AVC Events:     {len(events)}")
    print(f"Total Rules:    {len(rules)}")
    print()

    if not events:
        print("⚠ No events captured. Make sure:")
        print("   1. The application is running")
        print("   2. The application is performing file operations")
        print("   3. You have root privileges")
        return

    logger.log(f"Starting analysis: {len(events)} events, {len(rules)} rules")

    # Track used permissions: (scontext, tcontext, tclass, permission)
    used_permissions = set()

    # Process events
    print("Analyzing AVC decisions...")
    print("\nDEBUG: Sample AVC events (first 10):")
    for i, event in enumerate(events[:10], 1):
        tclass_name = get_class_name(event['tclass'])
        hook_type = "VFS" if event['is_vfs_mask'] else "AVC"
        perms = decode_permissions(event['allowed'], event['tclass'], is_vfs_mask=event['is_vfs_mask'])
        print(f"  {i}. PID={event['pid']} comm={event['comm']} "
              f"class={tclass_name} hook={hook_type} perms={perms}")

        if i <= 5:
            logger.log(f"AVC event: Sample {i}", {
                "pid": event['pid'],
                "comm": event['comm'],
                "tclass": event['tclass'],
                "requested": f"0x{event['requested']:08x}",
                "allowed": f"0x{event['allowed']:08x}",
                "is_vfs_mask": event['is_vfs_mask'],
                "from_cache": event['from_cache']
            })

    # Map events to policy rules
    # Note: We need to resolve ssid/tsid to context names
    # For now, we'll use a simplified approach based on tclass and permissions
    print("\nDEBUG: Processing events to extract used permissions...")
    for event in events:
        tclass_name = get_class_name(event['tclass'])
        perms = decode_permissions(event['allowed'], event['tclass'], is_vfs_mask=event['is_vfs_mask'])

        # For each permission in the allowed set
        for perm in perms:
            # We assume the source context is our target context
            # and try to match against policy rules
            # This is a simplification - ideally we'd resolve ssid/tsid
            for rule in rules:
                if rule['class'] == tclass_name:
                    if perm in rule['permissions']:
                        used_permissions.add((
                            rule['source'],
                            rule['target'],
                            rule['class'],
                            perm
                        ))

    print(f"DEBUG: Tracked {len(used_permissions)} unique permissions")

    # Print sample used permissions
    print("\nDEBUG: Sample used permissions:")
    for i, (src, tgt, cls, perm) in enumerate(sorted(used_permissions)[:15], 1):
        print(f"  {i}. (src) -> {tgt}:{cls} {{ {perm} }}")

    # Analyze rules
    print("\n" + "="*70)
    print("STATISTICS")
    print("="*70)

    total_permissions = sum(len(rule['permissions']) for rule in rules)
    used_count = len(used_permissions)
    unused_count = total_permissions - used_count

    print(f"Total Rules:        {len(rules)}")
    print(f"Total Permissions:  {total_permissions}")
    print(f"Used Permissions:   {used_count} ({100*used_count/total_permissions:.1f}%)")
    print(f"Unused Permissions: {unused_count} ({100*unused_count/total_permissions:.1f}%)")

    # Categorize rules
    fully_used = []
    partially_used = []
    completely_unused = []

    for rule in rules:
        used_perms = set()
        unused_perms = set()

        for perm in rule['permissions']:
            perm_tuple = (rule['source'], rule['target'], rule['class'], perm)
            if perm_tuple in used_permissions:
                used_perms.add(perm)
            else:
                unused_perms.add(perm)

        if len(used_perms) == 0:
            completely_unused.append((rule, unused_perms))
        elif len(unused_perms) == 0:
            fully_used.append((rule, used_perms))
        else:
            partially_used.append((rule, used_perms, unused_perms))

    # Report partially used rules
    if partially_used:
        print("\n" + "="*70)
        print("PARTIALLY USED RULES (Some permissions excessive)")
        print("="*70)
        for i, (rule, used, unused) in enumerate(partially_used, 1):
            print(f"\n{i:2d}. Rule: allow {rule['source']} {rule['target']}:{rule['class']}")
            print(f"    + Used:   {{ {' '.join(sorted(used))} }}")
            print(f"    - UNUSED: {{ {' '.join(sorted(unused))} }}  ← REMOVE THESE")

    # Report completely unused rules
    if completely_unused:
        print("\n" + "="*70)
        print("COMPLETELY UNUSED RULES (Remove entirely)")
        print("="*70)
        print("\n⚠ The following rules were NEVER used:\n")
        for i, (rule, unused) in enumerate(completely_unused, 1):
            print(f"{i:2d}. allow {rule['source']} {rule['target']}:{rule['class']} "
                  f"{{ {' '.join(sorted(unused))} }};")

        print("\nThese permissions may be unnecessary and could be removed to reduce")
        print("the attack surface.")

    # Report fully used rules
    if fully_used:
        print("\n" + "="*70)
        print("FULLY USED RULES (All permissions needed)")
        print("="*70)
        for i, (rule, used) in enumerate(fully_used, 1):
            print(f"{i:2d}. allow {rule['source']} {rule['target']}:{rule['class']} "
                  f"{{ {' '.join(sorted(used))} }};")

    print("\n" + "="*70)
    logger.log(f"Analysis complete: {len(used_permissions)} unique permissions used")


def main():
    if len(sys.argv) < 3:
        print("Usage: python3 avc_prober.py analyze <context>")
        print("\nExample:")
        print("    python3 avc_prober.py analyze my_app_t")
        sys.exit(1)

    action = sys.argv[1]
    context = sys.argv[2]

    if action != "analyze":
        print(f"Unknown action: {action}")
        sys.exit(1)

    # Initialize debug logger
    logger = DebugLogger(log_file="/tmp/avc_prober_debug.log")
    logger.log("=== AVC Prober Session Started ===", {"context": context})

    # Extract policy rules
    rules = extract_policy_rules(context)

    # Log the rules
    for rule in rules:
        logger.log(f"Policy rule: {rule['source']} -> {rule['target']}:{rule['class']}", {
            "permissions": rule['permissions']
        })

    # Track all PIDs seen for this context
    all_seen_pids = get_pids_for_context(context)

    # Start eBPF AVC probe
    probe = EBPFAVCProbe(target_pids=all_seen_pids, debug=True)
    probe.start(context=context)

    if all_seen_pids:
        print(f"Filtering for PIDs: {all_seen_pids}")

    print("\n" + "="*70)
    print("MONITORING ACTIVE")
    print("="*70)
    print("Run your application now.")
    print("Press Ctrl+C when done to generate report.")
    print("="*70 + "\n")

    # Monitor loop
    try:
        while probe.running:
            should_check_pids = probe.poll(timeout_ms=100)

            # Periodically check for new PIDs
            if should_check_pids:
                current_pids = get_pids_for_context(context)
                new_pids = current_pids - all_seen_pids
                if new_pids:
                    probe.update_target_pids(current_pids)  # Update filter with current active set
                    all_seen_pids.update(new_pids)
    except KeyboardInterrupt:
        pass

    # Stop monitoring
    probe.stop()

    # Analyze events
    events = probe.get_events()
    analyze_avc_events(events, rules, context, logger)

    # Write debug log summary
    logger.dump_summary()


if __name__ == "__main__":
    main()
