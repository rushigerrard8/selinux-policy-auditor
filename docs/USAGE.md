# SELinux Policy Auditor - Usage Guide

## Overview

**SELinux Policy Auditor** is a high-precision security analysis tool designed to identify overly permissive SELinux policies. It works by monitoring **granted** access decisions at the kernel level using eBPF, allowing you to see exactly which permissions an application actually uses versus what its policy allows.

## Who Is This For?

### Linux System Administrators

As an administrator, you can inspect an application's `.te` and `.fc` files to see what permissions it has granted itself—but there's no easy way to know if the application actually *needs* all those permissions.

**The risk:** Overly permissive policies are security holes. If an attacker compromises a process, they inherit all of its SELinux permissions. An application that grants itself `write`, `create`, and `unlink` permissions—but never uses them—gives attackers unnecessary capabilities.

**How this tool helps:** Run SELinux Policy Auditor against any application to see exactly which permissions it uses in practice. You can then work with vendors or your security team to tighten policies and reduce your attack surface.

### Linux Application Developers

When you modify your application, its permission requirements may change. Manually auditing your SELinux policy after every code change is tedious and error-prone.

**The challenge:** After refactoring, you might no longer need `write` access to a directory, or `execute` permission on a file—but your policy still grants them.

**How this tool helps:** Run your updated application through SELinux Policy Auditor to see which permissions are still needed. Remove the ones that aren't, keeping your policy minimal and secure without guesswork.

## Prerequisites

Before running the audit, ensure your system meets the following requirements:

### System Requirements

| Requirement | Minimum |
|-------------|---------|
| **OS** | RHEL 9.x, Ubuntu 22.04+, or any modern Linux distribution |
| **Kernel** | Version 5.x or newer (required for LSM hooks) |
| **SELinux** | Enabled and in enforcing or permissive mode |
| **Privileges** | Root/sudo access (required to load eBPF programs) |

### Required Software

1. **Python 3.8+**: The orchestrator is written in Python
2. **BCC (BPF Compiler Collection)**: Used to compile and load the eBPF hooks
3. **SETools**: Specifically `sesearch`, used to extract policy rules

#### Installation on RHEL/CentOS 9:

```bash
sudo dnf install -y python3-bcc setools-console
```

#### Installation on Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3-bpfcc setools
```

## Quick Start

```bash
# Navigate to the src directory
cd src

# Run the auditor (replace my_app_t with your target context)
sudo python3 se_policy_audit.py analyze my_app_t

# In another terminal, exercise your application
# Press Ctrl+C to generate the report
```

## Detailed Usage

### Step 1: Identify the Target Context

First, determine the SELinux context of the application you want to audit:

```bash
# Find running processes and their contexts
ps -eZ | grep your_app_name

# Example output:
# system_u:system_r:httpd_t:s0    1234 ?  00:00:05 httpd
```

The type field (e.g., `httpd_t`) is what you'll pass to the auditor.

### Step 2: Start the Audit

Run the auditor with the target context:

```bash
sudo python3 src/se_policy_audit.py analyze httpd_t
```

You'll see output indicating the hooks are attached:

```
Starting eBPF AVC Probe...
Strategy: Multi-hook approach (avc_has_perm + Precise LSM hooks)

✓ Attached kprobe to avc_has_perm
✓ Attached kretprobe to avc_has_perm
✓ Attached kprobe to selinux_file_open
✓ Attached kprobe to selinux_mmap_file
✓ Attached kprobe to selinux_inode_getattr
✓ Monitoring SELinux decisions for: httpd_t

======================================================================
MONITORING ACTIVE
======================================================================
Run your application now.
Press Ctrl+C when done to generate report.
======================================================================
```

### Step 3: Exercise the Application

In a separate terminal, run the application through its typical operations:

```bash
# Example: for a web server, make some requests
curl http://localhost/
curl http://localhost/api/data
```

The auditor will show captured events:

```
Captured 10 events from target PIDs...
Captured 20 events from target PIDs...
```

### Step 4: Generate the Report

Press **Ctrl+C** to stop monitoring and generate the analysis:

```
^C
Received interrupt signal, stopping...

~ Monitoring stopped

======================================================================
MONITORING STATISTICS
======================================================================
Total events captured: 47
  Slow path (AVC):     12
  Fast path (Cached):  35

Events by object class:
  file (tclass 6): 35 events
  dir (tclass 7): 12 events
======================================================================
```

## Understanding the Report

The report categorizes rules into three sections:

### 1. PARTIALLY USED RULES

Rules where some permissions were used, but others were not:

```
PARTIALLY USED RULES (Some permissions excessive)
======================================================================

1. Rule: allow my_app_t var_log_t:file
   + Used:   { getattr open read }
   - UNUSED: { append create unlink write }  ← REMOVE THESE
```

**Action**: Remove the unused permissions from your policy.

### 2. COMPLETELY UNUSED RULES

Rules that were never triggered during the monitoring period:

```
COMPLETELY UNUSED RULES (Remove entirely)
======================================================================

⚠ The following rules were NEVER used:

1. allow my_app_t tmp_t:file { read write create unlink };
```

**Action**: Consider removing these rules entirely, or extend monitoring time.

### 3. FULLY USED RULES

Rules where every permission was observed:

```
FULLY USED RULES (All permissions needed)
======================================================================

1. allow my_app_t lib_t:file { read open execute getattr map };
```

**Action**: These rules are correctly scoped. No changes needed.

## Advanced Options

### Check Available Kernel Hooks

Before running the auditor, you can verify which kernel hooks are available:

```bash
./scripts/check_avc_hooks.sh
```

### Debug Logging

Debug logs are written to `/tmp/avc_prober_debug.log`. View them with:

```bash
cat /tmp/avc_prober_debug.log | jq
```

## Troubleshooting

### No events captured

1. **Context Match**: Verify the application is running in the expected context:
   ```bash
   ps -eZ | grep my_app_t
   ```

2. **Root Privileges**: The auditor must run as root:
   ```bash
   sudo python3 src/se_policy_audit.py analyze my_app_t
   ```

3. **Application Activity**: Ensure the application is performing file operations during the monitoring window.

### Missing Hooks

If the tool reports it cannot attach to a hook:

```
! Note: Optional kprobe on selinux_file_open not available: ...
```

This means your kernel has inlined that function. The tool will continue with available hooks. At least one primary hook must be available.

### BCC Not Found

If you get import errors for BCC:

```bash
# RHEL/CentOS
sudo dnf install -y python3-bcc

# Ubuntu/Debian
sudo apt install -y python3-bpfcc
```

### sesearch Not Found

If policy extraction fails:

```bash
# RHEL/CentOS
sudo dnf install -y setools-console

# Ubuntu/Debian
sudo apt install -y setools
```

## Best Practices

1. **Monitor representative workloads**: Run the application through all its typical operations
2. **Extended monitoring**: For complex applications, monitor for longer periods
3. **Multiple runs**: Audit the same context multiple times to ensure coverage
4. **Test in staging**: Always test policy changes in a non-production environment first
5. **Incremental changes**: Remove permissions one at a time and verify functionality
