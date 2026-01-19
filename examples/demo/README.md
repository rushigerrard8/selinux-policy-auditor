# SELinux Policy Auditor - Demo Application

This demo illustrates how **SELinux Policy Auditor** identifies overly permissive SELinux policies in a real-world scenario.

## Overview

**Application**: `my_app` - A C program that monitors `/var/log` for changes.

**The Problem**: The application only needs to **read** and **stat** log files. However, the installed SELinux policy grants excessive permissions:
- **Grants**: `read`, `write`, `append`, `create`, `unlink`, `getattr`, `open`, `search`
- **Actually Needs**: `read`, `open`, `getattr`, `search`

**The Goal**: Use **SELinux Policy Auditor** to identify the unused `write`, `append`, `create`, and `unlink` permissions so they can be safely removed.

## Files in this Directory

| File | Description |
|------|-------------|
| `my_app.c` | Demo application (reads files every 10 seconds) |
| `my_app.te` | Type Enforcement policy with **excessive** permissions |
| `my_app.fc` | File contexts (labels `/usr/local/bin/my_app`) |
| `my_app_optimized.te` | Optimized policy with only the required permissions |
| `Makefile` | Build automation |

## Prerequisites

On your RHEL 9.x test machine:

```bash
# Install development and SELinux tools
sudo dnf install -y gcc make selinux-policy-devel
```

## Step-by-Step Demo

### 1. Build and Install the Demo

Compile the application and install the overly permissive policy:

```bash
make install
```

### 2. Verify the Environment

Ensure the application is running in its own context (`my_app_t`):

```bash
# Start the app in the background
sudo /usr/local/bin/my_app &

# Check its context
ps -eZ | grep my_app_t
```

### 3. Run the Audit

Open a new terminal, navigate to the `src` directory, and start the audit:

```bash
cd ../../src
sudo python3 se_policy_audit.py analyze my_app_t
```

### 4. Observe the Results

Let the audit run for 30-60 seconds while `my_app` performs its periodic scans. You will see events being captured:
- **Slow path** (initial AVC lookups)
- **Fast path** (cached LSM hooks for file opens and stats)

### 5. Generate the Report

Press **Ctrl+C** in the audit terminal. You will see a report similar to this:

```
PARTIALLY USED RULES (Some permissions excessive)
======================================================================

1. Rule: allow my_app_t var_log_t:file
   ✓ Used:   { getattr open read }
   × UNUSED: { append create unlink write }  ← REMOVE THESE

2. Rule: allow my_app_t var_log_t:dir
   ✓ Used:   { getattr read search }
   × UNUSED: { add_name open remove_name write }  ← REMOVE THESE
```

### 6. Optimize the Policy

Now that you know exactly what is unused, you can switch to the optimized policy:

```bash
make install-optimized
```

## Why This Matters

Without **SELinux Policy Auditor**, an administrator has no easy way to know if `my_app` actually needs `write` access to log files.

By using eBPF to monitor the **granted** decisions, we proved that the application never writes, creates, or deletes files. Removing these unused permissions significantly reduces the attack surface—if `my_app` were ever compromised, the attacker would still be unable to tamper with your log files.

## Cleanup

To remove the demo application and policy from your system:

```bash
make uninstall
make clean
```
