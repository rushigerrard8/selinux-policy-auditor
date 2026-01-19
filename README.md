<p align="center">
  <h1 align="center">SELinux Policy Auditor</h1>
  <p align="center">
    <strong>Identify and eliminate excessive SELinux permissions using eBPF</strong>
  </p>
  <p align="center">
    <a href="#features">Features</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#documentation">Documentation</a> •
    <a href="#contributing">Contributing</a>
  </p>
</p>

---

## The Problem

SELinux policies often grant more permissions than applications actually need. Without runtime analysis, administrators have no way to know which permissions are truly required versus which are excessive attack surface.

**Example:** Your policy grants `{ read write append create unlink }` but your app only ever calls `read()`.

## The Solution

**SELinux Policy Auditor** uses eBPF to monitor **granted** access decisions at the kernel level in real-time. It tells you exactly which permissions your application uses—and which ones you can safely remove.

```
PARTIALLY USED RULES (Some permissions excessive)
======================================================================

1. Rule: allow my_app_t var_log_t:file
   ✓ Used:   { getattr open read }
   × UNUSED: { append create unlink write }  ← REMOVE THESE
```

## Features

| Feature | Description |
|---------|-------------|
| **Precise LSM Hooks** | Hooks into specific SELinux checkpoints (`file_open`, `mmap`, `getattr`) for accurate intent capture |
| **AVC Cache Awareness** | Captures both slow-path (uncached) and fast-path (cached) permission decisions |
| **Kernel-Level Filtering** | Filters by PID inside the kernel for zero noise and minimal overhead |
| **Granular Analysis** | Breaks down `allow` rules to individual permissions (`read` vs `write`) |
| **Zero Policy Changes** | Works without `auditallow` or any modifications to your existing policy |

## Quick Start

### Prerequisites

- Linux kernel 5.x+ with SELinux enabled
- Python 3.8+
- Root/sudo access

### Installation

```bash
# RHEL/CentOS 9
sudo dnf install -y python3-bcc setools-console

# Ubuntu/Debian
sudo apt install -y python3-bpfcc setools
```

### Usage

```bash
# Clone the repository
git clone https://github.com/yourusername/selinux-policy-auditor.git
cd selinux-policy-auditor

# Run the auditor (replace my_app_t with your target context)
sudo python3 src/se_policy_audit.py analyze my_app_t

# In another terminal, exercise your application
# Then press Ctrl+C to generate the report
```

## How It Works

### The Challenge: AVC Caching

Standard SELinux monitoring misses most events because the kernel caches access decisions. Once "read" is allowed, subsequent reads are served from the cache and never trigger audit hooks.

### Our Solution: Multi-Hook Strategy

SELinux Policy Auditor deploys multiple eBPF probes to capture permissions regardless of caching:

```
┌─────────────────────────────────────────────────────────────┐
│                     Application                              │
└─────────────────────┬───────────────────────────────────────┘
                      │ System Call
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   LSM Hooks (Fast Path)                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────────────┐ │
│  │ file_open    │ │ mmap_file    │ │ inode_getattr        │ │
│  │ eBPF Probe   │ │ eBPF Probe   │ │ eBPF Probe           │ │
│  └──────┬───────┘ └──────┬───────┘ └──────────┬───────────┘ │
└─────────┼────────────────┼────────────────────┼─────────────┘
          │                │                    │
          ▼                ▼                    ▼
┌─────────────────────────────────────────────────────────────┐
│                   AVC (Slow Path)                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ avc_has_perm - eBPF kprobe/kretprobe                 │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│              SELinux Policy Auditor                          │
│  • Collect permission events                                 │
│  • Match against policy rules                                │
│  • Report used vs unused permissions                         │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

- **[Usage Guide](docs/USAGE.md)** - Detailed usage instructions and examples
- **[Technical Specification](docs/TECHNICAL_SPEC.md)** - Architecture and implementation details
- **[Demo Application](examples/demo/)** - Complete working example with overly permissive policy

## Project Structure

```
selinux-policy-auditor/
├── src/                        # Core source code
│   ├── se_policy_audit.py      # Main entry point
│   ├── ebpf_avc_probe.py       # eBPF probes and event capture
│   ├── selinux_mappings.py     # SELinux class/permission mappings
│   ├── policy_extractor.py     # Policy rule extraction (sesearch)
│   └── debug_logger.py         # Debug logging utilities
├── examples/
│   └── demo/                   # Demo application with excessive policy
│       ├── my_app.c            # Sample C application
│       ├── my_app.te           # Overly permissive policy
│       ├── my_app_optimized.te # Optimized policy (after audit)
│       ├── my_app.fc           # File contexts
│       ├── Makefile            # Build automation
│       └── README.md           # Demo instructions
├── scripts/
│   └── check_avc_hooks.sh      # Kernel hook availability checker
├── docs/
│   ├── USAGE.md                # Usage documentation
│   └── TECHNICAL_SPEC.md       # Technical specification
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

## Requirements

| Component | Minimum Version |
|-----------|-----------------|
| Linux Kernel | 5.x |
| Python | 3.8+ |
| BCC | 0.24+ |
| SETools | 4.x |

## Use Cases

- **Security Hardening**: Remove unnecessary permissions to reduce attack surface
- **Compliance Auditing**: Document exactly which permissions applications require
- **Policy Development**: Build minimal policies based on actual runtime behavior
- **Troubleshooting**: Understand what permissions an application is actually using

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [BCC (BPF Compiler Collection)](https://github.com/iovisor/bcc)
- Policy extraction powered by [SETools](https://github.com/SELinuxProject/setools)
