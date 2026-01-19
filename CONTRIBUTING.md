# Contributing to SELinux Policy Auditor

Thank you for your interest in contributing to SELinux Policy Auditor! This document provides guidelines and instructions for contributing.

## Code of Conduct

Please be respectful and constructive in all interactions. We're building security tools to help the community, and we welcome contributors of all backgrounds and experience levels.

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Use the bug report template** when creating a new issue
3. **Include**:
   - Linux distribution and kernel version
   - Python and BCC versions
   - SELinux mode and policy version
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant log output

### Suggesting Features

1. **Open an issue** describing the feature
2. **Explain the use case** - why is this feature needed?
3. **Consider backward compatibility**

### Submitting Pull Requests

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/my-feature`
3. **Make your changes**
4. **Test thoroughly** on a system with SELinux enabled
5. **Update documentation** if needed
6. **Submit a pull request**

## Development Setup

### Prerequisites

```bash
# RHEL/CentOS 9
sudo dnf install -y python3-bcc setools-console python3-pip

# Ubuntu/Debian
sudo apt install -y python3-bpfcc setools python3-pip
```

### Running Tests

```bash
# Install the demo application
cd examples/demo
make install

# Run the auditor against the demo
cd ../../src
sudo python3 se_policy_audit.py analyze my_app_t
```

### Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add docstrings to all public functions
- Comment complex eBPF logic

## Architecture Overview

```
se_policy_audit.py     # Main entry point, orchestrates the audit
    │
    ├── ebpf_avc_probe.py   # eBPF program loading and event capture
    │
    ├── policy_extractor.py # Extracts rules using sesearch
    │
    ├── selinux_mappings.py # Translates kernel IDs to names
    │
    └── debug_logger.py     # Debug logging utilities
```

### Key Components

1. **eBPF Probes** (`ebpf_avc_probe.py`)
   - Attaches to kernel functions
   - Filters events by PID in kernel space
   - Sends events to userspace via perf buffer

2. **Policy Extraction** (`policy_extractor.py`)
   - Calls `sesearch` to get allow rules
   - Parses rule format into structured data

3. **Permission Mapping** (`selinux_mappings.py`)
   - Maps class IDs (6=file, 7=dir, etc.)
   - Maps permission bitmasks to names

## Testing Checklist

Before submitting a PR, verify:

- [ ] Code runs without errors on RHEL 9.x
- [ ] Code runs without errors on Ubuntu 22.04+
- [ ] Demo application produces expected output
- [ ] No regressions in existing functionality
- [ ] Documentation updated if needed

## Questions?

Open an issue with the "question" label, and we'll be happy to help!
