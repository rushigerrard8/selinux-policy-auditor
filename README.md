<p align="center">
  <h1 align="center">SELinux Policy Auditor</h1>
  <p align="center">
    <strong>Identify and eliminate excessive SELinux permissions using eBPF</strong>
  </p>
  <p align="center">
    <a href="#installation">Installation</a> •
    <a href="#quick-start">Quick Start</a> •
    <a href="#example-output">Example Output</a> •
    <a href="docs/USAGE.md">Documentation</a>
  </p>
</p>

---

## Why SELinux Policy Auditor?

SELinux policies often grant more permissions than applications actually need. **SELinux Policy Auditor** uses eBPF to monitor which permissions are actually used at runtime—so you can safely remove the rest.

```
Before:  allow my_app_t var_log_t:file { read write append create unlink open };
After:   allow my_app_t var_log_t:file { read open };   # 4 excessive permissions removed
```

## Features

- **Runtime Analysis** — Monitors actual permission usage via eBPF kernel probes
- **Zero Policy Changes** — Works without modifying `auditallow` or existing policy
- **Granular Reporting** — Shows exactly which permissions are used vs. unused
- **Low Overhead** — Kernel-level PID filtering minimizes performance impact

## Installation

### Requirements

- Linux kernel 5.x+ with SELinux enabled
- Python 3.8+
- Root access

### Dependencies

```bash
# RHEL/CentOS 9
sudo dnf install -y python3-bcc setools-console

# Ubuntu/Debian
sudo apt install -y python3-bpfcc setools
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/rushigerrard8/selinux-policy-auditor.git
cd selinux-policy-auditor

# Run the auditor against a target SELinux context
sudo python3 src/se_policy_audit.py analyze <context>

# Example: audit the my_app_t context
sudo python3 src/se_policy_audit.py analyze my_app_t
```

Then exercise your application in another terminal. Press `Ctrl+C` to generate the report.

## Example Output

```
PARTIALLY USED RULES (Some permissions excessive)
======================================================================

1. Rule: allow my_app_t var_log_t:file
   ✓ Used:   { getattr open read }
   × UNUSED: { append create unlink write }  ← REMOVE THESE

2. Rule: allow my_app_t var_log_t:dir
   ✓ Used:   { getattr read search }
   × UNUSED: { add_name remove_name write }  ← REMOVE THESE

STATISTICS
======================================================================
Total Permissions:  15
Used Permissions:   6 (40.0%)
Unused Permissions: 9 (60.0%)
```

## Documentation

- **[Usage Guide](docs/USAGE.md)** — Detailed instructions and troubleshooting
- **[Technical Specification](docs/TECHNICAL_SPEC.md)** — Architecture and implementation details
- **[Demo Application](examples/demo/)** — Try it yourself with a sample app

## Use Cases

- **Security Hardening** — Remove unnecessary permissions to reduce attack surface
- **Compliance Auditing** — Document exactly which permissions applications require
- **Policy Development** — Build minimal policies based on actual runtime behavior

## Project Structure

```
selinux-policy-auditor/
├── src/                    # Core source code
├── examples/demo/          # Demo application with sample policy
├── scripts/                # Utility scripts
└── docs/                   # Documentation
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
