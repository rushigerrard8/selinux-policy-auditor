#!/usr/bin/env python3
"""
eBPF AVC Probe - Direct Access Vector Cache Monitoring

This tool hooks into the SELinux AVC lookup functions to capture
what permissions are actually being GRANTED (not just checked).

Strategy:
1. Hook avc_has_perm() - for general object permissions and directory operations.
2. Hook selinux_file_open() - for precise file open intentions (captures cached opens).
3. Hook selinux_mmap_file() - for precise memory mapping intentions.
4. Hook selinux_inode_getattr() - for precise metadata/stat checks.
"""

from bcc import BPF
import signal
import time
import ctypes as ct

# eBPF program - Multi-hook approach
BPF_PROGRAM = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>

// Structure to capture AVC decision
struct avc_event {
    u32 pid;
    u32 ssid;           // Source security ID
    u32 tsid;           // Target security ID
    u16 tclass;         // Object class
    u32 requested;      // Requested permissions (SELinux bits or VFS mask)
    u32 allowed;        // Allowed permissions
    u32 decided;        // Decided permissions
    char comm[16];
    u64 timestamp;
    u8 is_vfs_mask;     // 1 if requested is VFS mask, 0 if SELinux bits
    u8 from_cache;      // 1 if potentially from cache/fast-path
};

BPF_PERF_OUTPUT(events);

// Map to store target PIDs for filtering
BPF_HASH(target_pids, u32, u8);

// Hook 1: avc_has_perm - captures granted permission checks (slow path)
BPF_HASH(perm_check, u64, struct avc_event);

int trace_avc_has_perm_entry(struct pt_regs *ctx,
                             void *state,
                             u32 ssid,
                             u32 tsid,
                             u16 tclass,
                             u32 requested)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!target_pids.lookup(&pid)) {
        return 0;
    }

    struct avc_event event = {};
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    event.pid = pid;
    event.ssid = ssid;
    event.tsid = tsid;
    event.tclass = tclass;
    event.requested = requested;
    event.is_vfs_mask = 0;
    event.from_cache = 0;
    event.timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(&event.comm, comm, sizeof(event.comm));

    // Store for return probe
    perm_check.update(&pid_tgid, &event);

    return 0;
}

int trace_avc_has_perm_return(struct pt_regs *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct avc_event *event_ptr = perm_check.lookup(&pid_tgid);

    if (!event_ptr) {
        return 0;
    }

    struct avc_event event = *event_ptr;
    int ret = PT_REGS_RC(ctx);    // Return value: 0 = granted

    if (ret == 0) {
        // Filter: Only capture filesystem operations
        if (event.tclass >= 6 && event.tclass <= 13) {
            event.allowed = event.requested;
            event.decided = event.requested;
            events.perf_submit(ctx, &event, sizeof(event));
        }
    }

    perm_check.delete(&pid_tgid);
    return 0;
}

// Hook 2: selinux_file_open - captures file opens precisely
int trace_file_open(struct pt_regs *ctx, struct file *file)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!target_pids.lookup(&pid)) {
        return 0;
    }

    struct avc_event event = {};
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    event.pid = pid;
    event.tclass = 6; // file

    // SELinux 'open' bit is 0x00020000
    u32 requested = 0x00020000;

    // In the kernel, f_mode tells us the actual open intent
    unsigned int f_mode = 0;
    bpf_probe_read_kernel(&f_mode, sizeof(f_mode), (void *)&file->f_mode);

    if (f_mode & 0x1) requested |= 0x00000002; // read
    if (f_mode & 0x2) requested |= 0x00000004; // write

    event.requested = requested;
    event.allowed = requested;
    event.is_vfs_mask = 0;
    event.from_cache = 1;
    event.timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(&event.comm, comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Hook 3: selinux_mmap_file - captures file mapping (read/execute)
int trace_mmap_file(struct pt_regs *ctx, struct file *file, unsigned long prot)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!target_pids.lookup(&pid)) {
        return 0;
    }

    struct avc_event event = {};
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    event.pid = pid;
    event.tclass = 6; // file

    u32 requested = 0;
    // prot corresponds to PROT_READ (0x1), PROT_WRITE (0x2), PROT_EXEC (0x4)
    if (prot & 0x1) requested |= 0x00000002; // read
    if (prot & 0x2) requested |= 0x00000004; // write
    if (prot & 0x4) requested |= 0x00002000; // execute

    if (requested == 0) return 0;

    event.requested = requested;
    event.allowed = requested;
    event.is_vfs_mask = 0;
    event.from_cache = 1;
    event.timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(&event.comm, comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Hook 4: selinux_inode_getattr - captures stat() calls precisely
int trace_inode_getattr(struct pt_regs *ctx, const struct path *path)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    if (!target_pids.lookup(&pid)) {
        return 0;
    }

    struct avc_event event = {};
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    event.pid = pid;
    event.tclass = 6; // file
    event.requested = 0x00000010; // SELinux 'getattr' bit
    event.allowed = 0x00000010;
    event.is_vfs_mask = 0;
    event.from_cache = 1;
    event.timestamp = bpf_ktime_get_ns();
    __builtin_memcpy(&event.comm, comm, sizeof(event.comm));

    events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


class AVCEvent(ct.Structure):
    """Python structure matching the eBPF avc_event structure"""
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ssid", ct.c_uint32),
        ("tsid", ct.c_uint32),
        ("tclass", ct.c_uint16),
        ("requested", ct.c_uint32),
        ("allowed", ct.c_uint32),
        ("decided", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("timestamp", ct.c_uint64),
        ("is_vfs_mask", ct.c_uint8),
        ("from_cache", ct.c_uint8),
    ]


class EBPFAVCProbe:
    """eBPF probe for AVC (Access Vector Cache) monitoring"""

    def __init__(self, target_pids=None, debug=False):
        self.bpf = None
        self.target_pids = target_pids or set()
        self.events = []
        self.running = False
        self.debug = debug
        self.event_count = 0
        self.last_pid_check = time.time()
        self.pid_check_interval = 5
        self._warn_empty = True

        # Statistics
        self.stats = {
            'total_events': 0,
            'slow_path': 0,
            'fast_path': 0,
            'by_class': {},
        }

    def start(self, context=None):
        """Start eBPF monitoring"""
        print("Starting eBPF AVC Probe...")
        print("Strategy: Multi-hook approach (avc_has_perm + Precise LSM hooks)\n")

        # Load BPF program
        self.bpf = BPF(text=BPF_PROGRAM)

        hooks = [
            ("avc_has_perm", "trace_avc_has_perm_entry", "kprobe"),
            ("avc_has_perm", "trace_avc_has_perm_return", "kretprobe"),
            ("selinux_file_open", "trace_file_open", "kprobe"),
            ("selinux_mmap_file", "trace_mmap_file", "kprobe"),
            ("selinux_inode_getattr", "trace_inode_getattr", "kprobe"),
        ]

        attached_count = 0
        for event, fn, type in hooks:
            try:
                if type == "kprobe":
                    self.bpf.attach_kprobe(event=event, fn_name=fn)
                else:
                    self.bpf.attach_kretprobe(event=event, fn_name=fn)
                print(f"✓ Attached {type} to {event}")
                attached_count += 1
            except Exception as e:
                # Don't fail if one hook fails (some kernels inline these)
                if self.debug:
                    print(f"! Note: Optional {type} on {event} not available: {e}")

        if attached_count == 0:
            raise Exception("Failed to attach to any kernel hooks!")

        # Set up perf buffer
        self.bpf["events"].open_perf_buffer(self._handle_event, page_cnt=256)

        if context:
            print(f"✓ Monitoring SELinux decisions for: {context}")

        # Initialize BPF target_pids map
        if self.target_pids:
            bpf_pids = self.bpf["target_pids"]
            for pid in self.target_pids:
                bpf_pids[ct.c_uint32(pid)] = ct.c_uint8(1)

        self.running = True

        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\n\nReceived interrupt signal, stopping...")
        self.running = False

    def _handle_event(self, cpu, data, size):
        """Callback for perf buffer events"""
        event = ct.cast(data, ct.POINTER(AVCEvent)).contents

        # Filter by PID if target_pids is set
        if self.target_pids and event.pid not in self.target_pids:
            return

        # Store event data
        event_data = {
            'pid': event.pid,
            'comm': event.comm.decode('utf-8', 'replace'),
            'ssid': event.ssid,
            'tsid': event.tsid,
            'tclass': event.tclass,
            'requested': event.requested,
            'allowed': event.allowed,
            'decided': event.decided,
            'timestamp': event.timestamp,
            'is_vfs_mask': bool(event.is_vfs_mask),
            'from_cache': bool(event.from_cache),
        }

        self.events.append(event_data)
        self.event_count += 1

        # Update statistics
        self.stats['total_events'] += 1
        if event.from_cache:
            self.stats['fast_path'] += 1
        else:
            self.stats['slow_path'] += 1

        tclass = event.tclass
        self.stats['by_class'][tclass] = self.stats['by_class'].get(tclass, 0) + 1

        # Print progress every 10 events
        if self.event_count % 10 == 0:
            if self.target_pids:
                print(f"Captured {self.event_count} events from target PIDs...")
            else:
                print(f"Captured {self.event_count} events...")

    def update_target_pids(self, new_pids):
        """Add new target PIDs to the monitoring filter"""
        if not self.bpf:
            return

        bpf_pids = self.bpf["target_pids"]
        added = []
        for pid in new_pids:
            if pid not in self.target_pids:
                bpf_pids[ct.c_uint32(pid)] = ct.c_uint8(1)
                self.target_pids.add(pid)
                added.append(pid)

        if added:
            print(f"  Added new target PIDs to filter: {added}")

    def poll(self, timeout_ms=100):
        """Poll for events"""
        if self.bpf:
            # Check if target_pids is empty and warn if it's the first time
            if not self.target_pids and self._warn_empty:
                print("  (Waiting for process with target context to start...)")
                self._warn_empty = False
            elif self.target_pids:
                self._warn_empty = True

            self.bpf.perf_buffer_poll(timeout=timeout_ms)

            # Periodically check for new PIDs
            current_time = time.time()
            if current_time - self.last_pid_check >= self.pid_check_interval:
                self.last_pid_check = current_time
                return True  # Signal to check for new PIDs
        return False

    def stop(self):
        """Stop monitoring and cleanup"""
        self.running = False
        if self.bpf:
            self.bpf.cleanup()

        print("\n~ Monitoring stopped")
        print("\n" + "="*70)
        print("MONITORING STATISTICS")
        print("="*70)
        print(f"Total events captured: {self.stats['total_events']}")
        print(f"  Slow path (AVC):     {self.stats['slow_path']}")
        print(f"  Fast path (Cached):  {self.stats['fast_path']}")
        print("\nEvents by object class:")
        for tclass, count in sorted(self.stats['by_class'].items()):
            from selinux_mappings import get_class_name
            name = get_class_name(tclass)
            print(f"  {name} (tclass {tclass}): {count} events")
        print("="*70)

    def get_events(self):
        """Return captured events"""
        return self.events
