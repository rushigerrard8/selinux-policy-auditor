"""
SELinux kernel to policy mappings
Maps kernel class IDs and permission bitmasks to human-readable names
"""


def get_class_mappings():
    """Get SELinux class ID to name mappings"""
    return {
        1: 'security',
        2: 'process',
        3: 'system',
        4: 'capability',
        5: 'filesystem',
        6: 'file',
        7: 'dir',
        8: 'fd',
        9: 'lnk_file',
        10: 'chr_file',
        11: 'blk_file',
        12: 'sock_file',
        13: 'fifo_file',
        14: 'socket',
        15: 'tcp_socket',
        16: 'udp_socket',
        17: 'rawip_socket',
        18: 'node',
        19: 'netif',
        20: 'netlink_socket',
        21: 'packet_socket',
        22: 'key_socket',
        23: 'unix_stream_socket',
        24: 'unix_dgram_socket',
    }


def get_class_name(tclass):
    """Get class name from class ID"""
    class_map = get_class_mappings()
    return class_map.get(tclass, f'class_{tclass}')


def get_file_permissions():
    """File class permission bitmask mappings"""
    return {
        0x00000001: 'ioctl',
        0x00000002: 'read',
        0x00000004: 'write',
        0x00000008: 'create',
        0x00000010: 'getattr',
        0x00000020: 'setattr',
        0x00000040: 'lock',
        0x00000080: 'relabelfrom',
        0x00000100: 'relabelto',
        0x00000200: 'append',
        0x00000400: 'unlink',
        0x00000800: 'link',
        0x00001000: 'rename',
        0x00002000: 'execute',
        0x00004000: 'quotaon',
        0x00008000: 'mounton',
        0x00010000: 'audit_access',
        0x00020000: 'open',
        0x00040000: 'execmod',
    }


def get_dir_permissions():
    """Directory class permission bitmask mappings"""
    return {
        0x00000001: 'ioctl',
        0x00000002: 'read',
        0x00000004: 'write',
        0x00000008: 'create',
        0x00000010: 'getattr',
        0x00000020: 'setattr',
        0x00000040: 'lock',
        0x00000080: 'relabelfrom',
        0x00000100: 'relabelto',
        0x00000200: 'append',
        0x00000400: 'unlink',
        0x00000800: 'link',
        0x00001000: 'rename',
        0x00002000: 'execute',
        0x00004000: 'add_name',
        0x00008000: 'remove_name',
        0x00010000: 'reparent',
        0x00020000: 'search',
        0x00040000: 'rmdir',
        0x00080000: 'open',
    }


def get_vfs_mask_mappings():
    """Linux VFS MAY_* mask to SELinux permission mappings
    These are used by selinux_inode_permission and selinux_file_permission hooks
    """
    return {
        0x00000001: ['execute'],    # MAY_EXEC
        0x00000002: ['write'],      # MAY_WRITE
        0x00000004: ['read'],       # MAY_READ
        0x00000008: ['append'],     # MAY_APPEND
        0x00000010: ['open'],       # MAY_OPEN
        0x00000020: ['chdir'],      # MAY_CHDIR
        # Combinations
        0x00000006: ['read', 'write'],  # MAY_READ | MAY_WRITE
    }


def decode_permissions(perm_bits, tclass, is_vfs_mask=False):
    """Decode permission bitmask to permission names

    Args:
        perm_bits: Permission bitmask
        tclass: SELinux object class
        is_vfs_mask: If True, interpret as Linux VFS MAY_* mask instead of SELinux mask
    """
    if is_vfs_mask:
        # For inode_permission and file_permission hooks
        # These use Linux VFS MAY_* masks, not SELinux permission bits
        vfs_map = get_vfs_mask_mappings()

        # Try exact match first
        if perm_bits in vfs_map:
            return vfs_map[perm_bits]

        # Otherwise decode individual bits
        perms = []
        if perm_bits & 0x00000001:  # MAY_EXEC
            perms.append('execute')
        if perm_bits & 0x00000002:  # MAY_WRITE
            perms.append('write')
        if perm_bits & 0x00000004:  # MAY_READ
            perms.append('read')
        if perm_bits & 0x00000008:  # MAY_APPEND
            perms.append('append')
        if perm_bits & 0x00000010:  # MAY_OPEN
            perms.append('open')

        # For file operations, also add getattr (stat is always checked)
        if tclass == 6 and perms:  # file class
            if 'read' in perms or 'write' in perms:
                if 'getattr' not in perms:
                    perms.append('getattr')

        return perms if perms else [f'vfs_mask_0x{perm_bits:x}']
    else:
        # Standard SELinux permission bitmask (from avc_has_perm)
        if tclass == 6:  # file
            perm_map = get_file_permissions()
        elif tclass == 7:  # dir
            perm_map = get_dir_permissions()
        else:
            perm_map = get_file_permissions()  # default

        perms = []
        for bit, name in perm_map.items():
            if perm_bits & bit:
                perms.append(name)

        return perms if perms else [f'perm_0x{perm_bits:x}']
