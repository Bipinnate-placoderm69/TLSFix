#!/usr/bin/env python3
# patch_iphoneos_min.py <fat-macho> <arch> <min e.g. 3.0>
# Rewrites the LC_VERSION_MIN_IPHONEOS version word in the given arch slice of a fat Mach-O.
# The modern linker refuses to emit iOS min < ~6.0, but the field is just metadata old dyld reads,
# so we lower it post-link. Same load-command size; only the encoded version changes.
import struct, sys

CPU = {'armv6': (12, 6), 'armv7': (12, 9), 'armv7s': (12, 11), 'arm64': (0x0100000C, 0)}
LC_VERSION_MIN_IPHONEOS = 0x25

def ver(s):
    p = [int(x) for x in s.split('.')] + [0, 0]
    return (p[0] << 16) | (p[1] << 8) | p[2]

def patch_thin(buf, off, want_ver):
    magic, = struct.unpack_from('<I', buf, off)
    if magic not in (0xFEEDFACE, 0xFEEDFACF):
        return 0
    is64 = magic == 0xFEEDFACF
    ncmds, = struct.unpack_from('<I', buf, off + 16)
    p = off + (32 if is64 else 28)
    n = 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from('<II', buf, p)
        if cmd == LC_VERSION_MIN_IPHONEOS:
            struct.pack_into('<I', buf, p + 8, want_ver)   # version field
            n += 1
        p += cmdsize
    return n

def main():
    path, arch, minstr = sys.argv[1], sys.argv[2], sys.argv[3]
    ct, cs = CPU[arch]; want = ver(minstr)
    buf = bytearray(open(path, 'rb').read())
    magic, = struct.unpack_from('>I', buf, 0)
    total = 0
    if magic in (0xCAFEBABE, 0xCAFEBABF):                  # fat (big-endian header)
        nfat, = struct.unpack_from('>I', buf, 4)
        for i in range(nfat):
            base = 8 + i * 20
            cputype, cpusub, offset, size, align = struct.unpack_from('>IIIII', buf, base)
            if cputype == ct and (cs == 0 or (cpusub & 0xFF) == cs):
                total += patch_thin(buf, offset, want)
    else:
        total += patch_thin(buf, 0, want)
    open(path, 'wb').write(buf)
    print("patched %d LC_VERSION_MIN_IPHONEOS in %s slice -> %s" % (total, arch, minstr))

if __name__ == '__main__':
    main()
