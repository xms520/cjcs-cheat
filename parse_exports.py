#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parse Mach-O export trie of UnityFramework, dump il2cpp_* / useful symbols"""
import struct, sys

PATH = 'Payload/CJCS.app/Frameworks/UnityFramework.framework/UnityFramework'
d = open(PATH, 'rb').read()
EXPORT_OFF = 97088928
EXPORT_SIZE = 103288

def read_uleb(data, off):
    r = 0; s = 0
    while True:
        b = data[off]; off += 1
        r |= (b & 0x7f) << s
        if not (b & 0x80): break
        s += 7
    return r, off

out = {}
def walk(data, base, off, prefix):
    while True:
        term, off = read_uleb(data, off)
        if term == 0: break
        node_off = off - 1 if False else None
        start = off
        # node starts at terminator position? No: children nodes are at (node_start + child_offset)
        node_start = start - 1  # position where terminal-size uleb began
        name_end = data.index(b'\0', off)
        name = data[off:name_end].decode('utf-8', 'replace')
        off = name_end + 1
        child_count, off = read_uleb(data, off)
        if term != 0:
            flags, off2 = read_uleb(data, off)
            addr, off2 = read_uleb(data, off2)
            other, off2 = read_uleb(data, off2)
            # skip other depending on flags (for reexport/ stub)
            if flags & 0x08:  # REEXPORT
                _, off2 = read_uleb(data, off2)
            elif flags & 0x10:  # STUB_AND_RESOLVER
                _, off2 = read_uleb(data, off2)
            out[prefix + name] = (flags, addr)
            off = off2
        children = []
        for _ in range(child_count):
            coff, off = read_uleb(data, off)
            children.append((node_start + coff, prefix + name))
        for c, p in children:
            walk(data, base, c, p)

# simpler: iterative over full buffer
walk(d, EXPORT_OFF, EXPORT_OFF, '')

pat = sys.argv[1] if len(sys.argv) > 1 else 'il2cpp'
n = 0
for k in sorted(out):
    if pat in k:
        print(k, hex(out[k][1]))
        n += 1
print('matched', n, 'total exports', len(out))
