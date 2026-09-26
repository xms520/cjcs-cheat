#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lua payload keystream analysis - known-plaintext attack"""
import struct, json, collections, os

RAW = '/var/minis/workspace/cjcs/ast2/Payload/CJCS.app/Data/Raw'

def entries(path):
    """yield (name, total, hdr16, payload) for the .lua table inside a .ast pack"""
    d = open(path, 'rb').read()
    out = {}
    import re
    for m in re.finditer(rb'\.lua', d):
        p = m.start()
        for l in range(4, 200):
            o = p - (l - 4) - 4
            if o < 0: break
            if struct.unpack_from('<I', d, o)[0] != l: continue
            nm = d[o+4:o+4+l]
            if not nm.endswith(b'.lua') or b'\0' in nm: continue
            total = struct.unpack_from('<I', d, o+4+l)[0]
            if not (0 < total < 30_000_000) or o+8+l+total > len(d): continue
            key = nm.decode('latin1')
            if key in out: continue
            hdr = d[o+4+l+4:o+4+l+20]
            pay = d[o+4+l+20:o+4+l+total]
            out[key] = (total, hdr, pay, o)
    return out

if __name__ == '__main__':
    import sys
    allents = {}
    for f in sorted(os.listdir(RAW)):
        if not f.endswith('.ast'): continue
        e = entries(os.path.join(RAW, f))
        if e: print(f, len(e))
        allents[f] = e
    json.dump({k: {n: [v[0], v[1].hex(), bytes(v[2][:64]).hex(), v[3]] for n, v in e.items()}
               for k, e in allents.items()}, open('/tmp/lua_entries.json', 'w'))
