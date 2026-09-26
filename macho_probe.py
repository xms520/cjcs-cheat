#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mach-O 导出表(trie) + 符号表 双解析，判定 lua/il2cpp 符号是否可 dlsym"""
import struct, json, sys, re

PATH = '/var/minis/workspace/cjcs/Payload/CJCS.app/Frameworks/UnityFramework.framework/UnityFramework'
d = open(PATH, 'rb').read()

# --- 头 ---
ncmds = struct.unpack_from('<I', d, 16)[0]
off = 32
segs = {}
syms = {}
exp = None
symtab = None
for _ in range(ncmds):
    cmd, size = struct.unpack_from('<II', d, off)
    if cmd == 0x19:
        nm = d[off+8:off+24].rstrip(b'\0').decode()
        vmaddr, vmsize, foff, fsize = struct.unpack_from('<4Q', d, off+24)
        segs[nm] = (vmaddr, vmsize, foff, fsize)
    elif cmd == 0x2:
        symtab = struct.unpack_from('<IIII', d, off+8)
    elif cmd in (0x2b, 0x22, 0x80000022):
        if cmd == 0x2b:
            exp = struct.unpack_from('<II', d, off+8)
    off += size

print('segments:', {k: tuple(hex(x) for x in v) for k, v in segs.items()})
print('symtab:', symtab)
print('export trie:', tuple(hex(x) for x in exp) if exp else None)

# --- 导出 trie ---
def uleb(data, o):
    r = 0; s = 0
    while True:
        b = data[o]; o += 1
        r |= (b & 0x7f) << s
        if not b & 0x80: break
        s += 7
    return r, o

exports = {}
if exp:
    E, ESZ = exp
    # 把 trie 段拉到单独 buffer（用 vmaddr->fileoff 映射 __LINKEDIT: vmaddr 0x6054000 fileoff 0x5c80000）
    lk_vm, lk_vsz, lk_fo, lk_fs = segs['__LINKEDIT']
    def vm2fo(v): return v - lk_vm + lk_fo
    fstart = vm2fo(E)
    buf = d[fstart:fstart+ESZ]
    seen = set()
    def walk(node, prefix, depth=0):
        if depth > 600 or node >= ESZ or node in seen: return
        seen.add(node)
        term, o = uleb(buf, node)
        ne = buf.index(b'\0', o)
        name = buf[o:ne].decode('utf-8', 'replace')
        o = ne + 1
        cc, o = uleb(buf, o)
        if term:
            flags, o = uleb(buf, o)
            addr, o = uleb(buf, o)
            if flags & 0x08: _, o = uleb(buf, o)
            elif flags & 0x10: _, o = uleb(buf, o)
            exports[prefix + name] = (flags, addr)
        kids = []
        for _ in range(cc):
            c, o = uleb(buf, o); kids.append(node + c)
        for k in kids:
            walk(k, prefix + name, depth + 1)
    walk(0, '')
print('exports total:', len(exports))

# --- 符号表 ---
symoff, nsyms, stroff, strsize = symtab
st = d[stroff:stroff+strsize]
sy = d[symoff:symoff+nsyms*16]
allsyms = {}
for i in range(nsyms):
    n_strx, n_type, n_sect, n_desc, n_value = struct.unpack_from('<IBBHQ', sy, i*16)
    e = st.index(b'\0', n_strx)
    nm = st[n_strx:e].decode('utf-8', 'replace')
    if n_value:
        allsyms.setdefault(nm, n_value)
print('symtab total named:', len(allsyms))

WANT = ['_il2cpp_class_from_name','_il2cpp_thread_attach','_il2cpp_domain_get','_il2cpp_runtime_invoke',
        '_il2cpp_string_new','_il2cpp_class_get_method_from_name','_luaL_loadbufferx','_lua_pcallk',
        '_lua_gettop','_lua_settop','_lua_getglobal','_lua_setglobal','_lua_pushcclosure',
        '_lua_pushstring','_lua_pushnumber','_lua_tolstring','_lua_type','_lua_createtable','_luaL_newstate']
print()
print(f'{"symbol":40s} {"export?":8s} {"symtab":12s}')
for w in WANT:
    inex = 'YES' if w in exports else '-'
    inv = hex(allsyms[w]) if w in allsyms else 'MISSING'
    print(f'{w:40s} {inex:8s} {inv:12s}')
json.dump({k: v[1] for k, v in exports.items()}, open('/tmp/uf_exports.json', 'w'))
json.dump(allsyms, open('/tmp/uf_syms.json', 'w'))
