#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Il2Cpp global-metadata.dat v29 parser -> type/method/field dump"""
import struct, sys, json, re

PATH = 'Payload/CJCS.app/Data/Managed/Metadata/global-metadata.dat'
d = open(PATH, 'rb').read()

def hdr():
    off = 8
    names = ['stringLiteral','stringLiteralData','string','events','properties','methods',
             'parameterDefaultValues','fieldDefaultValues','fieldAndParameterDefaultValueData',
             'fieldMarshaledSizes','parameters','fields','genericParameters',
             'genericParameterConstraints','genericContainers','nestedTypes','interfaces',
             'vtableMethods','interfaceOffsets','typeDefinitions','images','assemblies',
             'fieldRefs','referencedAssemblies','attributeData','attributeDataRange',
             'unresolvedVirtualCallParameterTypes','unresolvedVirtualCallParameterRanges',
             'windowsRuntimeTypeNames','windowsRuntimeStrings','exportedTypeDefinitions']
    H = {}
    for n in names:
        o, s = struct.unpack_from('<ii', d, off); off += 8
        H[n] = (o, s)
    return H

H = hdr()
SOFF = H['string'][0]

def cstr(off):
    e = d.index(b'\0', off)
    return d[off:e].decode('utf-8', 'replace')

def S(idx):  # string table index -> text
    return cstr(SOFF + idx)

TYPESZ = 88
n_types = H['typeDefinitions'][1] // TYPESZ
assert H['typeDefinitions'][1] % TYPESZ == 0, H['typeDefinitions'][1]

def type_def(i):
    return _type_def_v(i)

TYPESZ = 88
def _type_def_v(i):
    o = H['typeDefinitions'][0] + i * TYPESZ
    ints = struct.unpack_from('<8i', d, o)            # name..flags
    offs = struct.unpack_from('<8i', d, o + 32)       # fieldStart..interfaceOffsetsStart
    cnts = struct.unpack_from('<8H', d, o + 64)
    bitfield, token = struct.unpack_from('<2I', d, o + 80)
    t = dict(zip(['nameIndex','namespaceIndex','byvalTypeIndex','byrefTypeIndex',
                  'declaringTypeIndex','parentIndex','elementTypeIndex','flags'], ints))
    t['genericContainerIndex'] = -1
    for k, val in zip(['fieldStart','methodStart','eventStart','propertyStart',
                       'nestedTypesStart','interfacesStart','vtableStart',
                       'interfaceOffsetsStart'], offs):
        t[k] = val
    for k, val in zip(['method_count','property_count','field_count','event_count',
                       'nested_type_count','vtable_count','interfaces_count',
                       'interface_offsets_count'], cnts):
        t[k] = val
    t['bitfield'] = bitfield
    t['token'] = token
    return t

METHODSZ = 32
def method_def(i):
    o = H['methods'][0] + i * METHODSZ
    v = struct.unpack_from('<6i4H', d, o)
    return dict(zip(['nameIndex','declaringType','returnType','parameterStart',
                     'genericContainerIndex','token','flags','iflags','slot','parameterCount'], v))

FIELDSZ = 12
def field_def(i):
    o = H['fields'][0] + i * FIELDSZ
    v = struct.unpack_from('<3i', d, o)
    return dict(zip(['nameIndex','typeIndex','token'], v))

PROPSZ = 20
def prop_def(i):
    o = H['properties'][0] + i * PROPSZ
    v = struct.unpack_from('<5i', d, o)
    return dict(zip(['nameIndex','get','set','attrs','token'], v))

IMAGESZ = 40
def image_def(i):
    o = H['images'][0] + i * IMAGESZ
    v = struct.unpack_from('<10i', d, o)
    return dict(zip(['nameIndex','assemblyIndex','typeStart','typeCount','exportedTypeStart',
                     'exportedTypeCount','entryPointIndex','token','customAttributeStart',
                     'customAttributeCount'], v))

n_img = H['images'][1] // IMAGESZ
imgs = []
for i in range(n_img):
    im = image_def(i)
    im['name'] = S(im['nameIndex'])
    imgs.append(im)

def img_of_type(ti):
    for im in imgs:
        if im['typeStart'] <= ti < im['typeStart'] + im['typeCount']:
            return im['name']
    return '?'

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'list'
    if mode == 'list':
        pat = re.compile(sys.argv[2]) if len(sys.argv) > 2 else None
        for i in range(n_types):
            t = type_def(i)
            full = (S(t['namespaceIndex']) + '.' if t['namespaceIndex'] else '') + S(t['nameIndex'])
            if pat and not pat.search(full): continue
            print(f'{i:6d} {img_of_type(i):32s} {full:70s} m={t["method_count"]:4d} f={t["field_count"]:3d} p={t["property_count"]:3d}')
    elif mode == 'show':
        ti = int(sys.argv[2])
        t = type_def(ti)
        print('TYPE', ti, S(t['namespaceIndex']) + '.' + S(t['nameIndex']), 'parent=%d' % t['parentIndex'])
        print('--- methods ---')
        for k in range(t['method_count']):
            m = method_def(t['methodStart'] + k)
            ps = []
            for p in range(m['parameterCount']):
                pp = struct.unpack_from('<2i', d, H['parameters'][0] + (m['parameterStart'] + p) * 8)
                ps.append(S(pp[0]))
            print(f'  [{k:3d}] {S(m["nameIndex"])}({", ".join(ps)}) pc={m["parameterCount"]} flags={m["flags"]:#x}')
        print('--- fields ---')
        for k in range(t['field_count']):
            f = field_def(t['fieldStart'] + k)
            print(f'  [{k:3d}] {S(f["nameIndex"])} typeIdx={f["typeIndex"]}')
        print('--- properties ---')
        for k in range(t['property_count']):
            p = prop_def(t['propertyStart'] + k)
            print(f'  [{k:3d}] {S(p["nameIndex"])} get={p["get"]} set={p["set"]}')
    elif mode == 'grep':
        # grep method/field names
        pat = re.compile(sys.argv[2], re.I)
        for i in range(n_types):
            t = type_def(i)
            full = (S(t['namespaceIndex']) + '.' if t['namespaceIndex'] else '') + S(t['nameIndex'])
            hits = []
            for k in range(t['method_count']):
                m = method_def(t['methodStart'] + k)
                if pat.search(S(m['nameIndex'])): hits.append('M:' + S(m['nameIndex']))
            for k in range(t['field_count']):
                f = field_def(t['fieldStart'] + k)
                if pat.search(S(f['nameIndex'])): hits.append('F:' + S(f['nameIndex']))
            for k in range(t['property_count']):
                p = prop_def(t['propertyStart'] + k)
                if pat.search(S(p['nameIndex'])): hits.append('P:' + S(p['nameIndex']))
            if hits:
                print(f'{i:6d} {img_of_type(i):30s} {full}  ->  {", ".join(hits[:12])}')
    elif mode == 'img':
        for im in imgs: print(im)
