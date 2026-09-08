"""Subaru Denso DBW 32-bit checksum (subarudbw). Validated against community ROMs.
Table = 17 x {addr_start(BE u32), addr_end(BE u32, inclusive), checksum_value(BE u32)}.
Rule: sum(BE u32 over [start, end+1)) + checksum_value == 0x5AA5A55A per active block.
Table offset by ROM size: 512K -> 0x7FB80, 1M -> 0xFFB80. (SH72531 1.25M: pass table_off explicitly.)
"""
import struct
MAGIC = 0x5AA5A55A

def table_offset(size):
    return {0x80000:0x7FB80, 0x100000:0xFFB80, 0x140000:0x13F500}.get(size)

def blocks(d, table_off):
    out=[]
    for i in range(17):
        e=table_off+i*12
        if e+12>len(d): break
        start=struct.unpack_from('>I',d,e)[0]
        end  =struct.unpack_from('>I',d,e+4)[0]
        cval =struct.unpack_from('>I',d,e+8)[0]
        out.append((i,e,start,end,cval))
    return out

def block_sum(d, start, end):
    s=0
    for a in range(start, end+1, 4):
        s=(s+struct.unpack_from('>I',d,a)[0])&0xFFFFFFFF
    return s

def validate(d, table_off=None):
    """Return (ok, active, passed, bad_list)."""
    if table_off is None: table_off=table_offset(len(d))
    if table_off is None: return (None,0,0,['unknown-size'])
    active=passed=disabled=0; bad=[]
    for i,e,start,end,cval in blocks(d,table_off):
        if start==0 and end==0:
            if cval==MAGIC: disabled+=1          # empty range + magic = disabled block (valid)
            else: bad.append((i,'disabled-badcval',hex(cval)))
            continue
        if start%4 or (end+1)%4 or start>=end or end>=len(d):
            bad.append((i,'badrange',hex(start),hex(end))); continue
        active+=1
        if ((block_sum(d,start,end)+cval)&0xFFFFFFFF)==MAGIC: passed+=1
        else: bad.append((i,'FAIL',hex(start),hex(end),hex(cval)))
    # valid if no bad entries AND either all active blocks pass, or the whole
    # table is disabled (checksum intentionally off -> the ECU accepts it)
    ok = (not bad) and ((active>0 and passed==active) or (active==0 and disabled>0))
    return (ok, active, passed, bad)

def fix(d, table_off=None):
    """Recompute and write each active block's checksum_value so it validates. Returns (bytearray, n_changed)."""
    d=bytearray(d)
    if table_off is None: table_off=table_offset(len(d))
    changed=0
    for i,e,start,end,cval in blocks(d,table_off):
        if start==0 and end==0: continue
        if start%4 or (end+1)%4 or start>=end or end>=len(d): continue
        need=(MAGIC - block_sum(d,start,end))&0xFFFFFFFF
        if need!=cval:
            struct.pack_into('>I',d,e+8,need); changed+=1
    return d, changed
