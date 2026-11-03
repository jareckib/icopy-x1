"""Read-only multi-capture comparison for Dump Diff 2.

No claims of cryptographic cloneability are made from dump differences.
"""

def analyze(captures, block_size, uid=None):
    if len(captures) < 2:
        raise ValueError('At least two complete captures required')
    if block_size not in (8, 16):
        raise ValueError('Unsupported block size')
    if any(not isinstance(c, (bytes, bytearray)) or not c or len(c) % block_size for c in captures):
        raise ValueError('Invalid capture')
    if len({len(c) for c in captures}) != 1:
        raise ValueError('Capture lengths differ')
    nblocks = len(captures[0]) // block_size
    changed = []
    details = []
    for block in range(nblocks):
        vals = [bytes(c[block*block_size:(block+1)*block_size]) for c in captures]
        if len(set(vals)) > 1:
            changed.append(block)
            details.append((block, vals))
    counters = []
    # Heuristic only: a 2- or 4-byte field strictly increments by a constant
    # across every capture. Check both byte orders; no crypto conclusions.
    for block, vals in details:
        for width in (2, 4):
            for pos in range(block_size-width+1):
                for order in ('big', 'little'):
                    numbers = [int.from_bytes(v[pos:pos+width], order) for v in vals]
                    steps = [b-a for a,b in zip(numbers, numbers[1:])]
                    if (steps and steps[0] in (1, -1) and all(x == steps[0] for x in steps)
                            and all(all(a[i] == b[i] for i in range(block_size)
                                        if not pos <= i < pos+width)
                                    for a,b in zip(vals,vals[1:]))):
                        counters.append({'block':block, 'offset':pos, 'width':width,
                                         'endian':order, 'step':steps[0]})
    # A 16-bit and 32-bit interpretation of the same changed bytes must
    # not be reported as two independent counters. Prefer wider field.
    unique=[]
    for c in sorted(counters,key=lambda c:(c['block'],c['offset'],-c['width'])):
        covered=set(range(c['offset'],c['offset']+c['width']))
        if any(p['block']==c['block'] and p['step']==c['step'] and
               p['endian']==c['endian'] and covered.issubset(
                   range(p['offset'],p['offset']+p['width'])) for p in unique):
            continue
        unique.append(c)
    counters=unique
    return {'scans':len(captures), 'blocks':nblocks, 'changed':changed,
            'details':details, 'possible_counters':counters,
            'identical':not changed, 'uid':uid}