##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://www.lab401.com)
#
# Copyright (c) 2026: ETOILE401 SAS & https://github.com
#
# This software is licensed under the PolyForm Noncommercial License 1.0.0.
# You may not use this software for commercial purposes.
#
# A copy of the license is available at:
# https://polyformproject.org
#
# This entire header "Required Notice" must remain in place.
##########################################################################

"""Dump Diff 2 - supplementary two-dump security diagnostics.

@copyright (2026) jareckib
Independent implementation. Concept inspired by Dump Diff by uaih3k9x.
These tests identify candidate structures; they do not prove Anti-Copy.
"""


def analyze(a, b, sequential=False):
    """Inspect MIFARE Classic data blocks, excluding manufacturer/trailers."""
    result = {'sequential': bool(sequential), 'counter': [], 'mirror': []}
    if len(a) != len(b) or len(a) < 64 or len(a) % 16:
        return result
    blocks = len(a) // 16
    if blocks not in (64, 256):  # MIFARE Classic 1K or 4K.
        return result
    def is_trailer(i):
        # Classic 4K: sectors 0-31 have 4 blocks; sectors 32-39 have 16.
        return (i % 4 == 3) if i < 128 else ((i - 128) % 16 == 15)
    data = [i for i in range(blocks) if i != 0 and not is_trailer(i)]
    if sequential:
        # Only a single, isolated byte increasing by one is a weak candidate.
        # Do not interpret arbitrary 16/32-bit overlapping windows as counters.
        for i in data:
            aa, bb = a[i*16:(i+1)*16], b[i*16:(i+1)*16]
            changed = [j for j in range(16) if aa[j] != bb[j]]
            if len(changed) == 1 and (bb[changed[0]] - aa[changed[0]]) == 1:
                result['counter'].append((i, changed[0]))
    # Mirror/complement: require 2-byte matching windows that CHANGE in both
    # dumps and preserve their relationship, to reduce incidental matches.
    changed_blocks = [i for i in data if a[i*16:(i+1)*16] != b[i*16:(i+1)*16]] if sequential else []
    for pos, i in enumerate(changed_blocks):
        for j in changed_blocks[pos+1:]:
            for off in range(15):
                x0, x1 = a[i*16+off:i*16+off+2], b[i*16+off:i*16+off+2]
                if x0 == x1:
                    continue
                for other in range(15):
                    y0, y1 = a[j*16+other:j*16+other+2], b[j*16+other:j*16+other+2]
                    if y0 == y1:
                        continue
                    if (x0 == y0 and x1 == y1) or (bytes(v ^ 255 for v in x0) == y0 and bytes(v ^ 255 for v in x1) == y1):
                        result['mirror'].append((i, j))
                        break
                if result['mirror'] and result['mirror'][-1] == (i, j):
                    break
    return result


def info_lines(report, enabled):
    lines = ['Security analysis']
    if not enabled:
        lines.extend(['Sequential: OFF', 'Counter: Disabled', 'Mirror: Disabled'])
    else:
        lines.append('Sequential: ELIGIBLE')
        lines.append('Counter: {} cand.'.format(len(report.get('counter', []))))
        lines.append('Mirror: {} cand.'.format(len(report.get('mirror', []))))
        for block, offset in report.get('counter', [])[:4]:
            lines.append('B{} byte{}: +1'.format(block, offset))
        for left, right in report.get('mirror', [])[:3]:
            lines.append('Mirror B{} / B{}'.format(left, right))
    lines.append('HEURISTIC - NOT PROOF')
    return lines