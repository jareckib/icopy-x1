##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://www.lab401.com)
#
# Copyright (c) 2026: ETOILE401 SAS & https://github.com
#
#
# This software is licensed under the PolyForm Noncommercial License 1.0.0.
# You may not use this software for commercial purposes.
#
# A copy of the license is available at:
# https://polyformproject.org
#
# This entire header "Required Notice" must remain in place.
##########################################################################

"""Anti-Copy Detection Module for Dump Diff 2

Read-only MIFARE Classic Anti-Copy signature diagnostics.
Detects potential Anti-Copy signatures using hexadecimal
patterns and heuristic analysis.

Supported protection families:
- NORALSY
- INTRATONE
- HEXACT
- COMELIT
- URMET
- Stored block 0 marker 0x88 (manufacturer-block heuristic only)

Features:
- Identification of known and experimental signature patterns.
- Independent analysis of dump A and dump B.
- Heuristic match reporting; not proof of active protection.

Research sources and acknowledgements:

1. Published Anti-Copy detection rules (independent of SAK analysis):
   Parklink Development Limited development team:
   quantum-x, danielebruneo and triplesprawl.
   Source: https://github.com/flipperdevices/flipperzero-firmware/issues/1345
   Covers Intratone (COGELEC), Hexact (COGELEC), Comelit,
   Noralsy and Urmet, with several generations of signatures.
   These are signature indicators, not proof that protection is active.
   Published rules may produce false positives. A counter need not
   change on every scan and may reside in the access-control system.

2. Other community discussions and implementation references:
   https://github.com/ikarus23/MifareClassicTool/issues/516
   TheDefender44 and other contributors are acknowledged for their
   published discussion and pattern adaptations.

3. Proxmark3 parser references (independent structural diagnostics):
   RfidResearchGroup/proxmark3 client/src/parsers/parsevigik.c
   and parsehexact.c. Urmet layout and stored 0x88 marker.
   Hexact payload XOR-mask decoding and cross-check are implemented.
   Based on parsehexact.c; diagnostic only, not an active-protection test.

4. Separate diagnostic heuristics developed/adapted for Dump Diff 2:
   - Differences between two dumps with a validated matching UID.
   - Stored block 0 marker 0x88 from manufacturer-block bytes.
     Reference: equipter, "Mifare Classic - SAK Swapping Explained"
     https://gist.github.com/equipter/3022aea4e371e585ff6e46de637e7769
     This is NOT a Parklink detection rule. A memory dump cannot
     establish the SAK returned during live anti-collision.

Implementation and integration: jareckib (Dump Diff 2).
Experimental adaptations of malformed published regexes are
explicitly marked UNVERIFIED; they have not been validated on tags.

Detection is heuristic and does not constitute definitive
proof of Anti-Copy protection.

@copyright (2026) jareckib
"""

import re

# Match original published regexes, except the documented broken/ambiguous
# Hexact C, Comelit C, Urmet A patterns, included as EXPERIMENTAL
# with documented syntax corrections. These are NOT validated on real tags.
PATTERNS = (
 ('Intratone', 'A', r'^[0-9A-F]{1412}(?:(?!00|FF)[0-9A-F]{2}).+?684578616374202D20434F47454C4543'),
 ('Hexact', 'A', r'484558414354787788008FA1D601D0A2(?!0000000000000000000000000000000000000000000000000000000000000000).+?000000000000000000000000000000004845584143547877880089347350BD36'),
 ('Hexact', 'B', r'^[0-9A-F]{1376}484558414354787788008FA1D601D0A204D26'),
 ('Comelit', 'A', r'[0-9A-F]{2}0000014A6352684677'),
 ('Comelit', 'B', r'^[0-9A-F]{216}(?:(?!0000)[0-9A-F]{4})*?[0-9A-F]{4}4A63526846777877'),
 ('Noralsy', 'A', r'675A3241377078778800395244733978'),
 ('Generic', 'A', r'^[0-9A-F]{1888}050908080008FF078069FFFFFFFFFFFF[0-9A-F]{8}20202020'),
)
# Primary rules: Parklink Development Limited, quantum-x,
# danielebruneo and triplesprawl:
# https://github.com/flipperdevices/flipperzero-firmware/issues/1345
# Related discussion: https://github.com/ikarus23/MifareClassicTool/issues/516
# The published expressions contain ambiguous/broken regex syntax:
# Hexact C: embedded ^ after a literal prefix (impossible anchor), removed.
# Comelit C: [^00]{3} matches 3 nonzero *characters*, not 3 nonzero bytes.
#   Preserve that literal interpretation for exploratory matches, but flag it.
# Urmet A: [5|A] matches the pipe character as well; use [5A].
# No rule here is evidence of an active anti-clone mechanism.
EXPERIMENTAL_PATTERNS = (
 ('Hexact', 'C', r'^[0-9A-F]{1376}484558414354787788008FA1D601D0A2[0-9A-F]{4}6'),
 ('Comelit', 'C', r'[^00]{3}[0-9]{2}00[0-9]{2}4A6352684677'),
 ('Urmet', 'A', r'^[0-9A-F]{1888}8829DA9DAF767F[0-9A-F]{109}[5A]'),
)
UNVERIFIED = ('Hexact C', 'Comelit C', 'Urmet A')

def _cogelec(data):
    if len(data) < 0x3d0: return False
    if data[0x3c0:0x3c6] != b'HEXACT' or data[0x3c9:0x3d0] != b'COGELEC': return False
    return all(data[i:i+16] not in (bytes(16), b'\xff'*16)
               for i in (0x2c0, 0x2d0, 0x2e0))

def _sak_swapping_candidate(data):
    """Heuristic for a SAK-swapping *candidate* in MIFARE Classic block 0.

    Source: equipter, "Mifare Classic - SAK Swapping Explained":
    https://gist.github.com/equipter/3022aea4e371e585ff6e46de637e7769

    For a complete 1K/4K dump with a four-byte UID, check the UID BCC
    and the manufacturer-block SAK-like byte (offset 5). The candidate
    marker 0x88, also documented in Proxmark parsevigik/parsehexact.
    A memory dump does NOT contain the live anti-collision response.
    Therefore this cannot verify actual SAK swapping or Double Cross.
    """
    if not isinstance(data, bytes) or len(data) not in (1024, 4096):
        return False
    uid = data[:4]
    if data[4] != (uid[0] ^ uid[1] ^ uid[2] ^ uid[3]):
        return False
    # 0x88 is documented as a marker by both Proxmark parsers.
    # Do not infer 0x98 solely from 4K capacity.
    return data[5] == 0x88

def _urmet_captiv_marker(data):
    """Heuristic for an Urmet Captiv use-counter *candidate*, structural and
    readable from a single dump (unlike the Counter/Mirror heuristics in
    dump_security.py, which need two dumps taken over time).

    Source: RfidResearchGroup/proxmark3, client/src/parsers/parsevigik.c,
    vigik_print_urmet_captiv(). Sector 2 block 1 stores one 3-byte value
    twice (offsets +5 and +9 within the block), each copy preceded by a
    1-byte prefix (offsets +4 and +8). Observed on all three Urmet Captiv
    cards in that research; the differing prefix is reported to take the
    shape of a use counter. Seen on three cards only: a candidate, not proof.
    """
    if not isinstance(data, bytes) or len(data) not in (1024, 4096):
        return None
    off = (2 * 4 + 1) * 16  # sector 2, block 1 (sectors 0-31 are 4 blocks each)
    if len(data) < off + 16:
        return None
    block = data[off:off + 16]
    if block[5:8] != block[9:12]:
        return None
    if block[5:8] in (b'\x00' * 3, b'\xff' * 3):
        return None
    return {'value': block[5:8], 'prefix_a': block[4], 'prefix_b': block[8]}


# Additional read-only diagnostics adapted from RRG/Iceman Proxmark3:
# client/src/parsers/parsevigik.c (vigik_print_urmet_captiv)
# client/src/parsers/parsehexact.c (HEXACT_BLOCK0_SAK).
# These are structural observations, NOT Parklink Anti-Copy signatures.
# The full Hexact decrypt/cross-check algorithm is NOT implemented here.


# Hexact decoder ported from RfidResearchGroup/proxmark3
# client/src/parsers/parsehexact.c (hexact_decrypt / hexact_cross_check).
# Read-only diagnostic; a consistency check is not proof of Anti-Copy.
_HEXACT_RECORDS = ((9, 0), (9, 1), (9, 2), (11, 0), (11, 1))
_HEXACT_CHECKS = (
    (0,4,0,4,0xFE), (0,7,2,7,0), (1,1,0,1,0),
    (1,4,0,4,0), (1,15,2,7,0), (2,0,0,0,0),
    (2,1,0,1,0), (2,4,0,4,0), (2,7,0,7,0),
    (3,7,2,7,0), (3,13,0,5,0), (4,1,0,1,0),
    (4,13,0,5,0), (4,15,2,7,0),
)

def _hexact_block(data, sector, local_block):
    # Classic 1K sectors 0..15 are four blocks each; works in 4K too.
    off = (sector * 4 + local_block) * 16
    return data[off:off + 16] if off + 16 <= len(data) else None

def _hexact_decode_block(raw, sector, local_block):
    seed = (0xB3 if sector == 9 else 0x5C) ^ (2 * local_block)
    return bytes(v ^ (((seed << (i & 7)) | (seed >> ((8 - (i & 7)) & 7))) & 255)
                 for i, v in enumerate(raw))

def hexact_validate(data):
    """Return Proxmark-compatible Hexact payload check result or None.

    Does not infer live SAK, validate a cryptographic signature, or
    claim that a card has active Anti-Copy protection.
    """
    if not isinstance(data, bytes) or len(data) not in (1024, 4096):
        return None
    marker = _hexact_block(data, 15, 0)
    if marker is None or marker[:6].lower() != b'hexact' or marker[9:16].lower() != b'cogelec':
        return None
    idn = _hexact_block(data, 0, 2)[:8]
    serial = _hexact_block(data, 15, 2)[:4]
    uid = data[:4]
    records = []
    written = []
    for sector, block in _HEXACT_RECORDS:
        raw = _hexact_block(data, sector, block)
        records.append(_hexact_decode_block(raw, sector, block))
        written.append(any(x not in (0, 255) for x in raw))
    if all(not x for x in written):
        return {'status':'EMPTY', 'passed':0, 'total':0, 'mismatches':[]}
    # Upstream skips cross-check when the 8-byte identifier is wiped.
    if not any(idn):
        return {'status':'ID WIPED', 'passed':0, 'total':0, 'mismatches':[]}
    passed = total = 0
    mismatches = []
    for rec, pos, source, idx, xor_value in _HEXACT_CHECKS:
        if not written[rec]:
            continue
        expected = idn[idx] ^ xor_value
        if source == 1 and idx < 4:
            expected ^= serial[idx]
        elif source == 2:
            expected ^= uid[0] ^ uid[2]
        total += 1
        if records[rec][pos] == expected:
            passed += 1
        else:
            mismatches.append('S{} B{} byte {}'.format(_HEXACT_RECORDS[rec][0], _HEXACT_RECORDS[rec][1], pos))
    if written[1] and written[2]:
        total += 1
        if records[2][15] == records[1][7] or records[2][7] == records[1][15]:
            passed += 1
        else:
            mismatches.append('S9 record tie')
    return {'status':('PASS' if total and passed == total else 'MISMATCH'),
            'passed':passed, 'total':total, 'mismatches':mismatches}

def _proxmark_diagnostics(data):
    """Return independently labelled structural observations from a raw MF1 dump."""
    if not isinstance(data, bytes) or len(data) not in (1024, 4096):
        return []
    notes = []
    # parsehexact.c and parsevigik.c both document 0x88 as a stored
    # anti-clone marker. It is not the live RF SAK response.
    if data[5] == 0x88:
        notes.append('Block0 SAK 88 marker [STORED ONLY]')
    # parsevigik.c: Urmet Captiv stores 11 ASCII digits in block 1,
    # bytes 5..15. This alone does not identify the vendor.
    number = data[16 + 5:16 + 16]
    rec = data[(2 * 4 + 1) * 16:(2 * 4 + 2) * 16]
    # Require the published Urmet key bytes in a trailer as an extra
    # indication, otherwise arbitrary ASCII card data is too common.
    urmet_key = bytes.fromhex('8829DA9DAF76')
    urmet_keys = 0
    for block in range(len(data) // 16):
        if _sector_trailer(block):
            trailer = data[block * 16:(block + 1) * 16]
            if trailer[:6] == urmet_key or trailer[10:16] == urmet_key:
                urmet_keys += 1
    if urmet_keys:
        notes.append('Urmet key candidate: {} trailer(s)'.format(urmet_keys))
        if all(48 <= x <= 57 for x in number):
            notes.append('Urmet layout: ASCII ID ' + number.decode('ascii'))
        if len(rec) == 16 and rec[5:8] == rec[9:12]:
            notes.append('Urmet record: repeated 3-byte field')
            if rec[4] != rec[8]:
                notes.append('Urmet record: differing prefix bytes')
    hx = hexact_validate(data)
    if hx is not None:
        if hx['total']:
            notes.append('Hexact checks: {}/{} [{}]'.format(hx['passed'], hx['total'], hx['status']))
            for item in hx['mismatches'][:3]:
                notes.append('Hexact mismatch: ' + item)
            if len(hx['mismatches']) > 3:
                notes.append('Hexact: +{} mismatches'.format(len(hx['mismatches']) - 3))
        else:
            notes.append('Hexact: ' + hx['status'] + ' (not validated)')
    # Hexact source also treats block0 byte 5 as a marker, but this
    # alone must not be interpreted as a successful Hexact cross-check.
    return notes

def scan(data):
    if not isinstance(data, bytes) or len(data) not in (1024, 4096):
        return {'status':'NOT TESTED','matches':[], 'experimental':[], 'reason':'Requires complete MIFARE Classic 1K/4K memory'}
    h=data.hex().upper()
    matches=[]
    experimental=[]
    hx = hexact_validate(data)
    # A marker/layout match is insufficient when a populated Hexact
    # record fails its independent cross-check. Keep the diagnostics.
    if _cogelec(data) and hx is not None and hx.get('status') == 'PASS':
        matches.append('COGELEC Generic')
    # Independent diagnostic heuristic, NOT a published Parklink rule.
    if _sak_swapping_candidate(data): experimental.append('Block0 88 marker')
    if _urmet_captiv_marker(data) is not None: experimental.append('Urmet Captiv marker')
    for vendor,variant,regex in PATTERNS:
        if re.search(regex,h,re.I|re.S):
            if vendor == 'Hexact' and hx is not None and hx.get('status') != 'PASS':
                continue
            matches.append(vendor+' '+variant)
    for vendor,variant,regex in EXPERIMENTAL_PATTERNS:
        if re.search(regex,h,re.I|re.S):
            if vendor == 'Hexact' and hx is not None and hx.get('status') != 'PASS':
                continue
            experimental.append(vendor+' '+variant)
    return {'status':'MATCH' if matches else ('EXPERIMENTAL' if experimental else 'NO MATCH'),
            'matches':matches, 'experimental':experimental,
            'reason':'Heuristic only; no match does not prove absence of protection',
            'diagnostics':_proxmark_diagnostics(data)}

def _mfc_sector(block):
    """Absolute Classic block index -> sector (1K and 4K)."""
    return block // 4 if block < 128 else 32 + (block - 128) // 16


def _sector_trailer(block):
    """Classic sector trailer position, including 4K large sectors."""
    return (block % 4 == 3) if block < 128 else ((block - 128) % 16 == 15)


def _mfc_uid(data):
    """Return a UID only when manufacturer-block BCC validates."""
    if len(data) < 16:
        return None
    if data[4] == (data[0] ^ data[1] ^ data[2] ^ data[3]):
        return data[:4]
    if data[7] == (data[3] ^ data[4] ^ data[5] ^ data[6]):
        return data[:3] + data[4:8]
    return None


def analyze(data_a, data_b):
    """Compare signatures and changed blocks, without claiming active protection.

    Changed data on two snapshots with the same validated UID is only a
    candidate for dynamic content. It is NOT evidence of a rolling code:
    application data, counters and ordinary updates can change too.
    """
    a, b = scan(data_a), scan(data_b)
    changed = []
    data_blocks = []
    trailer_blocks = []
    manufacturer_blocks = []
    valid = (isinstance(data_a, bytes) and isinstance(data_b, bytes)
             and len(data_a) == len(data_b)
             and len(data_a) in (1024, 4096))
    if valid:
        for block in range(len(data_a) // 16):
            off = block * 16
            if data_a[off:off+16] != data_b[off:off+16]:
                changed.append((_mfc_sector(block), block))
                if block == 0:
                    manufacturer_blocks.append(block)
                elif _sector_trailer(block):
                    trailer_blocks.append(block)
                else:
                    data_blocks.append(block)
    uid_a = _mfc_uid(data_a) if valid else None
    uid_b = _mfc_uid(data_b) if valid else None
    same_uid = bool(uid_a is not None and uid_a == uid_b)
    dynamic_candidate = bool(same_uid and data_blocks)
    status = ('POSSIBLE' if a['matches'] or b['matches'] else
              ('UNVERIFIED' if a['experimental'] or b['experimental'] else 'UNKNOWN'))
    return {'a': a, 'b': b, 'changed': changed, 'status': status,
            'same_uid': same_uid, 'uid_checked': bool(uid_a and uid_b),
            'data_blocks_changed': data_blocks,
            'trailer_blocks_changed': trailer_blocks,
            'manufacturer_blocks_changed': manufacturer_blocks,
            'dynamic_candidate': dynamic_candidate,
            'comparison_valid': valid}


def info_lines(result):
    if not result:
        return ['Anti-Copy: NOT TESTED']
    lines = ['Anti-Copy: ' + result['status']]
    for key in ('a', 'b'):
        obj = result[key]
        lines.append('Dump ' + key.upper() + ': ' + obj['status'])
        for match in obj['matches']:
            lines.append('  ' + match + ' [HEURISTIC]')
        for note in obj.get('diagnostics', []):
            lines.append('  ' + note)
        for match in obj.get('experimental', []):
            lines.append('  ' + match + (' [HEURISTIC]' if match in ('Block0 88 marker', 'Urmet Captiv marker') else ' [UNVERIFIED]'))
    if not result.get('comparison_valid'):
        lines.append('Comparison: NOT TESTED')
    else:
        lines.append('Changed blocks: ' + str(len(result['changed'])))
        lines.append('Data blocks: ' + str(len(result['data_blocks_changed'])))
        lines.append('Sector trailers: ' + str(len(result['trailer_blocks_changed'])))
        lines.append('Manufacturer blocks: ' + str(len(result.get('manufacturer_blocks_changed', []))))
        if result.get('uid_checked') and not result.get('same_uid'):
            lines.append('Different UID: no rolling inference')
        for sector, block in result['changed'][:24]:
            lines.append('S{} B{} changed'.format(sector, block))
        if len(result['changed']) > 24:
            lines.append('... more changes')
    lines += ['WARNING: Anti-Clone checks', 'are NOT 100% reliable.',
              'A signature match does', 'not confirm protection.',
              'Changed data does not', 'prove a rolling counter.',
              'Block0 marker does not', 'prove live SAK swapping.',
              'No signature found does', 'not rule it out.',
              'SAK: separate heuristic.',
              'Rules: Parklink team;',
              'SAK: independent source.',
              'UNVERIFIED: experimental']
    return lines

def analyze_mfc(data_a, data_b):
    """Backwards-compatible Stage 1 interface for existing tests."""
    if not isinstance(data_a, bytes) or not isinstance(data_b, bytes):
        raise ValueError('Expected bytes')
    if not data_a or not data_b or len(data_a)%16 or len(data_b)%16:
        raise ValueError('Invalid MIFARE Classic block data')
    if len(data_a)!=len(data_b):
        return {'status':'INCOMPLETE','anti_copy':'UNKNOWN','changed_blocks':[]}
    result=analyze(data_a,data_b)
    changes=[]
    for sector,block in result['changed']:
        off=block*16
        changes.append({'sector':sector,'block':block,'a':data_a[off:off+16].hex().upper(),'b':data_b[off:off+16].hex().upper()})
    return {'status':'CHANGED' if changes else 'UNCHANGED',
            'anti_copy':result['status'],'changed_blocks':changes}