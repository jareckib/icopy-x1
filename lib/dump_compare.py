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

"""Dump Diff 2 dump discovery, parsing and comparison utilities.

Read supported RFID dumps, format memory blocks, extract metadata,
and identify changed blocks for the comparison screen.

@copyright (2026) jareckib"""

# Dump Diff 2 - independent implementation by jareckib (2026).
# Concept inspired by Dump Diff by uaih3k9x; no source code reused.
import os, re, json

FORMATS = {
    'Paxton Net2': ('paxton', 'net2', 4),
    'Paxton Switch2': ('paxton', 'switch2', 4),
    'T5577': ('t55xx', None, 4),
    'MIFARE Classic': ('mf1', None, 16),
    'Ultralight / NTAG': ('mfu', None, 4),
    'iCLASS': ('iclass', None, 8),
}

def _hex(s):
    s = re.sub(r'\s+', '', s)
    if not s or len(s) % 2 or re.search(r'[^0-9a-fA-F]', s):
        raise ValueError('Invalid HEX data')
    return bytes.fromhex(s)

def _json_blocks(path):
    with open(path, 'r') as f: obj = json.load(f)
    blocks = obj.get('blocks')
    if not isinstance(blocks, dict) or not blocks:
        raise ValueError('Missing blocks')
    indexes = sorted(int(k) for k in blocks)
    if indexes != list(range(indexes[-1] + 1)):
        raise ValueError('Incomplete block sequence')
    return b''.join(_hex(blocks[str(k)]) for k in indexes)

def _paxton(path, kind):
    with open(path, 'r') as f: lines = [s.strip() for s in f if s.strip()]
    if not lines: raise ValueError('Empty dump')
    # Net2 first line contains blocks 1..7; UID is stored separately on line 2.
    # Compare the complete memory record, excluding only block 0 (UID).
    raw = _hex(lines[0])
    if kind == 'net2':
        if len(raw) != 28: raise ValueError('Unexpected Net2 record length')
        if len(lines) < 2 or len(_hex(lines[1])) != 4:
            raise ValueError('Missing or invalid Net2 UID')
        return raw
    if len(raw) != 28: raise ValueError('Unexpected Switch2 record length (expected 7 blocks)')
    if len(lines) < 2 or len(_hex(lines[1])) != 4:
        raise ValueError('Missing or invalid Switch2 UID')
    return raw


def paxton_detail_blocks(path, category):
    """Decode display-only Hitag2 records; preserve comparison loader semantics.

    Net2 files: 28-byte first line represents blocks 1..7, while the
    4-byte UID is held on the second line. Do not drop the first four bytes:
    they are block 1 (password), not a header for the details display.
    Switch2 files contain seven 4-byte data blocks (blocks 1..7) on line 1 and UID on line 2.
    """
    with open(path, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]
    if not lines:
        raise ValueError('Empty Paxton dump')
    raw = _hex(lines[0])
    if category == 'Paxton Net2':
        if len(raw) != 28:
            raise ValueError('Net2 details require seven complete 4-byte blocks')
        if len(lines) < 2:
            raise ValueError('Missing Net2 UID line')
        uid = _hex(lines[1])
        if len(uid) != 4:
            raise ValueError('Invalid Net2 UID')
        return [(0, 'UID', uid)] + [(i+1, ('Pwd','Key/Pwd','Config','User B4','User B5','User B6','User B7')[i], raw[i*4:(i+1)*4]) for i in range(7)]
    if category == 'Paxton Switch2':
        if len(raw) != 28:
            raise ValueError('Unexpected Switch2 record length (expected 7 blocks)')
        if len(lines) < 2 or len(_hex(lines[1])) != 4:
            raise ValueError('Missing or invalid Switch2 UID')
        uid = _hex(lines[1])
        names = ('Pwd', 'Key/Pwd', 'Config', 'User B4', 'User B5', 'User B6', 'User B7')
        return [(0, 'UID', uid)] + [(i+1, names[i], raw[i*4:(i+1)*4]) for i in range(7)]
    raise ValueError('Not a Paxton category')



def json_info_lines(path, category):
    """Use Proxmark3/iCopy JSON as the authoritative Info source.

    A selected .bin resolves to its same-stem .json sidecar. The memory
    comparison code continues to use the original binary dump.
    """
    if category not in ('MIFARE Classic', 'iCLASS'):
        return None
    json_path = os.path.splitext(path)[0] + '.json'
    if not os.path.isfile(json_path):
        return None
    with open(json_path, 'r') as f:
        obj = json.load(f)
    blocks = obj.get('blocks')
    if not isinstance(blocks, dict) or not blocks:
        raise ValueError('JSON missing blocks')
    unit = FORMATS[category][2]
    numbers = sorted((int(k) for k in blocks), key=int)
    if len(numbers) != len(blocks) or numbers[0] != 0 or numbers != list(range(numbers[-1] + 1)):
        raise ValueError('Invalid JSON block numbering')
    result = ['FileType: ' + str(obj.get('FileType', '?'))]
    card = obj.get('Card', {})
    if isinstance(card, dict):
        for key, value in card.items():
            if isinstance(value, (str, int)):
                result.append(str(key) + ': ' + str(value))
    for number in numbers:
        raw = _hex(blocks[str(number)])
        if len(raw) != unit:
            raise ValueError('Invalid JSON block %d length' % number)
        block_hex = raw.hex().upper()
        label = ('B%d:' % number).rjust(5) + ' '
        if len(block_hex) > 16:
            result.extend((label + block_hex[:16], ' ' * len(label) + block_hex[16:]))
        else:
            result.append(label + block_hex)
    return result

def detail_block_lines(path, category, data=None):
    if category in ('Paxton Net2', 'Paxton Switch2'):
        blocks = paxton_detail_blocks(path, category)
        return ['UID: ' + blocks[0][2].hex().upper(), 'Blocks: 8'] + [
            'B%d: %s' % (number, value.hex().upper()) for number, _, value in blocks]
    if data is None: data = load(path, category)
    if category == 'T5577':
        return ['P%d B%d: %s' % ((0 if i < 32 else 1), (i//4 if i < 32 else (i-32)//4), ' '.join('%02X' % b for b in data[i:i+4]))
                for i in range(0, len(data), 4)]
    if category in ('MIFARE Classic', 'Ultralight / NTAG', 'iCLASS'):
        unit = FORMATS[category][2]
        result = []
        for i in range(0, len(data), unit):
            block_hex = data[i:i+unit].hex().upper()
            label = 'B{}:'.format(i//unit)
            # Classic: 16 bytes = four 8-hex-digit rows; no truncation.
            # All rows are drawn at the same HEX X coordinate by both UIs.
            chunk = 16
            for offset in range(0, len(block_hex), chunk):
                piece = block_hex[offset:offset+chunk]
                result.append((label + ' ' + piece) if offset == 0 else (' ' * 6 + piece))
        return result
    return []

def _mfu_memory_bin(data, path=None):
    """Return only 4-byte tag pages from Proxmark3 MFU binary formats.

    New PM3 format: 56-byte prefix, offset 11 = last page index.
    Legacy PM3 format: 48-byte prefix, no page-count field.
    Raw dumps: pages start at byte zero. Ambiguous legacy/raw files are
    intentionally rejected rather than silently shifting page numbers.
    """
    if not data or len(data) % 4:
        raise ValueError('Invalid MFU page alignment')
    # New-format header has an explicit last-page index. Require its count
    # to agree exactly with the remaining memory length (and that the
    # remainder is a whole number of 4-byte pages, not a truncated guess).
    if len(data) >= 60 and (len(data) - 56) % 4 == 0 and data[11] + 1 == (len(data) - 56) // 4:
        pages = data[56:]
        if not pages or len(pages) > 1024:
            raise ValueError('Invalid MFU memory size')
        return pages
    # For legacy 48-byte headers, a JSON sidecar can establish the exact
    # memory bytes without guessing. It also works for partial raw dumps.
    if path:
        sidecar = os.path.splitext(path)[0] + '.json'
        if os.path.isfile(sidecar):
            reference = _json_blocks(sidecar)
            if data == reference:
                return data
            if len(data) >= 48 and data[48:] == reference:
                return reference
            if len(data) >= 56 and data[56:] == reference:
                return reference
    # Plain dumps may be 16, 20, 41, 45, 135 or 231 pages.
    # Use these sizes only to disambiguate; other sizes may be partial dumps.
    known_pages = (16, 20, 41, 45, 135, 231)
    if len(data) // 4 in known_pages:
        return data
    # A legacy 48-byte header has no reliable length discriminator.
    # Never guess: it could be a partial raw dump of the same size.
    raise ValueError('MFU BIN format ambiguous (raw or legacy 48-byte header); use matching JSON')


def _mf1_memory_bin(data, path=None):
    """MIFARE Classic: return 16-byte blocks only, without guessed offsets.

    Native raw Proxmark3/iCopy Classic dumps have no MFU-style prefix.
    A matching JSON sidecar can verify and remove an external wrapper.
    """
    if path:
        sidecar = os.path.splitext(path)[0] + '.json'
        if os.path.isfile(sidecar):
            reference = _json_blocks(sidecar)
            if any(len(reference) == n * 16 for n in (20, 64, 128, 256)):
                if data == reference:
                    return data
                # Accept a header only if the full payload matches JSON exactly.
                if len(data) > len(reference) and data.endswith(reference):
                    return reference
                raise ValueError('MIFARE Classic BIN and JSON blocks disagree')
            raise ValueError('Unsupported MIFARE Classic JSON block count')
    valid_sizes = (20*16, 64*16, 128*16, 256*16)
    if len(data) in valid_sizes:
        return data
    raise ValueError('Unsupported/ambiguous MIFARE Classic BIN size (%d bytes); provide matching JSON' % len(data))

def load(path, category):
    if category not in FORMATS: raise ValueError('Unsupported category')
    _, variant, unit = FORMATS[category]
    ext = os.path.splitext(path)[1].lower()
    if os.path.getsize(path) > 1024 * 1024: raise ValueError('Dump exceeds safe 1 MiB limit')
    if variant: return _paxton(path, variant)
    if ext == '.bin':
        with open(path, 'rb') as f: data = f.read()
    elif ext == '.json': data = _json_blocks(path)
    else: raise ValueError('Unsupported file extension')
    if category == 'Ultralight / NTAG' and ext == '.bin':
        data = _mfu_memory_bin(data, path)
    if category == 'MIFARE Classic' and ext == '.bin':
        data = _mf1_memory_bin(data, path)
    if not data or len(data) % unit: raise ValueError('Invalid memory size')
    return data

def identity(path, category, data):
    """Return (kind, value) when tag identity is reliably available.

    T5577 has no factory UID; its encoded credential depends on modulation and
    format, so do not confuse its configuration blocks with a card identifier.
    """
    name = os.path.basename(path)
    if category == 'MIFARE Classic':
        if len(data) < 16:
            return None
        # Never present all-zero/all-FF manufacturer blocks as a real UID.
        # A four-byte UID has BCC at manufacturer byte 4.
        uid4 = data[:4]
        if uid4 not in (bytes(4), b'\xFF'*4) and data[4] == (uid4[0] ^ uid4[1] ^ uid4[2] ^ uid4[3]):
            return ('UID', uid4.hex().upper())
        # ISO14443A seven-byte cascade format: UID0..2 + BCC0,
        # UID3..6 + BCC1. Both BCC bytes must validate.
        if (data[3] == (0x88 ^ data[0] ^ data[1] ^ data[2]) and
                data[8] == (data[4] ^ data[5] ^ data[6] ^ data[7])):
            uid7 = data[:3] + data[4:8]
            if uid7 not in (bytes(7), b'\xFF'*7):
                return ('UID', uid7.hex().upper())
        return None
    if category == 'iCLASS':
        return ('CSN', data[:8].hex().upper()) if len(data) >= 8 else None
    if category == 'Ultralight / NTAG':
        # iCopy MFU dumps may include a metadata prefix, not only raw pages.
        # Prefer the UID in the native dump filename over assuming raw offset 0.
        match = re.search(r'M0-[^_]+_([0-9A-Fa-f]{14})_', name)
        if match:
            return ('UID', match.group(1).upper())
        # Raw 7-byte UID page layout with valid BCC0/BCC1.
        if len(data) >= 12 and data[3] == (0x88 ^ data[0] ^ data[1] ^ data[2]) and data[8] == (data[4] ^ data[5] ^ data[6] ^ data[7]):
            return ('UID', (data[:3] + data[4:8]).hex().upper())
    return None

def compare(path_a, path_b, category):
    a, b = load(path_a, category), load(path_b, category)
    if category in ('MIFARE Classic', 'Ultralight / NTAG', 'iCLASS') and len(a) != len(b):
        raise ValueError('Incompatible dump sizes')
    unit = FORMATS[category][2]
    id_a, id_b = identity(path_a, category, a), identity(path_b, category, b)
    different_fob = bool(id_a and id_b and id_a[0] == id_b[0] and id_a[1] != id_b[1])
    changes = []
    for offset in range(0, max(len(a), len(b)), unit):
        x, y = a[offset:offset+unit], b[offset:offset+unit]
        if x != y:
            change = {'block': offset//unit + (1 if category in ('Paxton Net2', 'Paxton Switch2') else 0), 'offset': offset + (4 if category in ('Paxton Net2', 'Paxton Switch2') else 0),
                      'a': x.hex().upper() or '--', 'b': y.hex().upper() or '--'}
            if category == 'T5577':
                change['page'] = 0 if offset < 32 else 1
                change['block'] = offset//4 if offset < 32 else (offset-32)//4
            changes.append(change)
    return {'same': not changes, 'changes': changes, 'size_a':len(a), 'size_b':len(b), 'different_fob':different_fob, 'identity_a':id_a, 'identity_b':id_b}

def discover(root, category):
    folder, variant, _ = FORMATS[category]
    directory = os.path.join(root, folder)
    if not os.path.isdir(directory): return []
    entries = []
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if not os.path.isfile(path): continue
        ext = os.path.splitext(name)[1].lower()
        if variant:
            if ext != '.txt': continue
            try:
                with open(path, 'r') as f: txt=f.read(250).lower()
                if 'type=' + variant not in txt: continue
            except (IOError, OSError): continue
        elif ext not in ('.bin','.json'): continue
        entries.append(path)
    # Treat BIN and JSON with the same basename as one logical dump.
    grouped = {}
    for path in entries:
        stem = os.path.splitext(os.path.basename(path))[0]
        previous = grouped.get(stem)
        if previous is None or path.lower().endswith('.bin'):
            grouped[stem] = path
    return sorted(grouped.values(), key=lambda p: (-os.path.getmtime(p), os.path.basename(p)))