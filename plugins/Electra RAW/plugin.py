##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://www.lab401.com)
#
# Copyright (c) 2026: ETOILE401 SAS & https://github.com/quantum-x/
#
# This software is licensed under the PolyForm Noncommercial License 1.0.0.
# You may not use this software for commercial purposes.
#
# A copy of the license is available at:
# https://polyformproject.org/licenses/noncommercial/1.0.0
#
# This entire header "Required Notice" must remain in place.
##########################################################################
"""
Electra RAW Clone plugin for iCopy-XS

Electra (Romania) is a modified EM4100 format where the standard 64-bit
EM4100 data is followed by a 64-bit "epilogue".

Decoding and encoding logic is a Python port of the "Electra" LF-RFID
protocol handler from Flipper Zero firmware
(lib/lfrfid/protocols/protocol_electra.c), written by Leptoptilos
<leptoptilos@icloud.com> (2024), itself based on Flipper's EM4100
implementation. GNU GPLv3.

Known Electra epilogue variants include:
  7E71AAAA, 0030AAAA, and 7E1EAAAA.

On the current Iceman Proxmark3 firmware, tests with the 7E71
variant showed that the standard 'lf em 410x reader' command did
not decode the tag, even with RF/64, inverted data, and different
demodulation error limits. In these tests, the 0030 and 7E1E
variants could be decoded by the standard EM410x decoder.
These observations do not necessarily apply to other firmware versions.

To support all three variants, the plugin acquires raw antenna
samples using:

  'lf read'
  'data rawdemod --am'

It independently validates the EM4100 base frame and Electra
epilogue before accepting the complete 128-bit RAW bitstream.
Facility Code, Card ID, and Epilogue data are decoded for display.

The cloning process writes the captured 128-bit RAW data directly to a
T5577 as blocks 0-4 (Manchester / RF64 configuration + RAW data blocks),
preserving the original bitstream without re-encoding.

iCopy-X adaptation and integration by @jareckib (Jarek Barwinski).

"""

import re
import os

LAST_RAW_DIR  = '/mnt/upan/dump/electra'
LAST_RAW_FILE = os.path.join(LAST_RAW_DIR, 'last_raw.txt')

TIMEOUT_ACQUIRE  = 10000
TIMEOUT_WRITE    = 8000
TIMEOUT_DET      = 6000

BLOCK0_CONFIG = 0x00148080

def _ensure_dir():
    try:
        if not os.path.exists('/mnt/upan'):
            return False
        os.makedirs(LAST_RAW_DIR, mode=0o775, exist_ok=True)
        return True
    except Exception:
        return False

def _save_last_raw(raw):
    """Save the complete 128-bit Electra RAW as 32 hexadecimal characters."""
    raw = (raw or '').strip().upper()
    if not re.fullmatch(r'[0-9A-F]{32}', raw):
        return False
    if not _ensure_dir():
        return False
    try:
        with open(LAST_RAW_FILE, 'w') as f:
            f.write(raw + '\n')
        return True
    except Exception:
        return False


def _load_last_raw():
    """Load and validate the last saved 128-bit Electra RAW."""
    try:
        with open(LAST_RAW_FILE, 'r') as f:
            raw = f.read().strip().upper()
        if _valid_electra_raw(raw):
            return raw
    except (OSError, IOError):
        pass
    return None


# Only supported Electra epilogues; filler is uniform (AA or 00).
ELECTRA_EPILOGUES = ('7E71', '0030', '7E1E')


def _valid_electra_raw(raw):
    if not isinstance(raw, str) or not re.fullmatch(r'[0-9A-Fa-f]{32}', raw):
        return False
    bits = format(int(raw[:16], 16), '064b')
    if bits[:9] != '111111111' or bits[63] != '0':
        return False
    rows = [bits[9 + 5 * i:14 + 5 * i] for i in range(10)]
    if any(len(row) != 5 or row.count('1') % 2 for row in rows):
        return False
    if any((sum(int(row[col]) for row in rows) + int(bits[59 + col])) % 2
           for col in range(4)):
        return False
    epi = raw[16:].upper()
    if epi[:4] not in ELECTRA_EPILOGUES:
        return False
    filler = epi[4:6]
    return filler in ('AA', '00') and epi[4:] == filler * 6


def _extract_demod_bits(output):
    """Accept only demodulated binary lines, not diagnostic numbers."""
    if not output:
        return None
    parts = []
    for line in output.splitlines():
        s = re.sub(r'^\s*\[\+\]\s*', '', line).strip()
        # A raw demod line must be a substantial uninterrupted bit sequence.
        if re.fullmatch(r'[01]{32,}', s):
            parts.append(s)
    return ''.join(parts) if parts else None


def _has_valid_em4100(bitstream):
    """Identify a complete, parity-correct 64-bit EM4100 frame."""
    if not bitstream:
        return False
    for match in re.finditer(r'(?=111111111)', bitstream):
        pos = match.start()
        if pos + 64 > len(bitstream):
            continue
        bits = bitstream[pos:pos + 64]
        if bits[63] != '0':
            continue
        rows = [bits[9 + 5 * i:14 + 5 * i] for i in range(10)]
        if any(row.count('1') % 2 for row in rows):
            continue
        if any((sum(int(row[c]) for row in rows) + int(bits[59 + c])) % 2 for c in range(4)):
            continue
        return True
    return False


def _find_raw128_from_preamble(bitstream):
    """Scan all bit offsets, reject invalid frames and ambiguous captures."""
    if not bitstream or len(bitstream) < 128:
        return None
    found = set()
    for match in re.finditer(r'(?=111111111)', bitstream):
        pos = match.start()
        if pos + 128 > len(bitstream):
            continue
        chunk = bitstream[pos:pos + 128]
        raw = '%032X' % int(chunk, 2)
        if _valid_electra_raw(raw):
            found.add(raw)
            if len(found) > 1:
                return None  # never silently choose between different IDs
    return next(iter(found)) if found else None

def _tag_detected(output):
    if not output:
        return False
    for line in output.splitlines():
        low = line.lower()
        if re.search(r'chip\s*type.*t55', low):
            return True
        if re.search(r'chipset.*t55', low):
            return True
        if 't55' in low:
            return True
    return False

def _extract_block_hex(output, block_num):
    """Require an explicit numbered readback row; never parse error text."""
    if not output:
        return None
    for line in output.splitlines():
        match = re.search(
            r'(?<![0-9])(?:0?[0-7])\s*\|\s*([0-9A-Fa-f]{8})(?![0-9A-Fa-f])',
            line)
        if match:
            prefix = line[:match.start(1)].split('|')[0].strip()
            prefix = re.sub(r'^\[.\w+\- ]+\]\s*', '', prefix).strip()
            if prefix.isdigit() and int(prefix) == block_num:
                return match.group(1).upper()
    return None

class ElectraPlugin(object):

    def __init__(self, host=None):
        self.host = host

    def _pm3(self, cmd, timeout=TIMEOUT_WRITE):
        return self.host.pm3_command(cmd, timeout=timeout)

    def _detect_t5577(self):
        ok, out = self._pm3('lf t55 detect', TIMEOUT_DET)
        if ok and _tag_detected(out):
            return True
        ok2, out2 = self._pm3('lf search', TIMEOUT_DET)
        if ok2 and _tag_detected(out2):
            return True
        return False

    # ---------- EM4100 / Electra decode (for display only) ----------

    def _decode_em4100(self, base_hex):
        base = int(base_hex, 16) & ((1 << 64) - 1)
        for _ in range(9):
            base = (base << 1) & ((1 << 64) - 1)
        decoded_bytes = []
        value = 0
        for r in range(10):
            nibble = 0
            for i in range(5):
                bit = (base >> 63) & 1
                base = (base << 1) & ((1 << 64) - 1)
                if i < 4:
                    nibble = ((nibble << 1) | bit)
            value = ((value << 4) | nibble)
            if r % 2 == 1:
                decoded_bytes.append(value & 0xFF)
                value = 0
        return decoded_bytes  # 5 bytes: [facility_hi, facility_lo, id_hi, id_mid, id_lo]

    def _decode_epilogue(self, epi_hex):
        # The first 3 bytes of the epilogue, in the order the tag
        # actually transmits them, are the meaningful variant marker
        # (e.g. 7E 71 AA for the most common variant per
        # protocol_electra.c's own worked example); the remaining bytes
        # are arbitrary filler.
        return int(epi_hex[0:2], 16), int(epi_hex[2:4], 16), int(epi_hex[4:6], 16)

    def _decode_and_store_raw(self, raw):
        """Decode a 32-hex-char RAW into facility/ID/epilogue and store
        all of it (plus electra_raw/current_id) in the host vars, shared
        by both the fresh-read and the load-last-RAW paths so the
        display always shows the same thing however the RAW got there."""
        if not _valid_electra_raw(raw):
            self.host.set_var('error_msg', 'Invalid Electra RAW.')
            return False

        base_hex = raw[0:16]
        epi_hex = raw[16:32]

        decoded = self._decode_em4100(base_hex)
        if len(decoded) != 5:
            self.host.set_var('error_msg', 'EM4100 decode failed.')
            return False

        # facility = top 16 bits, id = bottom 24 bits of the 40-bit
        # standard EM410x ID (matches pm3's own "Pattern ELECTRA : fc id"
        # split in cmdlfem410x.c, verified against real captured data).
        facility = (decoded[0] << 8) | decoded[1]
        card_id = (decoded[2] << 16) | (decoded[3] << 8) | decoded[4]
        em_id = f"{facility:04X}{card_id:06X}"

        ep_b0, ep_b1, ep_b2 = self._decode_epilogue(epi_hex)
        ep_hex = f"{ep_b0:02X}{ep_b1:02X}{ep_b2:02X}"

        self.host.set_var('electra_raw', raw)
        self.host.set_var('current_id', em_id)
        self.host.set_var('electra_facility', f"{facility:04X}")
        self.host.set_var('electra_id', f"{card_id:06X}")
        self.host.set_var('electra_epilogue', ep_hex)
        return True

    # ---------- READ Electra (RAW via single-pass rawdemod) ----------

    def do_read_tag(self):
        self.host.set_var('retry_action', 'read')
        self.host.set_var('error_msg', '')
        self.host.set_var('electra_raw', '')
        self.host.set_var('electra_facility', '')
        self.host.set_var('electra_id', '')
        self.host.set_var('electra_epilogue', '')
        self.host.set_var('current_id', '')

        acquired, _ = self._pm3('lf read', TIMEOUT_ACQUIRE)
        if not acquired:
            self.host.set_var('error_msg', 'LF capture failed.')
            return {'status': 'error'}
        ok, out = self._pm3('data rawdemod --am', TIMEOUT_DET)
        if not ok:
            self.host.set_var('error_msg', 'RAW demod failed.')
            return {'status': 'error'}

        bitstream = _extract_demod_bits(out)
        raw = _find_raw128_from_preamble(bitstream)

        if not raw:
            if _has_valid_em4100(bitstream):
                self.host.set_var('error_msg', 'EM4100/4102 detected.\nNot an Electra tag.')
                return {'status': 'wrong_tag'}
            self.host.set_var('error_msg', 'No Tag Found\nCheck tag position.')
            return {'status': 'error'}

        if not self._decode_and_store_raw(raw):
            return {'status': 'error'}

        _save_last_raw(raw)

        return {
            'status': 'found',
            'raw': raw,
        }

    # ---------- Show last saved RAW (before cloning it again) ----------

    def do_show_last_raw(self):
        self.host.set_var('retry_action', 'load')
        self.host.set_var('error_msg', '')
        self.host.set_var('electra_raw', '')
        self.host.set_var('electra_facility', '')
        self.host.set_var('electra_id', '')
        self.host.set_var('electra_epilogue', '')
        self.host.set_var('current_id', '')

        raw = _load_last_raw()
        if not raw:
            self.host.set_var('error_msg', 'No saved RAW found.\nRead a tag first.')
            return {'status': 'error'}

        if not self._decode_and_store_raw(raw):
            return {'status': 'error'}

        return {
            'status': 'found_last',
            'raw': raw,
        }

    # ---------- RAW -> T5577 (direct passthrough clone) ----------

    def _write_blocks(self, b0, b1, b2, b3, b4):
        for n, b in ((0, b0), (1, b1), (2, b2), (3, b3), (4, b4)):
            ok, _ = self._pm3(f'lf t55 write -b {n} -d {b:08X}')
            if not ok:
                return False
        return True

    def _verify(self, b0, b1, b2, b3, b4):
        # Force exact parameters from the verified device profile (ASK, RF/64, Offset 33, Seq Term)
        # to guarantee immediate responses and prevent long auto-modulation searches on bad tags.
        configured, _ = self._pm3('lf t55 config --ASK --rate 64 -o 33 --st')
        if not configured:
            return False
        
        # Fast-fail check: read and verify block 0 first
        ok0, o0 = self._pm3('lf t55 read -b 0')
        r0 = _extract_block_hex(o0, 0)
        if not ok0 or r0 != f"{b0:08X}":
            return False  # Card is damaged or missing - abort immediately

        # Read the remaining blocks using the forced active configuration
        ok1, o1 = self._pm3('lf t55 read -b 1')
        ok2, o2 = self._pm3('lf t55 read -b 2')
        ok3, o3 = self._pm3('lf t55 read -b 3')
        ok4, o4 = self._pm3('lf t55 read -b 4')

        r1 = _extract_block_hex(o1, 1)
        r2 = _extract_block_hex(o2, 2)
        r3 = _extract_block_hex(o3, 3)
        r4 = _extract_block_hex(o4, 4)

        return (
            ok1 and ok2 and ok3 and ok4 and
            r0 == f"{b0:08X}" and
            r1 == f"{b1:08X}" and
            r2 == f"{b2:08X}" and
            r3 == f"{b3:08X}" and
            r4 == f"{b4:08X}"
        )

    def do_clone_raw(self):
        self.host.set_var('retry_action', 'clone')
        self.host.set_var('error_msg', '')

        raw = (self.host.get_var('electra_raw', '') or '').strip().upper()

        if not _valid_electra_raw(raw):
            self.host.set_var(
                'error_msg',
                'No valid Electra RAW.\nRead a tag first.'
            )
            return {'status': 'error'}

        base_hex = raw[0:16]
        epi_hex  = raw[16:32]

        encoded_base = int(base_hex, 16)
        encoded_epi  = int(epi_hex, 16)

        b0 = BLOCK0_CONFIG
        b1 = (encoded_base >> 32) & 0xFFFFFFFF
        b2 = encoded_base & 0xFFFFFFFF
        b3 = (encoded_epi >> 32) & 0xFFFFFFFF
        b4 = encoded_epi & 0xFFFFFFFF

        if not self._write_blocks(b0, b1, b2, b3, b4):
            self.host.set_var('error_msg', 'Replace T5577 tag.\nWrite failed.')
            return {'status': 'error'}

        if not self._verify(b0, b1, b2, b3, b4):
            self.host.set_var('error_msg', 'Replace T5577 tag.\nVerify failed.')
            return {'status': 'error'}

        count = int(self.host.get_var('clone_count', '0')) + 1
        self.host.set_var('clone_count', str(count))

        return {'status': 'done'}

    def do_error_retry(self):
        action = self.host.get_var('retry_action', '')
        if action == 'read':
            return self.do_read_tag()
        if action == 'load':
            return self.do_show_last_raw()
        if action == 'clone':
            return self.do_clone_raw()
        self.host.set_var('error_msg', 'Nothing to retry.')
        return {'status': 'error'}

    def do_init(self):
        self.host.set_var('error_msg', '')
        self.host.set_var('electra_raw', '')
        self.host.set_var('electra_facility', '')
        self.host.set_var('electra_id', '')
        self.host.set_var('electra_epilogue', '')
        self.host.set_var('current_id', '')
        self.host.set_var('clone_count', '0')
        self.host.set_var('retry_action', '')
        return {'status': 'ok'}