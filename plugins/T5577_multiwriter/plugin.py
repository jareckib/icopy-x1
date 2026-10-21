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

"""T5577 Multiwriter plugin for iCopy-XS

Port of lf_t55xx_multiwriter.lua by jareckib - Jarek Barwinski

Stores up to 3 EM4102 UIDs on a single T5577 tag.
This version restricts HEX input to exactly 10 hex characters (EM4102).
Supports:
  - Manual HEX input (exactly 10 hex)
  - Manual DEC input (Free-growing up to 10 decimal digits = engraved ID)
  - Read from original fob via PM3
"""

import re

from lib.input_dec import FreeDecInput
from lib.input_hex import FreeHexInput

TIMEOUT_READ  = 10000
TIMEOUT_WRITE = 8000
TIMEOUT_DET   = 6000

BLOCK0 = {1: '00148040', 2: '00148080', 3: '001480C0'}


# ---------------------------------------------------------------------------
# EM4102 encoding
# ---------------------------------------------------------------------------

def _hex_to_bin40(hex_value):
    """Convert exactly 10-hex EM4102 UID into its raw 40-bit binary representation.

    Accept only 10 hex characters (40 bits). Return None on invalid input.
    """
    if not re.match(r'^[0-9A-Fa-f]{10}$', hex_value):
        return None
    val_clean = hex_value.upper()
    dec = int(val_clean, 16)
    return '{:040b}'.format(dec)


def _even_parity(bits):
    return '0' if bits.count('1') % 2 == 0 else '1'


def encode_uid(uid_hex):
    """Encode EM4102 UID into T5577 format (two 8-hex blocks).

    uid_hex must be a 10-hex string (40 bits). Returns (block_a, block_b) or None.
    """
    uid_bin = _hex_to_bin40(uid_hex.upper())
    if uid_bin is None:
        return None

    # 9 start bits (1 + 8x1)
    start_bits = '1' + '1' * 8

    # 40 data bits + parity bit every 4 bits
    data_with_parity = ''
    for i in range(0, 40, 4):
        nibble = uid_bin[i:i+4]
        data_with_parity += nibble + _even_parity(nibble)

    # 4 column parity bits
    col_parity = ''
    for col in range(4):
        col_bits = data_with_parity[col::5]
        col_parity += _even_parity(col_bits)

    # Stop bit
    full_bin = start_bits + data_with_parity + col_parity + '0'

    # Convert to hex (64 bits = 16 hex characters = 2 blocks of 8)
    full_hex = '{:016X}'.format(int(full_bin, 2))
    return full_hex[:8], full_hex[8:]


def dec_to_hex_uid(dec_str):
    """Convert a 1..10-digit decimal (engraved ID) to a 10-character hex string."""
    if not re.match(r'^\d{1,10}$', dec_str):
        return None
    return '{:010X}'.format(int(dec_str))


# ---------------------------------------------------------------------------
# PM3 output parsers
# ---------------------------------------------------------------------------

def _parse_em410x_id(output):
    """Extract EM410x ID from 'lf em 410x reader' / 'lf em 410x_read' output."""
    if not output:
        return None
    for line in output.splitlines():
        m = re.search(r'EM\s*410x(?:\s+XL)?\s*ID\s*([0-9A-Fa-f]{8,16})', line, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def _parse_block(output, block_num):
    """Extract block N value from 'lf t55xx dump' output."""
    if not output:
        return None
    # match e.g. "[+]  0 | 00148040" or "  0 | 00148040"
    pattern = r'\[\s*\+\s*\]\s*{:02X}\s*\|\s*([0-9A-Fa-f]{{8}})'.format(block_num)
    m = re.search(pattern, output, re.IGNORECASE)
    if m:
        return m.group(1).upper()
    m2 = re.search(r'\b{:02d}\s*\|\s*([0-9A-Fa-f]{{8}})'.format(block_num), output)
    if m2:
        return m2.group(1).upper()
    return None


# ---------------------------------------------------------------------------
# Plugin Class Implementation
# ---------------------------------------------------------------------------

class T55xxMultiwriterPlugin(object):

    def __init__(self, host=None):
        self.host = host
        self._dec = None
        self._hex = None

    # -- helpers ----------------------------------------------------------

    def _tr(self, text):
        """Translate a display string when the host provides translations."""
        translate = getattr(self.host, 'tr', None)
        if callable(translate):
            try:
                return translate(text)
            except Exception:
                pass
        return text

    def _pm3(self, cmd, timeout=TIMEOUT_WRITE):
        return self.host.pm3_command(cmd, timeout=timeout)

    def _get_uid_list(self):
        """Load the UID list from state variables."""
        uids = []
        for i in range(1, 4):
            uid = self.host.get_var('uid{}'.format(i), '')
            if uid:
                uids.append(uid)
        return uids

    def _set_uid(self, index, uid):
        self.host.set_var('uid{}'.format(index), uid)

    def _clear_uids(self):
        for i in range(1, 4):
            self.host.set_var('uid{}'.format(i), '')
        self.host.set_var('uid_count', '0')

    def _update_uid_count(self):
        count = len(self._get_uid_list())
        self.host.set_var('uid_count', str(count))
        if count == 1:
            self.host.set_var('uid_count_label', self._tr('{} UID stored').format(count))
        else:
            self.host.set_var('uid_count_label', self._tr('{} UIDs stored').format(count))
        # Summary
        lines = []
        for i, uid in enumerate(self._get_uid_list(), 1):
            lines.append(self._tr('UID{}: {}').format(i, uid))
        self.host.set_var('uid_summary', '\n'.join(lines) if lines else self._tr('No UIDs yet'))
        return count

    # -- Initialization ----------------------------------------------------

    def do_init(self):
        self._clear_uids()
        self.host.set_var('error_msg', '')
        self.host.set_var('last_uid', '')
        self.host.set_var('written_count', '0')
        self.host.set_var('uid_summary', self._tr('No UIDs yet'))
        self.host.set_var('uid_count_label', self._tr('0 UIDs stored'))
        self.host.set_var('input_mode', '')
        self._dec = None
        self._hex = None
        return {'status': 'ok'}

    # -- DEC input --------------------------------------------------------

    def show_dec_input(self):
        canvas = self.host.getCanvas()
        self._dec = FreeDecInput(
            canvas, label=self._tr('INPUT DEC:'),
            hint=self._tr('Up/Down digit   Left/Right move'),
            max_length=10,
        )
        self._dec.show()

    def dec_roll_up(self):
        if self._dec is not None:
            self._dec.rollUp()

    def dec_roll_down(self):
        if self._dec is not None:
            self._dec.rollDown()

    def dec_move_left(self):
        if self._dec is not None:
            self._dec.moveLeft()

    def dec_move_right(self):
        if self._dec is not None:
            self._dec.moveRight()

    def do_capture_dec(self):
        """Get UID from the dec input (10 decimal digits = engraved ID)."""
        self.host.set_var('error_msg', '')
        dec = self._dec.getValue() if self._dec is not None else ''

        if not dec:
            self.host.set_var('error_msg', self._tr('Enter a digit.'))
            return {'status': 'error'}

        if int(dec) == 0:
            self.host.set_var('error_msg', self._tr('ID cannot be all zeros.'))
            return {'status': 'error'}

        uid = dec_to_hex_uid(dec)
        if uid is None:
            self.host.set_var('error_msg', self._tr('Conversion failed.'))
            return {'status': 'error'}

        return self._store_uid(uid)

    # -- HEX input (fixed 10 hex) ----------------------------------------

    def show_hex_input(self):
        canvas = self.host.getCanvas()
        # Force exactly 10 hex characters for EM4102
        self._hex = FreeHexInput(
            canvas, label=self._tr('INPUT HEX:'),
            hint=self._tr('Up/Down digit   Left/Right move'),
            max_length=10,
            per_line=10,
        )
        self._hex.show()

    def hex_roll_up(self):
        if self._hex is not None:
            self._hex.rollUp()

    def hex_roll_down(self):
        if self._hex is not None:
            self._hex.rollDown()

    def hex_move_left(self):
        if self._hex is not None:
            self._hex.moveLeft()

    def hex_move_right(self):
        if self._hex is not None:
            self._hex.moveRight()

    def do_capture_hex(self):
        """Get UID from the hex input widget. Only exactly 10 hex chars accepted."""
        self.host.set_var('error_msg', '')
        val = self._hex.getValue() if self._hex is not None else ''
        if not val:
            self.host.set_var('error_msg', self._tr('Enter hex characters.'))
            return {'status': 'error'}

        uid = val.upper()
        # Enforce exact 10-hex length for EM4102
        if not re.match(r'^[0-9A-F]{10}$', uid):
            self.host.set_var('error_msg', self._tr('Invalid length.\nMust be exactly 10 hex (EM4102).'))
            return {'status': 'error'}

        if int(uid, 16) == 0:
            self.host.set_var('error_msg', self._tr('UID cannot be all zeros.'))
            return {'status': 'error'}

        return self._store_uid(uid)

    # -- Read original fob ------------------------------------------------

    def do_read_fob(self):
        """Read UID from the original fob via PM3."""
        self.host.set_var('error_msg', '')
        ok, out = self._pm3('lf em 410x reader', TIMEOUT_READ)
        uid = _parse_em410x_id(out) if out else None

        if not uid:
            self.host.set_var('error_msg', self._tr('No EM410x tag detected.\nAdjust position and retry.'))
            return {'status': 'error'}

        if not re.fullmatch(r'[0-9A-F]{10}', uid):
            self.host.set_var('error_msg', self._tr('Read UID has unsupported length or format.\nExpected exactly 10 hex (EM4102).'))
            return {'status': 'error'}

        return self._store_uid(uid)

    def _store_uid(self, uid):
        """Save the UID into the next available slot."""
        uids = self._get_uid_list()
        if len(uids) >= 3:
            self.host.set_var('error_msg', self._tr('Maximum 3 UIDs reached.'))
            return {'status': 'full'}

        # Encode and verify
        result = encode_uid(uid)
        if result is None:
            self.host.set_var('error_msg', self._tr('Encoding failed for:\n{}').format(uid))
            return {'status': 'error'}

        # Store in the first empty slot. This also keeps the slot index correct
        # if the state was left partially populated after navigating Back.
        idx = None
        for slot in range(1, 4):
            if not self.host.get_var('uid{}'.format(slot), ''):
                idx = slot
                break

        if idx is None:
            self.host.set_var('error_msg', self._tr('Maximum 3 UIDs reached.'))
            return {'status': 'full'}

        self._set_uid(idx, uid)
        count = self._update_uid_count()
        self.host.set_var('last_uid', uid)

        if count < 3:
            return {'status': 'stored_more'}
        else:
            return {'status': 'stored_full'}

    # -- Write to T5577 ---------------------------------------------------

    def do_write(self):
        """Encode all UIDs and write them to the T5577 tag."""
        self.host.set_var('error_msg', '')
        uids = self._get_uid_list()

        if not uids:
            self.host.set_var('error_msg', self._tr('No UIDs to write.'))
            return {'status': 'error'}

        # Encode all UIDs
        all_blocks = []
        for uid in uids:
            result = encode_uid(uid)
            if result is None:
                self.host.set_var('error_msg', self._tr('Encoding failed for:\n{}').format(uid))
                return {'status': 'error'}

            blk_a, blk_b = result
            all_blocks.append(blk_a)
            all_blocks.append(blk_b)

        block0 = BLOCK0[len(uids)]

        ok, _ = self._pm3('lf t55xx write -b 0 -d {}'.format(block0), TIMEOUT_WRITE)
        if not ok:
            self.host.set_var('error_msg', self._tr('Write failed on block 0.\nCheck tag position.'))
            return {'status': 'error'}

        # Write data blocks using short flags
        for i, blk in enumerate(all_blocks, 1):
            ok, _ = self._pm3('lf t55xx write -b {} -d {}'.format(i, blk), TIMEOUT_WRITE)
            if not ok:
                self.host.set_var('error_msg', self._tr('Write failed on block {}.\nCheck tag position.').format(i))
                return {'status': 'error'}

        # Save to state for verification
        self.host.set_var('written_block0', block0)
        for i, blk in enumerate(all_blocks, 1):
            self.host.set_var('written_block{}'.format(i), blk)
        self.host.set_var('written_count', str(len(all_blocks)))

        return {'status': 'done'}

    def do_verify(self):
        """Post-write verification — reads blocks via dump sequence."""
        self.host.set_var('error_msg', '')

        block0 = self.host.get_var('written_block0', '')
        n = int(self.host.get_var('written_count', '0'))

        if not block0 or n == 0:
            self.host.set_var('error_msg', self._tr('No write data to verify.'))
            return {'status': 'error'}

        # Require a successful detect before attempting the dump. Do not claim
        # that the reader is ready when the device did not acknowledge detection.
        detect_ok, detect_output = self._pm3('lf t55xx detect', TIMEOUT_DET)
        if not detect_ok:
            self.host.set_var('error_msg', self._tr('Verification failed.\nT5577 detection command failed.'))
            return {'status': 'failed'}

        ok, all_output = self._pm3('lf t55xx dump', TIMEOUT_READ)
        if not ok or not all_output:
            self.host.set_var('error_msg', self._tr('Verification failed.\nCannot dump T5577 data.'))
            return {'status': 'failed'}

        # Check block 0
        found0 = _parse_block(all_output, 0)
        if not found0 or found0.upper() != block0.upper():
            self.host.set_var('error_msg', self._tr('Block 0 mismatch.\nExpected: {}\nFound: {}').format(block0, found0 or 'N/A'))
            return {'status': 'failed'}

        # Check data blocks
        for i in range(1, n + 1):
            expected = self.host.get_var('written_block{}'.format(i), '')
            found = _parse_block(all_output, i)
            if not found or found.upper() != expected.upper():
                self.host.set_var('error_msg', self._tr('Block {} mismatch.\nExpected: {}\nFound: {}').format(i, expected, found or 'N/A'))
                return {'status': 'failed'}

        return {'status': 'ok'}

    def do_cancel_write(self):
        """Cancel the current write attempt without deleting the UID list."""
        self.host.set_var('error_msg', '')
        # Invalidate verification data from the failed/abandoned attempt.
        self.host.set_var('written_count', '0')
        self.host.set_var('written_block0', '')
        for i in range(1, 7):
            self.host.set_var('written_block{}'.format(i), '')
        count = self._update_uid_count()
        if count >= 3:
            return {'status': 'stored_full'}
        if count > 0:
            return {'status': 'stored_more'}
        return {'status': 'empty'}

    def do_remove_last(self):
        """Remove the last UID and return the state matching the remaining list."""
        self.host.set_var('error_msg', '')
        uids = self._get_uid_list()
        if not uids:
            self.host.set_var('error_msg', self._tr('No UIDs to remove.'))
            self._update_uid_count()
            return {'status': 'empty'}

        # UIDs are stored sequentially, so removing the last item leaves no gaps.
        self.host.set_var('uid{}'.format(len(uids)), '')
        count = self._update_uid_count()

        # A previous write/verification no longer represents the current UID list.
        self.host.set_var('written_count', '0')
        self.host.set_var('written_block0', '')
        for i in range(1, 7):
            self.host.set_var('written_block{}'.format(i), '')

        if count == 0:
            self.host.set_var('last_uid', '')
            return {'status': 'empty'}
        if count >= 3:
            return {'status': 'stored_full'}
        return {'status': 'stored_more'}
