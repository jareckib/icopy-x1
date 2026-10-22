##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://lab401.com)
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

"""EM4102 From Decimal plugin for iCopy-XS

Useful for recovering damaged tags that cannot be read by iCopy-X 
but still have a visible engraved ID number.
The plugin converts it to a hex UID, encodes EM4102 and clones to T5577.
Copyright (c) 2026: jareckib
"""

import re

from lib.input_dec import FreeDecInput

TIMEOUT_WRITE = 8000
TIMEOUT_CLONE = 15000
TIMEOUT_VERIFY = 3000

def dec_to_hex_uid(dec_str):
    if not re.match(r'^\d{1,10}$', dec_str):
        return None
    return '{:010X}'.format(int(dec_str))

def _extract_em410x_id(output):
    """Pull the 10-hex-digit ID out of 'lf em 410x reader' output."""
    if not output:
        return None
    for line in output.splitlines():
        m = re.search(r'\bEM\s*410x\s*ID\s*([0-9A-Fa-f]{10})\b', line, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None
class Em4102DecPlugin(object):

    def __init__(self, host=None):
        self.host = host
        self._dec = None

    def _pm3(self, cmd, timeout=TIMEOUT_WRITE):
        return self.host.pm3_command(cmd, timeout=timeout)

    def do_init(self):
        self.host.set_var('error_msg', '')
        self.host.set_var('dec_id', '')
        self.host.set_var('hex_uid', '')
        self.host.set_var('clone_count', '0')
        return {'status': 'ok'}

    def show_dec_input(self):
        canvas = self.host.getCanvas()
        self._dec = FreeDecInput(
            canvas, label='INPUT DEC:',
            hint='Up/Down digit   Left/Right move',
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

    def dec_back_cleanse(self):
        if self._dec is not None:
            self._dec.hide()
            self._dec = None
        return {'status': 'ok'}

    def do_capture_dec(self):
        self.host.set_var('error_msg', '')
        dec = self._dec.getValue() if self._dec is not None else ''

        if not dec:
            self.host.set_var('error_msg', 'Enter a digit.')
            return {'status': 'error'}

        if int(dec) == 0:
            self.host.set_var('error_msg', 'ID cannot be all zeros.')
            return {'status': 'error'}

        uid = dec_to_hex_uid(dec)
        if uid is None:
            self.host.set_var('error_msg', 'Conversion failed.')
            return {'status': 'error'}

        if self._dec is not None:
            self._dec.hide()
            self._dec = None

        self.host.set_var('dec_id', dec)
        self.host.set_var('hex_uid', uid)
        return {'status': 'ok'}

    def do_clone(self):
        self.host.set_var('error_msg', '')
        uid = self.host.get_var('hex_uid', '')

        if not re.match(r'^[0-9A-F]{10}$', uid):
            self.host.set_var('error_msg', 'No valid UID.')
            return {'status': 'error'}

        ok, _ = self._pm3('lf em 410x clone --id {}'.format(uid), TIMEOUT_CLONE)
        if not ok:
            self.host.set_var('error_msg', 'Clone failed.\nCheck T5577 position.')
            return {'status': 'error'}

        ok2, out2 = self._pm3('lf em 410x reader', TIMEOUT_VERIFY)
        read_id = _extract_em410x_id(out2) if ok2 else None
        if not read_id or read_id != uid:
            self.host.set_var('error_msg', 'Verify failed.\nCheck T5577 position.')
            return {'status': 'error'}

        count = int(self.host.get_var('clone_count', '0')) + 1
        self.host.set_var('clone_count', str(count))
        return {'status': 'done'}
