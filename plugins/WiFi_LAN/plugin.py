##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://www.lab401.com)
#
# Copyright (c) 2026: ETOILE401 SAS & https://github.com/quantum-x/
# Copyright (c) 2026: jareckib
#
# This software is licensed under the PolyForm Noncommercial License 1.0.0.
# You may not use this software for commercial purposes.
#
# A copy of the license is available at:
# https://polyformproject.org/licenses/noncommercial/1.0.0
#
# This entire header "Required Notice" must remain in place.
##########################################################################
##########################################################################
# Wi-Fi LAN - iCopy-X / iCopy-XS plugin
# Copyright (c) 2026: jareckib
#
# Connects the device to a WPA2 Wi-Fi network using DHCP. Supports Wi-Fi
# scanning, saved credentials, connection status, and direct disconnect.
# SSH/SFTP is provided by the operating system; the plugin checks its status.
# Requires Python 3.8 and PluginActivity support for call: actions.
##########################################################################
"""Wi-Fi LAN: WPA2/DHCP network access and SSH/SFTP status for iCopy-X/XS."""
import io
import os
import re
import subprocess
import time
import signal
import shutil
import tempfile
import textwrap
import inspect
import string

from lib.input_txt import FreeTextInput
from lib import resources

CONFIG = '/mnt/upan/wifi_remote_access/credentials.conf'
RUNTIME = '/tmp/icopy_wifi_remote'

class WiFiTextInput(FreeTextInput):
    """Password charset with compatibility for older installed input_txt.py.

    New libraries implement password=True themselves; older installed copies
    do not yet accept this argument, so only then use a local character group.
    Filename editors outside this plugin remain untouched.
    """

    def __init__(self, canvas, **kwargs):
        password = bool(kwargs.pop('password', False))
        try:
            supports_password = 'password' in inspect.signature(FreeTextInput.__init__).parameters
        except (TypeError, ValueError):
            supports_password = False
        self._legacy_input = not supports_password
        if supports_password:
            super(WiFiTextInput, self).__init__(canvas, password=password, **kwargs)
        else:
            super(WiFiTextInput, self).__init__(canvas, **kwargs)
            # Older iCopy-XS firmware lacks password=; keep the extended
            # charset local to Wi-Fi LAN until that library is installed.
            from lib.input_txt import UPPER, LOWER, DIGITS, SPECIAL
            special = SPECIAL
            if password:
                special += ''.join(c for c in string.punctuation if c not in special)
            self._charsets = (UPPER, LOWER, DIGITS, special)
            self._charset_names = ('ABC', 'abc', '123', 'sym' if password else '-_.')

    def _legacy_roll(self, direction):
        charset = self._charsets[self._charset_idx]
        current = self._chars[self._cursor]
        index = charset.index(current) if current in charset else -1
        candidate = charset[(index + direction) % len(charset)]
        proposed = self._chars[:]
        proposed[self._cursor] = candidate
        if self._fits_text(''.join(proposed)):
            self._chars[self._cursor] = candidate
        self._redraw()

    def rollUp(self):
        if self._legacy_input:
            self._legacy_roll(1)
        else:
            super(WiFiTextInput, self).rollUp()

    def rollDown(self):
        if self._legacy_input:
            self._legacy_roll(-1)
        else:
            super(WiFiTextInput, self).rollDown()

    def nextCharset(self):
        if self._legacy_input:
            self._charset_idx = (self._charset_idx + 1) % len(self._charsets)
            charset = self._charsets[self._charset_idx]
            if self._chars[self._cursor] not in charset:
                proposed = self._chars[:]
                proposed[self._cursor] = charset[0]
                if self._fits_text(''.join(proposed)):
                    self._chars[self._cursor] = charset[0]
            self._redraw()
        else:
            super(WiFiTextInput, self).nextCharset()
        return True

    def getCharsetName(self):
        if self._legacy_input:
            return self._charset_names[self._charset_idx]
        return super(WiFiTextInput, self).getCharsetName()

    def moveRight(self):
        if not self._legacy_input:
            return super(WiFiTextInput, self).moveRight()
        limit = self._max_length
        if self._cursor < len(self._chars) - 1:
            self._cursor += 1
        elif ((limit is None or len(self._chars) < limit) and
              self._fits_text(''.join(self._chars) + self._charsets[self._charset_idx][0])):
            self._chars.append(self._charsets[self._charset_idx][0])
            self._cursor += 1
        self._redraw()

    def prevChar(self):
        self.moveLeft()

    def nextChar(self):
        self.moveRight()

    def delete(self):
        if len(self._chars) > 1:
            self._chars.pop(self._cursor)
            self._cursor = min(self._cursor, len(self._chars) - 1)
        else:
            self._chars = [self._charsets[self._charset_idx][0]]
            self._cursor = 0
        self._redraw()


class WrappedWiFiInput(WiFiTextInput):
    """Use the shared input_txt key handling and draw up to four 16-char rows.

    This changes only presentation: character editing and charset switching
    still come from FreeTextInput (password=True).  The editor's entire input
    remains available through getValue(), including spaces.
    """
    ROW_SIZE = 16
    MAX_LENGTH = 63
    ROW_GAP = 21

    def __init__(self, canvas, translate=None, **kwargs):
        self._translate = translate or (lambda text: text)
        kwargs['max_length'] = self.MAX_LENGTH
        kwargs['hint'] = ''
        super(WrappedWiFiInput, self).__init__(canvas, password=True, **kwargs)
        self._font = ('Courier New', 12)

    def _fits_text(self, value):
        if len(value) > self.MAX_LENGTH:
