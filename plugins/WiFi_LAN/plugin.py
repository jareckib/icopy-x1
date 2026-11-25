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
            return False
        # Count is a hard cap; pixel width is checked on every row to avoid
        # overlap with screen edges for non-ASCII SSIDs or translated labels.
        prefix = self._translate(self._label) + ' '
        x = self._x0 + self._text_width(prefix)
        for i in range(0, len(value), self.ROW_SIZE):
            if x + self._text_width(value[i:i + self.ROW_SIZE]) > 236:
                return False
        return True

    def _redraw(self):
        canvas = self._canvas
        tag = '_txt_input'
        canvas.delete(tag)
        label = self._translate(self._label) + ' '
        canvas.create_text(self._x0, self._y_offset, text=label,
                           font=self._font, fill='#000000', anchor='w', tags=tag)
        data_x = self._x0 + self._text_width(label)
        for i, char in enumerate(self._chars):
            row = i // self.ROW_SIZE
            col = i % self.ROW_SIZE
            y = self._y_offset + self.ROW_GAP * row
            row_start = row * self.ROW_SIZE
            preceding = ''.join(self._chars[row_start:row_start + col])
            x = data_x + self._text_width(preceding)
            item = canvas.create_text(x, y, text=char, font=self._font,
                                      fill=self._text_color, anchor='w', tags=tag)
            if i == self._cursor:
                bounds = canvas.bbox(item)
                if bounds:
                    canvas.create_line(bounds[0], bounds[3] + 2,
                                       bounds[2], bounds[3] + 2,
                                       fill=self._text_color, width=2, tags=tag)


class SSID32Input(WrappedWiFiInput):
    """Up to 32 UTF-8 bytes, displayed on two lines of at most 16 chars."""
    MAX_LENGTH = 32


class Password63Input(WrappedWiFiInput):
    """8-63 ASCII printable characters displayed on up to four lines."""
    MAX_LENGTH = 63

    def _redraw(self):
        super(Password63Input, self)._redraw()
        # Two blue hints directly above the lower button bar, gap 2 pixels.
        canvas = self._canvas
        tag = '_txt_input'
        info_font = ('Courier New', 10)
        color = '#1647D6'
        lower = canvas.create_text(
            120, 196, text=self._translate('OK - Save'),
            font=info_font, fill=color, anchor='s', tags=tag)
        upper = canvas.create_text(
            120, 175, text=self._translate('SRW - Re-enter'),
            font=info_font, fill=color, anchor='s', tags=tag)
        lower_bbox = canvas.bbox(lower)
        upper_bbox = canvas.bbox(upper)
        if lower_bbox and upper_bbox:
            canvas.move(upper, 0, lower_bbox[1] - 2 - upper_bbox[3])


class WiFiRemoteAccessPlugin(object):
    def __init__(self, host=None):
        self.host = host
        self._ssid = ''
        self._password_parts = []
        self._networks = []
        self._menu_index = 0
        self._network_index = 0
        self._last_error = 'Unknown Wi-Fi error'

    # Same physical menu styling as the user's MIFARE Classic Repair plugin:
    # green #38A757 selection, blue arrows at the right, blue page counter.
    # All drawing and selection methods run on the UI thread through call:.
    _MENU_ITEMS = (
        ('Scan Wi-Fi', 'set_state:scanning'),
        ('Connect saved Wi-Fi', 'set_state:connecting'),
        ('Enter SSID manually', 'call:begin_manual'),
        ('Connection info', 'set_state:loading_status'),
        ('Disconnect Wi-Fi', 'set_state:disconnecting'),
    )
    _VISIBLE_ROWS = 5

    def tr(self, message):
        translator = getattr(self.host, 'tr', None)
        return translator(message) if callable(translator) else message

    def _translate_display(self, message):
        """Translate fixed English text; retain runtime details and addresses."""
        message = str(message)
        translated = self.tr(message)
        if translated != message:
            return translated
        for prefix in ('Save failed: ', 'Scan failed: ', 'Connect failed: ',
                       'Status failed: ', 'Disconnect failed: ', 'Connected: ', 'IP: '):
            if message.startswith(prefix):
                detail = message[len(prefix):]
                # Known exceptions from saved Wi-Fi must also be localised.
                for known in ('No saved Wi-Fi. Scan or enter SSID first',
                              'Invalid saved SSID', 'Invalid saved password'):
                    detail = detail.replace(known, self.tr(known))
                return self.tr(prefix) + detail
        return message

    def _format_error_lines(self, message, width=21, maximum=5):
        """Prepare short display lines without splitting Unicode codepoints."""
        message = ' '.join(self._translate_display(message or 'Unknown Wi-Fi error').split())
        lines = textwrap.wrap(message, width=width, break_long_words=True,
                              break_on_hyphens=False, replace_whitespace=True,
                              drop_whitespace=True)
        if len(lines) > maximum:
            lines = lines[:maximum]
            if len(lines[-1]) > width - 3:
                lines[-1] = lines[-1][:width - 3]
            lines[-1] = lines[-1].rstrip() + '...'
        return lines or ['Unknown Wi-Fi error']

    def _draw_error_now(self):
        if getattr(self.host, '_current_state_id', None) != 'error':
            return
        if not self.host or not hasattr(self.host, 'getCanvas'):
            return
        canvas = self.host.getCanvas()
        if canvas is None:
            return
        tag = '_wifi_error'
        canvas.delete(tag)
        lines = self._format_error_lines(self._last_error)
        # Stay within the 50..198 content region; never touch the bottom bar.
        font_size = 12
        spacing = 19
        first_y = 123 - ((len(lines) - 1) * spacing) / 2.0
        for index, line in enumerate(lines):
            canvas.create_text(120, first_y + index * spacing,
                               text=line, fill='#D00000',
                               font=('Courier New', font_size),
                               anchor='center', tags=(tag, '_jr_content'))

    def clear_error(self):
        if self.host and hasattr(self.host, 'getCanvas'):
            canvas = self.host.getCanvas()
            if canvas is not None:
                canvas.delete('_wifi_error')

    # Shared footer for non-paged screens: Courier 10, BLUE, just above the bar.
    # Paged lists use a separate BLUE two-line footer (OK - Select / Page n/n).
    def _draw_action_hint(self, tag, message, y=196):
        canvas = self.host.getCanvas()
        canvas.create_text(120, y, text=self.tr(message), anchor='s',
                           font=('Courier New', 10), fill='#1647D6',
                           tags=(tag, '_jr_content'))

    def _draw_paged_footer(self, canvas, tag, page, pages):
        """Two blue lines; exactly 2 canvas pixels between text bounding boxes."""
        color = '#1647D6'
        page_item = canvas.create_text(
            120, 196, text=self.tr('Page %d/%d') % (page + 1, pages),
            anchor='s', font=('Courier New', 9), fill=color,
