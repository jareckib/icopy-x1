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
            tags=(tag, '_jr_content'))
        page_bbox = canvas.bbox(page_item)
        hint_item = canvas.create_text(
            120, 175, text=self.tr('OK - Select'), anchor='s',
            font=('Courier New', 10), fill=color,
            tags=(tag, '_jr_content'))
        hint_bbox = canvas.bbox(hint_item)
        if page_bbox and hint_bbox:
            # Tk canvas bbox has half-open outer edges; the empty gap is 2 px.
            canvas.move(hint_item, 0, page_bbox[1] - 2 - hint_bbox[3])

    def _draw_info_screen(self, state, tag, lines, hint=None):
        if getattr(self.host, '_current_state_id', None) != state:
            return
        canvas = self.host.getCanvas()
        canvas.delete(tag)
        canvas.create_rectangle(0, 49, 239, 198, fill='white', outline='',
                                tags=(tag, '_jr_content'))
        # Wrap all fields sequentially: the old formula (i * 2 + j)
        # overlapped rows when a field wrapped to three lines.
        rendered = []
        for line in lines:
            txt = self.tr(str(line))
            rendered.extend(textwrap.wrap(txt, width=21,
                                          break_long_words=True,
                                          break_on_hyphens=False) or [''])
        if len(rendered) > 5:
            rendered = rendered[:5]
            rendered[-1] = rendered[-1][:18].rstrip() + '...'
        spacing = 19
        first_y = 75 if len(rendered) >= 4 else 86
        for index, chunk in enumerate(rendered):
            canvas.create_text(120, first_y + index * spacing, text=chunk,
                               anchor='n', font=('Courier New', 12),
                               fill='#555555', tags=(tag, '_jr_content'))
        if hint:
            self._draw_action_hint(tag, hint)

    def draw_status_screen(self):
        self._draw_status_now()
        canvas = self.host.getCanvas()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_status_now)

    def _draw_status_now(self):
        values = getattr(self.host, '_state', {}) or {}
        info = values.get('connection_info', 'Not connected')
        ssh = values.get('ssh_text', 'SSH: checking on status')
        self._draw_info_screen('status', '_wifi_status', [str(info), str(ssh)],
                               'OK - Refresh')

    def draw_error(self):
        self._draw_error_now()
        self._draw_action_hint('_wifi_error', 'OK - Menu')
        canvas = self.host.getCanvas() if self.host else None
        if canvas is not None and hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_error_and_hint)

    def _draw_error_and_hint(self):
        if getattr(self.host, '_current_state_id', None) == 'error':
            self._draw_error_now()
            self._draw_action_hint('_wifi_error', 'OK - Menu')

    def _draw_choice_list(self, tag, entries, selected):
        canvas = self.host.getCanvas()
        canvas.delete(tag)
        # Separate from _jr_content so host.onResume cannot erase the menu.
        canvas.create_rectangle(0, 49, 239, 198, fill='white', outline='',
                                tags=(tag, '_jr_content'))
        total = len(entries)
        # Five 12-px rows fit above the two-line footer on every page.
        visible = self._VISIBLE_ROWS
        pages = max(1, (total + visible - 1) // visible)
        page = min(max(0, selected // visible), pages - 1)
        begin = page * visible
        for row, index in enumerate(range(begin, min(begin + visible, total))):
            y = 68 + row * 20
            if index == selected:
                canvas.create_rectangle(6, y - 10, 234, y + 11,
                                        fill='#38A757', outline='',
                                        tags=(tag, '_jr_content'))
            label = self.tr(str(entries[index]))
            if len(label) > 21:
                label = label[:18] + '...'
            canvas.create_text(15, y, anchor='w', text=label,
                               font=('Courier New', 12),
                               fill='#FFFFFF' if index == selected else '#555555',
                               tags=(tag, '_jr_content'))
        self._draw_paged_footer(canvas, tag, page, pages)
        # Match Dump Diff 2 / Emergency Backup / Paxton CloneDown precisely:
        # arrows on the extreme right border, not inside the list rows.
        if page > 0:
            canvas.create_text(235, 43, text='▲', anchor='ne',
                               font=('Arial', 9), fill='#1647D6',
                               tags=(tag, '_jr_content'))
        if page + 1 < pages:
            canvas.create_text(235, 198, text='▼', anchor='se',
                               font=('Arial', 9), fill='#1647D6',
                               tags=(tag, '_jr_content'))

    def _draw_menu_now(self):
        if getattr(self.host, '_current_state_id', None) != 'menu':
            return
        self._draw_choice_list('_wifi_menu',
                               [label for label, _ in self._MENU_ITEMS],
                               self._menu_index)

    def draw_menu(self):
        # PluginActivity.onResume may clear _jr_content just after onCreate.
        # Queue one redraw after initialization and check current state first.
        canvas = self.host.getCanvas()
        self._draw_menu_now()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_menu_now)

    def clear_menu(self):
        self.host.getCanvas().delete('_wifi_menu')

    def menu_up(self):
        self._menu_index = (self._menu_index - 1) % len(self._MENU_ITEMS)
        self.draw_menu()

    def menu_down(self):
        self._menu_index = (self._menu_index + 1) % len(self._MENU_ITEMS)
        self.draw_menu()

    def menu_select(self):
        self.clear_menu()
        return {'choice': ('scan', 'saved', 'manual', 'info', 'disconnect')[self._menu_index]}

    def _network_entries(self):
        names = self._networks
        return names + ['Manual SSID', 'Rescan']

    def _draw_networks_now(self):
        if getattr(self.host, '_current_state_id', None) != 'networks':
            return
        self._network_index = min(self._network_index, len(self._network_entries()) - 1)
        self._draw_choice_list('_wifi_networks', self._network_entries(),
                               self._network_index)

    def draw_networks(self):
        canvas = self.host.getCanvas()
        self._draw_networks_now()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_networks_now)

    def clear_networks(self):
        self.host.getCanvas().delete('_wifi_networks')

    def networks_up(self):
        self._network_index = (self._network_index - 1) % len(self._network_entries())
        self.draw_networks()

    def networks_down(self):
        self._network_index = (self._network_index + 1) % len(self._network_entries())
        self.draw_networks()

    def networks_select(self):
        selected = self._network_index
        self.clear_networks()
        if selected < len(self._networks):
            self._choose(selected)
            return {'choice': 'password'}
        if selected == len(self._networks):
            self._password_parts = []
            return {'choice': 'manual'}
        return {'choice': 'rescan'}

    def on_load(self):
        self._var('summary', 'Scan or use saved Wi-Fi.')
        self._var('network_note', 'Choose a network.')
        for index in range(8):
            self._var('ap%d' % index, '%d. (none)' % (index + 1))
        self._var('connection_info', 'Not connected')
        self._var('error_msg', '')
        self._var('ssh_text', 'SSH: checking on status')
        self._var('ssid_label', 'SSID:')

    def on_destroy(self):
        # Preserve Wi-Fi for ongoing SSH/SFTP connections.
        self._password_parts = []

    def _var(self, key, value):
        if self.host is not None and hasattr(self.host, 'set_var'):
            self.host.set_var(key, self._translate_display(value))

    def _toast(self, message):
        if self.host is not None and hasattr(self.host, 'show_toast'):
            self.host.show_toast(self._translate_display(message), timeout=2600)

    def _create_input(self, label, max_length):
        if not self.host or not hasattr(self.host, 'getCanvas'):
            raise RuntimeError('PluginActivity with canvas required')
        canvas = self.host.getCanvas()
        if canvas is None:
            raise RuntimeError('Canvas unavailable')
        # SSIDs are network identifiers, not filenames; retain punctuation support.
        widget = SSID32Input(canvas, label=label, max_length=max_length,
                             x0=8, y_offset=107, font_size=12,
                             translate=self.tr)
        self.host._input_widget = widget
        widget.show()
        if hasattr(self.host, 'setRightButton'):
            self.host.setRightButton(widget.getCharsetName())

    # UI-thread setup; no I/O here.
    def input_ssid(self):
        self._create_input('SSID:', 32)

    def input_password(self):
        if not self.host or not hasattr(self.host, 'getCanvas'):
            raise RuntimeError('PluginActivity with canvas required')
        canvas = self.host.getCanvas()
        if canvas is None:
            raise RuntimeError('Canvas unavailable')
        widget = Password63Input(canvas, label='Pwd:', x0=8, y_offset=79,
                                 font_size=12, translate=self.tr)
        self.host._input_widget = widget
        widget.show()
        if hasattr(self.host, 'setRightButton'):
            self.host.setRightButton(widget.getCharsetName())

    def begin_manual(self):
        self._password_parts = []
        return {'choice': 'manual'}

    def accept_ssid(self):
        value = self.host.get_input()
        if not value or not value.strip():
            self._toast('SSID cannot be empty')
            return
        if len(value.encode('utf-8')) > 32 or '\n' in value or '\r' in value:
            self._toast('SSID too long/invalid')
            return
        self._ssid = value
        self._password_parts = []
        return {'status': 'password'}

    def finish_password(self):
        """OK always confirms the entire 1- or 2-row password."""
        value = self.host.get_input()
        if not value or len(value) > 63:
            self._toast('Password: 8-63 chars')
            return
        if len(value) < 8:
            # OK finishes editing even for 6 characters; WPA2 rejects it.
            self._last_error = 'WPA2 requires 8-63 chars. Enter a longer password.'
            self._var('error_msg', self._last_error)
            return {'status': 'error'}
        self._password_parts = [value]
        return {'status': 'save'}

    def restart_password(self):
        """Reset password editor when the SRW action is available."""
        self._password_parts = []
        old = getattr(self.host, '_input_widget', None)
        if old is not None:
            old.hide()
        self.input_password()

    def discard_password(self):
        self._password_parts = []
        return {'status': 'menu'}

    def save_credentials(self):
        password = ''.join(self._password_parts)
        if not 8 <= len(password) <= 63:
            return self._error('Password must have 8-63 characters')
        if any(ord(c) < 32 or ord(c) > 126 for c in password):
            return self._error('ASCII password required')
        if (not self._ssid or len(self._ssid.encode('utf-8')) > 32 or
                any(ch in self._ssid for ch in ('\n', '\r', '\x00'))):
            return self._error('Invalid SSID')
        # Persist with restrictive mode, atomically. No password in logs or UI variables.
        try:
            return self._save_credentials_impl(password)
        except (OSError, ValueError) as exc:
            self._password_parts = []
            return self._error('Save failed: %s' % str(exc)[:65])

    def _save_credentials_impl(self, password):
        folder = os.path.dirname(CONFIG)
        os.makedirs(folder, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(prefix='.wifi-', dir=folder)
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, 'w') as handle:
                handle.write('ssid=%s\npsk=%s\ncountry=GB\n' % (self._ssid, password))
                handle.flush()
                os.fsync(handle.fileno())
            os.rename(temp_path, CONFIG)
            os.chmod(CONFIG, 0o600)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            self._password_parts = []
            password = None
        return {'status': 'saved'}

    def _safe_run(self, argv, timeout=8):
        """Run system command with timeout; no persistent diagnostics."""
        try:
            result = subprocess.run(argv, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, '', str(exc)

    def _wireless_interfaces(self):
        paths = ('/sys/class/net',)
        names = []
        for directory in paths:
            try:
                for name in sorted(os.listdir(directory)):
                    if not re.match(r'^[a-zA-Z0-9_.-]+$', name):
                        continue
                    base = os.path.join(directory, name)
                    if os.path.exists(os.path.join(base, 'wireless')) or os.path.exists(os.path.join(base, 'phy80211')):
                        names.append(name)
            except OSError:
                pass
        return names

    @staticmethod
    def _parse_iwlist(output):
        found = []
        for match in re.finditer(r'ESSID:"((?:\\.|[^"\\])*)"', output):
            ssid = match.group(1).replace('\\"', '"').replace('\\\\', '\\')
            if ssid and ssid not in found:
                found.append(ssid)
        return found

    @staticmethod
    def _parse_iw_scan(output):
        names = []
        for line in output.splitlines():
            match = re.match(r'\s*SSID: (.*)$', line)
            if match and match.group(1) and match.group(1) not in names:
                names.append(match.group(1))
        return names

    def scan(self):
        interfaces = self._wireless_interfaces()
        if not interfaces:
            return self._error('No Wi-Fi interface. Check USB adapter and driver.')
        try:
            nets = []
            for iface in interfaces[:2]:
                self._safe_run(['ip', 'link', 'set', iface, 'up'], timeout=8)
                rc, out, err = self._safe_run(['iw', 'dev', iface, 'scan'], timeout=24)
                current = self._parse_iw_scan(out) if rc == 0 else []
                if not current:
                    rc, out, err = self._safe_run(['iwlist', iface, 'scanning'], timeout=24)
                    if rc == 0:
                        current = self._parse_iwlist(out)
                for name in current:
                    if '\n' not in name and '\r' not in name and len(name.encode('utf-8')) <= 32 and name not in nets:
                        nets.append(name)
            self._networks = nets
            self._network_index = 0
            for n in range(8):
                name = self._networks[n] if n < len(self._networks) else '(none)'
                self._var('ap%d' % n, '%d. %s' % (n + 1, name))
            self._var('network_note', '%d networks found' % len(nets))
            return {'status': 'found'}
        except Exception as exc:
            return self._error('Scan failed: %s' % str(exc)[:70])

    def _error(self, message):
        message = str(message)[:120]
        self._last_error = self._translate_display(message)
        self._var('error_msg', self._last_error)
        return {'status': 'error', 'error_msg': message}

    def _choose(self, index):
        if index >= len(self._networks):
            self._toast('Network not found')
            return
        self._ssid = self._networks[index]
        self._password_parts = []
        return {'choice': 'password'}

    def choose_ap0(self): self._choose(0)
    def choose_ap1(self): self._choose(1)
    def choose_ap2(self): self._choose(2)
    def choose_ap3(self): self._choose(3)
    def choose_ap4(self): self._choose(4)
    def choose_ap5(self): self._choose(5)
    def choose_ap6(self): self._choose(6)
    def choose_ap7(self): self._choose(7)

    @staticmethod
    def _wpa_quote(s):
        if not isinstance(s, str) or '\n' in s or '\r' in s or '\x00' in s:
            raise ValueError('Invalid WPA text')
        return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'

    def _read_credentials(self):
        result = {}
        if not os.path.isfile(CONFIG):
            raise ValueError('No saved Wi-Fi. Scan or enter SSID first')
        with open(CONFIG, 'r', encoding='utf-8') as f:
            for line in f:
                if '=' in line:
                    key, val = line.rstrip('\r\n').split('=', 1)
                    result[key] = val
        ssid, password = result.get('ssid', ''), result.get('psk', '')
        if not ssid or len(ssid.encode('utf-8')) > 32:
            raise ValueError('Invalid saved SSID')
        if len(password) < 8 or len(password) > 63 or not all(ord(c) < 128 for c in password):
            raise ValueError('Invalid saved password')
        if any(ord(c) < 32 or ord(c) > 126 for c in password):
            raise ValueError('Invalid saved password')
        return ssid, password

    @staticmethod
    def _ip_address(iface):
        try:
            result = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'dev', iface],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=6)
            match = re.search(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+', result.stdout)
            return match.group(1) if match else ''
        except (OSError, subprocess.TimeoutExpired):
            return ''

    def _read_own_pid(self):
        try:
            with open(os.path.join(RUNTIME, 'wpa.pid'), 'r') as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return 0

    def _stop_own_wpa(self):
        pid = self._read_own_pid()
        if pid > 1:
            try:
                with open('/proc/%d/cmdline' % pid, 'rb') as f:
                    cmdline = f.read().replace(b'\x00', b' ')
                if b'wpa_supplicant' in cmdline and RUNTIME.encode('utf-8') in cmdline:
                    os.kill(pid, signal.SIGTERM)
            except (OSError, IOError):
                pass
        try:
            os.unlink(os.path.join(RUNTIME, 'wpa.pid'))
        except OSError:
            pass

    def _dhcp(self, iface):
        if shutil.which('dhclient'):
            return self._safe_run(['dhclient', '-1', '-v', '-pf', os.path.join(RUNTIME, 'dhclient.pid'), iface], timeout=40)[0] == 0
        if shutil.which('udhcpc'):
            return self._safe_run(['udhcpc', '-i', iface, '-n', '-q', '-t', '5', '-T', '3'], timeout=35)[0] == 0
        if shutil.which('dhcpcd'):
            return self._safe_run(['dhcpcd', '-w', '-t', '30', iface], timeout=36)[0] == 0
        raise RuntimeError('No DHCP client available')

    def _wpa_cli_status(self, iface):
        if not shutil.which('wpa_cli'):
            return ''
        rc, out, err = self._safe_run(['wpa_cli', '-i', iface, 'status'], timeout=5)
        if rc == 0 and ('wpa_state=' in out or 'address=' in out):
            return out
        return ''

    def _wpa_cli_command(self, iface, *args):
        rc, out, err = self._safe_run(['wpa_cli', '-i', iface] + list(args), timeout=9)
        if rc != 0 or 'FAIL' in out.splitlines():
            raise RuntimeError('wpa_cli %s failed' % (args[0] if args else ''))
        return out.strip()

    def _configure_existing_wpa(self, iface, ssid, password):
        # Reuse the current supplicant rather than starting a second daemon.
        # Never modify persistent wpa_supplicant configuration.
        net_id = self._wpa_cli_command(iface, 'add_network').splitlines()[-1].strip()
        if not net_id.isdigit():
            raise RuntimeError('Cannot create network in WPA')
        try:
            self._wpa_cli_command(iface, 'set_network', net_id, 'ssid', self._wpa_quote(ssid))
            self._wpa_cli_command(iface, 'set_network', net_id, 'psk', self._wpa_quote(password))
            self._wpa_cli_command(iface, 'set_network', net_id, 'key_mgmt', 'WPA-PSK')
            self._wpa_cli_command(iface, 'enable_network', net_id)
            self._wpa_cli_command(iface, 'select_network', net_id)
            self._wpa_cli_command(iface, 'reassociate')
        except Exception:
            try:
                self._wpa_cli_command(iface, 'remove_network', net_id)
            except Exception:
                pass
            raise
        return net_id

    @staticmethod


    def _launch_wpa(self, iface, conf):
        for driver in ('nl80211', 'wext'):
            pid = os.path.join(RUNTIME, 'wpa.pid')
            # Avoid accidentally reusing a stale pid file.
            try:
                os.unlink(pid)
            except OSError:
                pass
            cmd = ['wpa_supplicant', '-B', '-i', iface, '-c', conf,
                   '-D', driver, '-P', pid]
            rc, out, err = self._safe_run(cmd, timeout=16)
            if rc == 0:
                return True, driver
            # Another service might have started WPA concurrently.
            if self._wpa_cli_status(iface):
                return False, 'existing'
        return False, 'failed'

    def do_connect(self):
        iface = ''
        try:
            ssid, password = self._read_credentials()
            interfaces = self._wireless_interfaces()
            if not interfaces:
                return self._error('No Wi-Fi adapter detected')
            iface = interfaces[0]
            if not shutil.which('wpa_supplicant') or not shutil.which('ip'):
                return self._error('Missing WPA or IP tool')
            os.makedirs(RUNTIME, mode=0o700, exist_ok=True)
            os.chmod(RUNTIME, 0o700)
            conf = os.path.join(RUNTIME, 'wpa.conf')
            fd = os.open(conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                handle.write('ctrl_interface=/var/run/wpa_supplicant\ncountry=GB\n')
                handle.write('network={\n  ssid=%s\n  psk=%s\n  key_mgmt=WPA-PSK\n}\n' %
                             (self._wpa_quote(ssid), self._wpa_quote(password)))
            rc, out, err = self._safe_run(['ip', 'link', 'set', iface, 'up'], timeout=8)
            if rc != 0:
                return self._error('Cannot activate Wi-Fi interface')
            # Existing daemon is preferred; a second one produces an interface-busy error.
            reused = bool(self._wpa_cli_status(iface))
            managed_network_id = None
            if reused:
                if not shutil.which('wpa_cli'):
                    return self._error('WPA control tool missing')
                managed_network_id = self._configure_existing_wpa(iface, ssid, password)
            else:
                self._stop_own_wpa()
                try:
                    os.makedirs('/var/run/wpa_supplicant', mode=0o755, exist_ok=True)
                except OSError:
                    pass
                started, driver = self._launch_wpa(iface, conf)
                if not started:
                    if driver == 'existing':
                        managed_network_id = self._configure_existing_wpa(iface, ssid, password)
                    else:
                        return self._error('WPA start failed')
            password = None
            associated = False
            for _ in range(20):
                rc, out, err = self._safe_run(['wpa_cli', '-i', iface, 'status'], timeout=3)
                if rc == 0 and 'wpa_state=COMPLETED' in out:
                    associated = True
                    break
                time.sleep(1)
            if not associated:
                return self._error('Wi-Fi authentication failed or timed out')
            if not self._dhcp(iface):
                return self._error('DHCP failed. No IP assigned by router')
            ip = self._ip_address(iface)
            if not ip:
                return self._error('No DHCP IPv4 address')
            with open(os.path.join(RUNTIME, 'iface'), 'w') as handle:
                handle.write(iface)
            if managed_network_id is not None:
                with open(os.path.join(RUNTIME, 'network_id'), 'w') as handle:
                    handle.write(str(managed_network_id))
            else:
                try:
                    os.unlink(os.path.join(RUNTIME, 'network_id'))
                except OSError:
                    pass
            self._var('connection_info', 'IP: %s' % ip)
            self._var('summary', 'Connected: %s' % ip)
            self._var('ssh_text', self._ssh_description())
            return {'status': 'connected'}
        except Exception as exc:
            return self._error('Connect failed: %s' % str(exc)[:70])

    def _live_info(self):
        found = []
        for iface in self._wireless_interfaces():
            ip = self._ip_address(iface)
            if ip:
                found.append('IP: %s' % ip)
        return found[0] if found else 'Not connected'

    def do_status(self):
        try:
            self._var('connection_info', self._live_info())
            self._var('ssh_text', self._ssh_description())
            return {'status': 'status'}
        except Exception as exc:
            return self._error('Status failed: %s' % str(exc)[:70])

    def _ssh_description(self):
        # Listening on :22 does not guarantee reachability or credentials.
        for command in (['ss', '-ltn'], ['netstat', '-ltn']):
            rc, out, _ = self._safe_run(command, timeout=5)
            if rc == 0:
                if re.search(r'(?:0\.0\.0\.0|\*|\[::\]|::):22\s', out):
                    return self.tr('SSH: port 22 listening')
                return self.tr('SSH: port 22 not on LAN')
        return self.tr('SSH: status unknown')

    def do_disconnect(self):
        """Disconnect Wi-Fi regardless of who started wpa_supplicant.

        Never terminate a system-managed WPA daemon or stop SSH.  Disabling
        the plugin-added WPA network, disassociating, clearing its IPv4 and
        bringing the adapter down is scoped to the chosen wireless device.
        """
        try:
            iface = ''
            try:
                with open(os.path.join(RUNTIME, 'iface'), 'r') as handle:
                    iface = handle.read().strip()
            except OSError:
                pass
            available = self._wireless_interfaces()
            if iface not in available:
                iface = available[0] if available else ''
            if not iface:
                return self._error('No Wi-Fi adapter detected')

            # Best-effort teardown through the existing wpa_supplicant.
            if shutil.which('wpa_cli') and self._wpa_cli_status(iface):
                network_id = ''
                try:
                    with open(os.path.join(RUNTIME, 'network_id'), 'r') as handle:
                        network_id = handle.read().strip()
                except OSError:
                    pass
                if network_id.isdigit():
                    self._safe_run(['wpa_cli', '-i', iface, 'disable_network', network_id], timeout=8)
                    self._safe_run(['wpa_cli', '-i', iface, 'remove_network', network_id], timeout=8)
                self._safe_run(['wpa_cli', '-i', iface, 'disconnect'], timeout=8)

            # Release an address acquired by this plugin's dhclient, if any.
            pidfile = os.path.join(RUNTIME, 'dhclient.pid')
            if os.path.isfile(pidfile) and shutil.which('dhclient'):
                self._safe_run(['dhclient', '-r', '-pf', pidfile, iface], timeout=12)

            # Drop address + interface even if a system-owned WPA daemon remains.
            # Do not stop the SSH service itself (it can remain available on LAN).
            if not shutil.which('ip'):
                return self._error('Cannot disconnect: ip tool missing')
            rc_flush, _, err_flush = self._safe_run(['ip', '-4', 'addr', 'flush', 'dev', iface], timeout=8)
            rc_down, _, err_down = self._safe_run(['ip', 'link', 'set', 'dev', iface, 'down'], timeout=8)
            if rc_flush != 0 or rc_down != 0:
                return self._error('Wi-Fi disconnect failed (IP/link)')
            self._stop_own_wpa()
            for filename in ('iface', 'network_id', 'dhclient.pid'):
                try:
                    os.unlink(os.path.join(RUNTIME, filename))
                except OSError:
                    pass
            # Avoid showing a false success when an external manager reconnects.
            if self._ip_address(iface):
                return self._error('Wi-Fi IP still active; check network manager')
            self._var('connection_info', 'Not connected')
            self._var('summary', 'Wi-Fi disconnected')
            self._var('ssh_text', 'SSH: system managed')
            return {'status': 'disconnected'}
        except Exception as exc:
            return self._error('Disconnect failed: %s' % str(exc)[:70])
