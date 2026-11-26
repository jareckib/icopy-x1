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
# Wi-Fi Adapter Compatibility
# LAN / phone hotspot tested: RTL8188EUS (0bda:8179), MT7601U (148f:7601).
# Wi-Fi Direct unavailable in tests with r8188eu and mt7601u.
# P2P code detected in 88XXau and 8821cu; hardware tests pending.
# Candidates: RTL8811AU/8821AU/8812AU/8814AU, RTL8811CU/8821CU.
# USB candidates: 2357:011e, 2357:010d, 0bda:c811.
# Actual P2P availability depends on adapter and driver capabilities.
##########################################################################
# Remote Access - iCopy-X / iCopy-XS plugin
# Copyright (c) 2026: jareckib
#
# Connects the device to a WPA2 Wi-Fi network using DHCP. Supports Wi-Fi
# scanning, saved credentials, connection status, and direct disconnect.
# SSH/SFTP is provided by the operating system; the plugin checks its status.
# Requires Python 3.8 and PluginActivity support for call: actions.
##########################################################################
"""Remote Access: network access, mirroring, authenticated UDUMP access and SSH status."""
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
import sys
import secrets
import ipaddress
import socket
import struct
import fcntl
import importlib.util
import types
import threading

_SERVICE_CACHE = sys.modules.setdefault('_icopy_remote_access_runtime', types.ModuleType('_icopy_remote_access_runtime'))
_FILE_SERVICE = getattr(_SERVICE_CACHE, 'files', None)
_USB_SERVICE = getattr(_SERVICE_CACHE, 'usb', None)
_SERIAL_SERVICE = getattr(_SERVICE_CACHE, 'serial', None)
_MIRROR_SERVICE = getattr(_SERVICE_CACHE, 'mirror', None)
_BATTERY = getattr(_SERVICE_CACHE, 'battery', None)


def _battery_guard():
    global _BATTERY
    if _BATTERY is None:
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
        sys.path.insert(0, directory)
        try:
            from battery_guard import BatteryGuard
            _BATTERY = BatteryGuard()
            _SERVICE_CACHE.battery = _BATTERY
        finally:
            sys.path.remove(directory)
    return _BATTERY


def _usb_service():
    global _USB_SERVICE
    if _USB_SERVICE is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib', 'usb_network.py')
        spec = importlib.util.spec_from_file_location('remote_access_usb_network', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _USB_SERVICE = module.USBNetwork()
        _SERVICE_CACHE.usb = _USB_SERVICE
    return _USB_SERVICE

def _file_service():
    global _FILE_SERVICE
    if _FILE_SERVICE is None:
        directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
        sys.path.insert(0, directory)
        try:
            from service_lifecycle import FileService
            _FILE_SERVICE = FileService(require_mount=True, battery=_battery_guard())
            _SERVICE_CACHE.files = _FILE_SERVICE
        finally:
            sys.path.remove(directory)
    return _FILE_SERVICE

from lib.input_txt import FreeTextInput
from lib import resources

CONFIG = '/mnt/upan/wifi_remote_access/credentials.conf'
RUNTIME = '/tmp/icopy_wifi_remote'

_TOOL_PATH = ':'.join(filter(None, (os.environ.get('PATH'), '/sbin:/usr/sbin:/bin:/usr/bin:/usr/local/sbin:/usr/local/bin')))

def _tool(name):
    return shutil.which(name, path=_TOOL_PATH)


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
        self._mirror_mode = 0
        self._mirror_transport = 1
        self._network_index = 0
        self._last_error = 'Unknown Wi-Fi error'
        self._file_page = 0
        self._file_pairing = None
        self._prefer_usb = bool(_USB_SERVICE and _USB_SERVICE.owned)
        self._status_page = 0

    # Same physical menu styling as the user's MIFARE Classic Repair plugin:
    # green #38A757 selection, blue arrows at the right, blue page counter.
    # All drawing and selection methods run on the UI thread through call:.
    _MENU_ITEMS = (
        ('Connection Status', 'info'),
        ('USB Serial', 'serial'),
        ('Secure Access', 'files'),
        ('Scan Wi-Fi', 'scan'),
        ('Connect saved Wi-Fi', 'saved'),
        ('USB Network', 'usb'),
        ('Wi-Fi Direct', 'direct'),
        ('Stop services', 'stop'),
        ('Enter SSID manually', 'manual'),
        ('SSH Terminal', 'ssh'),
        ('File Manager', 'file_manager'),
        ('Disconnect Wi-Fi', 'disconnect'),
    )
    _VISIBLE_ROWS = 5
    _MIRROR_PORT = 8765
    _MIRROR_PID = '/tmp/icopy_wifi_remote/mirror.pid'
    _MIRROR_TOKEN = '/mnt/upan/wifi_remote_access/mirror_token'

    def tr(self, message):
        translator = getattr(self.host, 'tr', None)
        return translator(message) if callable(translator) else message

    def _translate_display(self, message):
        """Translate fixed English text; retain runtime details and addresses."""
        message = str(message)
        translated = self.tr(message)
        if translated != message:
            return translated
        command_error = re.fullmatch(r'wpa_cli (.*?) failed', message)
        if command_error:
            return self.tr('wpa_cli %s failed') % command_error.group(1)
        for prefix in ('Save failed: ', 'Scan failed: ', 'Connect failed: ',
                       'Status failed: ', 'Disconnect failed: ', 'Connected: ', 'IP: ', 'PIN: '):
            if message.startswith(prefix):
                detail = message[len(prefix):]
                if prefix in ('IP: ', 'PIN: '):
                    return self.tr(prefix) + self.tr(detail)
                if prefix in ('Save failed: ', 'Scan failed: ', 'Connect failed: ',
                              'Status failed: ', 'Disconnect failed: '):
                    detail = self._translate_display(detail)
                # Known exceptions from saved Wi-Fi must also be localised.
                for known in ('No saved Wi-Fi. Scan or enter SSID first',
                              'Invalid saved SSID', 'Invalid saved password', 'UDUMP unavailable'):
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
                               anchor='center', tags=(tag, '_ra_content', '_jr_content'))

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
                           tags=(tag, '_ra_content', '_jr_content'))

    def _draw_paged_footer(self, canvas, tag, page, pages):
        """Two blue lines; exactly 2 canvas pixels between text bounding boxes."""
        color = '#1647D6'
        page_item = canvas.create_text(
            120, 196, text=self.tr('Page %d/%d') % (page + 1, pages),
            anchor='s', font=('Courier New', 9), fill=color,
            tags=(tag, '_ra_content', '_jr_content'))
        page_bbox = canvas.bbox(page_item)
        hint_item = canvas.create_text(
            120, 175, text=self.tr('OK - Select'), anchor='s',
            font=('Courier New', 10), fill=color,
            tags=(tag, '_ra_content', '_jr_content'))
        hint_bbox = canvas.bbox(hint_item)
        if page_bbox and hint_bbox:
            # Tk canvas bbox has half-open outer edges; the empty gap is 2 px.
            canvas.move(hint_item, 0, page_bbox[1] - 2 - hint_bbox[3])

    def clear_custom(self):
        if self.host and hasattr(self.host, 'getCanvas'):
            canvas = self.host.getCanvas()
            if canvas is not None: canvas.delete('_ra_content')

    def _draw_info_screen(self, state, tag, lines, hint=None):
        self._paint_info_screen(state, tag, lines, hint)
        canvas = self.host.getCanvas()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(lambda: self._paint_info_screen(state, tag, lines, hint))

    def _paint_info_screen(self, state, tag, lines, hint=None):
        if getattr(self.host, '_current_state_id', None) != state:
            return
        canvas = self.host.getCanvas()
        canvas.delete(tag)
        canvas.create_rectangle(0, 49, 239, 198, fill='white', outline='',
                                tags=(tag, '_ra_content', '_jr_content'))
        # Wrap all fields sequentially: the old formula (i * 2 + j)
        # overlapped rows when a field wrapped to three lines.
        rendered = []
        for line in lines:
            txt = self._translate_display(line)
            rendered.extend(textwrap.wrap(txt, width=21,
                                          break_long_words=True,
                                          break_on_hyphens=False) or [''])
        if len(rendered) > 5:
            rendered = rendered[:5]
            rendered[-1] = rendered[-1][:18].rstrip() + '...'
        spacing = 19
        first_y = 62 if len(rendered) >= 5 else (75 if len(rendered) == 4 else 86)
        for index, chunk in enumerate(rendered):
            canvas.create_text(120, first_y + index * spacing, text=chunk,
                               anchor='n', font=('Courier New', 12),
                               fill=('#216aab' if chunk.startswith(('PIN:', 'PIN :')) else '#555555'), tags=(tag, '_ra_content', '_jr_content'))
        if hint:
            self._draw_action_hint(tag, hint)

    def _battery_text(self):
        level = getattr(self, '_status_battery', None)
        if level is None: return 'Battery unknown'
        return self.tr('Battery low: %d%%' if level <= 30 else 'Battery: %d%%') % level

    def _status_content(self):
        pages = getattr(self, '_status_pages', [['Not connected']])
        page = self._status_page % len(pages)
        return pages[page], (self.tr('Page %d/%d') % (page+1,len(pages)) if len(pages)>1 else 'OK - Refresh')

    def _publish_status(self):
        lines, hint = self._status_content()
        for i in range(5):
            self._var('status_line%d' % i, lines[i] if i < len(lines) else '')
        self._var('status_hint', hint)
        return {'status': 'status'}

    def draw_status_screen(self):
        self._draw_status_now()
        canvas = self.host.getCanvas()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_status_now)
        self._schedule_view_refresh('status')

    def _draw_status_now(self):
        if getattr(self.host, '_current_state_id', None) != 'status':
            return
        if self._serial_running():
            self._status_pages = [['USB Serial', self._serial_state(), self._battery_text(), self.tr('PIN: ') + _SERIAL_SERVICE.pin]]
            self._status_page = 0
        elif getattr(self, '_status_pages', None) and len(self._status_pages) == 1 and self._status_pages[0][0] == 'USB Serial':
            self._status_pages = [['USB Serial', 'Serial: OFF', self._battery_text()]]
        lines, hint = self._status_content()
        self._publish_status()
        self._paint_info_screen('status', '_wifi_status', lines, hint)

    def status_prev(self):
        self._status_page -= 1
        self._draw_status_now()

    def status_next(self):
        self._status_page += 1
        self._draw_status_now()

    def _serial_state(self):
        service = _SERIAL_SERVICE
        if service is None or not service.running: return 'Serial: OFF'
        return 'Serial connected' if service.connected else 'Waiting for phone'

    def _stock_mirror_active(self):
        for name in ('lib.mirror_service', 'mirror_service'):
            instance = getattr(sys.modules.get(name), '_instance', None)
            if instance is not None:
                active = getattr(instance, 'is_running', False)
                if callable(active): active = active()
                if active: return True
        return False

    def _serial_blocker(self):
        if _USB_SERVICE is not None and _USB_SERVICE.owned: return 'Stop USB Network'
        if _FILE_SERVICE is not None and _FILE_SERVICE.server is not None: return 'Stop Secure Access'
        if self._mirror_running(): return 'Stop Screen Mirror'
        if self._stock_mirror_active(): return 'Stop Lab401 Mirror'
        return None

    def stop_services(self):
        # Explicit local confirmation only. Never stop SSH or the stock mirror.
        try:
            if _FILE_SERVICE is not None and _FILE_SERVICE.server is not None:
                _FILE_SERVICE.stop()
            if self._mirror_running():
                result = self.mirror_toggle()
                if result.get('status') == 'error': return result
            self._p2p_cleanup()
            if _SERIAL_SERVICE is not None and _SERIAL_SERVICE.running:
                _SERIAL_SERVICE.stop()
            if _USB_SERVICE is not None and _USB_SERVICE.owned:
                _USB_SERVICE.stop()
                self._prefer_usb = False
            if self._stock_mirror_active(): return self._error('Stop Lab401 Mirror')
            return self.do_status()
        except Exception:
            return self._error('Service stop failed')

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

    def _draw_choice_list(self, tag, entries, selected, disabled=()):
        canvas = self.host.getCanvas()
        canvas.delete(tag)
        # Tag all custom content for the native renderer to clear on transitions.
        canvas.create_rectangle(0, 49, 239, 198, fill='white', outline='',
                                tags=(tag, '_ra_content', '_jr_content'))
        total = len(entries)
        # Five 12-px rows fit above the two-line footer on every page.
        visible = self._VISIBLE_ROWS
        pages = max(1, (total + visible - 1) // visible)
        page = min(max(0, selected // visible), pages - 1)
        begin = page * visible
        for row, index in enumerate(range(begin, min(begin + visible, total))):
            y = 68 + row * 20
            if index == selected and index not in disabled:
                canvas.create_rectangle(6, y - 10, 234, y + 11,
                                        fill='#38A757', outline='',
                                        tags=(tag, '_ra_content', '_jr_content'))
            label = self.tr(str(entries[index]))
            if len(label) > 21:
                label = label[:18] + '...'
            canvas.create_text(15, y, anchor='w', text=label,
                               font=('Courier New', 12),
                               fill='#AAAAAA' if index in disabled else ('#FFFFFF' if index == selected else '#555555'),
                               tags=(tag, '_ra_content', '_jr_content'))
        self._draw_paged_footer(canvas, tag, page, pages)
        # Match Dump Diff 2 / Emergency Backup / Paxton CloneDown precisely:
        # arrows on the extreme right border, not inside the list rows.
        if page > 0:
            canvas.create_text(235, 43, text='▲', anchor='ne',
                               font=('Arial', 9), fill='#1647D6',
                               tags=(tag, '_ra_content', '_jr_content'))
        if page + 1 < pages:
            canvas.create_text(235, 198, text='▼', anchor='se',
                               font=('Arial', 9), fill='#1647D6',
                               tags=(tag, '_ra_content', '_jr_content'))

    def _serial_running(self):
        return bool(_SERIAL_SERVICE is not None and _SERIAL_SERVICE.running)

    def _disabled_menu(self):
        # Public preview: expose only the USB Serial workflow.
        enabled = {'info', 'serial', 'stop', 'ssh'}
        return {i for i, (_, choice) in enumerate(self._MENU_ITEMS)
                if choice not in enabled}

    def _draw_menu_now(self):
        if getattr(self.host, '_current_state_id', None) != 'menu':
            return
        disabled = self._disabled_menu()
        if self._menu_index in disabled:
            self._menu_index = 0
        self._draw_choice_list('_wifi_menu',
                               [label for label, _ in self._MENU_ITEMS],
                               self._menu_index, disabled)

    def draw_menu(self):
        canvas = self.host.getCanvas()
        self._draw_menu_now()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_menu_now)

    def clear_menu(self):
        self.host.getCanvas().delete('_wifi_menu')

    def _move_menu(self, step):
        disabled = self._disabled_menu()
        for _ in self._MENU_ITEMS:
            self._menu_index = (self._menu_index + step) % len(self._MENU_ITEMS)
            if self._menu_index not in disabled:
                break
        self.draw_menu()

    def menu_up(self):
        self._move_menu(-1)

    def menu_down(self):
        self._move_menu(1)

    def menu_select(self):
        if self._menu_index in self._disabled_menu():
            self.draw_menu()
            return None
        self.clear_menu()
        choice = self._MENU_ITEMS[self._menu_index][1]
        if self._serial_running() and choice == 'file_manager':
            return {'choice': 'serial_' + choice}
        return {'choice': choice}

    def draw_serial_mirror_info(self):
        self._draw_info_screen('serial_mirror', '_wifi_serial_tool',
                               ['USB Serial', self._serial_state(), 'View and control'],
                               'OK - Refresh')

    def draw_serial_ssh_info(self):
        self._draw_info_screen('serial_ssh', '_wifi_serial_tool',
                               ['USB Serial', 'Use SSH on phone', 'OK - Refresh'])

    def draw_serial_files_info(self):
        self._draw_info_screen('serial_file_manager', '_wifi_serial_tool',
                               ['USB Serial', 'Files not available', 'Planned feature'])

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
        # Preserve Wi-Fi and remote services across menu exits.
        self._password_parts = []
        timer = getattr(self, '_serial_ui_timer', None)
        if timer is not None:
            try: self.host.getCanvas().after_cancel(timer)
            except Exception: pass
            self._serial_ui_timer = None
        self.clear_custom()

    def _var(self, key, value):
        if self.host is not None and hasattr(self.host, 'set_var'):
            # Protocol/state values must not be translated before use by UI logic.
            self.host.set_var(key, value if key in ('mirror_active', 'mirror_ip', 'mirror_code', 'usb_ip')
                              else self._translate_display(value))

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
            result = subprocess.run([_tool(argv[0]) or argv[0]] + list(argv[1:]), stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 127, '', str(exc)

    def _wireless_interfaces(self):
        directory = '/sys/class/net'
        try:
            available = set(os.listdir(directory))
        except OSError:
            available = set()
        names = set()
        for name in available:
            base = os.path.join(directory, name)
            if os.path.exists(os.path.join(base, 'wireless')) or os.path.exists(os.path.join(base, 'phy80211')):
                names.add(name)
        try:
            with open('/proc/net/wireless') as handle:
                for line in handle:
                    match = re.match(r'^\s*([\w.-]+):', line)
                    if match: names.add(match.group(1))
        except OSError:
            pass
        # Only run fallbacks when kernel sysfs/WEXT did not detect Wi-Fi.
        if not names:
            rc, out, _ = self._safe_run(['iw', 'dev'], timeout=4)
            if rc == 0:
                names.update(re.findall(r'^\s*Interface\s+([\w.-]+)\s*$', out, re.M))
            rc, out, _ = self._safe_run(['iwconfig'], timeout=4)
            if rc == 0:
                names.update(re.findall(r'^([\w.-]+)\s+IEEE\s+802\.11', out, re.M))
        return sorted(n for n in names if re.fullmatch(r'[a-zA-Z0-9_.-]+', n)
                      and not n.startswith(('p2p-', 'p2p0'))
                      and (not available or n in available))

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
            if not os.path.ismount('/mnt/upan') and CONFIG.startswith('/mnt/upan/'):
                raise ValueError('UDUMP unavailable')
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
    def _usable_ipv4(value):
        try:
            ip = ipaddress.IPv4Address(value)
            return not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or
                        ip.is_link_local or ip == ipaddress.IPv4Address('255.255.255.255'))
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _ip_address(iface):
        # Read the current kernel address, never a previously saved IP.
        # Older iproute/BusyBox variants may not support -o; use ioctl as fallback.
        for args in (['-4', '-o', 'addr', 'show', 'dev', iface],
                     ['-4', 'addr', 'show', 'dev', iface]):
            try:
                result = subprocess.run([_tool('ip') or 'ip'] + args,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        universal_newlines=True, timeout=3)
                if result.returncode == 0:
                    for address in re.findall(r'\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+', result.stdout):
                        if WiFiRemoteAccessPlugin._usable_ipv4(address):
                            return address
            except (OSError, subprocess.TimeoutExpired):
                break
        try:
            encoded = iface.encode('ascii')
            if not 0 < len(encoded) < 16:
                return ''
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                data = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack('256s', encoded))
            address = socket.inet_ntoa(data[20:24])
            return address if WiFiRemoteAccessPlugin._usable_ipv4(address) else ''
        except (OSError, ValueError, UnicodeError):
            return ''

    def _wifi_address(self):
        interfaces = self._wireless_interfaces()
        # Prefer the interface that successfully connected to the saved network,
        # but only if it is still a detected wireless interface with a live IP.
        try:
            with open(os.path.join(RUNTIME, 'iface')) as handle:
                selected = handle.read().strip()
        except OSError:
            selected = ''
        if selected in interfaces:
            interfaces = [selected] + [name for name in interfaces if name != selected]
        for iface in interfaces:
            address = self._ip_address(iface)
            if address:
                return address
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
                    for _ in range(20):
                        if not os.path.exists('/proc/%d' % pid):
                            break
                        time.sleep(0.05)
            except (OSError, IOError):
                pass
        try:
            os.unlink(os.path.join(RUNTIME, 'wpa.pid'))
        except OSError:
            pass

    def _dhcp(self, iface):
        if _tool('dhclient'):
            return self._safe_run(['dhclient', '-1', '-v', '-pf', os.path.join(RUNTIME, 'dhclient.pid'), iface], timeout=40)[0] == 0
        if _tool('udhcpc'):
            return self._safe_run(['udhcpc', '-i', iface, '-n', '-q', '-t', '5', '-T', '3'], timeout=35)[0] == 0
        if _tool('dhcpcd'):
            return self._safe_run(['dhcpcd', '-w', '-t', '30', iface], timeout=36)[0] == 0
        raise RuntimeError('No DHCP client available')

    def _wpa_cli_status(self, iface):
        if not _tool('wpa_cli'):
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
            if self._serial_running():
                return self._error('Stop USB Serial first')
            ssid, password = self._read_credentials()
            interfaces = self._wireless_interfaces()
            if not interfaces:
                return self._error('No Wi-Fi adapter detected')
            iface = interfaces[0]
            # Reuse a live association to the requested SSID, including after
            # leaving/reopening the plugin. Do not reset a working connection.
            for candidate in interfaces:
                status = dict(line.split('=', 1) for line in self._wpa_cli_status(candidate).splitlines() if '=' in line)
                if status.get('wpa_state') == 'COMPLETED' and status.get('ssid') == ssid:
                    iface = candidate
                    address = self._ip_address(iface)
                    if address:
                        os.makedirs(RUNTIME, mode=0o700, exist_ok=True)
                        with open(os.path.join(RUNTIME, 'iface'), 'w') as handle:
                            handle.write(iface)
                        self._prefer_usb = False
                        self._var('connection_info', 'IP: %s' % address)
                        self._var('summary', 'Connected: %s' % address)
                        self._var('ssh_text', self._ssh_description())
                        return self._network_connected(address)
                    break
            if self._mirror_running() or (_FILE_SERVICE is not None and _FILE_SERVICE.pairing):
                return self._error('Stop remote services')
            if not _tool('wpa_supplicant') or not _tool('ip'):
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
                if not _tool('wpa_cli'):
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
            self._prefer_usb = False
            self._var('connection_info', 'IP: %s' % ip)
            self._var('summary', 'Connected: %s' % ip)
            self._var('ssh_text', self._ssh_description())
            return self._network_connected(ip)
        except Exception as exc:
            return self._error('Connect failed: %s' % str(exc)[:70])

    def _network_connected(self, address):
        result = self._ensure_network_access(address)
        if result.get('status') == 'error':
            return result
        self.do_status()
        return {'status': 'connected'}

    def _ensure_network_access(self, address):
        """Explicit transport start opens one PIN-protected, standard session.

        Never rotate a live session, start expert mode, or start the old
        unauthenticated HTTP mirror automatically.
        """
        if self._serial_running():
            return self._error('Stop USB Serial first')
        if not address or address == 'Not connected':
            return self._error('Connect network first')
        if self._mirror_running() or self._stock_mirror_active():
            return self._error('Stop remote services')
        service = _file_service()
        try:
            with service.lock:
                if service.pairing:
                    if (service.pairing.get('host') == address
                            and not service.pairing.get('expert')
                            and service.pairing.get('mirror')
                            and service.thread is not None and service.thread.is_alive()):
                        return self.files_status()
                    return self._error('Stop remote services')
                if not os.path.ismount('/mnt/upan'):
                    return self._error('UDUMP unavailable')
                mirror = self._secure_mirror()
                if mirror[1] is None:
                    return self._error('Key dispatcher unavailable')
                service.start(address, mirror=mirror)
                return self.files_status()
        except Exception:
            return self._error('File service failed')

    def _stop_network_access(self):
        if _FILE_SERVICE is not None:
            _FILE_SERVICE.stop()
        # A group created by this plugin is removed only after its service stops.
        self._p2p_cleanup()

    def direct_start(self):
        if self._serial_running():
            return self._error('Stop USB Serial first')
        if self._mirror_running() or self._stock_mirror_active() or (_FILE_SERVICE is not None and _FILE_SERVICE.pairing):
            return self._error('Stop remote services')
        if not self._p2p_available():
            return self._error('P2P not supported')
        try:
            address = self._p2p_start()
            result = self._ensure_network_access(address)
            if result.get('status') == 'error':
                self._p2p_cleanup()
            return result
        except Exception:
            self._p2p_cleanup()
            return self._error('P2P start failed')

    def serial_status(self):
        self._status_battery = _battery_guard().display_sample()[0]
        lines, hint = self._serial_lines()
        for i, line in enumerate(lines):
            self._var('serial_line%d' % i, line)
        self._var('serial_hint', hint)
        return {'status': 'serial'}

    def serial_confirmed(self):
        return self.serial_toggle(confirmed=True)

    def serial_toggle(self, confirmed=False):
        global _SERIAL_SERVICE
        try:
            if _SERIAL_SERVICE is not None and _SERIAL_SERVICE.running:
                _SERIAL_SERVICE.stop()
                return self.serial_status()
            blocker = self._serial_blocker()
            if blocker: return self._error(blocker)
            source, dispatch = self._secure_mirror()
            if dispatch is None:
                return self._error('Key dispatcher unavailable')
            directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
            sys.path.insert(0, directory)
            try:
                from usb_serial import USBSerial
                from usb_network import BootDetachConfirmation
                _SERIAL_SERVICE = USBSerial()
                _SERVICE_CACHE.serial = _SERIAL_SERVICE
            finally:
                sys.path.remove(directory)
            try:
                _SERIAL_SERVICE.start(source, dispatch, _battery_guard(), confirmed=confirmed)
            except BootDetachConfirmation:
                return {'status': 'serial_confirm'} if not confirmed else self._error('Unplug USB cable first')
            return self.serial_status()
        except RuntimeError as exc:
            return self._error(str(exc))
        except Exception:
            return self._error('USB setup failed')

    def _serial_lines(self):
        service = _SERIAL_SERVICE
        if service is not None and service.running:
            return ['Serial: ON', 'PIN: ' + service.pin, self._serial_state(), self._battery_text()], 'OK - Stop USB'
        return ['Serial: OFF', 'Unplug USB devices', 'OTG on phone side', 'Plug cable after OK'], 'OK - Start USB'

    def draw_serial(self):
        # Native JSON content is the fallback; a guarded repaint restores exact
        # Courier layout after any framework render/resume on older hosts.
        self._draw_serial_now()
        canvas = self.host.getCanvas()
        if hasattr(canvas, 'after_idle'):
            canvas.after_idle(self._draw_serial_now)
        self._schedule_view_refresh('serial')

    def _draw_serial_now(self):
        if getattr(self.host, '_current_state_id', None) != 'serial':
            return
        lines, hint = self._serial_lines()
        for i, line in enumerate(lines):
            self._var('serial_line%d' % i, line)
        self._var('serial_hint', hint)
        self._paint_info_screen('serial', '_wifi_serial', lines, hint)

    def _schedule_view_refresh(self, state):
        canvas = self.host.getCanvas()
        if not hasattr(canvas, 'after'):
            return
        old = getattr(self, '_serial_ui_timer', None)
        if old is not None:
            try: canvas.after_cancel(old)
            except Exception: pass
        def refresh():
            self._serial_ui_timer = None
            if getattr(self.host, '_current_state_id', None) != state:
                return
            # Cache only: no serial or RF I/O from the UI thread.
            guard = _BATTERY
            if guard is not None:
                # Refresh HMI at most every five seconds off the Tk thread.
                now = time.monotonic()
                previous = getattr(self, '_battery_refresh_time', None)
                worker = getattr(self, '_battery_refresh_worker', None)
                if (previous is None or now - previous >= 5) and (worker is None or not worker.is_alive()):
                    self._battery_refresh_time = now
                    worker = threading.Thread(target=guard.display_sample, daemon=True)
                    self._battery_refresh_worker = worker
                    worker.start()
                old_battery = self._battery_text()
                self._status_battery = guard.display_cached()[0]
                new_battery = self._battery_text()
                if state == 'status' and old_battery != new_battery:
                    for page in getattr(self, '_status_pages', []):
                        for i, line in enumerate(page):
                            if line == old_battery:
                                page[i] = new_battery
            if state == 'serial':
                self._draw_serial_now()
            else:
                self._draw_status_now()
            self._schedule_view_refresh(state)
        self._serial_ui_timer = canvas.after(1000, refresh)

    def _usb_address(self):
        # Read an existing gadget address without modifying the USB mode.
        for name in ('usb0', 'rndis0'):
            if os.path.isdir('/sys/class/net/' + name):
                address = self._ip_address(name)
                if address:
                    return address
        return ''

    def usb_status(self):
        address = self._usb_address()
        self._var('usb_ip', address)
        self._var('usb_link', _usb_service().link_active() if address else False)
        return {'status': 'usb'}

    def usb_select(self):
        if self._serial_running():
            return self._error('Stop USB Serial first')
        service = _usb_service()
        started = False
        try:
            if service.owned and _FILE_SERVICE is not None and _FILE_SERVICE.pairing:
                return self._ensure_network_access(self._usb_address())
            if not self._usb_address():
                if self._mirror_running() or self._stock_mirror_active() or (_FILE_SERVICE is not None and _FILE_SERVICE.pairing):
                    return self._error('Stop remote services')
                service.start()
                started = True
            address = self._usb_address()
            self._prefer_usb = True
            result = self._ensure_network_access(address)
            if result.get('status') == 'error' and started:
                if _FILE_SERVICE is None or not _FILE_SERVICE.pairing:
                    service.stop()
                    self._prefer_usb = False
            return result
        except RuntimeError as exc:
            return self._error(str(exc))
        except Exception:
            return self._error('USB setup failed')

    def draw_usb(self):
        values = getattr(self.host, '_state', {}) or {}
        address = values.get('usb_ip', '')
        if address and _usb_service().owned:
            lines = ['IP: ' + address, 'USB link active' if values.get('usb_link') else 'Waiting for USB', 'OTG on phone side', 'Connect data cable' if not values.get('usb_link') else 'Preferred: USB']
            hint = 'OK - Connect'
        elif address:
            lines = ['USB Network', 'IP: ' + address, 'Preferred: USB' if self._prefer_usb else 'Preferred: Wi-Fi']
            hint = 'OK - Connect'
        elif _usb_service().owned:
            lines = ['USB Network', 'USB recovery', 'Stop remote services']
            hint = 'OK - Connect'
        else:
            lines = ['Unplug USB devices', 'Start USB first', 'OTG on phone side', 'Plug cable after OK']
            hint = 'OK - Start USB'
        self._draw_info_screen('usb', '_wifi_usb', lines, hint)

    def _live_info(self):
        # SSH/File Manager use the selected preference; mirror has its own
        # explicit transport and never silently switches between interfaces.
        wifi = self._wifi_address()
        usb = self._usb_address()
        address = (usb or wifi) if self._prefer_usb else (wifi or usb)
        return 'IP: ' + address if address else 'Not connected'

    def _mirror_lan_address(self):
        return self._usb_address() if self._mirror_transport == 2 else self._wifi_address()

    def _mirror_choices(self):
        choices = [(1, 'Wi-Fi LAN'), (2, 'USB Network')]
        if getattr(self, '_mirror_p2p_cap', False):
            choices.append((0, 'Wi-Fi Direct'))
        return choices

    def diagnostics(self):
        import glob
        ifaces = self._wireless_interfaces()
        try:
            self._read_credentials()
            saved = 'valid'
        except (OSError, ValueError, UnicodeError):
            saved = 'missing' if not os.path.exists(CONFIG) else 'unreadable/invalid'
        mounted = os.path.ismount('/mnt/upan')
        lines = ['Remote Access R15', 'Wi-Fi IPv4: ' + (self._wifi_address() or 'none'), 'USB IPv4: ' + (self._usb_address() or 'none'), 'Wi-Fi: ' + repr(ifaces), 'Saved configuration: ' + saved,
                 'Credentials path: ' + CONFIG, 'UDUMP mounted: ' + str(mounted), 'UID: ' + str(os.geteuid())]
        for args in (['lsusb'], ['ip','link','show'], ['ip','-4','-o','addr','show'], ['iw','dev'],
                     ['ss','-ltn'], ['netstat','-ltn'], ['modprobe','-n','g_ether']):
            rc, out, err = self._safe_run(args, timeout=5)
            lines.extend(['$ ' + ' '.join(args) + ' (exit %d)' % rc, out.strip(), err.strip()])
        for iface in ifaces:
            status = self._wpa_cli_status(iface)
            # WPA status can contain private SSID/BSSID; only report association state.
            state = next((line for line in status.splitlines() if line.startswith('wpa_state=')), 'wpa_state=unknown')
            lines.append(iface + ': ' + state)
        for name in ('g_serial','g_ether','g_mass_storage','g_acm_ms','r8188eu','mt7601u','88XXau','8821cu'):
            lines.append(name + ': ' + str(os.path.isdir('/sys/module/'+name)))
        for path in glob.glob('/sys/class/udc/*/state'):
            try:
                with open(path) as stream: lines.append(path + ': ' + stream.read().strip())
            except OSError: pass
        self._diag_lines = ['Wi-Fi: detected' if ifaces else 'Wi-Fi: not detected',
                            'Saved Wi-Fi: OK' if saved == 'valid' else 'Saved Wi-Fi: error',
                            'UDUMP: mounted' if mounted else 'UDUMP unavailable', 'Report not saved']
        if mounted:
            try:
                fd, temporary = tempfile.mkstemp(prefix='.remote-diag-', dir='/mnt/upan')
                try:
                    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                        stream.write('\n'.join(lines) + '\n')
                    os.replace(temporary, '/mnt/upan/remote_access_diagnostics.txt')
                    self._diag_lines[-1] = 'Report saved: UDUMP'
                finally:
                    if os.path.exists(temporary): os.unlink(temporary)
            except OSError: pass
        return {'status':'diag'}

    def draw_diagnostics(self):
        self._draw_info_screen('diag', '_wifi_diag', self._diag_lines, 'OK - Refresh')

    def do_status(self):
        try:
            serial = self._serial_state()
            self._status_battery = _battery_guard().display_sample()[0]
            if serial != 'Serial: OFF':
                self._status_pages = [['USB Serial', serial, self._battery_text(), self.tr('PIN: ') + _SERIAL_SERVICE.pin]]
                self._status_page = 0
                self._var('connection_info', serial)
                return self._publish_status()
            wifi, usb = self._wifi_address(), self._usb_address()
            self._var('connection_info', self._live_info())
            self._var('ssh_text', self._ssh_description())
            usb_state = ('USB link active' if _usb_service().link_active() else 'Waiting for USB') if usb else 'USB Network: OFF'
            self._status_pages = [
                ['USB Serial', serial, self._battery_text()],
                ['Wi-Fi LAN', 'IP: '+wifi if wifi else 'Not connected', 'USB Network', 'IP: '+usb if usb else 'Not connected', usb_state],
                ['Screen Mirror: '+('ON' if self._mirror_running() or (_FILE_SERVICE is not None and _FILE_SERVICE.pairing and _FILE_SERVICE.pairing.get('mirror')) else 'OFF'),
                 'Secure Access: '+('ON' if _FILE_SERVICE is not None and _FILE_SERVICE.server is not None else 'OFF'),
                 'Lab401 Mirror: '+('ON' if self._stock_mirror_active() else 'OFF'),
                 self._ssh_description()]]
            if serial == 'Serial: OFF':
                pairing = _FILE_SERVICE.pairing if _FILE_SERVICE is not None else None
                address = pairing.get('host') if pairing else self._mirror_address() if self._mirror_running() else None
                if address:
                    mode = 'USB Network' if address == usb else 'Wi-Fi LAN' if address == wifi else 'Wi-Fi Direct'
                    self._status_pages.insert(0, [mode, 'IP: '+address, 'Secure Access: ON' if pairing else 'Screen Mirror: ON', self._battery_text()])
                elif wifi or usb:
                    if usb and (self._prefer_usb or not wifi):
                        current = ['USB Network', 'IP: '+usb, usb_state, self._battery_text()]
                    else:
                        current = ['Wi-Fi LAN', 'IP: '+wifi, self._battery_text()]
                    self._status_pages.insert(0, current)
                else: self._status_pages[0].insert(0, 'Not connected')
            self._status_page = 0
            return self._publish_status()
        except Exception as exc:
            return self._error('Status failed: %s' % str(exc)[:70])

    def _mirror_script(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'lib', 'mirror_server.py')

    def _mirror_running(self):
        if _MIRROR_SERVICE is not None and _MIRROR_SERVICE.running:
            return True
        return self._legacy_mirror_running()

    def _legacy_mirror_running(self):
        try:
            with open(self._MIRROR_PID, 'r') as handle:
                pid = int(handle.read().strip())
            if pid <= 1:
                return False
            os.kill(pid, 0)
            with open('/proc/%d/cmdline' % pid, 'rb') as handle:
                cmdline = handle.read().replace(b'\x00', b' ')
            return b'mirror_server.py' in cmdline
        except (OSError, ValueError):
            return False

    def _mirror_code(self):
        if _MIRROR_SERVICE is not None and _MIRROR_SERVICE.running:
            return _MIRROR_SERVICE.token
        with open(self._MIRROR_TOKEN, 'r') as handle:
            return handle.read().strip()

    def _new_mirror_code(self):
        # New sessions keep their temporary PIN in memory; legacy sessions
        # can still be stopped and read their old token file.
        return '%06d' % secrets.randbelow(1000000) if self._mirror_mode == 0 else ''

    def mirror_status(self):
        global _MIRROR_SERVICE
        active = self._mirror_running()
        if active and _MIRROR_SERVICE is not None and _MIRROR_SERVICE.running:
            transport = getattr(_MIRROR_SERVICE, 'transport', None)
            if transport in (1, 2):
                current = self._wifi_address() if transport == 1 else self._usb_address()
                if current != _MIRROR_SERVICE.address:
                    try:
                        _MIRROR_SERVICE.stop()
                    except Exception:
                        return self._error('Mirror stop failed')
                    _MIRROR_SERVICE = None
                    _SERVICE_CACHE.mirror = None
                    return self._error('IP changed. Restart mirror')
        self._var('mirror_active', 'ON' if active else 'OFF')
        self._var('mirror_ip', self._mirror_address() if active else (self._wifi_address() or 'Not connected'))
        try:
            self._var('mirror_code', self._mirror_code() if active else '')
        except OSError:
            return self._error('Mirror start failed')
        if not active:
            self._mirror_p2p_cap = self._p2p_available()
            self._mirror_transport = 1
        return {'status': 'mirror' if active else 'mirror_transport'}

    def _p2p_available(self):
        if not all(_tool(x) for x in ('iw', 'ip', 'wpa_cli', 'wpa_supplicant', 'dnsmasq')):
            return False
        interfaces = self._wireless_interfaces()
        if not interfaces:
            return False
        phy = os.path.realpath('/sys/class/net/' + interfaces[0] + '/phy80211')
        if not os.path.isdir(phy):
            return False
        rc, caps, _ = self._safe_run(['iw', 'phy', os.path.basename(phy), 'info'])
        modes = re.search(r'Supported interface modes:\s*\n((?:[ \t]+\*[^\n]+\n?)+)', caps)
        return bool(rc == 0 and modes and re.search(r'\*\s*P2P-GO\s*$', modes.group(1), re.M))

    def draw_mirror_transport(self):
        choices = self._mirror_choices()
        selected = next((i for i, item in enumerate(choices) if item[0] == self._mirror_transport), 0)
        self._draw_choice_list('_wifi_mirror_transport', [label for _, label in choices], selected)

    def mirror_transport_up(self):
        choices = self._mirror_choices()
        current = next((i for i, item in enumerate(choices) if item[0] == self._mirror_transport), 0)
        self._mirror_transport = choices[(current - 1) % len(choices)][0]
        self.draw_mirror_transport()

    def mirror_transport_down(self):
        choices = self._mirror_choices()
        current = next((i for i, item in enumerate(choices) if item[0] == self._mirror_transport), 0)
        self._mirror_transport = choices[(current + 1) % len(choices)][0]
        self.draw_mirror_transport()

    def clear_mirror_transport(self):
        self.host.getCanvas().delete('_wifi_mirror_transport')

    def mirror_transport_select(self):
        return {'choice': 'selected'}

    def _mirror_address(self):
        if _MIRROR_SERVICE is not None and _MIRROR_SERVICE.running:
            return _MIRROR_SERVICE.address
        try:
            with open(os.path.join(RUNTIME, 'mirror_address')) as f:
                return f.read().strip()
        except OSError:
            return 'Not connected'

    def _p2p_cleanup(self):
        record = os.path.join(RUNTIME, 'mirror_p2p')
        try:
            with open(record) as f:
                parent, group = f.read().splitlines()
        except (OSError, ValueError):
            return
        pidfile = os.path.join(RUNTIME, 'mirror_dnsmasq.pid')
        try:
            with open(pidfile) as f:
                pid = int(f.read())
            with open('/proc/%d/cmdline' % pid, 'rb') as f:
                if b'dnsmasq' in f.read() and pid > 1:
                    os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError):
            pass
        if group != parent:
            self._safe_run(['wpa_cli', '-i', parent, 'p2p_group_remove', group], timeout=5)
        for path in (record, pidfile):
            try: os.unlink(path)
            except OSError: pass

    def _p2p_start(self):
        if not all(_tool(x) for x in ('iw', 'ip', 'wpa_cli', 'wpa_supplicant', 'dnsmasq')):
            raise RuntimeError('P2P tools missing')
        interfaces = self._wireless_interfaces()
        if not interfaces:
            raise RuntimeError('No Wi-Fi adapter detected')
        parent = interfaces[0]
        phy = os.path.realpath('/sys/class/net/' + parent + '/phy80211')
        if not os.path.isdir(phy):
            raise RuntimeError('P2P not supported')
        rc, caps, _ = self._safe_run(['iw', 'phy', os.path.basename(phy), 'info'])
        modes = re.search(r'Supported interface modes:\s*\n((?:[ \t]+\*[^\n]+\n?)+)', caps)
        if rc != 0 or not modes or not re.search(r'\*\s*P2P-GO\s*$', modes.group(1), re.M):
            raise RuntimeError('P2P not supported')
        if not self._wpa_cli_status(parent):
            os.makedirs(RUNTIME, mode=0o700, exist_ok=True)
            conf = os.path.join(RUNTIME, 'p2p.conf')
            with open(conf, 'w') as f:
                f.write('ctrl_interface=/var/run/wpa_supplicant\ncountry=GB\ndevice_name=iCopy-X\n')
            os.chmod(conf, 0o600)
            self._safe_run(['ip', 'link', 'set', parent, 'up'])
            started, driver = self._launch_wpa(parent, conf)
            if not started and driver != 'existing':
                raise RuntimeError('P2P start failed')
        def groups():
            rc, out, _ = self._safe_run(['iw', 'dev'])
            return set(re.findall(r'Interface\s+(\S+)\s+[^\n]*(?:\n(?!\s*Interface)[^\n]*)*?\n\s*type P2P-GO', out))
        before = groups()
        if before:
            raise RuntimeError('P2P already active')
        self._wpa_cli_command(parent, 'p2p_group_add')
        group = None
        for _ in range(15):
            found = groups() - before
            if len(found) == 1:
                group = found.pop()
                break
            time.sleep(1)
        if not group or group == parent:
            if group == parent:
                self._safe_run(['wpa_cli', '-i', parent, 'p2p_group_remove', parent])
            raise RuntimeError('P2P group failed')
        with open(os.path.join(RUNTIME, 'mirror_p2p'), 'w') as f:
            f.write(parent + '\n' + group + '\n')
        try:
            address = '192.168.49.1'
            if self._safe_run(['ip', 'addr', 'add', address+'/24', 'dev', group])[0] != 0:
                raise RuntimeError('P2P address failed')
            if self._safe_run(['ip', 'link', 'set', group, 'up'])[0] != 0:
                raise RuntimeError('P2P group failed')
            pidfile = os.path.join(RUNTIME, 'mirror_dnsmasq.pid')
            if self._safe_run(['dnsmasq', '--conf-file=/dev/null', '--port=0', '--interface='+group,
                    '--bind-interfaces', '--dhcp-range=192.168.49.20,192.168.49.60,255.255.255.0,5m',
                    '--dhcp-option=3', '--dhcp-option=6', '--pid-file='+pidfile])[0] != 0:
                raise RuntimeError('P2P DHCP failed')
            self._wpa_cli_command(group, 'wps_pbc')
            return address
        except Exception:
            self._p2p_cleanup()
            raise

    def draw_mirror_mode(self):
        if getattr(self.host, '_current_state_id', None) == 'mirror_mode':
            self._draw_choice_list('_wifi_mirror_mode', ['With PIN', 'View only (no PIN)'], self._mirror_mode)

    def mirror_mode_up(self):
        self._mirror_mode = 1 - self._mirror_mode
        self.draw_mirror_mode()

    def clear_mirror_mode(self):
        self.host.getCanvas().delete('_wifi_mirror_mode')

    def mirror_mode_select(self):
        return {'choice': 'start'}

    def mirror_toggle(self):
        if _SERIAL_SERVICE is not None and _SERIAL_SERVICE.running:
            return self._error('Stop USB Serial first')
        if _FILE_SERVICE is not None and _FILE_SERVICE.pairing is not None:
            return self._error('Stop remote services')
        global _MIRROR_SERVICE
        if self._mirror_running():
            if _MIRROR_SERVICE is not None:
                try:
                    _MIRROR_SERVICE.stop()
                except Exception:
                    return self._error('Mirror stop failed')
                _MIRROR_SERVICE = None
                _SERVICE_CACHE.mirror = None
            # Allow removal of a server left by the previous plugin revision.
            if self._legacy_mirror_running():
                try:
                    with open(self._MIRROR_PID, 'r') as handle:
                        pid = int(handle.read().strip())
                    if self._legacy_mirror_running():
                        os.kill(pid, signal.SIGTERM)
                except (OSError, ValueError):
                    pass
                for _ in range(20):
                    if not self._legacy_mirror_running(): break
                    time.sleep(0.1)
                if self._legacy_mirror_running():
                    return self._error('Mirror stop failed')
            try:
                os.unlink(self._MIRROR_PID)
            except OSError:
                pass
            self._p2p_cleanup()
            self._mirror_mode = 0
            return self.mirror_status()
        lease = _FILE_SERVICE.lease if _FILE_SERVICE is not None else None
        if lease is not None and lease.valid():
            return self._error('Stop Expert first')
        if self._mirror_transport in (1, 2) and not self._mirror_lan_address():
            return self._error('Wi-Fi has no IPv4' if self._mirror_transport == 1 else 'USB has no IPv4')
        if not any(os.path.exists(x) for x in ('/dev/fb_st7789v', '/dev/fb1', '/dev/fb0')):
            return self._error('Framebuffer unavailable')
        try:
            code = self._new_mirror_code()
            script = self._mirror_script()
            if not os.path.isfile(script):
                return self._error('Mirror server missing')
            # Lab401 uses a process-local keymap singleton. Prefer the already
            # bound dispatcher, never a fresh instance in a child process.
            from lib import keymap
            candidates = [getattr(keymap, 'key', None),
                          getattr(sys.modules.get('keymap'), 'key', None)]
            dispatcher = next((k for k in candidates if callable(getattr(k, 'onKey', None))
                               and getattr(k, '_target', None) is not None), None)
            if dispatcher is None and code:
                return self._error('Key dispatcher unavailable')
            os.makedirs(RUNTIME, exist_ok=True)
            self._p2p_cleanup()
            address = self._p2p_start() if self._mirror_transport == 0 else self._mirror_lan_address()
            if not address:
                return self._error('Wi-Fi has no IPv4' if self._mirror_transport == 1 else 'USB has no IPv4')
            with open(os.path.join(RUNTIME, 'mirror_address'), 'w') as f:
                f.write(address)
            spec = importlib.util.spec_from_file_location('remote_access_mirror_server', script)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _MIRROR_SERVICE = module.open_session(code, address, self._MIRROR_PORT,
                dispatcher.onKey if dispatcher is not None else None, battery=_battery_guard())
            _MIRROR_SERVICE.transport = self._mirror_transport
            _SERVICE_CACHE.mirror = _MIRROR_SERVICE
            return self.mirror_status()
        except RuntimeError as exc:
            self._p2p_cleanup()
            return self._error(str(exc))
        except (OSError, ValueError, ImportError):
            self._p2p_cleanup()
            return self._error('Mirror start failed')

    def draw_mirror_screen(self):
        state = getattr(self.host, '_state', {}) or {}
        active = state.get('mirror_active', 'OFF')
        ip = state.get('mirror_ip', 'Not connected')
        token = str(state.get('mirror_code', ''))
        if active == 'ON':
            lines = ['Mirror: ON', 'IP: ' + ip, self.tr('Port: %d') % self._MIRROR_PORT,
                     self.tr('PIN: ') + token if token else 'Without PIN']
            hint = 'OK - Stop mirror'
        else:
            lines = ['Mirror: OFF', 'IP: ' + ip,
                     'Press OK to start']
            hint = 'OK - Start mirror'
        self._draw_info_screen('mirror', '_wifi_mirror', lines, hint)

    def files_status(self):
        service = _file_service()
        with service.lock:
            if service.lease is not None and not service.lease.valid():
                service.stop()
            self._file_pairing = service.pairing
        self._file_page = 0
        return {'status': 'files'}

    def _secure_mirror(self):
        # Use the exact process-local dispatcher used by the firmware.
        from lib import keymap
        candidates = [getattr(keymap, 'key', None), getattr(sys.modules.get('keymap'), 'key', None)]
        dispatcher = next((k for k in candidates if callable(getattr(k, 'onKey', None)) and getattr(k, '_target', None) is not None), None)
        spec = importlib.util.spec_from_file_location('remote_access_secure_mirror', self._mirror_script())
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        path, width, bpp, stride = module.find_framebuffer()
        source = module.FrameSource(path, bpp=bpp, source_width=width, stride=stride)
        source.frame()
        return (source, dispatcher.onKey if dispatcher is not None else None)

    def files_toggle(self):
        if self._serial_running():
            return self._error('Stop USB Serial first')
        service = _file_service()
        if service.pairing:
            return self.files_status()
        return self._ensure_network_access(self._live_info().replace('IP: ', ''))

    def files_expert_start(self):
        if _SERIAL_SERVICE is not None and _SERIAL_SERVICE.running:
            return self._error('Stop USB Serial first')
        service = _file_service()
        level, _ = _battery_guard().sample()
        if level is None:
            # The first query is asynchronous. Give HMI a short opportunity to reply.
            time.sleep(1.5)
            level, _ = _battery_guard().sample()
        if level is None or level < 30:
            self._blocked_battery_level = level
            return {'status': 'battery_locked'}
        try:
            if self._mirror_running():
                return self._error('Stop mirror first')
            # Do not display a privileged pairing secret over Lab401 USB mirror.
            for name in ('lib.mirror_service', 'mirror_service'):
                module = sys.modules.get(name)
                mirror = getattr(module, '_instance', None)
                if mirror is not None and getattr(mirror, 'is_running', False):
                    return self._error('Stop mirror first')
            address = service.pairing['host'] if service.pairing else self._live_info().replace('IP: ', '')
            if address == 'Not connected':
                return self._error('Connect network first')
            service.start(address, expert=True)
            return self.files_status()
        except Exception as exc:
            from battery_guard import BatteryBlocked
            if isinstance(exc, BatteryBlocked):
                self._blocked_battery_level = _battery_guard().sample()[0]
                return {'status': 'battery_locked'}
            return self._error('File service failed')

    def draw_battery_locked(self):
        if getattr(self.host, '_current_state_id', None) != 'battery_locked': return
        level = getattr(self, '_blocked_battery_level', None)
        canvas = self.host.getCanvas()
        tag = '_wifi_battery_locked'
        canvas.delete(tag)
        lines = [self.tr('Expert Mode locked'), self.tr('Battery too low') if level is not None else self.tr('Battery unknown'),
                 self.tr('Battery: %d%%') % level if level is not None else self.tr('No fresh HMI data'), self.tr('Minimum: 30%'), self.tr('Please recharge')]
        for i, line in enumerate(lines):
            canvas.create_text(120, 65+i*23, text=line, anchor='n', font=('Courier New',12), fill='#D00000' if i<2 else '#555555', tags=(tag,'_ra_content','_jr_content'))
        self._draw_action_hint(tag, 'OK - Continue')

    def clear_battery_locked(self):
        self.host.getCanvas().delete('_wifi_battery_locked')

    def draw_expert_warning(self):
        self._draw_info_screen('files_expert_confirm', '_wifi_expert',
            ['Expert Mode', 'System files at risk', 'Device may not boot', 'At your own risk'],
            'OK - Confirm')

    def files_page(self, delta):
        if self._file_pairing:
            self._file_page = (self._file_page + delta) % 2
            self.draw_files()

    def files_next(self): self.files_page(1)
    def files_prev(self): self.files_page(-1)

    def draw_files(self):
        pairing = _file_service().pairing
        self._file_pairing = pairing
        if not pairing:
            self._file_page = 0
            lines = ['Secure Access: OFF', 'UDUMP + Mirror', 'Press OK to start', 'Right - Expert']
        elif self._file_page == 0:
            lines = ['Expert: ON' if pairing.get('expert') else 'Secure Access: ON', 'IP: ' + pairing['host'], self.tr('PIN: ') + pairing['pin'], 'Down - Verify code']
        else:
            code = pairing['fingerprint'][:16].upper()
            lines = ['Verify on phone', code[:8] + ' ' + code[8:], 'Compare, not enter', 'Up - PIN']
        self._draw_info_screen('files', '_wifi_files', lines, 'OK - Refresh' if pairing else 'OK - Start files')

    def ssh_status(self):
        self._var('ssh_text', self._ssh_description())
        if self._serial_running() and _SERIAL_SERVICE.connected:
            protocol = _SERIAL_SERVICE.protocol
            if protocol is not None and hasattr(protocol, 'request_ssh_terminal'):
                protocol.request_ssh_terminal()
        return {'status':'ssh'}

    def _ssh_phone_line(self):
        if not self._serial_running():
            return ''
        if not _SERIAL_SERVICE.connected:
            return 'Connect phone first'
        protocol = _SERIAL_SERVICE.protocol
        if not hasattr(protocol, 'ssh_open_status'):
            return 'Restart USB service'
        return {'idle': 'OK - Open on phone', 'pending': 'Waiting for phone',
                'received': 'Phone: request read', 'opened': 'Phone: SSH opened'}.get(protocol.ssh_open_status(), '')

    def draw_ssh(self):
        state = getattr(self.host, '_state', {}) or {}
        lines = ['USB Serial' if self._serial_running() else self._live_info(), state.get('ssh_text','SSH: status unknown')]
        phone = self._ssh_phone_line()
        if phone:
            lines.append(phone)
        self._draw_info_screen('ssh', '_wifi_ssh', lines, 'OK - Retry' if self._serial_running() else 'OK - Refresh')
        canvas = self.host.getCanvas()
        if getattr(self, '_ssh_ui_timer', None) is not None:
            try: canvas.after_cancel(self._ssh_ui_timer)
            except Exception: pass
        if self._serial_running() and hasattr(canvas, 'after'):
            def update():
                self._ssh_ui_timer = None
                if getattr(self.host, '_current_state_id', None) == 'ssh':
                    self.draw_ssh()
            self._ssh_ui_timer = canvas.after(1000, update)

    def _ssh_description(self):
        # Listening on :22 does not guarantee reachability or credentials.
        for command in (['ss', '-ltn'], ['netstat', '-ltn']):
            rc, out, _ = self._safe_run(command, timeout=5)
            if rc == 0:
                if self._serial_running() and re.search(r'(?:127\.0\.0\.1|0\.0\.0\.0|\*|\[::\]|::):22\s', out):
                    return self.tr('SSH: port 22 listening')
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
            if self._mirror_running():
                return self._error('Stop remote services')
            if _FILE_SERVICE is not None and _FILE_SERVICE.pairing:
                if _FILE_SERVICE.pairing.get('host') != self._wifi_address():
                    return self._error('Stop remote services')
                self._stop_network_access()
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
            if _tool('wpa_cli') and self._wpa_cli_status(iface):
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
            if os.path.isfile(pidfile) and _tool('dhclient'):
                self._safe_run(['dhclient', '-r', '-pf', pidfile, iface], timeout=12)

            # Drop address + interface even if a system-owned WPA daemon remains.
            # Do not stop the SSH service itself (it can remain available on LAN).
            if not _tool('ip'):
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
