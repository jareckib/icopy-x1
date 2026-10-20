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
"""Paxton Clone&Down plugin for iCopy-XS"""

import re
import os

from lib._constants import SCREEN_W
from lib import resources

PAXTON_KEY = 'BDF5E846'

DUMP_DIR = '/mnt/upan/dump/paxton'
LOG_PATH = os.path.join(DUMP_DIR, 'Paxton_log.txt')

READ_TIMEOUT = 20000
WRITE_TIMEOUT = 10000
CLONE_TIMEOUT = 15000

PICK_ROWS = 8
LOG_SEP = '--------------------------'

try:
    from lib.input_txt import FreeTextInput
except Exception:
    FreeTextInput = None


def _hex_to_bin(hex_string):
    return ''.join('{:04b}'.format(int(c, 16)) for c in hex_string.upper())


def _process_block(block_hex):
    binary = _hex_to_bin(block_hex)[:-2]
    chunks = [binary[i:i+5] for i in range(0, len(binary), 5)]
    return [c[1:] for c in chunks if len(c) == 5]


def calculate_id_net(blocks):
    nibbles = [format(int(n, 2), 'X') for blk in blocks for n in _process_block(blk)]
    selected = []
    for h in nibbles:
        if h == 'F':
            break
        selected.append(h)
    if not selected:
        return None, None
    combined = ''.join(selected)
    if not combined.isdigit():
        return None, None
    d = int(combined)
    return d, '{:010X}'.format(d)


def calculate_id_switch(blocks):
    dec = [int(n, 2) for blk in blocks for n in _process_block(blk)]
    if len(dec) < 15:
        return None, None
    nums = [str(dec[p - 1]) for p in [9, 11, 13, 15, 2, 4, 6, 8]]
    d = int(''.join(nums))
    return d, '{:010X}'.format(d)


def _parse_hitag_blocks(output):
    blocks = {}
    if not output:
        return blocks
    for line in output.splitlines():
        m = re.match(r'\s*(\d+)\s*/0x0[0-7]\s*\|\s*([0-9A-Fa-f]{2}\s+){3}[0-9A-Fa-f]{2}', line)
        if not m:
            m = re.match(r'\s*(\d+)\s*\|\s*([0-9A-Fa-f]{8})', line)
        if m:
            blk = int(m.group(1))
            data = re.search(r'([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})\s+([0-9A-Fa-f]{2})', line)
            if data:
                blocks[blk] = ''.join(data.groups()).upper()
            else:
                data2 = re.search(r'\|\s*([0-9A-Fa-f]{8})', line)
                if data2:
                    blocks[blk] = data2.group(1).upper()
    return blocks


def _parse_uid(output):
    if not output:
        return ''
    for line in output.splitlines():
        m = re.search(r'UID[\.\s]+([0-9A-Fa-f]{8})', line)
        if m:
            return m.group(1).upper()
    return ''


def _parse_type(output):
    if not output:
        return ''
    for line in output.splitlines():
        m = re.search(r'TYPE[\.\s]+(.+)', line)
        if m:
            t = m.group(1).strip()
            if t:
                return t
    return ''


def _ensure_dirs():
    try:
        if not os.path.exists('/mnt/upan'):
            return False
        os.makedirs(DUMP_DIR, mode=0o775, exist_ok=True)
        return True
    except Exception:
        return False


def _log_read_entries():
    try:
        with open(LOG_PATH, 'r') as f:
            lines = f.read().splitlines()
    except Exception:
        return []

    entries = []
    cur = None

    def _new(name):
        return {'name': name, 'date': '', 'mode': 'paxton', 'blocks': {},
                'em_id': '', 'variant': '', 'uid': ''}

    for raw in lines:
        line = raw.strip()
        if line.startswith('Name:'):
            if cur is not None:
                entries.append(cur)
            cur = _new(line[5:].strip())
            continue
        if cur is None:
            continue
        if line.startswith('---'):
            entries.append(cur)
            cur = None
            continue
        m = re.match(r'Mode:\s*(.+)$', line)
        if m:
            cur['mode'] = m.group(1).strip().lower()
            continue
        m = re.match(r'Date:\s*(.+)$', line)
        if m:
            cur['date'] = m.group(1).strip()
            continue
        m = re.match(r'Block\s+(\d+):\s*([0-9A-Fa-f]{8})\b', line)
        if m:
            cur['blocks'][int(m.group(1))] = m.group(2).upper()
            continue
        m = re.match(r'EM4102 ID:\s*([0-9A-Fa-f]{10})\b', line)
        if m:
            cur['em_id'] = m.group(1).upper()
            continue
        m = re.match(r'Variant:\s*(.+)$', line)
        if m:
            v = m.group(1).strip()
            cur['variant'] = '' if v.lower() == 'nil' else v
            continue
        m = re.match(r'UID:\s*([0-9A-Fa-f]{8})\b', line)
        if m:
            cur['uid'] = m.group(1).upper()
            continue
    if cur is not None:
        entries.append(cur)
    return entries


def _log_paxton_entries():
    good = []
    for e in _log_read_entries():
        if e['mode'] != 'paxton' or not e['name']:
            continue
        if not all(re.match(r'^[0-9A-F]{8}$', e['blocks'].get(i, ''))
                   for i in range(4, 8)):
            continue
        good.append(e)
    good.sort(key=lambda e: e['name'].lower())
    return good


def _log_name_exists(name):
    low = name.lower()
    for e in _log_read_entries():
        if e['name'].lower() == low:
            return True
    return False


def _log_save(name, blocks, em_id, variant, uid):
    if not _ensure_dirs():
        return False
    try:
        from datetime import datetime
        with open(LOG_PATH, 'a') as f:
            f.write('Name: {}\n'.format(name))
            f.write('Date: {}\n'.format(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            f.write('Mode: paxton\n')
            for i in range(4, 8):
                f.write('Block {}: {}\n'.format(i, blocks.get(i, 'nil')))
            f.write('EM4102 ID: {}\n'.format(em_id or 'nil'))
            f.write('Variant: {}\n'.format(variant or 'nil'))
            f.write('UID: {}\n'.format(uid or 'nil'))
            f.write(LOG_SEP + '\n')
        return True
    except Exception:
        return False


def _dump_save(blocks, uid, variant):
    if not _ensure_dirs():
        return None
    try:
        uid = uid.upper() if re.match(r'^[0-9A-Fa-f]{8}$', uid or '') else '00000000'
        b5 = blocks[5]
        prefix = 'Paxton-ID_{}_{}_'.format(uid, b5)
        top = 0
        for fn in os.listdir(DUMP_DIR):
            m = re.match(r'^' + re.escape(prefix) + r'(\d+)\.txt$', fn)
            if m:
                top = max(top, int(m.group(1)))
        fname = '{}{}.txt'.format(prefix, top + 1)
        raw = ''.join(blocks[i] for i in range(4, 8))
        ptype = 'switch2' if (variant or '').lower().startswith('switch') else 'net2'
        with open(os.path.join(DUMP_DIR, fname), 'w') as f:
            f.write('{}\n{}_{}\ntype={}\n'.format(raw, uid, b5, ptype))
        return fname
    except Exception:
        return None


class PaxtonCloneDownPlugin(object):

    def __init__(self, host=None):
        self.host = host
        self._pick = []
        self._pick_idx = 0
        self._txt = None
        self._txt_mode = None

    def _pm3(self, cmd, timeout=WRITE_TIMEOUT):
        return self.host.pm3_command(cmd, timeout=timeout)

    def _toast(self, text):
        try:
            self.host.show_toast(text, timeout=2500)
        except Exception:
            pass

    def _fail(self, msg, back, retry_action=None, retry_kind='normal'):
        self.host.set_var('error_msg', msg)
        self.host.set_var('err_return', back)
        self.host.set_var('err_retry', retry_action or '')
        self.host.set_var('err_retry_kind', retry_kind)
        return {'status': 'error'}

    def _blank(self):
        s = self.host.set_var
        for k in ('error_msg', 'err_return', 'flow', 'uid', 'tag_variant',
                  'em_id', 'id_line', 'block4', 'block5', 'block6', 'block7',
                  'src_name', 'src_line', 'saved_name', 'dump_line',
                  'pick_pos', 'pick_view', 'txt_charset'):
            s(k, '')
        s('clone_count', '0')
        s('down_count', '0')
        s('err_retry', '')
        s('err_retry_kind', 'normal')
        self._txt = None
        self._txt_mode = None
        self._clear_mode_label()

    def _clear_read_write_cache(self):
        for k in ('uid', 'tag_variant', 'em_id', 'id_line',
                  'src_name', 'src_line', 'block4', 'block5', 'block6', 'block7'):
            self.host.set_var(k, '')

    def _get_blocks(self):
        return {i: self.host.get_var('block{}'.format(i), '') for i in range(4, 8)}

    def _blocks_ok(self, blocks):
        return all(re.match(r'^[0-9A-Fa-f]{8}$', blocks.get(i, '')) for i in range(4, 8))

    def _read_blocks(self):
        cmd = 'lf hitag read --ht2 --k {}'.format(PAXTON_KEY)
        last_out = ''
        for _ in range(2):
            ok, out = self._pm3(cmd, READ_TIMEOUT)
            last_out = out or last_out
            if ok and out:
                blocks = _parse_hitag_blocks(out)
                if all(i in blocks for i in range(4, 8)):
                    return blocks, _parse_uid(out), _parse_type(out), out
        try:
            self.host.set_var('last_pm3_out', last_out or '')
        except Exception:
            pass
        return None, '', '', last_out or ''

    def _detect_paxton(self, blocks):
        try:
            b5 = blocks.get(5, '')
            if len(b5) >= 4 and b5[3].upper() == 'F':
                variant = 'Net2'
                _, hex_id = calculate_id_net([blocks[4], blocks[5]])
            else:
                variant = 'Switch2'
                _, hex_id = calculate_id_switch([blocks[4], blocks[5], blocks[6], blocks[7]])
            return variant, hex_id
        except Exception:
            return '', None

    def _store(self, blocks, uid, variant, hex_id, src_name, src_line):
        s = self.host.set_var
        s('uid', uid or '')
        for i in range(4, 8):
            s('block{}'.format(i), blocks.get(i, ''))
        s('tag_variant', variant or '')
        s('em_id', hex_id or '')
        s('id_line', 'EM ID {}'.format(hex_id) if hex_id else 'EM ID n/a')
        s('src_name', src_name or '')
        s('src_line', src_line or '')
        s('clone_count', '0')
        s('down_count', '0')

    def _clear_mode_label(self):
        try:
            self.host.getCanvas().delete('_mode_lbl')
        except Exception:
            pass

    def _update_mode_label(self):
        """Refresh both the {txt_charset} var and the on-canvas 'Mode: xyz'
        label from the active FreeTextInput's charset. Combines what used
        to be two separate calls (_set_txt_charset + _draw_mode_label) kept
        in sync by hand at every call site."""
        mode = self._set_txt_charset()
        self._clear_mode_label()
        try:
            self.host.getCanvas().create_text(
                SCREEN_W // 2,
                50,
                text='Mode: ' + mode,
                fill='#000000',
                font=resources.get_font(16),
                anchor='n',
                tags='_mode_lbl',
            )
        except Exception:
            pass

    def do_init(self):
        self._blank()
        self._pick = []
        self._pick_idx = 0
        return {'status': 'ok'}

    def do_start_clone(self):
        self._clear_mode_label()
        self.host.set_var('flow', 'clone')
        self.host.set_var('src_name', '')
        return {'status': 'clone'}

    def do_start_down(self):
        self._clear_mode_label()
        self.host.set_var('flow', 'down')
        self.host.set_var('src_name', '')
        return {'status': 'down'}

    def do_start_log(self):
        self._clear_mode_label()
        if not _log_paxton_entries():
            return self._fail('No saved Paxton entries in the log.', 'menu')
        return {'status': 'log'}

    def _do_read(self, flow, need_id):
        self.host.set_var('flow', flow)
        self._toast('Reading fob...')
        blocks, uid, typ, out = self._read_blocks()
        back = 'read_' + flow
        if blocks is None:
            retry_action = 'do_read_clone' if flow == 'clone' else 'do_read_down'
            return self._fail(
                'No fob detected.\nAdjust position\nand try again.',
                back,
                retry_action=retry_action,
                retry_kind='readwrite'
            )
        variant, hex_id = self._detect_paxton(blocks)
        if need_id and not hex_id:
            retry_action = 'do_read_down' if flow == 'down' else 'do_read_clone'
            return self._fail(
                'ID calculation failed.\nIs it a Paxton fob?',
                back,
                retry_action=retry_action,
                retry_kind='readwrite'
            )
        self._store(blocks, uid, variant, hex_id, '', 'Read OK: {}'.format(variant or 'Paxton'))
        return {'status': 'found'}

    def do_read_clone(self):
        return self._do_read('clone', False)

    def do_read_down(self):
        return self._do_read('down', True)

    def do_clone_paxton(self):
        self.host.set_var('flow', 'clone')
        blocks = self._get_blocks()
        if not self._blocks_ok(blocks):
            return self._fail('No valid block data.\nRead a fob first.', 'menu')
        self._toast('Writing fob...')
        for page in range(4, 8):
            cmd = 'lf hitag wrbl --ht2 -p {} -d {} -k {}'.format(page, blocks[page], PAXTON_KEY)
            ok, _ = self._pm3(cmd, WRITE_TIMEOUT)
            if not ok:
                return self._fail(
                    'Block {} write failed\nCheck fob position'.format(page),
                    'readed_clone',
                    retry_action='do_clone_paxton',
                    retry_kind='write_retry'
                )
        read_blocks, uid, typ, out = self._read_blocks()
        if read_blocks is None:
            return self._fail(
                'Write verification failed.\nCheck fob position.',
                'readed_clone',
                retry_action='do_clone_paxton',
                retry_kind='write_retry'
            )
        failed = [str(i) for i in range(4, 8) if read_blocks.get(i, '') != blocks.get(i, '')]
        if failed:
            return self._fail(
                'Verify failed:\nblock {} differs.\nAdjust and retry.'.format(', '.join(failed)),
                'readed_clone',
                retry_action='do_clone_paxton',
                retry_kind='write_retry'
            )
        count = int(self.host.get_var('clone_count', '0') or '0') + 1
        self.host.set_var('clone_count', str(count))
        return {'status': 'done'}

    def do_clone_em4102(self):
        self.host.set_var('flow', 'down')
        em_id = self.host.get_var('em_id', '')
        if not re.match(r'^[0-9A-Fa-f]{10}$', em_id or ''):
            return self._fail('No valid EM4102 ID.\nRead a Paxton fob.', 'menu')
        self._toast('Writing T5577...')
        ok, out = self._pm3('lf em 410x clone --id {}'.format(em_id), CLONE_TIMEOUT)
        if not ok:
            return self._fail(
                'EM4102 write failed.\nReposition T5577.',
                'readed_down',
                retry_action='do_clone_em4102',
                retry_kind='write_retry'
            )

        ok2, out2 = self._pm3('lf em 410x read', READ_TIMEOUT)
        if not ok2 or not out2:
            return self._fail(
                'Write verification failed.\nReposition T5577.',
                'readed_down',
                retry_action='do_clone_em4102',
                retry_kind='write_retry'
            )
        found = None
        for line in out2.splitlines():
            m = re.search(r'EM\s?410x\s+ID[\s:]*([0-9A-Fa-f]{10})', line)
            if m:
                found = m.group(1).upper()
                break
        if not found:
            return self._fail(
                'Write verification failed.\nReposition T5577.',
                'readed_down',
                retry_action='do_clone_em4102',
                retry_kind='write_retry'
            )
        if found != em_id.upper():
            return self._fail(
                'ID mismatch!\nExp:   {}\nFound: {}'.format(em_id.upper(), found),
                'readed_down',
                retry_action='do_clone_em4102',
                retry_kind='write_retry'
            )
        count = int(self.host.get_var('down_count', '0') or '0') + 1
        self.host.set_var('down_count', str(count))
        return {'status': 'done'}

    def _set_txt_charset(self):
        mode = 'ABC'
        if self._txt is not None:
            try:
                mode = self._txt.getCharsetName()
            except Exception:
                mode = 'ABC'
        self.host.set_var('txt_charset', mode)
        return mode

    def show_txt_input_log(self):
        if FreeTextInput is None:
            self._txt = None
            self._txt_mode = None
            self._set_txt_charset()
            self._clear_mode_label()
            return {'status': 'ok'}

        canvas = self.host.getCanvas()
        self._txt = FreeTextInput(
            canvas,
            label='Name:',
            max_length=20,
            y_offset=180,
            text_color='#0000FF'
        )
        self._txt_mode = 'log'
        self._txt.show()
        self._update_mode_label()
        return {'status': 'ok'}

    def show_txt_input_find(self):
        if FreeTextInput is None:
            self._txt = None
            self._txt_mode = None
            self._set_txt_charset()
            self._clear_mode_label()
            return {'status': 'ok'}

        canvas = self.host.getCanvas()
        self._txt = FreeTextInput(
            canvas,
            label='Find:',
            max_length=20,
            y_offset=170,
            text_color='#FF0000'
        )
        self._txt_mode = 'find'
        self._txt.show()
        self._update_mode_label()
        return {'status': 'ok'}

    def txt_roll_up(self):
        if self._txt is not None:
            try:
                self._txt.rollUp()
                self._update_mode_label()
            except Exception:
                pass

    def txt_roll_down(self):
        if self._txt is not None:
            try:
                self._txt.rollDown()
                self._update_mode_label()
            except Exception:
                pass

    def txt_move_left(self):
        if self._txt is not None:
            try:
                self._txt.moveLeft()
            except Exception:
                pass

    def txt_move_right(self):
        if self._txt is not None:
            try:
                self._txt.moveRight()
            except Exception:
                pass

    def txt_next_charset(self):
        if self._txt is not None:
            try:
                self._txt.nextCharset()
                self._update_mode_label()
            except Exception:
                pass

    def do_capture_log_name(self):
        name = ''
        if self._txt is not None:
            try:
                name = self._txt.getValue().strip()
                self._txt.hide()
            except Exception:
                pass
            finally:
                self._txt = None
                self._txt_mode = None
                self._clear_mode_label()
                self._set_txt_charset()
        else:
            name = (self.host.get_input() or '').strip()

        return self._do_save_log_with_name(name)

    def do_capture_find(self):
        query = ''
        if self._txt is not None:
            try:
                query = self._txt.getValue().strip()
                self._txt.hide()
            except Exception:
                pass
            finally:
                self._txt = None
                self._txt_mode = None
                self._clear_mode_label()
                self._set_txt_charset()
        else:
            query = (self.host.get_input() or '').strip()

        if query.upper() == 'A':
            query = ''

        return self._do_find_with_query(query)

    def _do_save_log_with_name(self, name):
        name = (name or '').strip()
        if not name:
            return self._fail('Name cannot be\nempty.', 'log_name')
        if len(name) < 2:
            return self._fail('Name too short.\nMin 2 chars.', 'log_name')
        if _log_name_exists(name):
            return self._fail('Name already exists:\n{}'.format(name), 'log_name')
        blocks = self._get_blocks()
        if not self._blocks_ok(blocks):
            return self._fail('No valid block data.', 'menu')
        em_id = self.host.get_var('em_id', '')
        variant = self.host.get_var('tag_variant', '')
        uid = self.host.get_var('uid', '')
        if not _log_save(name, blocks, em_id, variant, uid):
            return self._fail('Could not save log.\nWrite failed.', 'log_name',
                              retry_action='do_capture_log_name', retry_kind='logname')
        dump = _dump_save(blocks, uid, variant)
        self.host.set_var('saved_name', name)
        self.host.set_var('dump_line', 'Dump entry saved' if dump else 'Dump NOT saved')
        return {'status': 'done'}

    def _do_find_with_query(self, query):
        q = (query or '').strip()
        entries = _log_paxton_entries()
        if not entries:
            return self._fail('No saved Paxton entries in the log.', 'menu')
        if not q:
            matches = entries
        else:
            low = q.lower()
            exact = [e for e in entries if e['name'].lower() == low]
            matches = exact or [e for e in entries if low in e['name'].lower()]
        if not matches:
            return self._fail('Not found:\n{}'.format(q), 'find_name')
        if len(matches) == 1:
            self._pick = matches
            self._load_entry(matches[0])
            return {'status': 'loaded'}
        self._pick = matches
        self._pick_idx = 0
        self._pick_refresh()
        return {'status': 'pick'}

    def do_back_from_write(self):
        if self.host.get_var('src_name', ''):
            return {'status': 'loaded'}
        flow = self.host.get_var('flow', 'clone')
        return {'status': 'read_down' if flow == 'down' else 'read_clone'}

    def do_back_to_result(self):
        flow = self.host.get_var('flow', 'clone')
        return {'status': 'down' if flow == 'down' else 'clone'}

    def do_error_retry(self):
        retry = self.host.get_var('err_retry', '')
        retry_kind = self.host.get_var('err_retry_kind', 'normal')

        if retry_kind == 'readwrite':
            self._clear_read_write_cache()

        if not retry:
            return {'status': self.host.get_var('err_return', '') or 'menu'}

        fn = getattr(self, retry, None)
        if not callable(fn):
            return {'status': self.host.get_var('err_return', '') or 'menu'}

        self.host.set_var('err_retry', '')
        self.host.set_var('err_retry_kind', 'normal')

        try:
            result = fn()
        except Exception:
            return {'status': self.host.get_var('err_return', '') or 'menu'}

        return self._resolve_retry_result(result)

    def _resolve_retry_result(self, result):
        """Translate a retried action's raw status ('found'/'done'/'error')
        into an explicit status the `error` screen's transitions can match.
        A bare 'found'/'done' is ambiguous on its own (both read_clone and
        read_down report 'found', both write actions report 'done'), so
        disambiguate using the current flow."""
        status = (result or {}).get('status', '')
        if status == 'error':
            # fn() already called self._fail(...) again, which refreshed
            # error_msg / err_retry / err_retry_kind for another attempt.
            return {'status': 'error'}
        flow = self.host.get_var('flow', 'clone')
        if status == 'found':
            return {'status': 'readed_down' if flow == 'down' else 'readed_clone'}
        if status == 'done':
            return {'status': 'down_ok' if flow == 'down' else 'clone_ok'}
        return result or {'status': self.host.get_var('err_return', '') or 'menu'}

    def _load_entry(self, e):
        blocks = e['blocks']
        variant, hex_id = self._detect_paxton(blocks)
        if not hex_id:
            hex_id = e.get('em_id', '')
            variant = e.get('variant', '') or variant
        self._store(blocks, e.get('uid', ''), variant, hex_id, e['name'], 'Log: {}'.format(e['name']))

    def _pick_refresh(self):
        n = len(self._pick)
        idx = self._pick_idx
        start = max(0, min(idx - PICK_ROWS // 2, n - PICK_ROWS))
        rows = []
        for i in range(start, min(n, start + PICK_ROWS)):
            nm = self._pick[i]['name'][:14]
            rows.append('> {} <'.format(nm) if i == idx else '  {}  '.format(nm))
        self.host.set_var('pick_pos', '{} / {}'.format(idx + 1, n))
        self.host.set_var('pick_view', '\n'.join(rows))

    def do_find(self):
        query = (self.host.get_input() or '').strip()
        entries = _log_paxton_entries()
        if not entries:
            return self._fail('No saved Paxton entries in the log.', 'menu')
        if not query:
            matches = entries
        else:
            q = query.lower()
            exact = [e for e in entries if e['name'].lower() == q]
            matches = exact or [e for e in entries if q in e['name'].lower()]
        if not matches:
            return self._fail('Not found:\n{}'.format(query), 'find_name')
        if len(matches) == 1:
            self._pick = matches
            self._load_entry(matches[0])
            return {'status': 'loaded'}
        self._pick = matches
        self._pick_idx = 0
        self._pick_refresh()
        return {'status': 'pick'}

    def do_pick_up(self):
        if self._pick:
            self._pick_idx = (self._pick_idx - 1) % len(self._pick)
            self._pick_refresh()
        return {'status': 'stay'}

    def do_pick_down(self):
        if self._pick:
            self._pick_idx = (self._pick_idx + 1) % len(self._pick)
            self._pick_refresh()
        return {'status': 'stay'}

    def do_pick_select(self):
        if not self._pick:
            return self._fail('Nothing selected.', 'find_name')
        self._load_entry(self._pick[self._pick_idx])
        return {'status': 'loaded'}

    def do_loaded_back(self):
        return {'status': 'pick' if len(self._pick) > 1 else 'find'}

    def do_load_clone(self):
        self.host.set_var('flow', 'clone')
        return {'status': 'clone'}

    def do_load_down(self):
        self.host.set_var('flow', 'down')
        return {'status': 'down'}