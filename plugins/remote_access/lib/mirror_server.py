#!/usr/bin/env python3
# -*- coding: utf-8 -*-
##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://www.lab401.com)
#
# Copyright (c) 2026: ETOILE401 SAS & https://github.com/quantum-x/
# Copyright (c) 2026: jareckib
#
# This software is licensed under the PolyForm Noncommercial License 1.0.0.
# You may not use this software for commercial purposes.
# A copy of the license is available at:
# https://polyformproject.org/licenses/noncommercial/1.0.0
# This entire header "Required Notice" must remain in place.
##########################################################################
"""iCopy-XS Wi-Fi screen mirror (Python 3.8 standard library).

HTTP endpoints:
  GET /api/info   -> width/height/frame mode and keys availability
  GET /api/frame  -> zlib-compressed, little-endian RGB565 (240*240*2 bytes)
  POST /api/key   -> ASCII key name; Lab401 dispatcher in main process
GET /api/auth reports whether PIN authentication is required.
Protected requests require a six-digit PIN in X-Mirror-Token when enabled.
Without PIN, any reachable LAN client can view the screen, but cannot send keys.
"""
import argparse
import hmac
import hashlib
import json
import os
import re
import struct
import subprocess
import threading
import collections
import time
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WIDTH = 240
HEIGHT = 240
DEFAULT_PORT = 8765
WEB_PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mirror_web.html')
FRAME_BYTES = WIDTH * HEIGHT * 2
KEYS = {
    'UP': 'Up', 'DOWN': 'Down', 'LEFT': 'Left', 'RIGHT': 'Right',
    'OK': 'Return', 'M1': 'F1', 'M2': 'F2', 'PWR': 'Escape', 'SRW': 'F3',
}


def find_framebuffer(path=None):
    candidates = [path] if path else ['/dev/fb_st7789v', '/dev/fb1', '/dev/fb0']
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        base = '/sys/class/graphics/' + os.path.basename(os.path.realpath(candidate))
        try:
            with open(base + '/virtual_size') as f:
                width, height = map(int, f.read().strip().split(','))
            with open(base + '/bits_per_pixel') as f:
                bpp = int(f.read())
            with open(base + '/stride') as f:
                stride = int(f.read())
            if (width, height) == (WIDTH, HEIGHT) and bpp in (16, 32) and stride >= width * (bpp // 8):
                return candidate, width, bpp, stride
        except (OSError, ValueError):
            continue
    raise IOError('Framebuffer unavailable')


def _rgb88832_to_rgb565(data, width=WIDTH, height=HEIGHT, stride=None):
    """Convert standard little-endian XRGB8888 framebuffer to RGB565."""
    if stride is None:
        stride = width * 4
    result = bytearray(width * height * 2)
    out = 0
    for y in range(height):
        base = y * stride
        for x in range(width):
            at = base + x * 4
            b, g, r = data[at], data[at + 1], data[at + 2]
            value = ((r & 0xf8) << 8) | ((g & 0xfc) << 3) | (b >> 3)
            result[out] = value & 0xff
            result[out + 1] = (value >> 8) & 0xff
            out += 2
    return bytes(result)


class FrameSource(object):
    def __init__(self, path='/dev/fb_st7789v', width=WIDTH, height=HEIGHT,
                 bpp=None, source_width=None, stride=None):
        self.path = path
        self.width = width
        self.height = height
        self.source_width = source_width or width
        self.bpp = bpp or 16
        self.stride = stride or self.source_width * (self.bpp // 8)
        if self.bpp not in (16, 32):
            raise ValueError('Unsupported framebuffer bpp: %d' % self.bpp)
        if self.source_width < width:
            raise ValueError('Framebuffer narrower than screen')
        self._lock = threading.Lock()
        self._last_time = 0.0
        self._last_frame = None
        self._packed_raw = None
        self._packed = None
        self._pack_lock = threading.Lock()

    def packed(self):
        pixels = self.frame()
        with self._pack_lock:
            if pixels != self._packed_raw:
                self._packed_raw = pixels
                self._packed = zlib.compress(pixels, 2)
            return self._packed, hashlib.sha256(pixels).hexdigest()

    def frame(self):
        needed = (self.height - 1) * self.stride + self.width * (self.bpp // 8)
        with self._lock:
            now = time.monotonic()
            if self._last_frame is not None and now - self._last_time < 0.15:
                return self._last_frame
            with open(self.path, 'rb', buffering=0) as handle:
                data = handle.read(max(needed, self.stride * self.height))
        if len(data) < needed:
            raise IOError('Framebuffer too short: %d of %d bytes' % (len(data), needed))
        if self.bpp == 32:
            result = _rgb88832_to_rgb565(data, self.width, self.height, self.stride)
        elif self.stride == self.width * 2:
            result = data[:FRAME_BYTES]
        else:
            result = b''.join(data[y*self.stride:y*self.stride+self.width*2]
                              for y in range(self.height))
        self._last_frame = result
        self._last_time = time.monotonic()
        return result


def make_handler(source, token, key_backend='none', display=':0', dispatch=None, battery=None):
    failures = collections.deque()
    auth_lock = threading.Lock()
    key_lock = threading.Lock()
    recent_keys = collections.deque()
    keys_enabled = bool(token and (callable(dispatch) or key_backend == 'xdotool'))
    class MirrorHandler(BaseHTTPRequestHandler):
        server_version = 'iCopyMirror/0.2'
        protocol_version = 'HTTP/1.0'

        def log_message(self, fmt, *args):
            # Deliberately no request logs or token exposure.
            return

        def _respond(self, status, payload=b'', mime='text/plain', etag=None):
            self.send_response(status)
            self.send_header('Content-Type', mime)
            if battery is not None:
                level, charging = battery.header()
                self.send_header('X-Battery-Level', level)
                self.send_header('X-Battery-Charging', charging)
            if etag:
                self.send_header('ETag', etag)
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (OSError, BrokenPipeError):
                pass

        def _authenticated(self):
            if not token:
                return True
            supplied = self.headers.get('X-Mirror-Token', '')
            with auth_lock:
                now = time.monotonic()
                while failures and now - failures[0] >= 60:
                    failures.popleft()
                if len(failures) >= 5:
                    self._respond(429, b'Try again later')
                    return False
                if not hmac.compare_digest(supplied.encode('utf-8'), token.encode('ascii')):
                    failures.append(now)
                    self._respond(403, b'Forbidden')
                    return False
            return True

        def do_GET(self):
            if self.path == '/':
                try:
                    with open(WEB_PAGE, 'rb') as handle:
                        page = handle.read()
                except OSError:
                    return self._respond(503, b'Viewer not found')
                return self._respond(200, page, 'text/html; charset=utf-8')
            if self.path == '/api/auth':
                return self._respond(200, json.dumps({'pin_required': bool(token)}).encode('ascii'), 'application/json')
            if not self._authenticated():
                return
            if self.path == '/api/info':
                data = json.dumps({'width': WIDTH, 'height': HEIGHT,
                    'pixel_format': 'rgb565le', 'compression': 'zlib',
                    'keys_enabled': keys_enabled,
                    'srw': True}).encode('ascii')
                return self._respond(200, data, 'application/json')
            if self.path == '/api/frame':
                if battery is not None and battery.pause_frames():
                    return self._respond(423, b'Battery critical; mirror paused')
                try:
                    packed, digest = source.packed()
                    etag = '"' + digest + '"'
                    if self.headers.get('If-None-Match') == etag:
                        return self._respond(304, etag=etag)
                except (OSError, ValueError) as exc:
                    return self._respond(503, b'Screen source not available')
                return self._respond(200, packed, 'application/octet-stream', etag=etag)
            return self._respond(404, b'Not found')

        def do_POST(self):
            if not self._authenticated():
                return
            if self.path != '/api/key':
                return self._respond(404, b'Not found')
            try:
                size = int(self.headers.get('Content-Length', '-1'))
            except ValueError:
                size = -1
            if not 1 <= size <= 16:
                return self._respond(400, b'Invalid body')
            try:
                self.connection.settimeout(2)
                raw = self.rfile.read(size)
                if len(raw) != size:
                    return self._respond(400, b'Invalid body')
                key = raw.decode('ascii').strip().upper()
            except (UnicodeError, OSError):
                return self._respond(400, b'Invalid body')
            if key not in KEYS:
                return self._respond(400, b'Invalid key')
            if not keys_enabled:
                return self._respond(501, b'Remote keys not available')
            # Reject concurrent presses rather than queueing stale commands.
            if not key_lock.acquire(False):
                return self._respond(503, b'Key busy')
            try:
                now = time.monotonic()
                while recent_keys and now - recent_keys[0] >= 1:
                    recent_keys.popleft()
                if len(recent_keys) >= 20:
                    return self._respond(429, b'Too many keys')
                recent_keys.append(now)
                if callable(dispatch):
                    dispatch('ALL' if key == 'SRW' else key)
                else:
                    env = os.environ.copy()
                    env['DISPLAY'] = display
                    subprocess.run(['xdotool', 'key', '--clearmodifiers', KEYS[key]],
                                   check=True, timeout=2, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                return self._respond(503, b'Key injection failed')
            finally:
                key_lock.release()
            self._respond(200, b'OK')

    return MirrorHandler


class ReusableHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class MirrorSession:
    """One background HTTP server inside the firmware process, not the UI activity."""
    def __init__(self, source, token, host, port, dispatcher, battery=None):
        if token and not re.fullmatch(r'[0-9]{6}', token):
            raise ValueError('Invalid mirror token')
        source.frame()
        self._active = threading.Event()
        self._active.set()
        self._gate = threading.Lock()
        self._dispatcher = dispatcher
        self.address = host
        self.token = token
        self.server = ReusableHTTPServer((host, port), make_handler(
            source, token, dispatch=self._dispatch if callable(dispatcher) else None, battery=battery))
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs={'poll_interval': 0.1}, daemon=True, name='RemoteAccessMirror')
        try:
            self.thread.start()
        except BaseException:
            self._active.clear()
            self.server.server_close()
            raise

    def _dispatch(self, key):
        with self._gate:
            if not self._active.is_set():
                raise RuntimeError('Mirror stopped')
            self._dispatcher(key)

    @property
    def running(self):
        return self._active.is_set() and self.thread.is_alive()

    def stop(self):
        if not self._active.is_set():
            return
        self._active.clear()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def open_session(token, host, port, dispatcher, battery=None):
    path, width, bpp, stride = find_framebuffer()
    source = FrameSource(path, bpp=bpp, source_width=width, stride=stride)
    return MirrorSession(source, token, host, port, dispatcher, battery)


def serve(source, token, host='0.0.0.0', port=DEFAULT_PORT,
          key_backend='none', display=':0'):
    if token and not re.fullmatch(r'[0-9]{6}', token):
        raise ValueError('Invalid mirror token')
    server = ReusableHTTPServer((host, port), make_handler(source, token,
                                                          key_backend, display))
    try:
        server.serve_forever(poll_interval=0.3)
    finally:
        server.server_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='iCopy-XS Wi-Fi mirror server')
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--token-file', required=True)
    parser.add_argument('--fb-file', default=None)
    parser.add_argument('--bpp', type=int, choices=(16, 32), default=None)
    parser.add_argument('--source-width', type=int, default=None)
    parser.add_argument('--key-backend', choices=('none', 'xdotool'), default='none')
    parser.add_argument('--display', default=':0')
    args = parser.parse_args(argv)
    with open(args.token_file, 'r') as handle:
        token = handle.read().strip()
    path, width, bpp, stride = find_framebuffer(args.fb_file)
    source = FrameSource(path, bpp=args.bpp or bpp, source_width=args.source_width or width, stride=stride)
    # Detect broken/no framebuffer before accepting any client.
    source.frame()
    serve(source, token, args.host, args.port, args.key_backend, args.display)


if __name__ == '__main__':
    main()
