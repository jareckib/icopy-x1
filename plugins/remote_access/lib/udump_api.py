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
"""Authenticated UDUMP API. Requires TLS; independent of mirror PIN."""
import hmac
import collections
import re
import json
import os
import ssl
import socket
import threading
import time
from contextlib import contextmanager, nullcontext
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
from udump_store import Store
from battery_guard import BatteryBlocked


class ExpertLease:
    def __init__(self, idle=120, lifetime=1800):
        self.lock = threading.RLock()
        self.idle = idle
        self.end = time.monotonic() + lifetime
        self.last = None
        self.pair_end = time.monotonic() + max(idle, 300)
        self.revoked = False

    def valid(self, touch=False):
        with self.lock:
            now = time.monotonic()
            if self.revoked or now >= self.end or (now >= self.pair_end if self.last is None else now - self.last >= self.idle):
                self.revoked = True
                return False
            if touch: self.last = now
            return True

    @contextmanager
    def mutation(self):
        # Serialize a short filesystem mutation with revocation, never hold
        # this lock during network reads or a complete upload.
        with self.lock:
            if not self.valid(touch=True):
                raise PermissionError('Session expired')
            yield

    def revoke(self):
        with self.lock: self.revoked = True


def handler(store, secret, lease=None, battery=None, pin=None, mirror=None):
    if len(secret) < 32:
        raise ValueError('File access requires a strong secret')
    attempts = collections.deque()
    pin_lock = threading.Lock()
    key_lock = threading.Lock()
    last_key = [0.0]
    if pin is not None and not re.fullmatch(r'[0-9]{6}', pin):
        raise ValueError('Invalid PIN')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def setup(self):
            super().setup()
            self.connection.settimeout(30)
        def battery_headers(self):
            if battery is not None:
                level, charging = battery.header()
                self.send_header('X-Battery-Level', level)
                self.send_header('X-Battery-Charging', charging)
                self.send_header('X-Battery-Minimum', '30' if lease is not None else ('10' if self.command == 'GET' else '15'))
        def reply(self, status, data):
            body = json.dumps(data, ensure_ascii=True).encode('ascii')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            if status != 401: self.battery_headers()
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def authorized(self):
            if not hmac.compare_digest(self.headers.get('Authorization','').encode('utf-8'), ('Bearer '+secret).encode('utf-8')):
                self.reply(401, {'error':'unauthorized'})
                return False
            if lease is not None and not lease.valid(touch=True):
                self.reply(401, {'error':'expert_expired'})
                return False
            return True
        def pair(self):
            if pin is None:
                return self.reply(404, {'error':'not_found'})
            if self.headers.get('Content-Length') != '6':
                return self.reply(400, {'error':'invalid_pin'})
            self.connection.settimeout(5)
            supplied = self.rfile.read(6)
            with pin_lock:
                now = time.monotonic()
                while attempts and now - attempts[0] >= 60:
                    attempts.popleft()
                if len(attempts) >= 5:
                    return self.reply(429, {'error':'retry'})
                if not hmac.compare_digest(supplied, pin.encode('ascii')):
                    attempts.append(now)
                    return self.reply(403, {'error':'invalid_pin'})
                if lease is not None and not lease.valid():
                    return self.reply(401, {'error':'expert_expired'})
                if lease is not None and battery is not None:
                    try: battery.require_write(expert=True)
                    except BatteryBlocked: return self.reply(423, {'error':'battery'})
                return self.reply(200, {'token':secret})
        def mirror_request(self, method):
            if mirror is None or lease is not None:
                return self.reply(404, {'error':'mirror_unavailable'})
            source, dispatcher = mirror
            if method == 'GET' and self.path == '/api/info':
                return self.reply(200, {'width':240,'height':240,'pixel_format':'rgb565le','compression':'zlib','keys_enabled':callable(dispatcher),'srw':True})
            if method == 'GET' and self.path == '/api/frame':
                if battery is not None and battery.pause_frames():
                    return self.reply(423, {'error':'battery'})
                try: packed, digest = source.packed()
                except (OSError, ValueError): return self.reply(503, {'error':'frame'})
                tag = '"' + digest + '"'
                unchanged = self.headers.get('If-None-Match') == tag
                self.send_response(304 if unchanged else 200)
                self.battery_headers()
                self.send_header('ETag',tag)
                self.send_header('Cache-Control','no-store')
                self.send_header('Content-Type','application/octet-stream')
                self.send_header('Content-Length',str(0 if unchanged else len(packed)))
                self.end_headers()
                if not unchanged: self.wfile.write(packed)
                return
            if method == 'POST' and self.path == '/api/key':
                if not callable(dispatcher): return self.reply(503, {'error':'keys'})
                if battery is not None and battery.pause_frames(): return self.reply(423, {'error':'battery'})
                try:
                    n = int(self.headers.get('Content-Length','0'))
                    if not 1 <= n <= 16: raise ValueError()
                    self.connection.settimeout(2)
                    key = self.rfile.read(n).decode('ascii')
                    if key not in ('UP','DOWN','LEFT','RIGHT','OK','M1','M2','PWR','SRW'): raise ValueError()
                except (ValueError, UnicodeError, OSError): return self.reply(400, {'error':'key'})
                with key_lock:
                    now = time.monotonic()
                    if now - last_key[0] < .05: return self.reply(429, {'error':'retry'})
                    last_key[0] = now
                    try: dispatcher('ALL' if key == 'SRW' else key)
                    except Exception: return self.reply(503, {'error':'keys'})
                return self.reply(200, {'ok':True})
            return self.reply(404, {'error':'not_found'})
        def dispatch(self, method):
            if method == 'POST' and self.path == '/pair': return self.pair()
            if not self.authorized(): return
            if self.path.startswith('/api/'): return self.mirror_request(method)
            try:
                u = urlsplit(self.path)
                q = parse_qs(u.query, keep_blank_values=True, strict_parsing=True)
                if any(len(v)!=1 for v in q.values()): raise ValueError('ambiguous query')
                p = q.get('path',[''])[0]
                if method=='GET' and u.path=='/files/info':
                    return self.reply(200, {'expert': lease is not None})
                if method=='POST' and u.path=='/files/close':
                    if lease is not None: lease.revoke()
                    return self.reply(200, {'ok':True})
                if battery is not None and lease is not None:
                    battery.require_write(expert=True)
                if battery is not None and method=='GET' and u.path=='/files/download' and battery.pause_frames():
                    raise BatteryBlocked('Battery critical')
                if method=='GET' and u.path=='/files/list':
                    return self.reply(200, {'entries':store.list(p), 'expert': lease is not None})
                if method=='GET' and u.path=='/files/download':
                    with store.download(p) as (stream, size):
                        self.send_response(200)
                        self.send_header('Content-Type','application/octet-stream')
                        self.battery_headers()
                        self.send_header('Cache-Control','no-store')
                        self.send_header('Content-Length',str(size))
                        self.end_headers()
                        # Keep the body consistent with the advertised size, even
                        # when another process appends to or truncates the file.
                        try:
                            remaining = size
                            while remaining:
                                if (battery is not None and (battery.pause_frames() or (lease is not None and (battery.sample()[0] is None or battery.sample()[0] < 30)))) or (lease is not None and not lease.valid(touch=True)):
                                    self.close_connection = True
                                    break
                                chunk = stream.read(min(remaining, 65536))
                                if not chunk:
                                    self.close_connection = True
                                    break
                                self.wfile.write(chunk)
                                remaining -= len(chunk)
                        except OSError:
                            self.close_connection = True
                    return
                if battery is not None and method in ('PUT','POST','DELETE'):
                    battery.require_write(expert=lease is not None)
                if method=='PUT' and u.path=='/files/upload':
                    if self.headers.get('Transfer-Encoding') or len(self.headers.get_all('Content-Length',[]))!=1:
                        raise ValueError('length required')
                    size=int(self.headers['Content-Length'])
                    if not 0<=size<=4294967295: raise ValueError('invalid size')
                    overwrite=q.get('overwrite',['0'])[0]
                    if overwrite not in ('0','1'): raise ValueError('invalid overwrite')
                    if lease is None and battery is None:
                        store.upload(p,self.rfile,size,overwrite=='1')
                    else:
                        def check_write():
                            if battery is not None: battery.require_write(expert=lease is not None)
                            return lease is None or lease.valid()
                        @contextmanager
                        def commit():
                            with (lease.mutation() if lease is not None else nullcontext()):
                                if battery is not None: battery.require_write(expert=lease is not None)
                                yield
                        class CheckedStream:
                            def read(inner, n):
                                if battery is not None: battery.require_write(expert=lease is not None)
                                if lease is not None and not lease.valid(touch=True): raise PermissionError('Session expired')
                                return self.rfile.read(n)
                        store.upload(p,CheckedStream(),size,overwrite=='1',check_write,commit_guard=commit)
                else:
                    with (lease.mutation() if lease is not None else nullcontext()):
                        if battery is not None: battery.require_write(expert=lease is not None)
                        if method=='POST' and u.path=='/files/mkdir': store.mkdir(p)
                        elif method=='POST' and u.path=='/files/rename': store.rename(p,q['destination'][0])
                        elif method=='DELETE' and u.path=='/files/delete': store.delete(p)
                        elif method=='POST' and u.path=='/files/chmod' and lease is not None:
                            mode=q.get('mode',[''])[0]
                            if len(mode)!=3 or any(c not in '01234567' for c in mode): raise ValueError('invalid mode')
                            store.chmod(p,int(mode,8))
                        else: return self.reply(404,{'error':'not_found'})
                return self.reply(200,{'ok':True})
            except (ValueError,KeyError): self.reply(400,{'error':'invalid_request'})
            except FileExistsError: self.reply(409,{'error':'exists'})
            except FileNotFoundError: self.reply(404,{'error':'not_found'})
            except BatteryBlocked: self.reply(423,{'error':'battery_guard','minimum':30 if lease is not None else (10 if method=='GET' else 15)})
            except PermissionError:
                if lease is not None and not lease.valid(): self.reply(401,{'error':'expert_expired'})
                else: self.reply(403,{'error':'denied'})
            except (OSError,NotImplementedError): self.reply(422,{'error':'operation_failed'})
        def do_GET(self): self.dispatch('GET')
        def do_PUT(self): self.dispatch('PUT')
        def do_POST(self): self.dispatch('POST')
        def do_DELETE(self): self.dispatch('DELETE')
    return Handler


class TLSServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, request_handler, context):
        self.context = context
        self.active = set()
        self.active_lock = threading.Lock()
        self.stopping = False
        super().__init__(address, request_handler)

    def process_request(self, request, client_address):
        with self.active_lock:
            if self.stopping:
                request.close()
                return
            self.active.add(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self.active_lock:
                self.active.discard(request)
            request.close()
            raise

    def process_request_thread(self, request, client_address):
        wrapped = None
        try:
            # Wrap without handshaking so a stalled client cannot block accept().
            with self.active_lock:
                if self.stopping:
                    return
                request.settimeout(10)
                wrapped = self.context.wrap_socket(request, server_side=True, do_handshake_on_connect=False)
                self.active.discard(request)
                self.active.add(wrapped)
            wrapped.do_handshake()
            self.finish_request(wrapped, client_address)
        except (OSError, ValueError):
            pass
        finally:
            with self.active_lock:
                self.active.discard(request)
                self.active.discard(wrapped)
            self.shutdown_request(wrapped if wrapped is not None else request)

    def server_close(self):
        with self.active_lock:
            self.stopping = True
            for conn in self.active:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()
        super().server_close()


def create_server(address, store, secret, certfile, keyfile, lease=None, battery=None, pin=None, mirror=None):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile,keyfile)
    return TLSServer(address, handler(store,secret,lease,battery,pin,mirror), context)
