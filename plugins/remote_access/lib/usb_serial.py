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
"""Explicit, PIN-protected point-to-point USB mirror. No Ethernet or mounts."""
import os
import glob
import hmac
import struct
import time
import select
import threading
import termios
import tty
import fcntl
import secrets
import socket
from usb_network import USBNetwork

DEVICE = '/dev/ttyGS0'
KEYS = ('UP', 'DOWN', 'LEFT', 'RIGHT', 'OK', 'M1', 'M2', 'PWR', 'ALL')
MAX_FRAME = 131072


def packet(kind, data=b''):
    return b'RA' + struct.pack('>BI', kind, len(data)) + data


class Protocol:
    def __init__(self, pin, source, dispatch, battery, clock=time.monotonic):
        self.pin, self.source, self.dispatch, self.battery = pin, source, dispatch, battery
        self.clock = clock
        self.auth = False
        self.session = b''
        self.last = 0
        self.failures = []
        self.last_key = -1
        self.buffer = bytearray()
        self.ssh = None
        self._tool_lock = threading.Lock()
        self._open_ssh_requested = False
        self._ssh_open_status = "idle"

    def request_ssh_terminal(self):
        with self._tool_lock:
            if self.auth and self.clock()-self.last <= 30:
                self._open_ssh_requested = True
                self._ssh_open_status = "pending"
                return True
            return False

    def ssh_open_status(self):
        with self._tool_lock:
            return self._ssh_open_status

    def _clear_tool_request(self):
        with self._tool_lock:
            self._open_ssh_requested = False
            self._ssh_open_status = "idle"

    def close_ssh(self):
        if self.ssh is not None:
            self.ssh.close()
            self.ssh = None

    def reset(self):
        self.close_ssh()
        self.auth = False
        self.session = b''
        self.buffer.clear()
        self._clear_tool_request()

    def feed(self, data):
        self.buffer.extend(data)
        replies = []
        while len(self.buffer) >= 7:
            if self.buffer[:2] != b'RA':
                del self.buffer[0]
                continue
            kind, n = struct.unpack('>BI', self.buffer[2:7])
            if n > (4112 if kind == 11 else 17):
                self.reset()
                break
            if len(self.buffer) < 7+n:
                break
            payload = bytes(self.buffer[7:7+n]); del self.buffer[:7+n]
            reply = self.handle(kind, payload)
            if reply is not None:
                replies.append(reply)
        return replies

    def handle(self, kind, data):
        now = self.clock()
        if kind == 4:
            self.close_ssh()
            self.auth = False
            self.session = b''
            self._clear_tool_request()
            self.failures = [t for t in self.failures if now-t < 60]
            if len(self.failures) >= 5:
                return packet(9, b'PIN locked for 60s')
            if not hmac.compare_digest(data, self.pin.encode('ascii')):
                self.failures.append(now)
                return packet(9, b'Wrong PIN')
            self.auth = True; self.last = now
            self.session = secrets.token_bytes(16)
            return packet(5, struct.pack('>HH', 240, 240) + self.session)
        if not self.auth or now-self.last > 30:
            self.reset()
            return packet(9, b'Reconnect with PIN')
        if len(data) < 16 or not hmac.compare_digest(data[:16], self.session):
            return packet(9, b'Invalid session')
        data = data[16:]
        self.last = now
        # USB-authenticated relay, restricted to the device's own SSH server.
        # SSH itself still authenticates the Linux user and verifies the host key.
        if kind == 13 and not data:
            with self._tool_lock:
                requested = self._open_ssh_requested
                if requested:
                    self._ssh_open_status = "received"
            return packet(13, b'\x01' if requested else b'\x00')
        if kind == 14 and not data:
            with self._tool_lock:
                if self._open_ssh_requested:
                    self._open_ssh_requested = False
                    self._ssh_open_status = "opened"
            return packet(7)
        if kind == 10 and not data:
            self.close_ssh()
            try:
                self.ssh = socket.create_connection(('127.0.0.1', 22), timeout=2)
                self.ssh.settimeout(0.5)
                return packet(7)
            except OSError:
                self.close_ssh()
                return packet(9, b'Local SSH unavailable')
        if kind == 12 and not data:
            self.close_ssh()
            return packet(7)
        if kind == 11:
            if self.ssh is None:
                return packet(11, b'\x01')
            try:
                if data:
                    self.ssh.sendall(data)
                if select.select([self.ssh], [], [], 0)[0]:
                    response = self.ssh.recv(16384)
                    if not response:
                        self.close_ssh()
                        return packet(11, b'\x01')
                    return packet(11, b'\x00' + response)
                return packet(11, b'\x00')
            except OSError:
                self.close_ssh()
                return packet(11, b'\x01')
        if kind == 8 and not data:
            level, charging = self.battery.header()
            return packet(8, (level + ',' + charging).encode('ascii'))
        if kind == 3 and not data:
            if self.battery.pause_frames():
                return packet(1)
            packed, _ = self.source.packed()
            if len(packed) > MAX_FRAME:
                return packet(9, b'Frame too large')
            return packet(1, packed)
        if kind == 2 and len(data) == 1 and 1 <= data[0] <= len(KEYS):
            if not self.battery.pause_frames() and now-self.last_key >= .08:
                self.dispatch(KEYS[data[0]-1]); self.last_key = now
            return packet(7)
        if kind == 6 and not data:
            self.reset()
            return packet(7)
        return packet(9, b'Invalid request')


def port_busy(path=DEVICE):
    # Check the stock service even if it is in this very process.
    target = os.path.realpath(path)
    for fd in glob.glob('/proc/[0-9]*/fd/*'):
        try:
            if os.path.realpath(os.readlink(fd)) == target:
                return True
        except OSError:
            continue
    return False


class USBSerial:
    def __init__(self, gadget=None):
        self.gadget = gadget or USBNetwork()
        self.thread = None
        self.stop_event = threading.Event()
        self.fd = None
        self.protocol = None
        self.pin = ''

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    @property
    def connected(self):
        p = self.protocol
        return bool(self.running and p is not None and p.auth and p.clock()-p.last <= 30)

    def prepare(self, confirmed=False):
        g = self.gadget
        detached = g._check_udc()
        if any(g.module(m) for m in ('g_acm_ms', 'g_multi', 'g_ether')):
            raise RuntimeError('USB mode busy')
        if g.module('g_mass_storage'):
            if g.module('g_serial'):
                raise RuntimeError('USB mode busy')
            backing = g._storage_backing()
            if backing not in ('', '/dev/mmcblk0p1', '/dev/mmcblk0p4'):
                raise RuntimeError('USB mode busy')
            g._check_storage(backing, detached, serial=True, confirmed=confirmed)
            g.run(['modprobe', '-n', 'g_serial'])
            if not g.module('g_mass_storage') or g._storage_backing() != backing or any(g.module(m) for m in ('g_serial', 'g_acm_ms', 'g_multi', 'g_ether')):
                raise RuntimeError('USB mode busy')
            g._check_storage(backing, g._check_udc(), serial=True, confirmed=confirmed)
            g.run(['modprobe', '-r', 'g_mass_storage'])
            # Never restore a writable disk export automatically.
        if not g.module('g_serial'):
            g.run(['modprobe', 'g_serial', 'use_acm=1'])
        for _ in range(20):
            if g.exists(DEVICE):
                return
            time.sleep(.1)
        raise RuntimeError('Serial port missing')

    def start(self, source, dispatch, battery, confirmed=False):
        if self.running:
            return
        if confirmed:
            self.prepare(confirmed=True)
        else:
            self.prepare()
        if port_busy():
            raise RuntimeError('Serial port busy')
        if not callable(dispatch):
            raise RuntimeError('Key dispatcher unavailable')
        self.stop_event.clear()
        self.pin = '%06d' % secrets.randbelow(1000000)
        self.protocol = Protocol(self.pin, source, dispatch, battery)
        self.fd = None
        self.thread = threading.Thread(target=self.loop, name='remote-access-usb', daemon=True)
        self.thread.start()

    @staticmethod
    def open_port():
        if port_busy():
            raise RuntimeError('Serial port busy')
        fd = os.open(DEVICE, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            fcntl.ioctl(fd, termios.TIOCEXCL)
            tty.setraw(fd, termios.TCSANOW)
            attrs = termios.tcgetattr(fd)
            attrs[2] |= termios.CLOCAL | termios.CREAD
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            return fd
        except Exception:
            os.close(fd)
            raise

    def write(self, data):
        end = time.monotonic()+4
        view = memoryview(data)
        while view and not self.stop_event.is_set():
            if time.monotonic() >= end:
                raise OSError('USB write timeout')
            if select.select([], [self.fd], [], .2)[1]:
                try:
                    n = os.write(self.fd, view)
                    if not n: raise OSError('USB closed')
                    view = view[n:]
                except BlockingIOError:
                    pass

    def close_port(self):
        if self.fd is not None:
            try:
                fcntl.ioctl(self.fd, termios.TIOCNXCL)
            except OSError:
                pass
            os.close(self.fd); self.fd = None

    def loop(self):
        try:
            while not self.stop_event.is_set():
                try:
                    if self.fd is None:
                        self.fd = self.open_port()
                    if not select.select([self.fd], [], [], .2)[0]:
                        if self.protocol.auth and self.protocol.clock()-self.protocol.last > 30:
                            self.protocol.reset()
                        continue
                    data = os.read(self.fd, 4096)
                    if not data: raise OSError('USB disconnected')
                    for reply in self.protocol.feed(data):
                        self.write(reply)
                except BlockingIOError:
                    continue
                except (OSError, RuntimeError):
                    self.protocol.reset()
                    self.close_port()
                    self.stop_event.wait(.3)
                except Exception:
                    break
        finally:
            self.protocol.reset()
            self.close_port()

    def stop(self):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(5)
            if self.thread.is_alive():
                raise RuntimeError('USB stop failed')
        self.thread = None
        self.pin = ''
