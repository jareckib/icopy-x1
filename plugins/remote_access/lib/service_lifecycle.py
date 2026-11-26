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
"""File service lifetime and ephemeral pairing credentials."""
import hashlib
import ipaddress
import os
import secrets
import ssl
import subprocess
import tempfile
import threading
from udump_api import create_server, ExpertLease
from expert_store import ExpertStore
from udump_store import Store


class FileService:
    def __init__(self, root='/mnt/upan', port=8766, require_mount=False, battery=None):
        self.battery = battery
        self.root = root
        self.require_mount = require_mount
        self.port = port
        self.lock = threading.RLock()
        self.server = self.thread = self.directory = self.pairing = self.lease = None
        self.lease_event = None

    def start(self, address, expert=False, mirror=None):
        address = str(ipaddress.IPv4Address(address))
        if address == '0.0.0.0' or ipaddress.IPv4Address(address).is_multicast:
            raise ValueError('Specific local address required')
        with self.lock:
            if expert and self.battery is not None: self.battery.require_write(expert=True)
            if self.server is not None:
                if self.pairing['host'] == address and self.thread.is_alive() and not expert and not self.pairing.get('expert'):
                    return dict(self.pairing)
                self.stop()
            directory = tempfile.TemporaryDirectory(prefix='icopy-files-')
            server = None
            try:
                cert = os.path.join(directory.name, 'cert.pem')
                key = os.path.join(directory.name, 'key.pem')
                subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=iCopy-X', '-keyout', key, '-out', cert], check=True, timeout=30, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                os.chmod(key, 0o600)
                with open(cert) as stream:
                    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(stream.read())).hexdigest()
                secret = secrets.token_hex(24)
                pin = "%06d" % secrets.randbelow(1000000)
                lease = ExpertLease() if expert else None
                store = ExpertStore() if expert else Store(self.root, require_mount=self.require_mount)
                if expert and self.battery is not None: self.battery.require_write(expert=True)
                server = create_server((address, self.port), store, secret, cert, key, lease, self.battery, pin, mirror)
                thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':0.1}, daemon=True)
                thread.start()
                self.directory, self.server, self.thread = directory, server, thread
                self.lease = lease
                self.pairing = dict(host=address, port=server.server_port, token=secret, fingerprint=fingerprint, expert=expert, pin=pin, mirror=mirror is not None)
                if lease is not None:
                    event = threading.Event()
                    self.lease_event = event
                    threading.Thread(target=self._watch_lease, args=(lease,event), daemon=True).start()
                return dict(self.pairing)
            except BaseException:
                if server is not None:
                    server.server_close()
                directory.cleanup()
                raise

    def _watch_lease(self, lease, event):
        while not event.wait(1):
            if not lease.valid():
                with self.lock:
                    if self.lease is lease:
                        self.stop()
                return

    def stop(self):
        with self.lock:
            if self.server is None:
                return
            if self.lease_event is not None: self.lease_event.set()
            self.lease_event = None
            if self.lease is not None: self.lease.revoke()
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=2)
            self.directory.cleanup()
            self.server = self.thread = self.directory = self.pairing = self.lease = None
