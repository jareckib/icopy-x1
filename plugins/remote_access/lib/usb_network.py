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
"""Opt-in USB Ethernet gadget, without touching mounts or persistent settings."""
import glob
import os
import subprocess
import time
import tempfile

ADDRESS = '192.168.7.2'
IFACE = 'usb0'
MUSB_MODE = '/sys/devices/platform/soc/1c19000.usb/musb-hdrc.4.auto/mode'
BOOT = '/dev/mmcblk0p1'
# R12 isolated, point-to-point test only: use an RFC 7042 documentation
# address with the local bit clear so older usbnet hosts can name ECM eth0.
# Do not bridge this test network to a physical LAN.
GADGET_ARGS = ('use_eem=0', 'host_addr=00:00:5e:00:53:07')

class BootDetachConfirmation(RuntimeError):
    """Physical disconnection must be confirmed locally."""


class USBNetwork:
    def __init__(self, run=None, exists=None, states=None, spawn=None, mode=None):
        self.run = run or self._run
        self.exists = exists or os.path.exists
        self.states = states or self._states
        self.spawn = spawn or self._spawn
        self.mode = mode or self._mode
        self.previous = None
        self.dhcp = None
        self.owned = False
        self.directory = None

    @staticmethod
    def _run(args):
        subprocess.run(([] if os.geteuid() == 0 else ['sudo', '-n']) + args, check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       stdin=subprocess.DEVNULL)

    @staticmethod
    def _spawn(args):
        # Run as the existing application user (normally root on the device).
        # No shell and no global DNS listener or default gateway advertisement.
        return subprocess.Popen(([] if os.geteuid() == 0 else ['sudo', '-n']) + args, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def _states():
        result = []
        for path in glob.glob('/sys/class/udc/*/state'):
            with open(path) as handle:
                result.append(handle.read().strip())
        return result

    def module(self, name):
        return self.exists('/sys/module/' + name)

    def _check_udc(self):
        states = self.states()
        if len(states) != 1 or states[0] not in (
                'not attached', 'attached', 'powered', 'default', 'addressed',
                'configured', 'suspended'):
            raise RuntimeError('USB state unknown')
        return states[0] == 'not attached'

    @staticmethod
    def _storage_backing():
        with open('/sys/module/g_mass_storage/parameters/file') as f:
            return f.read().strip()

    @staticmethod
    def _mode():
        try:
            with open(MUSB_MODE) as f:
                return f.read().strip()
        except OSError:
            return ''

    @staticmethod
    def _speed():
        paths = glob.glob('/sys/class/udc/*/current_speed')
        if len(paths) != 1:
            return ''
        try:
            with open(paths[0]) as f:
                return f.read().strip().lower()
        except OSError:
            return ''

    def _check_storage(self, backing, detached, serial=False, confirmed=False):
        if backing == BOOT:
            if serial:
                # Preserve R19's detached signature. A stale configured
                # peripheral cannot be distinguished from a live disk by sysfs.
                mode = self.mode()
                if detached and mode in ('b_idle', 'b_peripheral') and self._speed() == 'unknown':
                    return
                # Only the known boot export, never a host-mode session.
                if mode == 'b_peripheral' and not detached:
                    states = self.states()
                    if states == ['configured'] and self._speed() == 'high-speed':
                        if confirmed:
                            return
                        raise BootDetachConfirmation('Unplug USB cable first')
                raise RuntimeError('Unplug USB cable first')
            # Observed on iCopy-XS: UDC may retain 'configured' after
            # disconnection. Require MUSB b_idle (no active host or device
            # session), in addition to the on-screen unplug instruction.
            # Never detach a live peripheral or a host session.
            if self.mode() != 'b_idle':
                raise RuntimeError('Unplug USB cable first')
        elif backing and not detached:
            raise RuntimeError('Eject USB storage first')

    def link_active(self):
        try:
            with open('/sys/class/net/' + IFACE + '/carrier') as f:
                return f.read().strip() == '1'
        except OSError:
            return False

    def start(self):
        if self.owned:
            return
        detached = self._check_udc()
        if self.module('g_acm_ms') or self.module('g_multi') or self.module('g_ether') or self.exists('/sys/class/net/usb0'):
            raise RuntimeError('USB mode busy')
        mods = [m for m in ('g_mass_storage', 'g_serial') if self.module(m)]
        if len(mods) > 1:
            raise RuntimeError('USB mode busy')
        # Refuse an unknown or active mass storage configuration.
        # Never mount/unmount or change backing storage.
        backing = None
        if mods == ['g_mass_storage']:
            try:
                backing = self._storage_backing()
            except OSError:
                raise RuntimeError('USB mode busy')
            if backing not in ('', BOOT, '/dev/mmcblk0p4'):
                raise RuntimeError('USB mode busy')
            self._check_storage(backing, detached)
        # Validate module availability before detaching the previous gadget.
        self.run(['modprobe', '-n', 'g_ether'] + list(GADGET_ARGS))
        # Recheck just before changing the gadget. A connected phone is not
        # inherently unsafe; an exported disk with a possible host writer is.
        detached = self._check_udc()
        self._check_storage(backing, detached)
        self.previous = mods[0] if mods else ''
        try:
            if self.previous:
                self.run(['modprobe', '-r', self.previous])
            self.owned = True
            self.run(['modprobe', 'g_ether'] + list(GADGET_ARGS))
            for _ in range(20):
                if self.exists('/sys/class/net/' + IFACE):
                    break
                time.sleep(.1)
            else:
                raise RuntimeError('USB interface missing')
            self.run(['ip', 'addr', 'add', ADDRESS + '/24', 'dev', IFACE])
            self.run(['ip', 'link', 'set', IFACE, 'up'])
            self.directory = tempfile.TemporaryDirectory(prefix='icopy-usb-')
            self.dhcp = self.spawn(['dnsmasq', '--keep-in-foreground', '--conf-file=/dev/null',
                '--port=0', '--no-resolv', '--no-hosts', '--bind-interfaces',
                '--interface=' + IFACE, '--except-interface=lo',
                '--dhcp-range=192.168.7.10,192.168.7.20,255.255.255.0,10m',
                '--dhcp-option=3', '--dhcp-option=6', '--dhcp-leasefile=' + os.path.join(self.directory.name, 'leases'),
                '--pid-file='])
            time.sleep(.25)
            if self.dhcp.poll() is not None:
                raise RuntimeError('USB DHCP failed')
        except Exception:
            if self.owned:
                self.stop()
            raise

    def stop(self):
        if not self.owned:
            return
        # Ethernet can be stopped while a cable is connected. The caller
        # must stop dependent services first. Never automatically re-export
        # a writable block device: UDC state cannot prove physical detachment.
        if self.dhcp is not None:
            if self.dhcp.poll() is None:
                self.dhcp.terminate()
                try:
                    self.dhcp.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.dhcp.kill()
                    self.dhcp.wait(timeout=2)
            self.dhcp = None
        if self.directory is not None:
            self.directory.cleanup()
            self.directory = None
        if self.module('g_ether'):
            self.run(['modprobe', '-r', 'g_ether'])
        if self.previous in ('g_mass_storage', 'g_serial'):
            # Lab401's safe baseline gadget after PC Mode is g_serial.
            # The original PC Mode can explicitly export UDUMP when needed.
            self.run(['modprobe', 'g_serial'])
        self.owned = False
        self.previous = None
