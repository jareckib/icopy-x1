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
"""Advisory HMI battery guard; never manipulates charging or shuts down."""
import threading
import time
import sys


_INSTALL_LOCK = threading.RLock()


def display_percent(value):
    # HMI can report 110 at full charge. Reject nonsensical values;
    # this normalization is for display only, never the write guard.
    return min(value, 100) if type(value) is int and 0 <= value <= 110 else None

class HmiObserver:
    """Observe actual replies through the existing driver; never open UART twice."""
    def __init__(self, driver, clock=time.monotonic):
        self.driver, self.clock = driver, clock
        self.lock = threading.Lock()
        self.samples = {}
        self.port = None
        self.original = driver._serial_key_handle
        def observe(line):
            if isinstance(line, bytes):
                line = line.decode('ascii', errors='ignore')
            if isinstance(line, str):
                line = line.strip()
                if line in ('CHARGING!', 'DISCHARGIN!'):
                    with self.lock:
                        port = getattr(driver, '_ser', None)
                        if port is not self.port:
                            self.samples.clear(); self.port = port
                        self.samples['charging'] = (int(line == 'CHARGING!'), self.clock())
                for prefix, name in (("#batpct:", "level"), ("#charge:", "charging"), ("#batvol:", "voltage")):
                    if line.startswith(prefix):
                        try:
                            raw = line[len(prefix):].strip()
                            v = float(raw) if name == "voltage" else int(raw)
                            if name == "level" and not 0 <= v <= 110: raise ValueError()
                            if name == "charging" and v not in (0, 1): raise ValueError()
                            if name == "voltage" and not 0 < v < 10000: raise ValueError()
                        except (ValueError, OverflowError): v = None
                        with self.lock:
                            port = getattr(driver, '_ser', None)
                            if port is not self.port:
                                self.samples.clear(); self.port = port
                            stamp = self.clock()
                            if name == 'level':
                                self.samples['display_level'] = (display_percent(v), stamp)
                                # Preserve the original strict safety range.
                                if v is not None and v > 100: v = None
                            self.samples[name] = (v, stamp)
                        break
            return self.original(line)
        observe._remote_battery_observer = self
        driver._serial_key_handle = observe

    def snapshot(self, since=None, display=False):
        now = self.clock()
        with self.lock:
            port = getattr(self.driver, '_ser', None)
            if port is None or not getattr(port, 'is_open', False) or port is not self.port or not getattr(self.driver, '_running', False):
                self.samples.clear()
                self.port = None
                return None, None, None, None
            def fresh(name):
                v, t = self.samples.get(name, (None, -1e9))
                return (v, now-t) if 0 <= now-t <= 15 and (since is None or t >= since) else (None, None)
            level, age = fresh('display_level' if display else 'level'); charging, _ = fresh('charging'); voltage, _ = fresh('voltage')
            return level, None if charging is None else bool(charging), voltage, age

    def query(self, voltage=False):
        self.driver.readbatpercent()
        try: self.driver.requestChargeState()
        except (OSError, AttributeError, RuntimeError): pass
        if voltage: self.driver.readbatvol()


def get_observer():
    with _INSTALL_LOCK:
        for name in ('lib.hmi_driver', 'hmi_driver'):
            driver = sys.modules.get(name)
            if driver is None or not callable(getattr(driver, '_serial_key_handle', None)):
                continue
            old = getattr(driver._serial_key_handle, '_remote_battery_observer', None)
            port = getattr(driver, '_ser', None)
            if not getattr(driver, '_running', False) or not getattr(port, 'is_open', False):
                if old is not None: old.snapshot()
                continue
            return old if old is not None else HmiObserver(driver)
        return None


def read_batteryui_cache():
    """Use the same cached value as the running firmware battery indicator.

    This is display information, never evidence of a fresh HMI reply.
    Do not import or initialize a second driver or access the UART here.
    """
    for name in ('batteryui', 'lib.batteryui'):
        ui = sys.modules.get(name)
        if ui is None or getattr(ui, '__BATTERY_RUN', False) is not True:
            continue
        level = getattr(ui, '__BATTERY_VALUE', None)
        charging = getattr(ui, '__CHARGING_STATE', None)
        level = display_percent(level)
        if level is not None:
            return level, charging if type(charging) is bool else None
    return None, None


def read_display_hmi():
    """Read the firmware's public battery API (including a reported 100%).

    Private driver state differs between Python and compiled firmware.
    A public cached reading is not proof of a fresh measurement and cannot
    authorize writes or change the low-battery protection thresholds.
    """
    cached = read_batteryui_cache()
    if cached[0] is not None:
        return cached
    candidates = []
    for name in ('hmi_driver', 'lib.hmi_driver'):
        driver = sys.modules.get(name)
        if driver is None or any(driver is d for d in candidates):
            continue
        candidates.append(driver)
    for driver in candidates:
        # Skip only a driver explicitly known to have stopped, not a driver
        # that simply does not expose the Python implementation's internals.
        if getattr(driver, '_running', None) is False:
            continue
        port = getattr(driver, '_ser', None)
        if port is not None and getattr(port, 'is_open', None) is False:
            continue
        try:
            level = display_percent(driver.readbatpercent())
            if level is None:
                continue
            try: charging = driver.requestChargeState()
            except Exception: charging = None
            return level, charging if type(charging) is bool else None
        except Exception:
            continue
    return None, None


def read_hmi():
    observer = get_observer()
    if observer is None: return None, None
    observer.query()
    return observer.snapshot()[:2]


class BatteryBlocked(PermissionError):
    pass


class BatteryGuard:
    def __init__(self, reader=read_hmi, interval=5, clock=time.monotonic):
        self.reader, self.interval, self.clock = reader, interval, clock
        self.lock = threading.Lock()
        self.last = None
        self.value = (None, None)
        self.display_value = (None, None)
        self.display_last = None
        self.display_lock = threading.Lock()

    def sample(self):
        with self.lock:
            now = self.clock()
            if self.last is None or now - self.last >= self.interval:
                self.last = now
                try:
                    level, charging = self.reader()
                    if type(level) is not int or not 0 <= level <= 100:
                        raise ValueError('invalid battery')
                    self.value = (level, charging if type(charging) is bool else None)
                except Exception:
                    self.value = (None, None)
            if self.reader is read_hmi:
                observer = get_observer()
                return observer.snapshot()[:2] if observer is not None else (None, None)
            return self.value

    def display_cached(self):
        """No queries; safe for UI repaint. Expire old display fallback."""
        if self.reader is read_hmi:
            observer = get_observer()
            if observer is not None:
                raw = observer.snapshot(display=True)[:2]
                if raw[0] is not None:
                    return raw
        else:
            with self.lock:
                return self.value
        ui = read_batteryui_cache()
        if ui[0] is not None:
            return ui
        last = self.display_last
        if last is not None and 0 <= self.clock()-last <= 15:
            return self.display_value
        return None, None

    def display_sample(self):
        level, charging = self.sample()
        if level is not None or self.reader is not read_hmi:
            return level, charging
        observer = get_observer()
        if observer is not None:
            display = observer.snapshot(display=True)[:2]
            if display[0] is not None:
                return display
        with self.display_lock:
            now = self.clock()
            if self.display_last is None or now-self.display_last >= self.interval:
                self.display_value = read_display_hmi()
                self.display_last = now
            return self.display_value

    def require_write(self, expert=False):
        level, _ = self.sample()
        if level is None or level < (30 if expert else 15):
            raise BatteryBlocked('Battery low or unavailable')

    def pause_frames(self):
        level, _ = self.sample()
        return level is not None and level < 10

    def header(self):
        level, charging = self.display_sample()
        return ('unknown' if level is None else str(level),
                'unknown' if charging is None else ('1' if charging else '0'))
