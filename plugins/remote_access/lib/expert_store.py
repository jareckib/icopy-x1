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
"""Explicitly authorized, mounted-partition-only expert filesystem view."""
import os
import re
import stat
from contextlib import contextmanager
from udump_store import Store, FILE, DIR

PARTITIONS = (('UDUMP', 4), ('Userdata', 3), ('RootFS', 2), ('Boot', 1))

def _unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m.group(1), 8)), value)

def mounted_partitions(mountinfo='/proc/self/mountinfo'):
    """Match real block device numbers; never mount a partition ourselves."""
    devices = {}
    for label, number in PARTITIONS:
        try:
            st = os.stat('/dev/mmcblk0p%d' % number)
            if stat.S_ISBLK(st.st_mode):
                devices['%d:%d' % (os.major(st.st_rdev), os.minor(st.st_rdev))] = label
        except OSError:
            pass
    roots = {}
    with open(mountinfo) as source:
        for line in source:
            fields = line.split(' - ', 1)[0].split()
            if len(fields) < 6 or fields[2] not in devices or fields[3] != '/':
                continue
            label = devices[fields[2]]
            path = _unescape(fields[4])
            if label == 'UDUMP' and path != '/mnt/upan':
                continue
            if label == 'RootFS' and path != '/':
                continue
            if os.path.ismount(path):
                roots.setdefault(label, path)
    return roots

class ExpertStore:
    expert = True
    def __init__(self, roots=None, require_mount=True):
        self.stores = {k: Store(v, require_mount=require_mount) for k, v in
                       (mounted_partitions() if roots is None else roots).items() if k in dict(PARTITIONS)}
        if not self.stores:
            raise PermissionError('No mounted partitions')

    def select(self, path, root_ok=False):
        parts = Store.parts(path)
        if not parts or parts[0] not in self.stores or (len(parts)==1 and not root_ok):
            raise PermissionError('Partition root protected')
        return self.stores[parts[0]], '/'.join(parts[1:])

    def list(self, path=''):
        if path == '':
            return [dict(name=k, kind='directory', size=0) for k, _ in PARTITIONS if k in self.stores]
        store, sub = self.select(path, True)
        return store.list(sub)

    @contextmanager
    def download(self, path):
        store, sub = self.select(path)
        with store.download(sub) as result:
            yield result

    def mkdir(self, path):
        store, sub = self.select(path); store.mkdir(sub)

    def delete(self, path):
        store, sub = self.select(path); store.delete(sub)

    def upload(self, path, stream, size, overwrite=False, authorize=None, commit_guard=None):
        store, sub = self.select(path); store.upload(sub, stream, size, overwrite, authorize, commit_guard)

    def rename(self, path, dest):
        store, sub = self.select(path); other, dst = self.select(dest)
        if store is not other:
            raise PermissionError('Cross-partition rename denied')
        store.rename(sub, dst)

    def chmod(self, path, mode):
        if type(mode) is not int or not 0 <= mode <= 0o777:
            raise ValueError('Invalid mode')
        store, sub = self.select(path)
        with store.parent(sub) as (fd, name):
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise PermissionError('Special file')
            child = os.open(name, DIR if stat.S_ISDIR(st.st_mode) else FILE, dir_fd=fd)
            try:
                actual = os.fstat(child)
                if (actual.st_dev, actual.st_ino) != (st.st_dev, st.st_ino) or actual.st_dev != os.fstat(fd).st_dev:
                    raise PermissionError('File changed')
                if stat.S_ISREG(actual.st_mode) and actual.st_nlink != 1:
                    raise PermissionError('Hard link')
                os.fchmod(child, mode)
            finally:
                os.close(child)
