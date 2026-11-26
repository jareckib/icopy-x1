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
"""UDUMP file operations, anchored to an open directory descriptor.
No shell commands, no network listener. Linux/Python 3.8.
"""
import os
import stat
import secrets
from contextlib import contextmanager, nullcontext

DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

class Store:
    def __init__(self, root='/mnt/upan', require_mount=False):
        self.root = root
        self.require_mount = require_mount
        if require_mount and not os.path.ismount(root):
            raise PermissionError('UDUMP not mounted')
        fd = os.open(root, DIR)
        try:
            st = os.fstat(fd)
            self.identity = (st.st_dev, st.st_ino)
        finally:
            os.close(fd)

    @staticmethod
    def parts(path):
        if not isinstance(path, str) or '\x00' in path or '\\' in path:
            raise ValueError('Invalid path')
        if path == '':
            return []
        parts = path.split('/')
        if any(p in ('', '.', '..') for p in parts):
            raise ValueError('Invalid path')
        return parts

    @contextmanager
    def directory(self, parts):
        if self.require_mount and not os.path.ismount(self.root):
            raise PermissionError('UDUMP not mounted')
        fd = os.open(self.root, DIR)
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != self.identity:
                raise PermissionError('UDUMP changed')
            dev = st.st_dev
            for part in parts:
                child = os.open(part, DIR, dir_fd=fd)
                if os.fstat(child).st_dev != dev:
                    os.close(child)
                    raise PermissionError('Foreign filesystem')
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def parent(self, path):
        parts = self.parts(path)
        if not parts:
            raise ValueError('Root operation denied')
        with self.directory(parts[:-1]) as fd:
            yield fd, parts[-1]

    def list(self, path=''):
        with self.directory(self.parts(path)) as fd:
            result = []
            for name in sorted(os.listdir(fd)):
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                kind = 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'blocked'
                if st.st_dev != os.fstat(fd).st_dev or (kind == 'file' and st.st_nlink != 1):
                    kind = 'blocked'
                result.append(dict(name=name, kind=kind, size=st.st_size))
            return result

    @contextmanager
    def download(self, path):
        with self.parent(path) as (fd, name):
            f = os.open(name, FILE, dir_fd=fd)
            try:
                st = os.fstat(f)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_dev != os.fstat(fd).st_dev:
                    raise PermissionError('Not a regular local file')
                with os.fdopen(f, 'rb', closefd=False) as stream:
                    yield stream, st.st_size
            finally:
                os.close(f)

    def mkdir(self, path):
        with self.parent(path) as (fd, name):
            os.mkdir(name, dir_fd=fd)

    def delete(self, path):
        with self.parent(path) as (fd, name):
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                if st.st_dev != os.fstat(fd).st_dev:
                    raise PermissionError('Foreign filesystem')
                os.rmdir(name, dir_fd=fd)
            elif stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
                os.unlink(name, dir_fd=fd)
            else:
                raise PermissionError('Special file')

    def upload(self, path, stream, size, overwrite=False, authorize=None, commit_guard=None):
        if type(size) is not int or size < 0:
            raise ValueError('Invalid size')
        with self.parent(path) as (fd, name):
            space = os.fstatvfs(fd)
            if size > space.f_bavail * space.f_frsize:
                raise OSError('Insufficient space')
            previous = None
            if authorize is not None and overwrite:
                try:
                    previous = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISREG(previous.st_mode) or previous.st_nlink != 1 or previous.st_dev != os.fstat(fd).st_dev:
                        raise PermissionError('Invalid overwrite target')
                except FileNotFoundError:
                    pass
            temp = '.upload-' + secrets.token_hex(16)
            out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                with os.fdopen(out, 'wb') as target:
                    remaining = size
                    while remaining:
                        chunk = stream.read(min(remaining, 65536))
                        if not chunk or len(chunk) > remaining:
                            raise IOError('Incomplete upload')
                        target.write(chunk)
                        remaining -= len(chunk)
                    target.flush()
                    if previous is not None:
                        actual = os.fstat(target.fileno())
                        if (actual.st_uid, actual.st_gid) != (previous.st_uid, previous.st_gid):
                            os.fchown(target.fileno(), previous.st_uid, previous.st_gid)
                        os.fchmod(target.fileno(), previous.st_mode & 0o777)
                    os.fsync(target.fileno())
                with (commit_guard() if commit_guard is not None else nullcontext()):
                    if authorize is not None and not authorize():
                        raise PermissionError('Session expired')
                    if not overwrite:
                        # FAT32 lacks hard links. Atomic no-replace via renameat2.
                        self._rename_noreplace(fd, temp, fd, name)
                    else:
                        if authorize is not None:
                            try:
                                current = os.stat(name, dir_fd=fd, follow_symlinks=False)
                            except FileNotFoundError:
                                current = None
                            if previous is None:
                                # Do not overwrite a newly-created file that was not approved.
                                self._rename_noreplace(fd, temp, fd, name)
                                return
                            if current is None or (current.st_dev,current.st_ino) != (previous.st_dev,previous.st_ino):
                                raise PermissionError('Overwrite target changed')
                        os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
            finally:
                try:
                    os.unlink(temp, dir_fd=fd)
                except FileNotFoundError:
                    pass

    @staticmethod
    def _rename_noreplace(srcfd, src, dstfd, dst):
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        fn = getattr(libc, 'renameat2', None)
        if fn is None:
            # Fail closed, including older libc builds.
            raise NotImplementedError('Atomic no-replace unavailable')
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        fn.restype = ctypes.c_int
        if fn(srcfd, os.fsencode(src), dstfd, os.fsencode(dst), 1):
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), dst)

    def rename(self, source, destination):
        with self.parent(source) as (a, old), self.parent(destination) as (b, new):
            st = os.stat(old, dir_fd=a, follow_symlinks=False)
            if st.st_dev != os.fstat(a).st_dev or not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)):
                raise PermissionError('Invalid source')
            self._rename_noreplace(a, old, b, new)
