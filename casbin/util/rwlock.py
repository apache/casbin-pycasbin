# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Compatibility wrappers for the separately installed MIT-licensed readerwriterlock.

A lock handle from that library records acquisition state. Give each acquisition
its own handle so the context objects shared by SyncedEnforcer remain safe when
several threads enter the same read context concurrently.
"""

from threading import local

from readerwriterlock.rwlock import RWLockWrite as _WriterPreferredLock


class _ThreadLocks(local):
    def __init__(self):
        self.read = []
        self.write = []


class RWLockWrite:
    """A writer-preferring lock retaining Casbin's existing context/direct API."""

    def __init__(self):
        self._delegate = _WriterPreferredLock()
        self._held = _ThreadLocks()

    def aquire_read(self):
        # Preserve the historical method spelling for existing callers.
        handle = self._delegate.gen_rlock()
        handle.acquire()
        self._held.read.append(handle)

    def release_read(self):
        if not self._held.read:
            raise RuntimeError("No read lock acquired by this thread")
        self._held.read.pop().release()

    def aquire_write(self):
        handle = self._delegate.gen_wlock()
        handle.acquire()
        self._held.write.append(handle)

    def release_write(self):
        if not self._held.write:
            raise RuntimeError("No write lock acquired by this thread")
        self._held.write.pop().release()

    def gen_rlock(self):
        return ReadRWLock(self)

    def gen_wlock(self):
        return WriteRWLock(self)


class ReadRWLock:
    def __init__(self, rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.aquire_read()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_read()
        return False


class WriteRWLock:
    def __init__(self, rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.aquire_write()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_write()
        return False
