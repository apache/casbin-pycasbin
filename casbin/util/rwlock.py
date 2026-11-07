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


class RWLockWrite:
    """A writer-preferring lock retaining Casbin's existing context/direct API."""

    def __init__(self):
        self._delegate = _WriterPreferredLock()
        self._held = local()

    def _acquire(self, kind):
        handle = self._delegate.gen_rlock() if kind == "read" else self._delegate.gen_wlock()
        handle.acquire()
        stack = getattr(self._held, kind, None)
        if stack is None:
            stack = []
            setattr(self._held, kind, stack)
        stack.append(handle)

    def _release(self, kind):
        stack = getattr(self._held, kind, None)
        if not stack:
            raise RuntimeError("No {} lock acquired by this thread".format(kind))
        stack.pop().release()

    def aquire_read(self):
        # Preserve the historical method spelling for existing callers.
        self._acquire("read")

    def release_read(self):
        self._release("read")

    def aquire_write(self):
        self._acquire("write")

    def release_write(self):
        self._release("write")

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
