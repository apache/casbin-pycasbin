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

from threading import Condition


class RWLockWrite:
    """A writer-preferring lock with shared readers."""

    def __init__(self):
        self._condition = Condition()
        self._readers = 0
        self._writing = False
        self._writers_waiting = 0

    def aquire_read(self):
        with self._condition:
            while self._writing or self._writers_waiting:
                self._condition.wait()
            self._readers += 1

    def release_read(self):
        with self._condition:
            if not self._readers:
                raise RuntimeError("read lock is not held")
            self._readers -= 1
            if not self._readers and self._writers_waiting:
                self._condition.notify_all()

    def aquire_write(self):
        with self._condition:
            self._writers_waiting += 1
            try:
                while self._writing or self._readers:
                    self._condition.wait()
                self._writing = True
            finally:
                self._writers_waiting -= 1
                if not self._writing:
                    self._condition.notify_all()

    def release_write(self):
        with self._condition:
            if not self._writing:
                raise RuntimeError("write lock is not held")
            self._writing = False
            self._condition.notify_all()

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
