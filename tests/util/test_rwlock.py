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

from unittest import TestCase
from casbin.util.rwlock import RWLockWrite
from concurrent.futures import ThreadPoolExecutor
import time
import queue


class TestRWLock(TestCase):
    def gen_locks(self):
        rw_lock = RWLockWrite()
        rl = rw_lock.gen_rlock()
        wl = rw_lock.gen_wlock()
        return (rl, wl)

    def test_multiple_readers(self):
        [rl, _] = self.gen_locks()

        delay = 5 / 1000  # 5ms
        num_readers = 1000
        start = time.time()

        def read():
            with rl:
                time.sleep(delay)

        executor = ThreadPoolExecutor(num_readers)
        futures = [executor.submit(read) for i in range(num_readers)]
        [future.result() for future in futures]
        exec_time = time.time() - start

        self.assertLess(exec_time, delay * num_readers)

    def test_single_writer(self):
        [_, wl] = self.gen_locks()

        delay = 5 / 1000  # 5ms
        num_writers = 10
        start = time.time()

        def write():
            with wl:
                time.sleep(delay)

        executor = ThreadPoolExecutor(num_writers)
        futures = [executor.submit(write) for i in range(num_writers)]
        [future.result() for future in futures]
        exec_time = time.time() - start

        self.assertGreaterEqual(exec_time, delay * num_writers)

    def test_release_from_another_thread(self):
        reader, writer = self.gen_locks()
        with ThreadPoolExecutor(1) as executor:
            for lock in (reader, writer):
                with self.subTest(lock=type(lock).__name__):
                    self.assertIsNone(lock.__enter__())
                    self.assertFalse(executor.submit(lock.__exit__, None, None, None).result(timeout=5))
                    with lock:
                        pass

    def test_writer_preference(self):
        [rl, wl] = self.gen_locks()

        q = queue.Queue()
        delay = 5 / 1000  # 5ms
        start = time.time()

        def read():
            with rl:
                time.sleep(delay)
                q.put("r")

        def write():
            with wl:
                time.sleep(delay)
                q.put("w")

        executor = ThreadPoolExecutor(10)
        futures = [executor.submit(read) for i in range(3)]
        time.sleep(1 / 1000)
        futures += [executor.submit(write) for i in range(3)]
        time.sleep(1 / 1000)
        futures += [executor.submit(read) for i in range(3)]
        [future.result() for future in futures]

        sequence = ""
        while not q.empty():
            sequence += q.get()

        self.assertEqual(sequence, "rrrwwwrrr")
