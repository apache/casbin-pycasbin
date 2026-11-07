# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from unittest import TestCase
from casbin.util.rwlock import RWLockWrite
from concurrent.futures import ThreadPoolExecutor
import time
import queue
import threading


class TestRWLock(TestCase):
    def test_shared_read_context_keeps_both_readers_locked(self):
        lock = RWLockWrite()
        read = lock.gen_rlock()
        entered = [threading.Event(), threading.Event()]
        leave = [threading.Event(), threading.Event()]
        finished = [threading.Event(), threading.Event()]
        written = threading.Event()

        def reader(index):
            with read:
                entered[index].set()
                leave[index].wait(5)
            finished[index].set()

        def writer():
            with lock.gen_wlock():
                written.set()

        threads = [threading.Thread(target=reader, args=(i,), daemon=True) for i in range(2)]
        for thread in threads:
            thread.start()
        writer_thread = threading.Thread(target=writer, daemon=True)
        try:
            self.assertTrue(all(event.wait(2) for event in entered))
            writer_thread.start()
            self.assertFalse(written.wait(0.05))
            leave[0].set()
            self.assertTrue(finished[0].wait(2))
            self.assertFalse(written.wait(0.05))
            leave[1].set()
            self.assertTrue(written.wait(2))
        finally:
            for event in leave:
                event.set()
            for thread in threads:
                thread.join(2)
            if writer_thread.ident is not None:
                writer_thread.join(2)

    def test_direct_api_and_nested_read_contexts(self):
        lock = RWLockWrite()
        lock.aquire_read()
        with lock.gen_rlock():
            pass
        lock.release_read()
        lock.aquire_write()
        lock.release_write()
        with self.assertRaises(ValueError):
            with lock.gen_wlock():
                raise ValueError("caller failure")
        with lock.gen_wlock():
            pass

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
