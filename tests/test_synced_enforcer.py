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

import threading
from unittest import TestCase

import casbin
from tests.test_enforcer import get_examples


class LockingWatcher:
    """mimics the redis watcher, which holds a lock of its own both while notifying the
    other nodes and while running the update callback."""

    def __init__(self):
        self.mutex = threading.Lock()
        self.callback = None
        self.updates = []

    def set_update_callback(self, callback):
        self.callback = callback

    def update(self):
        with self.mutex:
            self.updates.append("update")
        return True

    def close(self):
        pass


class TestSyncedEnforcerWatcher(TestCase):
    """the lock the enforcer takes and the lock the watcher takes have to be taken in the
    same order everywhere, or the two deadlock. See
    https://github.com/casbin/pycasbin/issues/408"""

    def get_enforcer(self, adapter):
        return casbin.SyncedEnforcer(get_examples("basic_model.conf"), adapter)

    def test_watcher_is_notified(self):
        w = LockingWatcher()
        e = self.get_enforcer(casbin.persist.Adapter())
        e.set_watcher(w)

        e.add_policy("alice", "data1", "read")

        # the notification is deferred, but only until the lock is released: it still has
        # to have been delivered by the time add_policy() returns
        self.assertEqual(w.updates, ["update"])
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_get_watcher_returns_the_watcher_that_was_set(self):
        w = LockingWatcher()
        e = self.get_enforcer(casbin.persist.Adapter())
        e.set_watcher(w)

        self.assertIs(e.get_watcher(), w)

    def test_watcher_is_notified_outside_the_enforcer_lock(self):
        w = LockingWatcher()
        e = self.get_enforcer(casbin.persist.Adapter())
        e.set_watcher(w)

        reader_finished = threading.Event()

        def update():
            # a reader can only get through here if the write lock has been released
            reader = threading.Thread(target=lambda: (e.get_policy(), reader_finished.set()), daemon=True)
            reader.start()
            reader.join(timeout=5)

        w.update = update
        e.add_policy("alice", "data1", "read")

        self.assertTrue(reader_finished.is_set(), "the watcher was notified while the enforcer was still locked")

    def test_save_policy_notifies_outside_the_enforcer_lock(self):
        """save_policy() notifies the watcher too, and it holds the read lock while doing
        so, so the same deferral has to apply there."""
        w = LockingWatcher()
        e = self.get_enforcer(casbin.persist.Adapter())
        e.set_watcher(w)

        writer_finished = threading.Event()

        def update():
            # a writer can only get through here if the read lock has been released
            writer = threading.Thread(target=lambda: (e.load_policy(), writer_finished.set()), daemon=True)
            writer.start()
            writer.join(timeout=5)

        w.update = update
        e.save_policy()

        self.assertTrue(writer_finished.is_set(), "the watcher was notified while the enforcer was still locked")

    def test_callback_holding_the_watcher_lock_does_not_deadlock(self):
        """reproduces the issue: the subscribe thread holds the watcher lock and wants the
        enforcer lock, while the thread changing the policy holds the enforcer lock and
        wants the watcher lock."""
        w = LockingWatcher()
        enforcer_locked = threading.Event()
        callback_reached = threading.Event()

        class SlowAdapter(casbin.persist.Adapter):
            def add_policy(self, sec, ptype, rule):
                # the write lock is held for as long as we stay in here, so this is where
                # the subscribe thread gets its chance to ask for it
                enforcer_locked.set()
                callback_reached.wait(timeout=5)

        e = self.get_enforcer(SlowAdapter())
        e.set_watcher(w)
        w.set_update_callback(e.load_policy)

        def subscribe():
            with w.mutex:
                enforcer_locked.wait(timeout=5)
                callback_reached.set()
                w.callback()

        subscriber = threading.Thread(target=subscribe, daemon=True)
        subscriber.start()

        added = threading.Event()
        writer = threading.Thread(target=lambda: (e.add_policy("alice", "data1", "read"), added.set()), daemon=True)
        writer.start()

        self.assertTrue(added.wait(timeout=10), "add_policy deadlocked against the watcher lock")
        subscriber.join(timeout=10)
        self.assertFalse(subscriber.is_alive(), "the update callback deadlocked against the enforcer lock")
        self.assertEqual(w.updates, ["update"])
