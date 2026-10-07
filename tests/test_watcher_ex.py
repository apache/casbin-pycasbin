# Copyright 2023 The casbin Authors. All Rights Reserved.
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

import casbin
from tests.test_enforcer import get_examples, get_examples_copy, TestCaseBase
from unittest import IsolatedAsyncioTestCase


class SampleWatcher:
    def __init__(self):
        self.callback = None
        self.notify_message = None

    def close(self):
        pass

    def set_update_callback(self, callback):
        """
        sets the callback function to be called when the policy is updated
        :param callable callback: callback(event)
            - event: event received from the rabbitmq
        :return:
        """
        self.callback = callback

    def update(self, msg):
        """
        update the policy
        """
        self.notify_message = msg
        return True

    def update_for_add_policy(self, section, ptype, *params):
        """
        update for add policy
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:    True if updated
        """
        message = "called add policy"
        return self.update(message)

    def update_for_remove_policy(self, section, ptype, *params):
        """
        update for remove policy
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:    True if updated
        """
        message = "called remove policy"
        return self.update(message)

    def update_for_remove_filtered_policy(self, section, ptype, field_index, *params):
        """
        update for remove filtered policy
        :param section: section
        :param ptype:   policy type
        :param field_index: field index
        :param params: other params
        :return:
        """
        message = "called remove filtered policy"
        return self.update(message)

    def update_for_save_policy(self, model: casbin.Model):
        """
        update for save policy
        :param model: casbin model
        :return:
        """
        message = "called save policy"
        return self.update(message)

    def update_for_add_policies(self, section, ptype, *params):
        """
        update for add policies
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:
        """
        message = "called add policies"
        return self.update(message)

    def update_for_remove_policies(self, section, ptype, *params):
        """
        update for remove policies
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:
        """
        message = "called remove policies"
        return self.update(message)

    def start_watch(self):
        """
        starts the watch thread
        :return:
        """
        pass


class AsyncSampleWatcher:
    def __init__(self):
        self.callback = None
        self.notify_message = None

    async def close(self):
        pass

    async def set_update_callback(self, callback):
        """
        sets the callback function to be called when the policy is updated
        :param callable callback: callback(event)
            - event: event received from the rabbitmq
        :return:
        """
        self.callback = callback

    async def update(self, msg):
        """
        update the policy
        """
        self.notify_message = msg
        return True

    async def update_for_add_policy(self, section, ptype, *params):
        """
        update for add policy
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:    True if updated
        """
        message = "called add policy"
        return await self.update(message)

    async def update_for_remove_policy(self, section, ptype, *params):
        """
        update for remove policy
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:    True if updated
        """
        message = "called remove policy"
        return await self.update(message)

    async def update_for_remove_filtered_policy(self, section, ptype, field_index, *params):
        """
        update for remove filtered policy
        :param section: section
        :param ptype:   policy type
        :param field_index: field index
        :param params: other params
        :return:
        """
        message = "called remove filtered policy"
        return await self.update(message)

    async def update_for_save_policy(self, model: casbin.Model):
        """
        update for save policy
        :param model: casbin model
        :return:
        """
        message = "called save policy"
        return await self.update(message)

    async def update_for_add_policies(self, section, ptype, *params):
        """
        update for add policies
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:
        """
        message = "called add policies"
        return await self.update(message)

    async def update_for_remove_policies(self, section, ptype, *params):
        """
        update for remove policies
        :param section: section
        :param ptype:   policy type
        :param params:  other params
        :return:
        """
        message = "called remove policies"
        return await self.update(message)

    async def start_watch(self):
        """
        starts the watch thread
        :return:
        """
        pass


class TestWatcherEx(TestCaseBase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.Enforcer(
            model,
            adapter,
        )

    def test_auto_notify_enabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        w = SampleWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(True)

        e.save_policy()
        self.assertEqual(w.notify_message, "called save policy")

        e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called add policy")

        e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called remove policy")

        e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, "called remove filtered policy")

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]
        e.add_policies(rules)
        self.assertEqual(w.notify_message, "called add policies")

        e.remove_policies(rules)
        self.assertEqual(w.notify_message, "called remove policies")

    def test_auto_notify_disabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        w = SampleWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(False)

        e.save_policy()
        self.assertEqual(w.notify_message, "called save policy")

        w.notify_message = None

        e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, None)

        e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, None)

        e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, None)

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]
        e.add_policies(rules)
        self.assertEqual(w.notify_message, None)

        e.remove_policies(rules)
        self.assertEqual(w.notify_message, None)

    def test_auto_notify_with_auto_save_disabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        w = SampleWatcher()
        e.set_watcher(w)
        e.enable_auto_save(False)
        e.enable_auto_notify_watcher(True)

        e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called add policy")

        e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called remove policy")

        e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, "called remove filtered policy")

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
        ]
        e.add_policies(rules)
        self.assertEqual(w.notify_message, "called add policies")

        e.remove_policies(rules)
        self.assertEqual(w.notify_message, "called remove policies")


class AsyncMinimalWatcher:
    """A minimal async watcher that only implements async update() method."""

    def __init__(self):
        self.update_count = 0

    async def update(self):
        """update the policy"""
        self.update_count += 1
        return True

    async def close(self):
        pass

    async def set_update_callback(self, callback):
        pass


class TestAsyncWatcherEx(IsolatedAsyncioTestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.AsyncEnforcer(
            model,
            adapter,
        )

    async def test_auto_notify_enabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        await e.load_policy()

        w = AsyncSampleWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(True)

        await e.save_policy()
        self.assertEqual(w.notify_message, "called save policy")

        await e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called add policy")

        await e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called remove policy")

        await e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, "called remove filtered policy")

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]
        await e.add_policies(rules)
        self.assertEqual(w.notify_message, "called add policies")

        await e.remove_policies(rules)
        self.assertEqual(w.notify_message, "called remove policies")

    async def test_auto_notify_disabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        await e.load_policy()

        w = SampleWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(False)

        await e.save_policy()
        self.assertEqual(w.notify_message, "called save policy")

        w.notify_message = None

        await e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, None)

        await e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, None)

        await e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, None)

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]
        await e.add_policies(rules)
        self.assertEqual(w.notify_message, None)

        await e.remove_policies(rules)
        self.assertEqual(w.notify_message, None)

    async def test_auto_notify_with_auto_save_disabled(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        await e.load_policy()

        w = AsyncSampleWatcher()
        e.set_watcher(w)
        e.enable_auto_save(False)
        e.enable_auto_notify_watcher(True)

        await e.add_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called add policy")

        await e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.notify_message, "called remove policy")

        await e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.notify_message, "called remove filtered policy")

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
        ]
        await e.add_policies(rules)
        self.assertEqual(w.notify_message, "called add policies")

        await e.remove_policies(rules)
        self.assertEqual(w.notify_message, "called remove policies")

    async def test_async_minimal_watcher(self):
        """Test that a watcher with only async update() method works properly."""
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples_copy("basic_policy.csv"),
        )
        await e.load_policy()

        w = AsyncMinimalWatcher()
        e.set_watcher(w)
        e.enable_auto_notify_watcher(True)

        # Test save_policy
        await e.save_policy()
        self.assertEqual(w.update_count, 1)

        # Test add_policy - fallback to update()
        await e.add_policy("admin", "data1", "read")
        self.assertEqual(w.update_count, 2)

        # Test remove_policy - fallback to update()
        await e.remove_policy("admin", "data1", "read")
        self.assertEqual(w.update_count, 3)

        # Test remove_filtered_policy - fallback to update()
        await e.remove_filtered_policy(1, "data1")
        self.assertEqual(w.update_count, 4)

        # Test add_policies - fallback to update()
        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
        ]
        await e.add_policies(rules)
        self.assertEqual(w.update_count, 5)

        # Test remove_policies - fallback to update()
        await e.remove_policies(rules)
        self.assertEqual(w.update_count, 6)
