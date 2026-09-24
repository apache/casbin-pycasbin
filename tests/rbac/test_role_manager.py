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
from casbin.rbac import default_role_manager
from casbin.util import key_match, regex_match_func
import time
from concurrent.futures import ThreadPoolExecutor
import re


class TestRoleManager(TestCase):
    def get_role_manager(self):
        return default_role_manager.RoleManager(max_hierarchy_level=10)

    def test_role(self):
        rm = self.get_role_manager()
        rm.add_link("u1", "g1")
        rm.add_link("u2", "g1")
        rm.add_link("u3", "g2")
        rm.add_link("u4", "g2")
        rm.add_link("u4", "g3")
        rm.add_link("g1", "g3")

        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2

        self.assertTrue(rm.has_link("u1", "u1"))
        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertTrue(rm.has_link("u1", "g3"))
        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))
        self.assertTrue(rm.has_link("u2", "g3"))
        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertTrue(rm.has_link("u3", "g2"))
        self.assertFalse(rm.has_link("u3", "g3"))
        self.assertFalse(rm.has_link("u4", "g1"))
        self.assertTrue(rm.has_link("u4", "g2"))
        self.assertTrue(rm.has_link("u4", "g3"))

        self.assertEqual(rm.get_roles("u1"), ["g1"])
        self.assertEqual(rm.get_roles("u2"), ["g1"])
        self.assertEqual(rm.get_roles("u3"), ["g2"])
        self.assertEqual(sorted(rm.get_roles("u4")), sorted(["g2", "g3"]))
        self.assertEqual(rm.get_roles("g1"), ["g3"])
        self.assertEqual(rm.get_roles("g2"), [])
        self.assertEqual(rm.get_roles("g3"), [])

        rm.delete_link("g1", "g3")
        rm.delete_link("u4", "g2")

        # Current role inheritance tree after deleting the links:
        #             g3    g2
        #               \     \
        #          g1    u4    u3
        #         /  \
        #       u1    u2

        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u1", "g3"))
        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))
        self.assertFalse(rm.has_link("u2", "g3"))
        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertTrue(rm.has_link("u3", "g2"))
        self.assertFalse(rm.has_link("u3", "g3"))
        self.assertFalse(rm.has_link("u4", "g1"))
        self.assertFalse(rm.has_link("u4", "g2"))
        self.assertTrue(rm.has_link("u4", "g3"))

        self.assertEqual(rm.get_roles("u1"), ["g1"])
        self.assertEqual(rm.get_roles("u2"), ["g1"])
        self.assertEqual(rm.get_roles("u3"), ["g2"])
        self.assertEqual(rm.get_roles("u4"), ["g3"])
        self.assertEqual(rm.get_roles("g1"), [])
        self.assertEqual(rm.get_roles("g2"), [])
        self.assertEqual(rm.get_roles("g3"), [])

        rm.clear()

        match_fn = lambda name1, name2: True if re.match("^" + name2 + "$", name1) else False

        rm.add_matching_func(match_fn)

        rm.add_link("u2", r"g\d+")
        rm.add_link(r"u\d+", "any_user")
        rm.add_link(r"g\d+", "any_group")
        rm.add_link("u1", "g1")

        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertTrue(rm.has_link("u1", "any_user"))
        self.assertTrue(rm.has_link("u1", "any_group"))

        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertTrue(rm.has_link("u2", "g2"))
        self.assertTrue(rm.has_link("u2", "any_user"))
        self.assertTrue(rm.has_link("u2", "any_group"))

        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertFalse(rm.has_link("u3", "g2"))
        self.assertTrue(rm.has_link("u3", "any_user"))
        self.assertFalse(rm.has_link("u3", "any_group"))

        self.assertTrue(rm.has_link("g1", "any_group"))
        self.assertTrue(rm.has_link("g2", "any_group"))

        self.assertEqual(sorted(rm.get_roles("u1")), sorted(["g1", "any_user"]))
        self.assertEqual(sorted(rm.get_roles("u2")), sorted(["g2", "g1", r"g\d+", "any_user"]))
        self.assertEqual(rm.get_roles(r"u\d+"), ["any_user"])
        self.assertEqual(rm.get_roles("u3"), ["any_user"])
        self.assertEqual(rm.get_roles("g1"), ["any_group"])
        self.assertEqual(rm.get_roles("g2"), ["any_group"])

        rm.delete_link(r"u\d+", "any_user")
        rm.delete_link(r"g\d+", "any_group")
        rm.delete_link("u1", "g1")
        rm.add_link("u1", "g2")

        self.assertEqual(rm.get_roles("u1"), ["g2"])

        rm.clear()

        rm.add_link("alice", "location_1/department_1")
        rm.add_link("location_1/.*", "all_departments")

        self.assertFalse(rm.has_link("alice", "location_1/department_2"))

    def test_clear(self):
        rm = self.get_role_manager()
        rm.add_link("u1", "g1")
        rm.add_link("u2", "g1")
        rm.add_link("u3", "g2")
        rm.add_link("u4", "g2")
        rm.add_link("u4", "g3")
        rm.add_link("g1", "g3")

        # Current role inheritance tree:
        #             g3    g2
        #            /  \  /  \
        #          g1    u4    u3
        #         /  \
        #       u1    u2

        rm.clear()

        # All data is cleared.
        # No role inheritance now.

        self.assertFalse(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u1", "g3"))
        self.assertFalse(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))
        self.assertFalse(rm.has_link("u2", "g3"))
        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertFalse(rm.has_link("u3", "g2"))
        self.assertFalse(rm.has_link("u3", "g3"))
        self.assertFalse(rm.has_link("u4", "g1"))
        self.assertFalse(rm.has_link("u4", "g2"))
        self.assertFalse(rm.has_link("u4", "g3"))

    def test_matching_func(self):
        rm = self.get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link("u1", "g1")
        rm.add_link("u3", "g2")
        rm.add_link("u3", "g3")
        rm.add_link(r"u\d+", "g2")

        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertTrue(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u1", "g3"))

        self.assertFalse(rm.has_link("u2", "g1"))
        self.assertTrue(rm.has_link("u2", "g2"))
        self.assertFalse(rm.has_link("u2", "g3"))

        self.assertFalse(rm.has_link("u3", "g1"))
        self.assertTrue(rm.has_link("u3", "g2"))
        self.assertTrue(rm.has_link("u3", "g3"))

    def test_one_to_many(self):
        rm = self.get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link("u1", r"g\d+")
        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertTrue(rm.has_link("u1", "g2"))
        self.assertFalse(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))

    def test_many_to_one(self):
        rm = self.get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link(r"u\d+", "g1")
        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertFalse(rm.has_link("u1", "g2"))
        self.assertTrue(rm.has_link("u2", "g1"))
        self.assertFalse(rm.has_link("u2", "g2"))

    def test_matching_func_order(self):
        rm = self.get_role_manager()
        rm.add_matching_func(regex_match_func)

        rm.add_link(r"g\d+", "root")
        rm.add_link("u1", "g1")
        self.assertTrue(rm.has_link("u1", "root"))

        rm.clear()

        rm.add_link("u1", "g1")
        rm.add_link(r"g\d+", "root")
        self.assertTrue(rm.has_link("u1", "root"))

        rm.clear()

        rm.add_link("u1", r"g\d+")
        rm.add_link("g1", "root")
        self.assertTrue(rm.has_link("u1", "root"))

        rm.clear()

        rm.add_link("g1", "root")
        rm.add_link("u1", r"g\d+")
        self.assertTrue(rm.has_link("u1", "root"))

    def test_concurrent_has_link_with_matching_func(self):
        def matching_func(*args):
            time.sleep(0.01)
            return regex_match_func(*args)

        rm = self.get_role_manager()
        rm.add_matching_func(matching_func)
        rm.add_link(r"u\d+", "users")

        def test_has_link(role):
            return rm.has_link(role, "users")

        executor = ThreadPoolExecutor(10)
        futures = [executor.submit(test_has_link, "u" + str(i)) for i in range(10)]
        for future in futures:
            self.assertTrue(future.result())

    def test_delete_link_without_matching_func(self):
        rm = self.get_role_manager()
        rm.add_matching_func(None)
        rm.add_link("u*", "g1")
        rm.add_link("u1", "g2")
        rm.add_link("g1", "g*")
        self.assertFalse(rm.has_link("u1", "g1"))

        rm.delete_link("u*", "g1")

        self.assertFalse(rm.has_link("u*", "g1"))
        self.assertFalse(rm.has_link("u*", "g*"))
        self.assertTrue(rm.has_link("u1", "g2"))
        self.assertTrue(rm.has_link("g1", "g*"))
        self.assertEqual(rm.get_roles("u*"), [])
        self.assertEqual(rm.get_users("g1"), [])


class TestDomainManager(TestRoleManager):
    def get_role_manager(self):
        return default_role_manager.DomainManager(max_hierarchy_level=10)

    def test_domain_role(self):
        rm = self.get_role_manager()
        rm.add_link("u1", "g1", "domain1")
        rm.add_link("u2", "g1", "domain1")
        rm.add_link("u3", "admin", "domain2")
        rm.add_link("u4", "admin", "domain2")
        rm.add_link("u4", "admin", "domain1")
        rm.add_link("g1", "admin", "domain1")

        # Current role inheritance tree:
        #       domain1:admin    domain2:admin
        #            /       \  /       \
        #      domain1:g1     u4         u3
        #         /  \
        #       u1    u2

        self.assertTrue(rm.has_link("u1", "g1", "domain1"))
        self.assertFalse(rm.has_link("u1", "g1", "domain2"))
        self.assertTrue(rm.has_link("u1", "admin", "domain1"))
        self.assertFalse(rm.has_link("u1", "admin", "domain2"))

        self.assertTrue(rm.has_link("u2", "g1", "domain1"))
        self.assertFalse(rm.has_link("u2", "g1", "domain2"))
        self.assertTrue(rm.has_link("u2", "admin", "domain1"))
        self.assertFalse(rm.has_link("u2", "admin", "domain2"))

        self.assertFalse(rm.has_link("u3", "g1", "domain1"))
        self.assertFalse(rm.has_link("u3", "g1", "domain2"))
        self.assertFalse(rm.has_link("u3", "admin", "domain1"))
        self.assertTrue(rm.has_link("u3", "admin", "domain2"))

        self.assertFalse(rm.has_link("u4", "g1", "domain1"))
        self.assertFalse(rm.has_link("u4", "g1", "domain2"))
        self.assertTrue(rm.has_link("u4", "admin", "domain1"))
        self.assertTrue(rm.has_link("u4", "admin", "domain2"))

        rm.clear()
        match_fn = lambda name1, name2: True if re.match("^" + name2 + "$", name1) else False

        rm.add_domain_matching_func(match_fn)
        rm.add_link("alice", "user", ".*")
        rm.add_link("user", "users", "domain1")

        self.assertTrue(rm.has_link("alice", "user", "domain1"))
        self.assertTrue(rm.has_link("alice", "users", "domain1"))
        self.assertTrue(rm.has_link("alice", "user", "domain2"))
        self.assertFalse(rm.has_link("alice", "users", "domain2"))

    def test_delete_link_without_matching_func_across_domains(self):
        rm = self.get_role_manager()
        rm.add_matching_func(None)
        rm.add_domain_matching_func(key_match)
        rm.add_link("alice", "admin", "*")
        rm.add_link("bob", "admin", "*")
        domains = ["d1", "d2", "d3"]
        for d in domains:
            self.assertTrue(rm.has_link("alice", "admin", d))

        rm.delete_link("alice", "admin", "*")

        for d in domains:
            self.assertFalse(rm.has_link("alice", "admin", d))
            self.assertTrue(rm.has_link("bob", "admin", d))
        self.assertFalse(rm.has_link("alice", "admin", "d4"))