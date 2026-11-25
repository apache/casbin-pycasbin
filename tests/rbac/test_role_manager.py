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
        self.assertEqual(sorted(rm.get_roles("u2")), sorted(["g1", r"g\d+", "any_user"]))
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


class TestDomainManager(TestRoleManager):
    def get_role_manager(self):
        return default_role_manager.DomainManager(max_hierarchy_level=10)

    def test_domain_role_manager_cache_limit(self):
        rm = default_role_manager.DomainManager(max_hierarchy_level=10, max_cached_role_managers=2)
        rm.add_link("u1", "g1", "domain1")
        rm.add_link("u2", "g2", "domain2")
        rm.add_link("u3", "g3", "domain3")

        self.assertTrue(rm.has_link("u1", "g1", "domain1"))
        self.assertTrue(rm.has_link("u2", "g2", "domain2"))
        self.assertTrue(rm.has_link("u3", "g3", "domain3"))
        self.assertEqual(len(rm.rm_map), 2)
        self.assertEqual(list(rm.rm_map.keys()), ["domain2", "domain3"])

        self.assertTrue(rm.has_link("u1", "g1", "domain1"))
        self.assertEqual(len(rm.rm_map), 2)
        self.assertEqual(list(rm.rm_map.keys()), ["domain3", "domain1"])

    def test_domain_role_manager_cache_unbounded(self):
        rm = default_role_manager.DomainManager(max_hierarchy_level=10, max_cached_role_managers=0)
        for i in range(5):
            rm.add_link(f"u{i}", f"g{i}", f"domain{i}")

        for i in range(5):
            self.assertTrue(rm.has_link(f"u{i}", f"g{i}", f"domain{i}"))
        self.assertEqual(len(rm.rm_map), 5)

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

    def test_conditional_domain_pattern_link_condition(self):
        deny = lambda *args: False
        allow = lambda *args: True

        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_domain_matching_func(key_match)

        rm.add_link("bob", "admin", "domain2")
        rm.add_link("alice", "admin", "domain*")
        rm.add_domain_link_condition_func("alice", "admin", "domain*", deny)
        rm.add_link("carol", "admin", "domain*")
        rm.add_domain_link_condition_func("carol", "admin", "domain*", allow)

        for domain in ["domain*", "domain1", "domain2"]:
            self.assertFalse(rm.has_link("alice", "admin", domain))
            self.assertTrue(rm.has_link("carol", "admin", domain))
        self.assertTrue(rm.has_link("bob", "admin", "domain2"))

        rm.add_domain_link_condition_func("dave", "admin", "domain9", deny)
        rm.add_link("dave", "admin", "domain9")
        self.assertFalse(rm.has_link("dave", "admin", "domain9"))

        param = lambda *args: len(args) == 1 and args[0] == "yes"
        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_link("alice", "admin", "domain*")
        rm.add_domain_link_condition_func("alice", "admin", "domain*", param)
        rm.set_domain_link_condition_func_params("alice", "admin", "domain*", "no")
        rm.add_link("carol", "admin", "domain*")
        rm.add_domain_link_condition_func("carol", "admin", "domain*", param)
        rm.set_domain_link_condition_func_params("carol", "admin", "domain*", "yes")
        rm.add_domain_matching_func(key_match)

        for domain in ["domain*", "domain1"]:
            self.assertFalse(rm.has_link("alice", "admin", domain))
            self.assertTrue(rm.has_link("carol", "admin", domain))

    def test_conditional_domain_link_condition_scope(self):
        param = lambda *args: len(args) == 1 and args[0] == "yes"
        deny = lambda *args: False

        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_link("alice", "admin", "domain1")
        rm.add_domain_link_condition_func("alice", "admin", "domain1", param)
        rm.set_domain_link_condition_func_params("alice", "admin", "domain1", "yes")
        rm.add_link("bob", "admin", "domain2")
        self.assertNotIn("alice", rm.rm_map["domain2"].all_roles)
        self.assertTrue(rm.has_link("alice", "admin", "domain1"))
        self.assertFalse(rm.has_link("alice", "admin", "domain2"))
        rm.set_domain_link_condition_func_params("alice", "admin", "domain1", "no")
        self.assertFalse(rm.has_link("alice", "admin", "domain1"))

        rm.set_domain_link_condition_func_params("carol", "admin", "domain3", "yes")
        rm.add_domain_link_condition_func("carol", "admin", "domain3", param)
        rm.add_link("carol", "admin", "domain3")
        self.assertTrue(rm.has_link("carol", "admin", "domain3"))

        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_link("bob", "admin", "domain1")
        rm.add_link("alice", "admin", "domain*")
        rm.add_domain_link_condition_func("alice", "admin", "domain*", deny)
        rm.add_domain_matching_func(key_match)
        for domain in ["domain*", "domain1"]:
            self.assertFalse(rm.has_link("alice", "admin", domain))
        self.assertTrue(rm.has_link("bob", "admin", "domain1"))

        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_domain_matching_func(key_match)
        rm.add_domain_link_condition_func("alice", "admin", "domain*", deny)
        rm.add_link("bob", "admin", "domain1")
        rm.add_link("alice", "admin", "domain*")
        for domain in ["domain*", "domain1"]:
            self.assertFalse(rm.has_link("alice", "admin", domain))
        rm.add_link("dave", "admin", "domain2")
        rm.add_domain_link_condition_func("dave", "admin", "domain2", deny)
        self.assertNotIn("dave", rm.rm_map["domain1"].all_roles)

    def test_domain_pattern_delete_link(self):
        rm = default_role_manager.DomainManager(10)
        rm.add_domain_matching_func(key_match)

        rm.add_link("alice", "admin", "*")
        rm.add_link("alice", "admin", "domain1")
        self.assertTrue(rm.has_link("alice", "admin", "domain1"))
        rm.delete_link("alice", "admin", "domain1")
        self.assertTrue(rm.has_link("alice", "admin", "domain1"))

        rm.add_link("bob", "admin", "domain2")
        self.assertTrue(rm.has_link("bob", "admin", "domain2"))
        rm.add_link("bob", "admin", "*")
        rm.delete_link("bob", "admin", "*")
        self.assertTrue(rm.has_link("bob", "admin", "domain2"))
        self.assertFalse(rm.has_link("bob", "admin", "domain1"))

        rm.add_link("carol", "admin", "domain3")
        rm.add_domain_matching_func(key_match)
        rm.delete_link("alice", "admin", "*")
        self.assertFalse(rm.has_link("alice", "admin", "domain1"))
        self.assertFalse(rm.has_link("alice", "admin", "domain3"))
        self.assertTrue(rm.has_link("bob", "admin", "domain2"))
        self.assertTrue(rm.has_link("carol", "admin", "domain3"))

        rm.delete_link("bob", "admin", "domain2")
        self.assertFalse(rm.has_link("bob", "admin", "domain2"))

    def test_conditional_domain_pattern_delete_link(self):
        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_domain_matching_func(key_match)

        rm.add_link("alice", "admin", "*")
        rm.add_link("alice", "admin", "domain1")
        rm.delete_link("alice", "admin", "domain1")
        rm.add_link("bob", "admin", "domain2")
        rm.add_link("bob", "admin", "*")
        rm.delete_link("bob", "admin", "*")
        rm.add_domain_matching_func(key_match)

        self.assertTrue(rm.has_link("alice", "admin", "domain1"))
        self.assertTrue(rm.has_link("alice", "admin", "domain2"))
        self.assertTrue(rm.has_link("bob", "admin", "domain2"))
        self.assertFalse(rm.has_link("bob", "admin", "domain1"))


class TestTemporaryRoles(TestCase):
    def test_queries_do_not_store_roles(self):
        rm = default_role_manager.RoleManager(10)
        rm.add_link("u1", "g1")
        rm.add_link("g1", "g2")
        roles = set(rm.all_roles)

        for i in range(100):
            self.assertFalse(rm.has_link("user%d" % i, "g1"))
            self.assertFalse(rm.has_link("u1", "role%d" % i))
            self.assertEqual(rm.get_roles("user%d" % i), [])
            self.assertEqual(rm.get_users("role%d" % i), [])
        self.assertTrue(rm.has_link("u1", "g2"))
        self.assertEqual(set(rm.all_roles), roles)

    def test_queries_with_matching_func_do_not_store_roles(self):
        rm = default_role_manager.RoleManager(10)
        rm.add_matching_func(regex_match_func)
        rm.add_link(r"u\d+", "g1")
        rm.add_link("alice", r"book/\d+")
        rm.add_link("book/1", "reader")
        roles = set(rm.all_roles)

        for i in range(100):
            self.assertTrue(rm.has_link("u%d" % i, "g1"))
            self.assertFalse(rm.has_link("x%d" % i, "g1"))
            self.assertTrue(rm.has_link("alice", "book/%d" % (i + 2)))
        self.assertTrue(rm.has_link("alice", "reader"))
        self.assertEqual(rm.get_roles("u7"), ["g1"])
        self.assertEqual(set(rm.all_roles), roles)
        for role in rm.all_roles.values():
            self.assertTrue(all(r.name in roles for r in role.roles))
            self.assertTrue(all(u.name in roles for u in role.users))

    def test_conditional_queries_do_not_store_roles(self):
        rm = default_role_manager.ConditionalRoleManager(10)
        rm.add_link("u1", "g1")
        roles = set(rm.all_roles)

        for i in range(100):
            self.assertFalse(rm.has_link("user%d" % i, "g1"))
            self.assertFalse(rm.has_link("u1", "role%d" % i))
        self.assertTrue(rm.has_link("u1", "g1"))
        self.assertEqual(set(rm.all_roles), roles)

        rm = default_role_manager.ConditionalDomainManager(10)
        rm.add_link("u1", "g1", "domain1")
        roles = set(rm.rm_map["domain1"].all_roles)
        for i in range(100):
            self.assertFalse(rm.has_link("user%d" % i, "g1", "domain1"))
        self.assertTrue(rm.has_link("u1", "g1", "domain1"))
        self.assertEqual(set(rm.rm_map["domain1"].all_roles), roles)
