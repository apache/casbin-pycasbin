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

from unittest import IsolatedAsyncioTestCase

import casbin
from casbin.constant.constants import DOMAIN_INDEX
from tests.test_enforcer import get_examples, TestCaseBase


class TestRbacApi(TestCaseBase):
    def test_get_roles_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        self.assertEqual(e.get_roles_for_user("alice"), ["data2_admin"])
        self.assertEqual(e.get_roles_for_user("bob"), [])
        self.assertEqual(e.get_roles_for_user("data2_admin"), [])
        self.assertEqual(e.get_roles_for_user("non_exist"), [])

    def test_get_users_for_role(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        self.assertEqual(e.get_users_for_role("data2_admin"), ["alice"])

    def test_has_role_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

        self.assertTrue(e.has_role_for_user("alice", "data2_admin"))
        self.assertFalse(e.has_role_for_user("alice", "data1_admin"))

    def test_add_role_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.add_role_for_user("alice", "data1_admin")
        self.assertEqual(
            sorted(e.get_roles_for_user("alice")),
            sorted(["data2_admin", "data1_admin"]),
        )

    def test_delete_role_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.add_role_for_user("alice", "data1_admin")
        self.assertEqual(
            sorted(e.get_roles_for_user("alice")),
            sorted(["data2_admin", "data1_admin"]),
        )

        e.delete_role_for_user("alice", "data1_admin")
        self.assertEqual(e.get_roles_for_user("alice"), ["data2_admin"])

    def test_delete_roles_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.delete_roles_for_user("alice")
        self.assertEqual(e.get_roles_for_user("alice"), [])

    def test_delete_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.delete_user("alice")
        self.assertEqual(e.get_roles_for_user("alice"), [])

    def test_delete_role(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        e.delete_role("data2_admin")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_delete_permission(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        e.delete_permission("read")
        self.assertFalse(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("alice", "write"))
        self.assertFalse(e.enforce("bob", "read"))
        self.assertTrue(e.enforce("bob", "write"))

    def test_add_permission_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        e.delete_permission("read")
        e.add_permission_for_user("bob", "read")
        self.assertTrue(e.enforce("bob", "read"))
        self.assertTrue(e.enforce("bob", "write"))

    def test_delete_permission_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        e.add_permission_for_user("bob", "read")

        self.assertTrue(e.enforce("bob", "read"))
        e.delete_permission_for_user("bob", "read")
        self.assertFalse(e.enforce("bob", "read"))
        self.assertTrue(e.enforce("bob", "write"))

    def test_delete_permissions_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        e.delete_permissions_for_user("bob")

        self.assertTrue(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("bob", "read"))
        self.assertFalse(e.enforce("bob", "write"))

    def test_get_permissions_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        self.assertEqual(e.get_permissions_for_user("alice"), [["alice", "read"]])

    def test_has_permission_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        self.assertTrue(e.has_permission_for_user("alice", *["read"]))
        self.assertFalse(e.has_permission_for_user("alice", *["write"]))
        self.assertFalse(e.has_permission_for_user("bob", *["read"]))
        self.assertTrue(e.has_permission_for_user("bob", *["write"]))

    def test_enforce_implicit_roles_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )

        self.assertEqual(
            sorted(e.get_permissions_for_user("alice")),
            sorted([["alice", "data1", "read"]]),
        )
        self.assertEqual(
            sorted(e.get_permissions_for_user("bob")),
            sorted([["bob", "data2", "write"]]),
        )

        self.assertEqual(
            sorted(e.get_implicit_roles_for_user("alice")),
            sorted(
                ["admin", "data1_admin", "data2_admin"],
            ),
        )
        self.assertTrue(e.get_implicit_roles_for_user("bob") == [])

    def test_enforce_implicit_roles_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_hierarchy_with_domains_policy.csv"),
        )

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["role:global_admin"])
        self.assertEqual(
            sorted(e.get_implicit_roles_for_user("alice", "domain1")),
            sorted(["role:global_admin", "role:reader", "role:writer"]),
        )

    def test_enforce_implicit_permissions_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )

        self.assertEqual(
            sorted(e.get_permissions_for_user("alice")),
            sorted([["alice", "data1", "read"]]),
        )
        self.assertEqual(
            sorted(e.get_permissions_for_user("bob")),
            sorted([["bob", "data2", "write"]]),
        )
        self.assertEqual(
            sorted(e.get_implicit_permissions_for_user("alice")),
            sorted(
                [
                    ["alice", "data1", "read"],
                    ["data1_admin", "data1", "read"],
                    ["data1_admin", "data1", "write"],
                    ["data2_admin", "data2", "read"],
                    ["data2_admin", "data2", "write"],
                ]
            ),
        )
        self.assertEqual(
            sorted(e.get_implicit_permissions_for_user("bob")),
            sorted([["bob", "data2", "write"]]),
        )

    def test_implicit_permissions_api_does_not_expose_internal_rules(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )

        permissions = e.get_implicit_permissions_for_user("alice")
        for permission in permissions:
            permission[0] = "alice"

        self.assertEqual(
            sorted(e.get_policy()),
            sorted(
                [
                    ["alice", "data1", "read"],
                    ["bob", "data2", "write"],
                    ["data2_admin", "data2", "read"],
                    ["data2_admin", "data2", "write"],
                ]
            ),
        )
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_enforce_implicit_permissions_api_with_multiple_policy(self):
        e = self.get_enforcer(
            get_examples("rbac_with_multiple_policy_model.conf"),
            get_examples("rbac_with_multiple_policy_policy.csv"),
        )

        self.assertEqual(
            sorted(e.get_named_implicit_permissions_for_user("p", "alice")),
            sorted(
                [
                    ["user", "/data", "GET"],
                    ["admin", "/data", "POST"],
                ]
            ),
        )
        self.assertEqual(
            sorted(e.get_named_implicit_permissions_for_user("p2", "alice")),
            sorted(
                [
                    ["user", "view"],
                    ["admin", "create"],
                ]
            ),
        )

    def test_enforce_implicit_permissions_api_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_hierarchy_with_domains_policy.csv"),
        )

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["role:global_admin"])
        self.assertEqual(
            sorted(e.get_implicit_roles_for_user("alice", "domain1")),
            sorted(["role:global_admin", "role:reader", "role:writer"]),
        )
        self.assertEqual(
            sorted(e.get_implicit_permissions_for_user("alice", "domain1")),
            sorted(
                [
                    ["alice", "domain1", "data2", "read"],
                    ["role:reader", "domain1", "data1", "read"],
                    ["role:writer", "domain1", "data1", "write"],
                ]
            ),
        )
        self.assertEqual(e.get_implicit_permissions_for_user("bob", "domain1"), [])

    def test_enforce_implicit_permissions_api_with_domain_matching_function(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_and_policy_pattern_model.conf"),
            get_examples("rbac_with_domain_and_policy_pattern_policy.csv"),
        )

        e.get_role_manager().add_domain_matching_func(casbin.util.key_match2_func)

        self.assertEqual(
            e.get_implicit_permissions_for_user("alice", "domain.3"),
            [["user", "domain.*", "data3", "read"]],
        )

        self.assertEqual(
            e.get_implicit_permissions_for_user("alice", "domain.1"),
            [
                ["user", "domain.*", "data3", "read"],
                ["user", "domain.1", "data2", "read"],
                ["user", "domain.1", "data2", "write"],
            ],
        )

        self.assertEqual(
            e.get_implicit_permissions_for_user("bob", "domain.3"),
            [["admin", "domain.*", "data1", "read"]],
        )

        self.assertEqual(
            e.get_implicit_permissions_for_user("bob", "domain.2"),
            [],
        )

        self.assertEqual(sorted(e.get_implicit_permissions_for_user("bob", "domain.1")), [])

    def test_enforce_implicit_permissions_api_with_domain_ignore_domain_policies_filter(
        self,
    ):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_without_policy_matcher.conf"),
            get_examples("rbac_with_hierarchy_without_policy_domains.csv"),
        )

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["role:global_admin"])
        self.assertEqual(
            sorted(e.get_implicit_roles_for_user("alice", "domain1")),
            sorted(["role:global_admin", "role:reader", "role:writer"]),
        )
        self.assertEqual(
            sorted(e.get_implicit_permissions_for_user("alice", "domain1", filter_policy_dom=False)),
            sorted(
                [
                    ["alice", "data2", "read"],
                    ["role:reader", "data1", "read"],
                    ["role:writer", "data1", "write"],
                ]
            ),
        )
        self.assertEqual(e.get_implicit_permissions_for_user("bob", "domain1"), [])

    def test_enforce_get_users_in_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        print(e.get_users_for_role_in_domain("admin", "domain1"))
        self.assertTrue(e.get_users_for_role_in_domain("admin", "domain1") == ["alice"])
        self.assertTrue(e.get_users_for_role_in_domain("non_exist", "domain1") == [])
        self.assertTrue(e.get_users_for_role_in_domain("admin", "domain2") == ["bob"])
        self.assertTrue(e.get_users_for_role_in_domain("non_exist", "domain2") == [])
        e.delete_roles_for_user_in_domain("alice", "admin", "domain1")
        e.add_role_for_user_in_domain("bob", "admin", "domain1")
        self.assertTrue(e.get_users_for_role_in_domain("admin", "domain1") == ["bob"])
        self.assertTrue(e.get_users_for_role_in_domain("non_exist", "domain1") == [])
        self.assertTrue(e.get_users_for_role_in_domain("admin", "domain2") == ["bob"])
        self.assertTrue(e.get_users_for_role_in_domain("non_exist", "domain2") == [])

    def test_enforce_user_api_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertEqual(e.get_users_for_role_in_domain("admin", "domain1"), ["alice"])
        self.assertEqual(e.get_users_for_role_in_domain("non_exist", "domain1"), [])
        self.assertEqual(e.get_users_for_role_in_domain("admin", "domain2"), ["bob"])
        self.assertEqual(e.get_users_for_role_in_domain("non_exist", "domain2"), [])

        e.delete_roles_for_user_in_domain("alice", "admin", "domain1")
        e.add_role_for_user_in_domain("bob", "admin", "domain1")

        self.assertEqual(e.get_users_for_role_in_domain("admin", "domain1"), ["bob"])
        self.assertEqual(e.get_users_for_role_in_domain("non_exist", "domain1"), [])
        self.assertEqual(e.get_users_for_role_in_domain("admin", "domain2"), ["bob"])
        self.assertEqual(e.get_users_for_role_in_domain("non_exist", "domain2"), [])

    def test_enforce_get_roles_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain1"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("admin", "domain1"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("non_exist", "domain1"), [])

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain2"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("admin", "domain2"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("non_exist", "domain2"), [])

        e.delete_roles_for_user_in_domain("alice", "admin", "domain1")
        e.add_role_for_user_in_domain("bob", "admin", "domain1")

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain1"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain1"), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("admin", "domain1"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("non_exist", "domain1"), [])

        self.assertEqual(e.get_roles_for_user_in_domain("alice", "domain2"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertEqual(e.get_roles_for_user_in_domain("admin", "domain2"), [])
        self.assertEqual(e.get_roles_for_user_in_domain("non_exist", "domain2"), [])

    def test_get_all_roles_by_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertEqual(e.get_all_roles_by_domain("domain1"), ["admin"])
        self.assertEqual(e.get_all_roles_by_domain("domain2"), ["admin"])

        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy2.csv"),
        )
        self.assertEqual(e.get_all_roles_by_domain("domain1"), ["admin"])
        self.assertEqual(e.get_all_roles_by_domain("domain2"), ["admin"])
        self.assertEqual(e.get_all_roles_by_domain("domain3"), ["user"])

    def test_implicit_user_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )

        self.assertEqual(["alice"], e.get_implicit_users_for_permission("data1", "read"))
        self.assertEqual(["alice"], e.get_implicit_users_for_permission("data1", "write"))
        self.assertEqual(["alice"], e.get_implicit_users_for_permission("data2", "read"))
        self.assertEqual(["alice", "bob"], e.get_implicit_users_for_permission("data2", "write"))

    def test_get_implicit_users_for_resource(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )

        self.assertEqual([["alice", "data1", "read"]], e.get_implicit_users_for_resource("data1"))
        self.assertEqual(
            [
                ["bob", "data2", "write"],
                ["alice", "data2", "read"],
                ["alice", "data2", "write"],
            ],
            e.get_implicit_users_for_resource("data2"),
        )

        # test duplicate permissions
        e.add_grouping_policy("alice", "data2_admin_2")
        e.add_policies([["data2_admin_2", "data2", "read"], ["data2_admin_2", "data2", "write"]])
        self.assertEqual(
            [
                ["bob", "data2", "write"],
                ["alice", "data2", "read"],
                ["alice", "data2", "write"],
            ],
            e.get_implicit_users_for_resource("data2"),
        )

    def test_get_implicit_users_for_resource_by_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )

        self.assertEqual(
            [["alice", "domain1", "data1", "read"], ["alice", "domain1", "data1", "write"]],
            e.get_implicit_users_for_resource_by_domain("data1", "domain1"),
        )
        self.assertEqual(
            [],
            e.get_implicit_users_for_resource_by_domain("data2", "domain1"),
        )
        self.assertEqual(
            [["bob", "domain2", "data2", "read"], ["bob", "domain2", "data2", "write"]],
            e.get_implicit_users_for_resource_by_domain("data2", "domain2"),
        )

    def test_domain_match_model(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_pattern_model.conf"),
            get_examples("rbac_with_domain_pattern_policy.csv"),
        )
        e.get_role_manager().add_domain_matching_func(casbin.util.key_match2_func)

        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "write"))
        self.assertTrue(e.enforce("alice", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("alice", "domain2", "data2", "write"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "read"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "write"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "write"))

    def test_set_field_index(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertEqual(e.get_field_index("p", DOMAIN_INDEX), 1)
        e.set_field_index("p", DOMAIN_INDEX, 2)
        self.assertEqual(e.get_field_index("p", DOMAIN_INDEX), 2)


class TestRbacApiSynced(TestRbacApi):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.SyncedEnforcer(
            model,
            adapter,
        )


class TestRbacApiAsync(IsolatedAsyncioTestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.AsyncEnforcer(
            model,
            adapter,
        )

    async def test_get_roles_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()
        self.assertEqual(await e.get_roles_for_user("alice"), ["data2_admin"])
        self.assertEqual(await e.get_roles_for_user("bob"), [])
        self.assertEqual(await e.get_roles_for_user("data2_admin"), [])
        self.assertEqual(await e.get_roles_for_user("non_exist"), [])

    async def test_get_users_for_role(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        self.assertEqual(await e.get_users_for_role("data2_admin"), ["alice"])

    async def test_has_role_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        self.assertTrue(await e.has_role_for_user("alice", "data2_admin"))
        self.assertFalse(await e.has_role_for_user("alice", "data1_admin"))

    async def test_add_role_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        await e.add_role_for_user("alice", "data1_admin")
        self.assertEqual(
            sorted(await e.get_roles_for_user("alice")),
            sorted(["data2_admin", "data1_admin"]),
        )

    async def test_delete_role_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        await e.add_role_for_user("alice", "data1_admin")
        self.assertEqual(
            sorted(await e.get_roles_for_user("alice")),
            sorted(["data2_admin", "data1_admin"]),
        )

        await e.delete_role_for_user("alice", "data1_admin")
        self.assertEqual(await e.get_roles_for_user("alice"), ["data2_admin"])

    async def test_delete_roles_for_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        await e.delete_roles_for_user("alice")
        self.assertEqual(await e.get_roles_for_user("alice"), [])

    async def test_delete_user(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        await e.delete_user("alice")
        self.assertEqual(await e.get_roles_for_user("alice"), [])

    async def test_delete_role(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        await e.delete_role("data2_admin")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    async def test_delete_permission(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        await e.delete_permission("read")
        self.assertFalse(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("alice", "write"))
        self.assertFalse(e.enforce("bob", "read"))
        self.assertTrue(e.enforce("bob", "write"))

    async def test_add_permission_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        await e.delete_permission("read")
        await e.add_permission_for_user("bob", "read")
        self.assertTrue(e.enforce("bob", "read"))
        self.assertTrue(e.enforce("bob", "write"))

    async def test_delete_permission_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        await e.add_permission_for_user("bob", "read")

        self.assertTrue(e.enforce("bob", "read"))
        await e.delete_permission_for_user("bob", "read")
        self.assertFalse(e.enforce("bob", "read"))
        self.assertTrue(e.enforce("bob", "write"))

    async def test_delete_permissions_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        await e.delete_permissions_for_user("bob")

        self.assertTrue(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("bob", "read"))
        self.assertFalse(e.enforce("bob", "write"))

    async def test_get_permissions_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_permissions_for_user("alice"), [["alice", "read"]])

    async def test_has_permission_for_user(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(await e.has_permission_for_user("alice", *["read"]))
        self.assertFalse(await e.has_permission_for_user("alice", *["write"]))
        self.assertFalse(await e.has_permission_for_user("bob", *["read"]))
        self.assertTrue(await e.has_permission_for_user("bob", *["write"]))

    async def test_enforce_implicit_roles_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(
            sorted(await e.get_permissions_for_user("alice")),
            sorted([["alice", "data1", "read"]]),
        )
        self.assertEqual(
            sorted(await e.get_permissions_for_user("bob")),
            sorted([["bob", "data2", "write"]]),
        )

        self.assertEqual(
            sorted(await e.get_implicit_roles_for_user("alice")),
            sorted(
                ["admin", "data1_admin", "data2_admin"],
            ),
        )
        self.assertTrue(await e.get_implicit_roles_for_user("bob") == [])

    async def test_enforce_implicit_roles_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_hierarchy_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain1"), ["role:global_admin"])
        self.assertEqual(
            sorted(await e.get_implicit_roles_for_user("alice", "domain1")),
            sorted(["role:global_admin", "role:reader", "role:writer"]),
        )

    async def test_enforce_implicit_permissions_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(
            sorted(await e.get_permissions_for_user("alice")),
            sorted([["alice", "data1", "read"]]),
        )
        self.assertEqual(
            sorted(await e.get_permissions_for_user("bob")),
            sorted([["bob", "data2", "write"]]),
        )
        self.assertEqual(
            sorted(await e.get_implicit_permissions_for_user("alice")),
            sorted(
                [
                    ["alice", "data1", "read"],
                    ["data1_admin", "data1", "read"],
                    ["data1_admin", "data1", "write"],
                    ["data2_admin", "data2", "read"],
                    ["data2_admin", "data2", "write"],
                ]
            ),
        )
        self.assertEqual(
            sorted(await e.get_implicit_permissions_for_user("bob")),
            sorted([["bob", "data2", "write"]]),
        )

    async def test_enforce_implicit_permissions_api_with_multiple_policy(self):
        e = self.get_enforcer(
            get_examples("rbac_with_multiple_policy_model.conf"),
            get_examples("rbac_with_multiple_policy_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(
            sorted(await e.get_named_implicit_permissions_for_user("p", "alice")),
            sorted(
                [
                    ["user", "/data", "GET"],
                    ["admin", "/data", "POST"],
                ]
            ),
        )
        self.assertEqual(
            sorted(await e.get_named_implicit_permissions_for_user("p2", "alice")),
            sorted(
                [
                    ["user", "view"],
                    ["admin", "create"],
                ]
            ),
        )

    async def test_enforce_implicit_permissions_api_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_hierarchy_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain1"), ["role:global_admin"])
        self.assertEqual(
            sorted(await e.get_implicit_roles_for_user("alice", "domain1")),
            sorted(["role:global_admin", "role:reader", "role:writer"]),
        )
        self.assertEqual(
            sorted(await e.get_implicit_permissions_for_user("alice", "domain1")),
            sorted(
                [
                    ["alice", "domain1", "data2", "read"],
                    ["role:reader", "domain1", "data1", "read"],
                    ["role:writer", "domain1", "data1", "write"],
                ]
            ),
        )
        self.assertEqual(await e.get_implicit_permissions_for_user("bob", "domain1"), [])

    async def test_enforce_implicit_permissions_api_with_domain_matching_function(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_and_policy_pattern_model.conf"),
            get_examples("rbac_with_domain_and_policy_pattern_policy.csv"),
        )
        await e.load_policy()

        e.get_role_manager().add_domain_matching_func(casbin.util.key_match2_func)

        self.assertEqual(
            await e.get_implicit_permissions_for_user("alice", "domain.3"),
            [["user", "domain.*", "data3", "read"]],
        )

        self.assertEqual(
            await e.get_implicit_permissions_for_user("alice", "domain.1"),
            [
                ["user", "domain.*", "data3", "read"],
                ["user", "domain.1", "data2", "read"],
                ["user", "domain.1", "data2", "write"],
            ],
        )

        self.assertEqual(
            await e.get_implicit_permissions_for_user("bob", "domain.3"),
            [["admin", "domain.*", "data1", "read"]],
        )

        self.assertEqual(
            await e.get_implicit_permissions_for_user("bob", "domain.2"),
            [],
        )

        self.assertEqual(sorted(await e.get_implicit_permissions_for_user("bob", "domain.1")), [])

    async def test_enforce_implicit_permissions_api_with_domain_ignore_domain_policies_filter(
        self,
    ):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_without_policy_matcher.conf"),
            get_examples("rbac_with_hierarchy_without_policy_domains.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain1"), ["role:global_admin"])
        self.assertEqual(
            sorted(await e.get_implicit_roles_for_user("alice", "domain1")),
            sorted(["role:global_admin", "role:reader", "role:writer"]),
        )
        self.assertEqual(
            sorted(await e.get_implicit_permissions_for_user("alice", "domain1", filter_policy_dom=False)),
            sorted(
                [
                    ["alice", "data2", "read"],
                    ["role:reader", "data1", "read"],
                    ["role:writer", "data1", "write"],
                ]
            ),
        )
        self.assertEqual(await e.get_implicit_permissions_for_user("bob", "domain1"), [])

    async def test_enforce_get_users_in_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(await e.get_users_for_role_in_domain("admin", "domain1") == ["alice"])
        self.assertTrue(await e.get_users_for_role_in_domain("non_exist", "domain1") == [])
        self.assertTrue(await e.get_users_for_role_in_domain("admin", "domain2") == ["bob"])
        self.assertTrue(await e.get_users_for_role_in_domain("non_exist", "domain2") == [])
        await e.delete_roles_for_user_in_domain("alice", "admin", "domain1")
        await e.add_role_for_user_in_domain("bob", "admin", "domain1")
        self.assertTrue(await e.get_users_for_role_in_domain("admin", "domain1") == ["bob"])
        self.assertTrue(await e.get_users_for_role_in_domain("non_exist", "domain1") == [])
        self.assertTrue(await e.get_users_for_role_in_domain("admin", "domain2") == ["bob"])
        self.assertTrue(await e.get_users_for_role_in_domain("non_exist", "domain2") == [])

    async def test_enforce_user_api_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_users_for_role_in_domain("admin", "domain1"), ["alice"])
        self.assertEqual(await e.get_users_for_role_in_domain("non_exist", "domain1"), [])
        self.assertEqual(await e.get_users_for_role_in_domain("admin", "domain2"), ["bob"])
        self.assertEqual(await e.get_users_for_role_in_domain("non_exist", "domain2"), [])

        await e.delete_roles_for_user_in_domain("alice", "admin", "domain1")
        await e.add_role_for_user_in_domain("bob", "admin", "domain1")

        self.assertEqual(await e.get_users_for_role_in_domain("admin", "domain1"), ["bob"])
        self.assertEqual(await e.get_users_for_role_in_domain("non_exist", "domain1"), [])
        self.assertEqual(await e.get_users_for_role_in_domain("admin", "domain2"), ["bob"])
        self.assertEqual(await e.get_users_for_role_in_domain("non_exist", "domain2"), [])

    async def test_enforce_get_roles_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain1"), ["admin"])
        self.assertEqual(await e.get_roles_for_user_in_domain("bob", "domain1"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("admin", "domain1"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("non_exist", "domain1"), [])

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain2"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertEqual(await e.get_roles_for_user_in_domain("admin", "domain2"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("non_exist", "domain2"), [])

        await e.delete_roles_for_user_in_domain("alice", "admin", "domain1")
        await e.add_role_for_user_in_domain("bob", "admin", "domain1")

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain1"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("bob", "domain1"), ["admin"])
        self.assertEqual(await e.get_roles_for_user_in_domain("admin", "domain1"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("non_exist", "domain1"), [])

        self.assertEqual(await e.get_roles_for_user_in_domain("alice", "domain2"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("bob", "domain2"), ["admin"])
        self.assertEqual(await e.get_roles_for_user_in_domain("admin", "domain2"), [])
        self.assertEqual(await e.get_roles_for_user_in_domain("non_exist", "domain2"), [])

    async def test_get_all_roles_by_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_all_roles_by_domain("domain1"), ["admin"])
        self.assertEqual(await e.get_all_roles_by_domain("domain2"), ["admin"])

        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy2.csv"),
        )
        await e.load_policy()

        self.assertEqual(await e.get_all_roles_by_domain("domain1"), ["admin"])
        self.assertEqual(await e.get_all_roles_by_domain("domain2"), ["admin"])
        self.assertEqual(await e.get_all_roles_by_domain("domain3"), ["user"])

    async def test_implicit_user_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_with_hierarchy_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(["alice"], await e.get_implicit_users_for_permission("data1", "read"))
        self.assertEqual(["alice"], await e.get_implicit_users_for_permission("data1", "write"))
        self.assertEqual(["alice"], await e.get_implicit_users_for_permission("data2", "read"))
        self.assertEqual(["alice", "bob"], await e.get_implicit_users_for_permission("data2", "write"))

    async def test_get_implicit_users_for_resource(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual([["alice", "data1", "read"]], await e.get_implicit_users_for_resource("data1"))
        result = await e.get_implicit_users_for_resource("data2")
        self.assertEqual(
            [
                ["bob", "data2", "write"],
                ["alice", "data2", "read"],
                ["alice", "data2", "write"],
            ],
            result,
        )

        # test duplicate permissions
        await e.add_grouping_policy("alice", "data2_admin_2")
        await e.add_policies([["data2_admin_2", "data2", "read"], ["data2_admin_2", "data2", "write"]])
        result = await e.get_implicit_users_for_resource("data2")
        self.assertEqual(
            [
                ["bob", "data2", "write"],
                ["alice", "data2", "read"],
                ["alice", "data2", "write"],
            ],
            result,
        )

    async def test_get_implicit_users_for_resource_by_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(
            [["alice", "domain1", "data1", "read"], ["alice", "domain1", "data1", "write"]],
            await e.get_implicit_users_for_resource_by_domain("data1", "domain1"),
        )
        self.assertEqual(
            [],
            await e.get_implicit_users_for_resource_by_domain("data2", "domain1"),
        )
        self.assertEqual(
            [["bob", "domain2", "data2", "read"], ["bob", "domain2", "data2", "write"]],
            await e.get_implicit_users_for_resource_by_domain("data2", "domain2"),
        )

    async def test_domain_match_model(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_pattern_model.conf"),
            get_examples("rbac_with_domain_pattern_policy.csv"),
        )
        await e.load_policy()

        e.get_role_manager().add_domain_matching_func(casbin.util.key_match2_func)

        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "write"))
        self.assertTrue(e.enforce("alice", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("alice", "domain2", "data2", "write"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "read"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "write"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "write"))

    async def test_set_field_index(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertEqual(await e.get_field_index("p", DOMAIN_INDEX), 1)
        await e.set_field_index("p", DOMAIN_INDEX, 2)
        self.assertEqual(await e.get_field_index("p", DOMAIN_INDEX), 2)
