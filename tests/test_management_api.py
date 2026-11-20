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

from functools import partial
from unittest import IsolatedAsyncioTestCase

import casbin
from tests.test_enforcer import get_examples, TestCaseBase


class TestManagementApi(TestCaseBase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.Enforcer(
            model,
            adapter,
        )

    def test_get_list(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
            # True,
        )

        self.assertEqual(e.get_all_subjects(), ["alice", "bob", "data2_admin"])
        self.assertEqual(e.get_all_objects(), ["data1", "data2"])
        self.assertEqual(e.get_all_actions(), ["read", "write"])
        self.assertEqual(e.get_all_roles(), ["data2_admin"])

    def test_get_list_with_domains(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
            # True,
        )

        self.assertEqual(e.get_all_subjects(), ["admin"])
        self.assertEqual(e.get_all_objects(), ["data1", "data2"])
        self.assertEqual(e.get_all_actions(), ["read", "write"])
        self.assertEqual(e.get_all_roles(), ["admin"])

    def test_get_policy_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
            ],
        )

        self.assertEqual(e.get_filtered_policy(0, "alice"), [["alice", "data1", "read"]])
        self.assertEqual(e.get_filtered_policy(0, "bob"), [["bob", "data2", "write"]])
        self.assertEqual(
            e.get_filtered_policy(0, "data2_admin"),
            [["data2_admin", "data2", "read"], ["data2_admin", "data2", "write"]],
        )
        self.assertEqual(e.get_filtered_policy(1, "data1"), [["alice", "data1", "read"]])
        self.assertEqual(
            e.get_filtered_policy(1, "data2"),
            [
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
            ],
        )
        self.assertEqual(
            e.get_filtered_policy(2, "read"),
            [["alice", "data1", "read"], ["data2_admin", "data2", "read"]],
        )
        self.assertEqual(
            e.get_filtered_policy(2, "write"),
            [["bob", "data2", "write"], ["data2_admin", "data2", "write"]],
        )
        self.assertEqual(
            e.get_filtered_policy(0, "data2_admin", "data2"),
            [["data2_admin", "data2", "read"], ["data2_admin", "data2", "write"]],
        )

        # Note: "" (empty string) in fieldValues means matching all values.
        self.assertEqual(
            e.get_filtered_policy(0, "data2_admin", "", "read"),
            [["data2_admin", "data2", "read"]],
        )
        self.assertEqual(
            e.get_filtered_policy(1, "data2", "write"),
            [["bob", "data2", "write"], ["data2_admin", "data2", "write"]],
        )

        self.assertTrue(e.has_policy(["alice", "data1", "read"]))
        self.assertTrue(e.has_policy(["bob", "data2", "write"]))
        self.assertFalse(e.has_policy(["alice", "data2", "read"]))
        self.assertFalse(e.has_policy(["bob", "data3", "write"]))
        self.assertEqual(e.get_grouping_policy(), [["alice", "data2_admin"]])
        self.assertEqual(e.get_filtered_grouping_policy(0, "alice"), [["alice", "data2_admin"]])
        self.assertEqual(e.get_filtered_grouping_policy(0, "bob"), [])
        self.assertEqual(e.get_filtered_grouping_policy(1, "data1_admin"), [])
        self.assertEqual(e.get_filtered_grouping_policy(1, "data2_admin"), [["alice", "data2_admin"]])
        # Note: "" (empty string) in fieldValues means matching all values.
        self.assertEqual(
            e.get_filtered_grouping_policy(0, "", "data2_admin"),
            [["alice", "data2_admin"]],
        )
        self.assertTrue(e.has_grouping_policy(["alice", "data2_admin"]))
        self.assertFalse(e.has_grouping_policy(["bob", "data2_admin"]))

    def test_update_filtered_policies(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )

        e.update_filtered_policies(
            [
                ["data2_admin", "data3", "read"],
                ["data2_admin", "data3", "write"],
            ],
            0,
            "data2_admin",
        )
        self.assertTrue(e.enforce("data2_admin", "data3", "write"))
        self.assertTrue(e.enforce("data2_admin", "data3", "read"))

    def test_get_policy_matching_function(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_and_policy_pattern_model.conf"),
            get_examples("rbac_with_domain_and_policy_pattern_policy.csv"),
        )

        self.assertEqual(
            e.get_policy(),
            [
                ["admin", "domain.*", "data1", "read"],
                ["user", "domain.*", "data3", "read"],
                ["user", "domain.1", "data2", "read"],
                ["user", "domain.1", "data2", "write"],
            ],
        )

        km2_fn = casbin.util.key_match2_func
        self.assertEqual(
            e.get_filtered_grouping_policy(2, partial(km2_fn, "domain.3")),
            [["alice", "user", "*"], ["bob", "admin", "domain.3"]],
        )

        self.assertEqual(
            e.get_filtered_grouping_policy(2, partial(km2_fn, "domain.1")),
            [["alice", "user", "*"]],
        )

        # first and second p record matches to domain.3
        self.assertEqual(
            e.get_filtered_policy(1, partial(km2_fn, "domain.3")),
            [
                ["admin", "domain.*", "data1", "read"],
                ["user", "domain.*", "data3", "read"],
            ],
        )

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.1"), "", "read")),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.1", "data2", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

    def test_get_policy_multiple_matching_functions(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_and_policy_pattern_model.conf"),
            get_examples("rbac_with_domain_and_policy_pattern_policy.csv"),
        )

        self.assertEqual(
            e.get_policy(),
            [
                ["admin", "domain.*", "data1", "read"],
                ["user", "domain.*", "data3", "read"],
                ["user", "domain.1", "data2", "read"],
                ["user", "domain.1", "data2", "write"],
            ],
        )

        km2_fn = casbin.util.key_match2_func

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.2"), lambda a: "data" in a)),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.1"), lambda a: "data" in a, "read")),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.1", "data2", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.1"), "", "reading".startswith)),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.1", "data2", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

    def test_modify_policy_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
            # True,
        )
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
            ],
        )

        e.add_policy("eve", "data3", "read")
        e.add_named_policy("p", ["eve", "data3", "write"])
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
                ["eve", "data3", "read"],
                ["eve", "data3", "write"],
            ],
        )

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]

        named_policies = [
            ["jack", "data4", "write"],
            ["katy", "data4", "read"],
            ["leyo", "data4", "write"],
            ["ham", "data4", "read"],
        ]
        e.add_policies(rules)
        e.add_named_policies("p", named_policies)

        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
                ["eve", "data3", "read"],
                ["eve", "data3", "write"],
                ["jack", "data4", "read"],
                ["katy", "data4", "write"],
                ["leyo", "data4", "read"],
                ["ham", "data4", "write"],
                ["jack", "data4", "write"],
                ["katy", "data4", "read"],
                ["leyo", "data4", "write"],
                ["ham", "data4", "read"],
            ],
        )

        e.remove_policies(rules)
        e.remove_named_policies("p", named_policies)

        e.add_named_policy("p", "testing")
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
                ["eve", "data3", "read"],
                ["eve", "data3", "write"],
                ["testing"],
            ],
        )

        e.clear_policy()
        e.add_policies_ex([["user1", "data1", "read"], ["user1", "data1", "read"]])
        self.assertEqual(
            e.get_policy(),
            [["user1", "data1", "read"]],
        )
        e.add_policies_ex([["user1", "data1", "read"], ["user2", "data2", "read"]])
        self.assertEqual(
            e.get_policy(),
            [["user1", "data1", "read"], ["user2", "data2", "read"]],
        )
        e.add_named_policies_ex(
            "p", [["user1", "data1", "read"], ["user2", "data2", "read"], ["user3", "data3", "read"]]
        )
        self.assertEqual(
            e.get_policy(),
            [["user1", "data1", "read"], ["user2", "data2", "read"], ["user3", "data3", "read"]],
        )

    def test_modify_grouping_policy_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
            # True,
        )
        e.clear_policy()
        e.add_grouping_policies_ex([["user1", "member"]])
        self.assertCountEqual(
            e.get_users_for_role("member"),
            ["user1"],
        )
        e.add_grouping_policies_ex([["user1", "member"], ["user2", "member"]])
        self.assertCountEqual(
            e.get_users_for_role("member"),
            ["user1", "user2"],
        )
        e.add_named_grouping_policies_ex("g", [["user1", "member"], ["user2", "member"], ["user3", "member"]])
        self.assertCountEqual(
            e.get_users_for_role("member"),
            ["user1", "user2", "user3"],
        )


class TestManagementApiSynced(TestManagementApi):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.SyncedEnforcer(
            model,
            adapter,
        )


class TestManagementApiAsync(IsolatedAsyncioTestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.AsyncEnforcer(
            model,
            adapter,
        )

    async def test_get_list(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
            # True,
        )
        await e.load_policy()

        self.assertEqual(e.get_all_subjects(), ["alice", "bob", "data2_admin"])
        self.assertEqual(e.get_all_objects(), ["data1", "data2"])
        self.assertEqual(e.get_all_actions(), ["read", "write"])
        self.assertEqual(e.get_all_roles(), ["data2_admin"])

    async def test_get_policy_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        await e.load_policy()
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
            ],
        )

        self.assertEqual(e.get_filtered_policy(0, "alice"), [["alice", "data1", "read"]])
        self.assertEqual(e.get_filtered_policy(0, "bob"), [["bob", "data2", "write"]])
        self.assertEqual(
            e.get_filtered_policy(0, "data2_admin"),
            [["data2_admin", "data2", "read"], ["data2_admin", "data2", "write"]],
        )
        self.assertEqual(e.get_filtered_policy(1, "data1"), [["alice", "data1", "read"]])
        self.assertEqual(
            e.get_filtered_policy(1, "data2"),
            [
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
            ],
        )
        self.assertEqual(
            e.get_filtered_policy(2, "read"),
            [["alice", "data1", "read"], ["data2_admin", "data2", "read"]],
        )
        self.assertEqual(
            e.get_filtered_policy(2, "write"),
            [["bob", "data2", "write"], ["data2_admin", "data2", "write"]],
        )
        self.assertEqual(
            e.get_filtered_policy(0, "data2_admin", "data2"),
            [["data2_admin", "data2", "read"], ["data2_admin", "data2", "write"]],
        )

        # Note: "" (empty string) in fieldValues means matching all values.
        self.assertEqual(
            e.get_filtered_policy(0, "data2_admin", "", "read"),
            [["data2_admin", "data2", "read"]],
        )
        self.assertEqual(
            e.get_filtered_policy(1, "data2", "write"),
            [["bob", "data2", "write"], ["data2_admin", "data2", "write"]],
        )

        self.assertTrue(e.has_policy(["alice", "data1", "read"]))
        self.assertTrue(e.has_policy(["bob", "data2", "write"]))
        self.assertFalse(e.has_policy(["alice", "data2", "read"]))
        self.assertFalse(e.has_policy(["bob", "data3", "write"]))
        self.assertEqual(e.get_grouping_policy(), [["alice", "data2_admin"]])
        self.assertEqual(e.get_filtered_grouping_policy(0, "alice"), [["alice", "data2_admin"]])
        self.assertEqual(e.get_filtered_grouping_policy(0, "bob"), [])
        self.assertEqual(e.get_filtered_grouping_policy(1, "data1_admin"), [])
        self.assertEqual(e.get_filtered_grouping_policy(1, "data2_admin"), [["alice", "data2_admin"]])
        # Note: "" (empty string) in fieldValues means matching all values.
        self.assertEqual(
            e.get_filtered_grouping_policy(0, "", "data2_admin"),
            [["alice", "data2_admin"]],
        )
        self.assertTrue(e.has_grouping_policy(["alice", "data2_admin"]))
        self.assertFalse(e.has_grouping_policy(["bob", "data2_admin"]))

    async def test_update_filtered_policies(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        await e.load_policy()

        await e.update_filtered_policies(
            [
                ["data2_admin", "data3", "read"],
                ["data2_admin", "data3", "write"],
            ],
            0,
            "data2_admin",
        )
        self.assertTrue(e.enforce("data2_admin", "data3", "write"))
        self.assertTrue(e.enforce("data2_admin", "data3", "read"))

    async def test_get_policy_matching_function(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_and_policy_pattern_model.conf"),
            get_examples("rbac_with_domain_and_policy_pattern_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(
            e.get_policy(),
            [
                ["admin", "domain.*", "data1", "read"],
                ["user", "domain.*", "data3", "read"],
                ["user", "domain.1", "data2", "read"],
                ["user", "domain.1", "data2", "write"],
            ],
        )

        km2_fn = casbin.util.key_match2_func
        self.assertEqual(
            e.get_filtered_grouping_policy(2, partial(km2_fn, "domain.3")),
            [["alice", "user", "*"], ["bob", "admin", "domain.3"]],
        )

        self.assertEqual(
            e.get_filtered_grouping_policy(2, partial(km2_fn, "domain.1")),
            [["alice", "user", "*"]],
        )

        # first and second p record matches to domain.3
        self.assertEqual(
            e.get_filtered_policy(1, partial(km2_fn, "domain.3")),
            [
                ["admin", "domain.*", "data1", "read"],
                ["user", "domain.*", "data3", "read"],
            ],
        )

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.1"), "", "read")),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.1", "data2", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

    async def test_get_policy_multiple_matching_functions(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_and_policy_pattern_model.conf"),
            get_examples("rbac_with_domain_and_policy_pattern_policy.csv"),
        )
        await e.load_policy()

        self.assertEqual(
            e.get_policy(),
            [
                ["admin", "domain.*", "data1", "read"],
                ["user", "domain.*", "data3", "read"],
                ["user", "domain.1", "data2", "read"],
                ["user", "domain.1", "data2", "write"],
            ],
        )

        km2_fn = casbin.util.key_match2_func

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.2"), lambda a: "data" in a)),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.1"), lambda a: "data" in a, "read")),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.1", "data2", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

        self.assertEqual(
            sorted(e.get_filtered_policy(1, partial(km2_fn, "domain.1"), "", "reading".startswith)),
            sorted(
                [
                    ["admin", "domain.*", "data1", "read"],
                    ["user", "domain.1", "data2", "read"],
                    ["user", "domain.*", "data3", "read"],
                ]
            ),
        )

    async def test_modify_policy_api(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
            # True,
        )
        await e.load_policy()

        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
            ],
        )

        await e.add_policy("eve", "data3", "read")
        await e.add_named_policy("p", ["eve", "data3", "write"])
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
                ["eve", "data3", "read"],
                ["eve", "data3", "write"],
            ],
        )

        rules = [
            ["jack", "data4", "read"],
            ["katy", "data4", "write"],
            ["leyo", "data4", "read"],
            ["ham", "data4", "write"],
        ]

        named_policies = [
            ["jack", "data4", "write"],
            ["katy", "data4", "read"],
            ["leyo", "data4", "write"],
            ["ham", "data4", "read"],
        ]
        await e.add_policies(rules)
        await e.add_named_policies("p", named_policies)

        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
                ["eve", "data3", "read"],
                ["eve", "data3", "write"],
                ["jack", "data4", "read"],
                ["katy", "data4", "write"],
                ["leyo", "data4", "read"],
                ["ham", "data4", "write"],
                ["jack", "data4", "write"],
                ["katy", "data4", "read"],
                ["leyo", "data4", "write"],
                ["ham", "data4", "read"],
            ],
        )

        await e.remove_policies(rules)
        await e.remove_named_policies("p", named_policies)

        await e.add_named_policy("p", "testing")
        self.assertEqual(
            e.get_policy(),
            [
                ["alice", "data1", "read"],
                ["bob", "data2", "write"],
                ["data2_admin", "data2", "read"],
                ["data2_admin", "data2", "write"],
                ["eve", "data3", "read"],
                ["eve", "data3", "write"],
                ["testing"],
            ],
        )
