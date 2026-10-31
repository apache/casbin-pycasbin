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

from casbin.model import Model
from tests.test_enforcer import get_examples


class TestPolicy(TestCase):
    def test_get_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]

        m.add_policy("p", "p", rule)

        self.assertTrue(m.get_policy("p", "p") == [rule])

    def test_get_policy_returns_copies(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)

        returned = m.get_policy("p", "p")
        returned.append(["hacker", "domain1", "data1", "read"])
        returned[0][0] = "hacker"

        self.assertEqual(m.get_policy("p", "p"), [["admin", "domain1", "data1", "read"]])

    def test_get_filtered_policy_returns_copies(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)

        returned = m.get_filtered_policy("p", "p", 0, "admin")
        returned[0][0] = "hacker"

        self.assertEqual(m.get_policy("p", "p"), [["admin", "domain1", "data1", "read"]])

    def test_has_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)

        self.assertTrue(m.has_policy("p", "p", rule))

    def test_add_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]

        self.assertFalse(m.has_policy("p", "p", rule))

        m.add_policy("p", "p", rule)
        self.assertTrue(m.has_policy("p", "p", rule))

    def test_add_role_policy(self):
        m = Model()
        m.load_model(get_examples("rbac_model.conf"))

        p_rule1 = ["alice", "data1", "read"]
        m.add_policy("p", "p", p_rule1)
        self.assertTrue(m.has_policy("p", "p", p_rule1))

        p_rule2 = ["data2_admin", "data2", "read"]
        m.add_policy("p", "p", p_rule2)
        self.assertTrue(m.has_policy("p", "p", p_rule2))

        g_rule = ["alice", "data2_admin"]
        m.add_policy("g", "g", g_rule)
        self.assertTrue(m.has_policy("g", "g", g_rule))

        self.assertTrue(m.get_policy("p", "p") == [p_rule1, p_rule2])
        self.assertTrue(m.get_policy("g", "g") == [g_rule])

    def test_update_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        old_rule = ["admin", "domain1", "data1", "read"]
        new_rule = ["admin", "domain1", "data2", "read"]

        m.add_policy("p", "p", old_rule)
        self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policy("p", "p", old_rule, new_rule)
        self.assertFalse(m.has_policy("p", "p", old_rule))
        self.assertTrue(m.has_policy("p", "p", new_rule))

        m = Model()
        m.load_model(get_examples("priority_model_explicit.conf"))

        old_rule = ["1", "admin", "data1", "read", "allow"]
        new_rule = ["1", "admin", "data2", "read", "allow"]

        m.add_policy("p", "p", old_rule)
        self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policy("p", "p", old_rule, new_rule)
        self.assertFalse(m.has_policy("p", "p", old_rule))
        self.assertTrue(m.has_policy("p", "p", new_rule))

    def test_update_policies(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        old_rules = [
            ["admin", "domain1", "data1", "read"],
            ["admin", "domain1", "data2", "read"],
            ["admin", "domain1", "data3", "read"],
        ]
        new_rules = [
            ["admin", "domain1", "data4", "read"],
            ["admin", "domain1", "data5", "read"],
            ["admin", "domain1", "data6", "read"],
        ]

        m.add_policies("p", "p", old_rules)

        for old_rule in old_rules:
            self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policies("p", "p", old_rules, new_rules)

        for old_rule in old_rules:
            self.assertFalse(m.has_policy("p", "p", old_rule))
        for new_rule in new_rules:
            self.assertTrue(m.has_policy("p", "p", new_rule))

        m = Model()
        m.load_model(get_examples("priority_model_explicit.conf"))

        old_rules = [
            ["1", "admin", "data1", "read", "allow"],
            ["1", "admin", "data2", "read", "allow"],
            ["1", "admin", "data3", "read", "allow"],
        ]
        new_rules = [
            ["1", "admin", "data4", "read", "allow"],
            ["1", "admin", "data5", "read", "allow"],
            ["1", "admin", "data6", "read", "allow"],
        ]

        m.add_policies("p", "p", old_rules)

        for old_rule in old_rules:
            self.assertTrue(m.has_policy("p", "p", old_rule))

        m.update_policies("p", "p", old_rules, new_rules)

        for old_rule in old_rules:
            self.assertFalse(m.has_policy("p", "p", old_rule))
        for new_rule in new_rules:
            self.assertTrue(m.has_policy("p", "p", new_rule))

    def test_add_policies_bulk(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rules = [[f"user{i}", f"data{i}", "read"] for i in range(1000)]
        self.assertTrue(m.add_policies("p", "p", rules))
        self.assertEqual(m.get_policy("p", "p"), rules)
        self.assertEqual(m["p"]["p"].policy_map["user999,data999,read"], 999)

        self.assertFalse(
            m.add_policies(
                "p", "p", [["new", "data", "read"], ["user0", "data0", "read"]]
            )
        )
        self.assertEqual(len(m.get_policy("p", "p")), 1000)
        self.assertFalse(m.has_policy("p", "p", ["new", "data", "read"]))

        self.assertTrue(
            m.add_policies("p", "p", [["dup", "data", "read"], ["dup", "data", "read"]])
        )
        self.assertEqual(len(m.get_policy("p", "p")), 1001)
        self.assertTrue(m.has_policy("p", "p", ["dup", "data", "read"]))

    def test_add_policies_accepts_iterators(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rules = ([f"user{i}", f"data{i}", "read"] for i in range(3))
        self.assertTrue(m.add_policies("p", "p", rules))
        self.assertEqual(
            m.get_policy("p", "p"),
            [
                ["user0", "data0", "read"],
                ["user1", "data1", "read"],
                ["user2", "data2", "read"],
            ],
        )

    def test_add_policies_ex_bulk(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        m.add_policy("p", "p", ["user0", "data0", "read"])
        rules = [
            ["user0", "data0", "read"],
            ["user1", "data1", "read"],
            ["user1", "data1", "read"],
            ["user2", "data2", "read"],
        ]
        self.assertTrue(m.add_policies_ex("p", "p", rules))
        self.assertEqual(
            m.get_policy("p", "p"),
            [
                ["user0", "data0", "read"],
                ["user1", "data1", "read"],
                ["user2", "data2", "read"],
            ],
        )

        self.assertFalse(m.add_policies_ex("p", "p", [["user0", "data0", "read"]]))

    def test_add_policies_distinguishes_comma_in_rule(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        m.add_policy("p", "p", ["a,b", "read"])
        self.assertTrue(m.add_policies_ex("p", "p", [["a", "b", "read"]]))
        self.assertEqual(
            m.get_policy("p", "p"),
            [["a,b", "read"], ["a", "b", "read"]],
        )

    def test_add_policies_priority(self):
        rules = [
            ["2", "admin", "data2", "read", "allow"],
            ["1", "admin", "data1", "read", "allow"],
            ["3", "admin", "data3", "read", "allow"],
        ]

        sequential = Model()
        sequential.load_model(get_examples("priority_model_explicit.conf"))
        sequential.sort_policies_by_priority()
        for rule in rules:
            sequential.add_policy("p", "p", rule)

        bulk = Model()
        bulk.load_model(get_examples("priority_model_explicit.conf"))
        bulk.sort_policies_by_priority()
        self.assertTrue(bulk.add_policies("p", "p", rules))

        self.assertEqual(bulk.get_policy("p", "p"), sequential.get_policy("p", "p"))
        self.assertEqual(
            bulk.get_policy("p", "p"),
            [
                ["1", "admin", "data1", "read", "allow"],
                ["2", "admin", "data2", "read", "allow"],
                ["3", "admin", "data3", "read", "allow"],
            ],
        )

        self.assertTrue(
            bulk.add_policies_ex(
                "p",
                "p",
                [
                    ["2", "admin", "data2", "read", "allow"],
                    ["0", "admin", "data0", "read", "allow"],
                ],
            )
        )
        self.assertEqual(
            bulk.get_policy("p", "p"),
            [
                ["0", "admin", "data0", "read", "allow"],
                ["1", "admin", "data1", "read", "allow"],
                ["2", "admin", "data2", "read", "allow"],
                ["3", "admin", "data3", "read", "allow"],
            ],
        )

    def test_remove_policy(self):
        m = Model()
        m.load_model(get_examples("basic_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)
        self.assertTrue(m.has_policy("p", "p", rule))

        m.remove_policy("p", "p", rule)
        self.assertFalse(m.has_policy("p", "p", rule))
        self.assertFalse(m.remove_policy("p", "p", rule))

    def test_remove_filtered_policy(self):
        m = Model()
        m.load_model(get_examples("rbac_with_domains_model.conf"))

        rule = ["admin", "domain1", "data1", "read"]
        m.add_policy("p", "p", rule)

        res = m.remove_filtered_policy("p", "p", 1, "domain1", "data1")
        self.assertTrue(res)

        res = m.remove_filtered_policy("p", "p", 1, "domain1", "data1")
        self.assertFalse(res)
