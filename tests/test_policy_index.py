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

import casbin

ALLOW_AND_DENY = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"


def new_enforcer(effect=ALLOW_AND_DENY, with_eft=True):
    model = casbin.Model()
    model.add_def("r", "r", "sub, obj_type, obj, act")
    if with_eft:
        model.add_def("p", "p", "sub, obj_type, obj, act, eft")
    else:
        model.add_def("p", "p", "sub, obj_type, obj, act")
    model.add_def("g", "g", "_, _")
    model.add_def("e", "e", effect)
    model.add_def(
        "m",
        "m",
        "g(r.sub, p.sub) && matchObj(p.obj_type, p.obj, r.obj_type, r.obj) && r.act == p.act",
    )

    enforcer = casbin.Enforcer(model)
    calls = [0]

    def match_obj(p_type, p_obj, r_type, r_obj):
        calls[0] += 1
        return (p_type == "*" or p_type == r_type) and p_obj == r_obj

    enforcer.add_function("matchObj", match_obj)
    return enforcer, calls


def add_policies(enforcer, with_eft=True, with_deny=True):
    rules = [
        ["alice", "doc", "doc1", "read"],
        ["alice", "doc", "doc2", "read"],
        ["alice", "img", "img1", "read"],
        ["alice", "*", "video1", "read"],
    ]
    if with_eft:
        rules = [rule + ["allow"] for rule in rules]
    enforcer.add_policies(rules)
    if with_deny:
        enforcer.add_policy("alice", "doc", "doc3", "read", "deny")


def set_object_type_index(enforcer):
    enforcer.set_policy_index(
        "p",
        casbin.PolicyIndex(
            request_key=lambda rvals: (rvals[1], True),
            policy_key=lambda rule: rule[1],
        ),
    )


class PolicyIndexTest(TestCase):
    def test_matches_unindexed_decisions(self):
        indexed, _ = new_enforcer()
        add_policies(indexed)
        set_object_type_index(indexed)

        unindexed, _ = new_enforcer()
        add_policies(unindexed)

        indexed.add_grouping_policy("bob", "alice")
        unindexed.add_grouping_policy("bob", "alice")

        requests = [
            ("alice", "doc", "doc1", "read"),
            ("alice", "doc", "doc2", "read"),
            ("alice", "doc", "doc3", "read"),
            ("alice", "img", "img1", "read"),
            ("alice", "audio", "video1", "read"),
            ("alice", "audio", "missing", "read"),
            ("alice", "doc", "doc1", "write"),
            ("bob", "doc", "doc1", "read"),
            ("bob", "img", "img1", "read"),
            ("bob", "audio", "video1", "read"),
        ]
        for request in requests:
            indexed_result, indexed_explain = indexed.enforce_ex(*request)
            unindexed_result, unindexed_explain = unindexed.enforce_ex(*request)
            self.assertEqual(indexed_result, unindexed_result, request)
            self.assertEqual(indexed_explain, unindexed_explain, request)

    def test_skips_unrelated_rules(self):
        enforcer, calls = new_enforcer()
        add_policies(enforcer)
        set_object_type_index(enforcer)

        for request, expected_calls in [
            (("alice", "doc", "doc1", "read"), 4),
            (("alice", "img", "img1", "read"), 2),
            (("alice", "audio", "video1", "read"), 1),
        ]:
            calls[0] = 0
            enforcer.enforce(*request)
            self.assertEqual(calls[0], expected_calls, request)

        enforcer.remove_policy_index("p")
        calls[0] = 0
        enforcer.enforce("alice", "doc", "doc1", "read")
        self.assertEqual(calls[0], 5)

    def test_rebuilds_after_policy_changes(self):
        enforcer, calls = new_enforcer()
        add_policies(enforcer)
        set_object_type_index(enforcer)

        self.assertFalse(enforcer.enforce("alice", "doc", "doc4", "read"))

        enforcer.add_policy("alice", "doc", "doc4", "read", "allow")
        calls[0] = 0
        self.assertTrue(enforcer.enforce("alice", "doc", "doc4", "read"))
        self.assertEqual(calls[0], 5)

        enforcer.remove_policy("alice", "doc", "doc4", "read", "allow")
        self.assertFalse(enforcer.enforce("alice", "doc", "doc4", "read"))

        old_rule = ["alice", "img", "img1", "read", "allow"]
        new_rule = ["alice", "doc", "doc4", "read", "allow"]
        self.assertTrue(enforcer.update_policy(old_rule, new_rule))
        self.assertFalse(enforcer.enforce("alice", "img", "img1", "read"))
        self.assertTrue(enforcer.enforce("alice", "doc", "doc4", "read"))

        enforcer.clear_policy()
        self.assertFalse(enforcer.enforce("alice", "doc", "doc1", "read"))
        enforcer.add_policy("alice", "doc", "doc1", "read", "allow")
        self.assertTrue(enforcer.enforce("alice", "doc", "doc1", "read"))

    def test_disabled_for_unpartitioned_request(self):
        enforcer, calls = new_enforcer()
        add_policies(enforcer)
        enforcer.set_policy_index(
            "p",
            casbin.PolicyIndex(
                request_key=lambda rvals: ("", False),
                policy_key=lambda rule: rule[1],
            ),
        )

        calls[0] = 0
        enforcer.enforce("alice", "doc", "doc1", "read")
        self.assertEqual(calls[0], 5)

    def test_validation(self):
        enforcer, _ = new_enforcer()

        with self.assertRaises(TypeError):
            enforcer.set_policy_index("p", ("not", "an", "index"))
        with self.assertRaises(ValueError):
            set_object_type_index_to_missing_type(enforcer)
        with self.assertRaises(ValueError):
            enforcer.set_policy_index_by_token("p", "r_missing", "p_obj_type")
        with self.assertRaises(ValueError):
            enforcer.set_policy_index_by_token("p", "r_obj_type", "p_missing")

    def test_by_token(self):
        enforcer, calls = new_enforcer()
        add_policies(enforcer)
        enforcer.set_policy_index_by_token("p", "r_obj_type", "p_obj_type")

        calls[0] = 0
        self.assertTrue(enforcer.enforce("alice", "doc", "doc1", "read"))
        self.assertEqual(calls[0], 4)

    def test_allow_and_deny_short_circuits_without_deny_rules(self):
        for with_eft in [False, True]:
            enforcer, calls = new_enforcer(with_eft=with_eft)
            add_policies(enforcer, with_eft=with_eft, with_deny=False)

            calls[0] = 0
            self.assertTrue(enforcer.enforce("alice", "doc", "doc1", "read"))
            self.assertEqual(calls[0], 1, with_eft)

    def test_allow_and_deny_still_evaluates_when_deny_exists(self):
        enforcer, calls = new_enforcer()
        add_policies(enforcer)

        calls[0] = 0
        self.assertTrue(enforcer.enforce("alice", "doc", "doc1", "read"))
        self.assertEqual(calls[0], 5)

    def test_resets_when_model_changes(self):
        enforcer, calls = new_enforcer(with_eft=False)
        enforcer.add_policy("alice", "doc", "doc1", "read")
        enforcer.add_policy("alice", "img", "img1", "read")
        set_object_type_index(enforcer)

        self.assertTrue(enforcer.enforce("alice", "img", "img1", "read"))

        replacement = casbin.Model()
        replacement.add_def("r", "r", "sub, obj_type, obj, act")
        replacement.add_def("p", "p", "sub, obj_type, obj, act")
        replacement.add_def("g", "g", "_, _")
        replacement.add_def("e", "e", ALLOW_AND_DENY)
        replacement.add_def(
            "m",
            "m",
            "g(r.sub, p.sub) && matchObj(p.obj_type, p.obj, r.obj_type, r.obj) && r.act == p.act",
        )
        replacement.add_policy("p", "p", ["alice", "img", "img1", "read"])
        replacement.add_policy("p", "p", ["alice", "doc", "doc1", "read"])

        enforcer.set_model(replacement)

        def match_obj(p_type, p_obj, r_type, r_obj):
            calls[0] += 1
            return (p_type == "*" or p_type == r_type) and p_obj == r_obj

        enforcer.add_function("matchObj", match_obj)

        self.assertTrue(enforcer.enforce("alice", "img", "img1", "read"))


def set_object_type_index_to_missing_type(enforcer):
    enforcer.set_policy_index(
        "missing",
        casbin.PolicyIndex(
            request_key=lambda rvals: ("", True),
            policy_key=lambda rule: rule[0],
        ),
    )
