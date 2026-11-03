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

"""End-to-end checks for fixes included since the previous published version."""

from unittest import IsolatedAsyncioTestCase, TestCase

import casbin
from casbin.persist import Adapter
from casbin.util import ip_match, key_match2, key_match3, key_match5


def model(matcher="g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"):
    result = casbin.Model()
    result.load_model_from_text("""
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = """ + matcher)
    return result


def check_permissions(test, enforcer, permissions):
    test.assertEqual(permissions, [["admin", "data1", "read"]])
    permissions[0][2] = "write"
    permissions.append(["alice", "data2", "write"])
    test.assertEqual(enforcer.get_policy(), [["admin", "data1", "read"]])
    test.assertTrue(enforcer.enforce("alice", "data1", "read"))
    test.assertFalse(enforcer.enforce("alice", "data1", "write"))


class TestReleaseRegressions(TestCase):
    def test_explanations_do_not_change_policy_or_cached_decisions(self):
        for cls in (casbin.Enforcer, casbin.CachedEnforcer, casbin.SyncedEnforcer, casbin.SyncedCachedEnforcer):
            with self.subTest(enforcer=cls.__name__):
                enforcer = cls(model())
                enforcer.enable_auto_save(False)
                enforcer.add_policy("admin", "data1", "read")
                enforcer.add_grouping_policy("alice", "admin")
                for _ in range(2):
                    allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")
                    self.assertTrue(allowed)
                    self.assertEqual(explanation, ["admin", "data1", "read"])
                    explanation[2] = "write"
                    self.assertEqual(enforcer.get_policy(), [["admin", "data1", "read"]])
                    self.assertFalse(enforcer.enforce("alice", "data1", "write"))

    def test_implicit_permission_rows_do_not_change_policy(self):
        for cls in (casbin.Enforcer, casbin.CachedEnforcer, casbin.SyncedEnforcer, casbin.SyncedCachedEnforcer):
            with self.subTest(enforcer=cls.__name__):
                enforcer = cls(model(), Adapter())
                enforcer.add_policy("admin", "data1", "read")
                enforcer.add_grouping_policy("alice", "admin")
                check_permissions(self, enforcer, enforcer.get_implicit_permissions_for_user("alice"))

    def test_quoted_matcher_values_keep_their_spelling(self):
        for quote in ('"', "'"):
            for prefix in ("r.", "p.", "r2.", "p2."):
                literal = "role " + prefix + "owner"
                for cls in (casbin.Enforcer, casbin.CachedEnforcer, casbin.SyncedCachedEnforcer):
                    with self.subTest(quote=quote, prefix=prefix, enforcer=cls.__name__):
                        enforcer = cls(model("r.sub == " + quote + literal + quote), Adapter())
                        self.assertTrue(enforcer.enforce(literal, "data1", "read"))
                        self.assertFalse(enforcer.enforce(literal.replace(".", "_"), "data1", "read"))

    def test_synced_accessors_return_delegated_values(self):
        class FilteredAdapter(Adapter):
            def is_filtered(self):
                return True

        adapter = FilteredAdapter()
        enforcer = casbin.SyncedEnforcer(model(), adapter)
        self.assertIs(enforcer.get_adapter(), adapter)
        self.assertIs(enforcer.is_filtered(), True)

    def test_invalid_ip_stays_an_explicit_error(self):
        # Applications must reject malformed request IPs; a parsing exception is not an allow.
        with self.assertRaises(ValueError):
            ip_match("invalid-address", "192.0.2.0/24")
        self.assertFalse(ip_match("198.51.100.1", "192.0.2.0/24"))
        self.assertTrue(ip_match("192.0.2.1", "192.0.2.0/24"))

    def test_plain_wildcard_paths_avoid_regex_backtracking(self):
        from unittest.mock import patch

        # Check the fast path structurally rather than executing an expensive regex benchmark.
        with patch(
            "casbin.util.builtin_operators.regex_match", side_effect=AssertionError("unexpected regex fallback")
        ):
            for matcher in (key_match2, key_match3, key_match5):
                self.assertTrue(matcher("/a/b/end", "/*/*/end"))
                self.assertFalse(matcher("/a/b/other", "/*/*/end"))


class TestAsyncReleaseRegressions(IsolatedAsyncioTestCase):
    async def test_explanations_do_not_change_policy_or_cached_decisions(self):
        for cls in (casbin.AsyncEnforcer, casbin.AsyncCachedEnforcer):
            with self.subTest(enforcer=cls.__name__):
                enforcer = cls(model())
                enforcer.enable_auto_save(False)
                await enforcer.add_policy("admin", "data1", "read")
                await enforcer.add_grouping_policy("alice", "admin")
                for _ in range(2):
                    allowed, explanation = enforcer.enforce_ex("alice", "data1", "read")
                    self.assertTrue(allowed)
                    self.assertEqual(explanation, ["admin", "data1", "read"])
                    explanation[2] = "write"
                    self.assertEqual(enforcer.get_policy(), [["admin", "data1", "read"]])
                    self.assertFalse(enforcer.enforce("alice", "data1", "write"))

    async def test_implicit_permission_rows_do_not_change_policy(self):
        for cls in (casbin.AsyncEnforcer, casbin.AsyncCachedEnforcer):
            with self.subTest(enforcer=cls.__name__):
                enforcer = cls(model())
                enforcer.enable_auto_save(False)
                await enforcer.add_policy("admin", "data1", "read")
                await enforcer.add_grouping_policy("alice", "admin")
                permissions = await enforcer.get_implicit_permissions_for_user("alice")
                check_permissions(self, enforcer, permissions)
