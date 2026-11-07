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


def model(matcher="g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act"):
    result = casbin.Model()
    model_text = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = """
    result.load_model_from_text(model_text + matcher)
    return result


class TestReleaseRegressions(TestCase):
    def test_explanations_do_not_change_policy_or_cached_decisions(self):
        for cls in (
            casbin.Enforcer,
            casbin.CachedEnforcer,
            casbin.SyncedEnforcer,
            casbin.SyncedCachedEnforcer,
        ):
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
