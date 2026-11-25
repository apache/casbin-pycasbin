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

from casbin import Model
from casbin.persist.adapters.string_adapter import StringAdapter
from tests import TestCaseBase


class TestStringAdapter(TestCaseBase):
    def test_key_match_rbac(self):
        conf = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub)  && keyMatch(r.obj, p.obj) && regexMatch(r.act, p.act)
"""
        line = """
p, alice, /alice_data/*, (GET)|(POST)
p, alice, /alice_data/resource1, POST
p, data_group_admin, /admin/*, POST
p, data_group_admin, /bob_data/*, POST
g, alice, data_group_admin
"""
        adapter = StringAdapter(line)
        model = Model()
        model.load_model_from_text(conf)
        e = self.get_enforcer(model, adapter)
        sub = "alice"
        obj = "/alice_data/login"
        act = "POST"
        self.assertTrue(e.enforce(sub, obj, act))

    def test_comment_marker_in_matcher_string(self):
        conf = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (r.act == "#write" || r.obj == 'a;b') # comment
"""
        model = Model()
        model.load_model_from_text(conf)
        e = self.get_enforcer(model, StringAdapter("p, alice, data1, read"))

        self.assertTrue(e.enforce("alice", "data1", "#write"))
        self.assertTrue(e.enforce("alice", "a;b", "read"))
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_operators_in_matcher_string(self):
        conf = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && (r.obj == "a&&b||c" || r.act == 'hi!' || r.act == "x\\"!") && !(r.obj == "deny")
"""
        model = Model()
        model.load_model_from_text(conf)
        e = self.get_enforcer(model, StringAdapter("p, alice, data1, read"))

        self.assertTrue(e.enforce("alice", "a&&b||c", "read"))
        self.assertFalse(e.enforce("alice", "a and b or c", "read"))
        self.assertTrue(e.enforce("alice", "data1", "hi!"))
        self.assertFalse(e.enforce("alice", "data1", "hinot "))
        self.assertTrue(e.enforce("alice", "data1", 'x"!'))
        self.assertFalse(e.enforce("alice", "deny", "hi!"))
        self.assertFalse(e.enforce("bob", "a&&b||c", "read"))

    def test_string_rbac(self):
        conf = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""
        line = """
p, alice, data1, read
p, data_group_admin, data3, read
p, data_group_admin, data3, write
g, alice, data_group_admin
"""
        adapter = StringAdapter(line)
        model = Model()
        model.load_model_from_text(conf)
        e = self.get_enforcer(model, adapter)
        sub = "alice"
        obj = "data1"
        act = "read"
        self.assertTrue(e.enforce(sub, obj, act))

    def test_save_and_load_back(self):
        conf = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""
        model = Model()
        model.load_model_from_text(conf)
        adapter = StringAdapter("p, alice, data1, read")
        e = self.get_enforcer(model, adapter)
        e.enable_auto_save(False)
        e.add_policy("bob", "a, b", "read")
        e.save_policy()
        self.assertEqual(adapter.line, 'p, alice, data1, read\np, bob, "a, b", read')

        e.load_policy()
        self.assertEqual(e.get_policy(), [["alice", "data1", "read"], ["bob", "a, b", "read"]])

        e.add_policy("bob", "d\np, mallory, data2, read", "read")
        with self.assertRaises(ValueError):
            e.save_policy()
        self.assertNotIn("mallory", adapter.line)
