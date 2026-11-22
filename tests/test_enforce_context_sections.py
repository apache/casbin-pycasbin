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
from casbin import Model
from casbin.core_enforcer import EnforceContext
from casbin.persist.adapters.string_adapter import StringAdapter


def new_enforcer(conf, policy):
    model = Model()
    model.load_model_from_text(conf)
    return casbin.Enforcer(model, StringAdapter(policy))


class TestEnforceContextSections(TestCase):
    def test_non_default_effect_type(self):
        e = new_enforcer(
            """
[request_definition]
r = sub, obj, act
r2 = sub, obj, act

[policy_definition]
p = sub, obj, act, eft
p2 = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow))
e2 = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
m2 = r2.sub == p2.sub && r2.obj == p2.obj && r2.act == p2.act
""",
            """
p, alice, data1, read, allow
p, alice, data1, write, allow
p, alice, data1, write, deny
p2, alice, data2, read, allow
p2, alice, data2, read, deny
p2, alice, data3, read, deny
p2, alice, data4, read, allow
""",
        )
        ctx = e.new_enforce_context("2")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce(ctx, "alice", "data2", "read"))
        self.assertFalse(e.enforce(ctx, "alice", "data3", "read"))
        self.assertTrue(e.enforce(ctx, "alice", "data4", "read"))
        self.assertFalse(e.enforce(ctx, "alice", "data5", "read"))

    def test_subject_priority_in_non_default_effect_type(self):
        e = new_enforcer(
            """
[request_definition]
r = sub, obj, act
r2 = sub, obj, act

[policy_definition]
p = sub, obj, act, eft
p2 = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))
e2 = subjectPriority(p.eft) || deny

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
m2 = g(r2.sub, p2.sub) && r2.obj == p2.obj && r2.act == p2.act
""",
            """
p2, admin, data1, read, allow
p2, alice, data1, read, deny
g, alice, admin
""",
        )
        ctx = e.new_enforce_context("2")
        self.assertFalse(e.enforce(ctx, "alice", "data1", "read"))
        self.assertTrue(e.enforce(ctx, "admin", "data1", "read"))

    def test_policy_index_by_token_ignores_other_request_types(self):
        e = new_enforcer(
            """
[request_definition]
r = sub, obj, act
r2 = obj, sub

[policy_definition]
p = sub, obj, act, eft

[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))

[matchers]
m = (p.sub == "*" || r.sub == p.sub) && r.obj == p.obj && r.act == p.act
m2 = (p.sub == "*" || r2.sub == p.sub) && r2.obj == p.obj
""",
            """
p, *, data1, read, allow
p, alice, data1, read, deny
""",
        )
        ctx = EnforceContext(rtype="r2", ptype="p", etype="e", mtype="m2")
        self.assertFalse(e.enforce(ctx, "data1", "alice"))

        e.set_policy_index_by_token("p", "r_sub", "p_sub")
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce(ctx, "data1", "alice"))
