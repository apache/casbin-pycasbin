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

import atexit
import copy
import os
import shutil
import tempfile
import time
from itertools import count
from unittest import TestCase, IsolatedAsyncioTestCase

import casbin
from casbin import util


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


_scratch_dir = tempfile.mkdtemp(prefix="pycasbin-tests-")
atexit.register(shutil.rmtree, _scratch_dir, ignore_errors=True)
_scratch_counter = count()


def get_examples_copy(path):
    """Returns the path of a throwaway copy of an example file.

    Tests that call save_policy() must use this instead of get_examples(), so that
    they do not rewrite the checked-in examples (which, on Windows, also flips their
    line endings to CRLF and leaves the working tree dirty).
    """
    destination = os.path.join(_scratch_dir, "{}-{}".format(next(_scratch_counter), os.path.basename(path)))
    shutil.copyfile(get_examples(path), destination)
    return destination


class MockSub:
    def __init__(self, name, age):
        self.name = name
        self.age = age


class TestCaseBase(TestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.Enforcer(
            model,
            adapter,
        )


class TestConfig(TestCaseBase):
    def test_enforcer_basic(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "write"))

    def test_enforce_ex_basic(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        self.assertTupleEqual(e.enforce_ex("alice", "data1", "read"), (True, ["alice", "data1", "read"]))
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "read"), (False, []))
        self.assertTupleEqual(e.enforce_ex("bob", "data2", "write"), (True, ["bob", "data2", "write"]))
        self.assertTupleEqual(e.enforce_ex("bob", "data1", "write"), (False, []))

    def test_batch_enforce(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        results = [True, False, True, False]
        self.assertEqual(
            e.batch_enforce(
                [
                    ("alice", "data1", "read"),
                    ("alice", "data2", "read"),
                    ("bob", "data2", "write"),
                    ("bob", "data1", "write"),
                ]
            ),
            results,
        )

    def test_model_set_load(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        if not isinstance(e, casbin.SyncedEnforcer):
            e.set_model(None)
            self.assertTrue(e.model is None)
            # creating new model
            e.load_model()
            self.assertTrue(e.model is not None)

    def test_enforcer_basic_without_spaces(self):
        e = self.get_enforcer(
            get_examples("basic_model_without_spaces.conf"),
            get_examples("basic_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_enforce_basic_with_root(self):
        e = self.get_enforcer(get_examples("basic_with_root_model.conf"), get_examples("basic_policy.csv"))
        self.assertTrue(e.enforce("root", "any", "any"))

    def test_enforce_basic_without_resources(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("alice", "write"))
        self.assertTrue(e.enforce("bob", "write"))
        self.assertFalse(e.enforce("bob", "read"))

    def test_enforce_basic_without_users(self):
        e = self.get_enforcer(
            get_examples("basic_without_users_model.conf"),
            get_examples("basic_without_users_policy.csv"),
        )
        self.assertTrue(e.enforce("data1", "read"))
        self.assertFalse(e.enforce("data1", "write"))
        self.assertTrue(e.enforce("data2", "write"))
        self.assertFalse(e.enforce("data2", "read"))

    def test_enforce_ip_match(self):
        e = self.get_enforcer(get_examples("ipmatch_model.conf"), get_examples("ipmatch_policy.csv"))
        self.assertTrue(e.enforce("192.168.2.1", "data1", "read"))
        self.assertFalse(e.enforce("192.168.3.1", "data1", "read"))

    def test_enforce_key_match(self):
        e = self.get_enforcer(get_examples("keymatch_model.conf"), get_examples("keymatch_policy.csv"))
        self.assertTrue(e.enforce("alice", "/alice_data/test", "GET"))
        self.assertFalse(e.enforce("alice", "/bob_data/test", "GET"))
        self.assertTrue(e.enforce("cathy", "/cathy_data", "GET"))
        self.assertTrue(e.enforce("cathy", "/cathy_data", "POST"))
        self.assertFalse(e.enforce("cathy", "/cathy_data/12", "POST"))

    def test_enforce_key_match2(self):
        e = self.get_enforcer(get_examples("keymatch2_model.conf"), get_examples("keymatch2_policy.csv"))
        self.assertTrue(e.enforce("alice", "/alice_data/resource", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data2/123/using/456", "GET"))

    def test_enforce_key_match_custom_model(self):
        e = self.get_enforcer(
            get_examples("keymatch_custom_model.conf"),
            get_examples("keymatch2_policy.csv"),
        )

        def custom_function(key1, key2):
            if key1 == "/alice_data2/myid/using/res_id" and key2 == "/alice_data/:resource":
                return True
            elif key1 == "/alice_data2/myid/using/res_id" and key2 == "/alice_data2/:id/using/:resId":
                return True
            return False

        e.add_function("keyMatchCustom", custom_function)

        self.assertFalse(e.enforce("alice", "/alice_data2/myid", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data2/myid/using/res_id", "GET"))

    def test_enforce_glob_match(self):
        e = self.get_enforcer(
            get_examples("globmatch_model.conf"),
            get_examples("globmatch_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "/alice_data/test_all", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data/123", "POST"))
        self.assertTrue(e.enforce("bob", "/alice_data/1", "GET"))
        self.assertFalse(e.enforce("bob", "/alice_data/0", "GET"))
        self.assertTrue(e.enforce("bob", "/bob_data/0", "POST"))
        self.assertFalse(e.enforce("bob", "/bob_data/1", "POST"))

    def test_enforce_priority(self):
        e = self.get_enforcer(get_examples("priority_model.conf"), get_examples("priority_policy.csv"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

    def test_enforce_priority_explicit(self):
        e = self.get_enforcer(
            get_examples("priority_model_explicit.conf"),
            get_examples("priority_policy_explicit.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "read"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "write"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "read"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "write"))

        e.add_policy("1", "bob", "data2", "write", "deny")

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "read"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "write"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "read"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "write"))

    def test_enforce_priority_indeterminate(self):
        e = self.get_enforcer(
            get_examples("priority_model.conf"),
            get_examples("priority_indeterminate_policy.csv"),
        )
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_enforce_subpriority(self):
        e = self.get_enforcer(
            get_examples("subject_priority_model.conf"),
            get_examples("subject_priority_policy.csv"),
        )
        self.assertTrue(e.enforce("jane", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_enforce_subpriority_with_domain(self):
        e = self.get_enforcer(
            get_examples("subject_priority_model_with_domain.conf"),
            get_examples("subject_priority_policy_with_domain.csv"),
        )
        self.assertTrue(e.enforce("alice", "data1", "domain1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "domain2", "write"))

    def test_multiple_policy_definitions(self):
        e = self.get_enforcer(
            get_examples("multiple_policy_definitions_model.conf"),
            get_examples("multiple_policy_definitions_policy.csv"),
        )

        enforce_context = e.new_enforce_context("2")
        enforce_context.etype = "e"

        sub1 = MockSub("alice", 70)
        sub2 = MockSub("bob", 30)

        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce(enforce_context, sub1, "/data1", "read"))
        self.assertTrue(e.enforce(enforce_context, sub2, "/data1", "read"))
        self.assertFalse(e.enforce(enforce_context, sub2, "/data1", "write"))
        self.assertFalse(e.enforce(enforce_context, sub1, "/data2", "read"))

    def test_enforce_rbac(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bogus", "data2", "write"))  # test non-existent subject

    def test_enforce_rbac_empty_policy(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("empty_policy.csv"))
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_enforce_rbac_with_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_enforce_ex_rbac_with_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        # Test that enforce_ex returns explanations for both allow and deny cases
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "read"), (True, ["data2_admin", "data2", "read", "allow"]))
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "write"), (False, ["alice", "data2", "write", "deny"]))

    def test_enforce_rbac_with_domains(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "write"))

        self.assertFalse(e.enforce("bob", "domain2", "data1", "read"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "write"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "write"))

    def test_enforce_rbac_with_not_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_not_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        self.assertFalse(e.enforce("alice", "data2", "write"))

    def test_enforce_rbac_with_resource_roles(self):
        e = self.get_enforcer(
            get_examples("rbac_with_resource_roles_model.conf"),
            get_examples("rbac_with_resource_roles_policy.csv"),
        )
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_enforce_rbac_with_pattern(self):
        e = self.get_enforcer(
            get_examples("rbac_with_pattern_model.conf"),
            get_examples("rbac_with_pattern_policy.csv"),
        )

        # set matching function to key_match2
        e.add_named_matching_func("g2", casbin.util.key_match2)

        self.assertTrue(e.enforce("alice", "/book/1", "GET"))
        self.assertTrue(e.enforce("alice", "/book/2", "GET"))
        self.assertTrue(e.enforce("alice", "/pen/1", "GET"))
        self.assertFalse(e.enforce("alice", "/pen/2", "GET"))
        self.assertFalse(e.enforce("bob", "/book/1", "GET"))
        self.assertFalse(e.enforce("bob", "/book/2", "GET"))
        self.assertTrue(e.enforce("bob", "/pen/1", "GET"))
        self.assertTrue(e.enforce("bob", "/pen/2", "GET"))

        # replace key_match2 with key_match3
        e.add_named_matching_func("g2", casbin.util.key_match3)
        self.assertTrue(e.enforce("alice", "/book2/1", "GET"))
        self.assertTrue(e.enforce("alice", "/book2/2", "GET"))
        self.assertTrue(e.enforce("alice", "/pen2/1", "GET"))
        self.assertFalse(e.enforce("alice", "/pen2/2", "GET"))
        self.assertFalse(e.enforce("bob", "/book2/1", "GET"))
        self.assertFalse(e.enforce("bob", "/book2/2", "GET"))
        self.assertTrue(e.enforce("bob", "/pen2/1", "GET"))
        self.assertTrue(e.enforce("bob", "/pen2/2", "GET"))

    def test_rbac_with_multipy_matched_pattern(self):
        e = self.get_enforcer(
            get_examples("rbac_with_multiply_matched_pattern.conf"),
            get_examples("rbac_with_multiply_matched_pattern.csv"),
        )

        e.add_named_matching_func("g2", casbin.util.glob_match)

        self.assertTrue(e.enforce("root@localhost", "/", "org.create"))

    def test_enforce_abac_log_enabled(self):
        e = self.get_enforcer(get_examples("abac_model.conf"))
        sub = "alice"
        obj = {"Owner": "alice", "id": "data1"}
        self.assertTrue(e.enforce(sub, obj, "write"))

    def test_abac_with_sub_rule(self):
        e = self.get_enforcer(get_examples("abac_rule_model.conf"), get_examples("abac_rule_policy.csv"))

        sub1 = MockSub("alice", 16)
        sub2 = MockSub("bob", 20)
        sub3 = MockSub("alice", 65)

        self.assertFalse(e.enforce(sub1, "/data1", "read"))
        self.assertFalse(e.enforce(sub1, "/data2", "read"))
        self.assertFalse(e.enforce(sub1, "/data1", "write"))
        self.assertTrue(e.enforce(sub1, "/data2", "write"))

        self.assertTrue(e.enforce(sub2, "/data1", "read"))
        self.assertFalse(e.enforce(sub2, "/data2", "read"))
        self.assertFalse(e.enforce(sub2, "/data1", "write"))
        self.assertTrue(e.enforce(sub2, "/data2", "write"))

        self.assertTrue(e.enforce(sub3, "/data1", "read"))
        self.assertFalse(e.enforce(sub3, "/data2", "read"))
        self.assertFalse(e.enforce(sub3, "/data1", "write"))
        self.assertFalse(e.enforce(sub3, "/data2", "write"))

    def test_abac_with_updated_sub_rule(self):
        e = self.get_enforcer(get_examples("abac_rule_model.conf"), get_examples("abac_rule_policy.csv"))
        e.enable_auto_save(False)

        sub = MockSub("alice", 16)
        self.assertFalse(e.enforce(sub, "/data1", "read"))

        e.remove_policy("r.sub.age > 18", "/data1", "read")
        e.add_policy("r.sub.age > 10", "/data1", "read")
        self.assertTrue(e.enforce(sub, "/data1", "read"))

        e.remove_policy("r.sub.age > 10", "/data1", "read")
        e.add_policy("r.sub.age > 18", "/data1", "read")
        self.assertFalse(e.enforce(sub, "/data1", "read"))

    def test_abac_with_multiple_sub_rules(self):
        e = self.get_enforcer(
            get_examples("abac_multiple_rules_model.conf"),
            get_examples("abac_multiple_rules_policy.csv"),
        )

        sub1 = MockSub("alice", 16)
        sub2 = MockSub("alice", 20)
        sub3 = MockSub("bob", 65)
        sub4 = MockSub("bob", 35)

        self.assertFalse(e.enforce(sub1, "/data1", "read"))
        self.assertFalse(e.enforce(sub1, "/data2", "read"))
        self.assertFalse(e.enforce(sub1, "/data1", "write"))
        self.assertFalse(e.enforce(sub1, "/data2", "write"))

        self.assertTrue(e.enforce(sub2, "/data1", "read"))
        self.assertFalse(e.enforce(sub2, "/data2", "read"))
        self.assertFalse(e.enforce(sub2, "/data1", "write"))
        self.assertFalse(e.enforce(sub2, "/data2", "write"))

        self.assertFalse(e.enforce(sub3, "/data1", "read"))
        self.assertFalse(e.enforce(sub3, "/data2", "read"))
        self.assertFalse(e.enforce(sub3, "/data1", "write"))
        self.assertFalse(e.enforce(sub3, "/data2", "write"))

        self.assertFalse(e.enforce(sub4, "/data1", "read"))
        self.assertFalse(e.enforce(sub4, "/data2", "read"))
        self.assertFalse(e.enforce(sub4, "/data1", "write"))
        self.assertTrue(e.enforce(sub4, "/data2", "write"))

    def test_matcher_using_in_operator_bracket(self):
        e = self.get_enforcer(
            get_examples("rbac_model_matcher_using_in_op_bracket.conf"),
            get_examples("rbac_policy.csv"),
        )

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data3", "scribble"))
        self.assertFalse(e.enforce("alice", "data4", "scribble"))

    def test_temporal_roles_model(self):
        e = self.get_enforcer(
            get_examples("rbac_with_temporal_roles_model.conf"),
            get_examples("rbac_with_temporal_roles_policy.csv"),
        )

        e.add_named_link_condition_func("g", "alice", "data2_admin", util.time_match_func)
        e.add_named_link_condition_func("g", "alice", "data3_admin", util.time_match_func)
        e.add_named_link_condition_func("g", "alice", "data4_admin", util.time_match_func)
        e.add_named_link_condition_func("g", "alice", "data5_admin", util.time_match_func)
        e.add_named_link_condition_func("g", "alice", "data6_admin", util.time_match_func)
        e.add_named_link_condition_func("g", "alice", "data7_admin", util.time_match_func)
        e.add_named_link_condition_func("g", "alice", "data8_admin", util.time_match_func)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data3", "read"))
        self.assertTrue(e.enforce("alice", "data3", "write"))
        self.assertTrue(e.enforce("alice", "data4", "read"))
        self.assertTrue(e.enforce("alice", "data4", "write"))
        self.assertTrue(e.enforce("alice", "data5", "read"))
        self.assertTrue(e.enforce("alice", "data5", "write"))
        self.assertFalse(e.enforce("alice", "data6", "read"))
        self.assertFalse(e.enforce("alice", "data6", "write"))
        self.assertTrue(e.enforce("alice", "data7", "read"))
        self.assertTrue(e.enforce("alice", "data7", "write"))
        self.assertFalse(e.enforce("alice", "data8", "read"))
        self.assertFalse(e.enforce("alice", "data8", "write"))

    def test_temporal_roles_model_with_domain(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domain_temporal_roles_model.conf"),
            get_examples("rbac_with_domain_temporal_roles_policy.csv"),
        )

        e.add_named_domain_link_condition_func("g", "alice", "data2_admin", "domain2", util.time_match_func)
        e.add_named_domain_link_condition_func("g", "alice", "data3_admin", "domain3", util.time_match_func)
        e.add_named_domain_link_condition_func("g", "alice", "data4_admin", "domain4", util.time_match_func)
        e.add_named_domain_link_condition_func("g", "alice", "data5_admin", "domain5", util.time_match_func)
        e.add_named_domain_link_condition_func("g", "alice", "data6_admin", "domain6", util.time_match_func)
        e.add_named_domain_link_condition_func("g", "alice", "data7_admin", "domain7", util.time_match_func)
        e.add_named_domain_link_condition_func("g", "alice", "data8_admin", "domain8", util.time_match_func)

        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain2", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain2", "data2", "write"))
        self.assertTrue(e.enforce("alice", "domain3", "data3", "read"))
        self.assertTrue(e.enforce("alice", "domain3", "data3", "write"))
        self.assertTrue(e.enforce("alice", "domain4", "data4", "read"))
        self.assertTrue(e.enforce("alice", "domain4", "data4", "write"))
        self.assertTrue(e.enforce("alice", "domain5", "data5", "read"))
        self.assertTrue(e.enforce("alice", "domain5", "data5", "write"))
        self.assertFalse(e.enforce("alice", "domain6", "data6", "read"))
        self.assertFalse(e.enforce("alice", "domain6", "data6", "write"))
        self.assertTrue(e.enforce("alice", "domain7", "data7", "read"))
        self.assertTrue(e.enforce("alice", "domain7", "data7", "write"))
        self.assertFalse(e.enforce("alice", "domain8", "data8", "read"))
        self.assertFalse(e.enforce("alice", "domain8", "data8", "write"))

        self.assertFalse(e.enforce("alice", "domain_not_exist", "data1", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data2", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data3", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data3", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data4", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data4", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data5", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data5", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data6", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data6", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data7", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data7", "write"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data8", "read"))
        self.assertFalse(e.enforce("alice", "domain_not_exist", "data8", "write"))

    def test_link_condition_function(self):
        e = self.get_enforcer(
            get_examples("rbac_with_temporal_roles_model.conf"),
            get_examples("rbac_with_temporal_roles_condition_policy.csv"),
        )

        true_func = lambda *args: True if args[0] == "_" or args[0] == "true" else False
        false_func = lambda *args: True if args[0] == "_" or args[0] == "false" else False

        e.add_named_link_condition_func("g", "alice", "data2_admin", true_func)
        e.add_named_link_condition_func("g", "alice", "data3_admin", true_func)
        e.add_named_link_condition_func("g", "alice", "data4_admin", false_func)
        e.add_named_link_condition_func("g", "alice", "data5_admin", false_func)

        e.set_named_link_condition_func_params("g", "alice", "data2_admin", "true")
        e.set_named_link_condition_func_params("g", "alice", "data3_admin", "not true")
        e.set_named_link_condition_func_params("g", "alice", "data4_admin", "false")
        e.set_named_link_condition_func_params("g", "alice", "data5_admin", "not false")

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data3", "read"))
        self.assertFalse(e.enforce("alice", "data3", "write"))
        self.assertTrue(e.enforce("alice", "data4", "read"))
        self.assertTrue(e.enforce("alice", "data4", "write"))
        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data5", "write"))

        e = self.get_enforcer(
            get_examples("rbac_with_domain_temporal_roles_model.conf"),
            get_examples("rbac_with_domain_temporal_roles_condition_policy.csv"),
        )

        e.add_named_domain_link_condition_func("g", "alice", "data2_admin", "domain2", true_func)
        e.add_named_domain_link_condition_func("g", "alice", "data3_admin", "domain3", true_func)
        e.add_named_domain_link_condition_func("g", "alice", "data4_admin", "domain4", false_func)
        e.add_named_domain_link_condition_func("g", "alice", "data5_admin", "domain5", false_func)

        e.set_named_domain_link_condition_func_params("g", "alice", "data2_admin", "domain2", "true")
        e.set_named_domain_link_condition_func_params("g", "alice", "data3_admin", "domain3", "not true")
        e.set_named_domain_link_condition_func_params("g", "alice", "data4_admin", "domain4", "false")
        e.set_named_domain_link_condition_func_params("g", "alice", "data5_admin", "domain5", "not false")

        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertTrue(e.enforce("alice", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("alice", "domain2", "data2", "write"))
        self.assertFalse(e.enforce("alice", "domain3", "data3", "read"))
        self.assertFalse(e.enforce("alice", "domain3", "data3", "write"))
        self.assertTrue(e.enforce("alice", "domain4", "data4", "read"))
        self.assertTrue(e.enforce("alice", "domain4", "data4", "write"))
        self.assertFalse(e.enforce("alice", "domain5", "data5", "read"))
        self.assertFalse(e.enforce("alice", "domain5", "data5", "write"))


class TestConfigSynced(TestConfig):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.SyncedEnforcer(
            model,
            adapter,
        )

    def test_auto_loading_policy(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

        e.start_auto_load_policy(5 / 1000)
        self.assertTrue(e.is_auto_loading_running())
        e.stop_auto_load_policy()
        # thread needs a moment to exit
        time.sleep(10 / 1000)
        self.assertFalse(e.is_auto_loading_running())


class TestConfigAsync(IsolatedAsyncioTestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.AsyncEnforcer(
            model,
            adapter,
        )

    async def test_enforcer_basic(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "write"))

    async def test_enforce_ex_basic(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()
        self.assertTupleEqual(e.enforce_ex("alice", "data1", "read"), (True, ["alice", "data1", "read"]))
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "read"), (False, []))
        self.assertTupleEqual(e.enforce_ex("bob", "data2", "write"), (True, ["bob", "data2", "write"]))
        self.assertTupleEqual(e.enforce_ex("bob", "data1", "write"), (False, []))

    async def test_batch_enforce(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()

        results = [True, False, True, False]
        self.assertEqual(
            e.batch_enforce(
                [
                    ("alice", "data1", "read"),
                    ("alice", "data2", "read"),
                    ("bob", "data2", "write"),
                    ("bob", "data1", "write"),
                ]
            ),
            results,
        )

    async def test_model_set_load(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()

        if not isinstance(e, casbin.SyncedEnforcer):
            e.set_model(None)
            self.assertTrue(e.model is None)
            # creating new model
            e.load_model()
            self.assertTrue(e.model is not None)

    async def test_enforcer_basic_without_spaces(self):
        e = self.get_enforcer(
            get_examples("basic_model_without_spaces.conf"),
            get_examples("basic_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    async def test_enforce_basic_with_root(self):
        e = self.get_enforcer(get_examples("basic_with_root_model.conf"), get_examples("basic_policy.csv"))
        await e.load_policy()

        self.assertTrue(e.enforce("root", "any", "any"))

    async def test_enforce_basic_without_resources(self):
        e = self.get_enforcer(
            get_examples("basic_without_resources_model.conf"),
            get_examples("basic_without_resources_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "read"))
        self.assertFalse(e.enforce("alice", "write"))
        self.assertTrue(e.enforce("bob", "write"))
        self.assertFalse(e.enforce("bob", "read"))

    async def test_enforce_basic_without_users(self):
        e = self.get_enforcer(
            get_examples("basic_without_users_model.conf"),
            get_examples("basic_without_users_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("data1", "read"))
        self.assertFalse(e.enforce("data1", "write"))
        self.assertTrue(e.enforce("data2", "write"))
        self.assertFalse(e.enforce("data2", "read"))

    async def test_enforce_ip_match(self):
        e = self.get_enforcer(get_examples("ipmatch_model.conf"), get_examples("ipmatch_policy.csv"))
        await e.load_policy()

        self.assertTrue(e.enforce("192.168.2.1", "data1", "read"))
        self.assertFalse(e.enforce("192.168.3.1", "data1", "read"))

    async def test_enforce_key_match(self):
        e = self.get_enforcer(get_examples("keymatch_model.conf"), get_examples("keymatch_policy.csv"))
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "/alice_data/test", "GET"))
        self.assertFalse(e.enforce("alice", "/bob_data/test", "GET"))
        self.assertTrue(e.enforce("cathy", "/cathy_data", "GET"))
        self.assertTrue(e.enforce("cathy", "/cathy_data", "POST"))
        self.assertFalse(e.enforce("cathy", "/cathy_data/12", "POST"))

    async def test_enforce_key_match2(self):
        e = self.get_enforcer(get_examples("keymatch2_model.conf"), get_examples("keymatch2_policy.csv"))
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "/alice_data/resource", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data2/123/using/456", "GET"))

    async def test_enforce_key_match_custom_model(self):
        e = self.get_enforcer(
            get_examples("keymatch_custom_model.conf"),
            get_examples("keymatch2_policy.csv"),
        )
        await e.load_policy()

        def custom_function(key1, key2):
            if key1 == "/alice_data2/myid/using/res_id" and key2 == "/alice_data/:resource":
                return True
            elif key1 == "/alice_data2/myid/using/res_id" and key2 == "/alice_data2/:id/using/:resId":
                return True
            return False

        e.add_function("keyMatchCustom", custom_function)

        self.assertFalse(e.enforce("alice", "/alice_data2/myid", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data2/myid/using/res_id", "GET"))

    async def test_enforce_glob_match(self):
        e = self.get_enforcer(
            get_examples("globmatch_model.conf"),
            get_examples("globmatch_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "/alice_data/test_all", "GET"))
        self.assertTrue(e.enforce("alice", "/alice_data/123", "POST"))
        self.assertTrue(e.enforce("bob", "/alice_data/1", "GET"))
        self.assertFalse(e.enforce("bob", "/alice_data/0", "GET"))
        self.assertTrue(e.enforce("bob", "/bob_data/0", "POST"))
        self.assertFalse(e.enforce("bob", "/bob_data/1", "POST"))

    async def test_enforce_priority(self):
        e = self.get_enforcer(get_examples("priority_model.conf"), get_examples("priority_policy.csv"))
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

    async def test_enforce_priority_explicit(self):
        e = self.get_enforcer(
            get_examples("priority_model_explicit.conf"),
            get_examples("priority_policy_explicit.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "read"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "write"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "read"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "write"))

        await e.add_policy("1", "bob", "data2", "write", "deny")

        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "read"))
        self.assertFalse(e.enforce("data1_deny_group", "data1", "write"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "read"))
        self.assertTrue(e.enforce("data2_allow_group", "data2", "write"))

    async def test_enforce_priority_indeterminate(self):
        e = self.get_enforcer(
            get_examples("priority_model.conf"),
            get_examples("priority_indeterminate_policy.csv"),
        )
        await e.load_policy()

        self.assertFalse(e.enforce("alice", "data1", "read"))

    async def test_enforce_subpriority(self):
        e = self.get_enforcer(
            get_examples("subject_priority_model.conf"),
            get_examples("subject_priority_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("jane", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "read"))

    async def test_enforce_subpriority_with_domain(self):
        e = self.get_enforcer(
            get_examples("subject_priority_model_with_domain.conf"),
            get_examples("subject_priority_policy_with_domain.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "domain1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "domain2", "write"))

    async def test_multiple_policy_definitions(self):
        e = self.get_enforcer(
            get_examples("multiple_policy_definitions_model.conf"),
            get_examples("multiple_policy_definitions_policy.csv"),
        )
        await e.load_policy()

        enforce_context = e.new_enforce_context("2")
        enforce_context.etype = "e"

        sub1 = MockSub("alice", 70)
        sub2 = MockSub("bob", 30)

        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce(enforce_context, sub1, "/data1", "read"))
        self.assertTrue(e.enforce(enforce_context, sub2, "/data1", "read"))
        self.assertFalse(e.enforce(enforce_context, sub2, "/data1", "write"))
        self.assertFalse(e.enforce(enforce_context, sub1, "/data2", "read"))

    async def test_enforce_rbac(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bogus", "data2", "write"))  # test non-existent subject

    async def test_enforce_rbac_empty_policy(self):
        e = self.get_enforcer(get_examples("rbac_model.conf"), get_examples("empty_policy.csv"))
        await e.load_policy()

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    async def test_enforce_rbac_with_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    async def test_enforce_rbac_with_domains(self):
        e = self.get_enforcer(
            get_examples("rbac_with_domains_model.conf"),
            get_examples("rbac_with_domains_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("alice", "domain1", "data1", "write"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))
        self.assertFalse(e.enforce("alice", "domain1", "data2", "write"))

        self.assertFalse(e.enforce("bob", "domain2", "data1", "read"))
        self.assertFalse(e.enforce("bob", "domain2", "data1", "write"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "write"))

    async def test_enforce_rbac_with_not_deny(self):
        e = self.get_enforcer(
            get_examples("rbac_with_not_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        await e.load_policy()

        self.assertFalse(e.enforce("alice", "data2", "write"))

    async def test_enforce_rbac_with_resource_roles(self):
        e = self.get_enforcer(
            get_examples("rbac_with_resource_roles_model.conf"),
            get_examples("rbac_with_resource_roles_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    async def test_enforce_rbac_with_pattern(self):
        e = self.get_enforcer(
            get_examples("rbac_with_pattern_model.conf"),
            get_examples("rbac_with_pattern_policy.csv"),
        )
        await e.load_policy()

        # set matching function to key_match2
        e.add_named_matching_func("g2", casbin.util.key_match2)

        self.assertTrue(e.enforce("alice", "/book/1", "GET"))
        self.assertTrue(e.enforce("alice", "/book/2", "GET"))
        self.assertTrue(e.enforce("alice", "/pen/1", "GET"))
        self.assertFalse(e.enforce("alice", "/pen/2", "GET"))
        self.assertFalse(e.enforce("bob", "/book/1", "GET"))
        self.assertFalse(e.enforce("bob", "/book/2", "GET"))
        self.assertTrue(e.enforce("bob", "/pen/1", "GET"))
        self.assertTrue(e.enforce("bob", "/pen/2", "GET"))

        # replace key_match2 with key_match3
        e.add_named_matching_func("g2", casbin.util.key_match3)
        self.assertTrue(e.enforce("alice", "/book2/1", "GET"))
        self.assertTrue(e.enforce("alice", "/book2/2", "GET"))
        self.assertTrue(e.enforce("alice", "/pen2/1", "GET"))
        self.assertFalse(e.enforce("alice", "/pen2/2", "GET"))
        self.assertFalse(e.enforce("bob", "/book2/1", "GET"))
        self.assertFalse(e.enforce("bob", "/book2/2", "GET"))
        self.assertTrue(e.enforce("bob", "/pen2/1", "GET"))
        self.assertTrue(e.enforce("bob", "/pen2/2", "GET"))

    async def test_rbac_with_multipy_matched_pattern(self):
        e = self.get_enforcer(
            get_examples("rbac_with_multiply_matched_pattern.conf"),
            get_examples("rbac_with_multiply_matched_pattern.csv"),
        )
        await e.load_policy()

        e.add_named_matching_func("g2", casbin.util.glob_match)

        self.assertTrue(e.enforce("root@localhost", "/", "org.create"))

    async def test_enforce_abac_log_enabled(self):
        e = self.get_enforcer(get_examples("abac_model.conf"))
        sub = "alice"
        obj = {"Owner": "alice", "id": "data1"}
        self.assertTrue(e.enforce(sub, obj, "write"))

    async def test_abac_with_sub_rule(self):
        e = self.get_enforcer(get_examples("abac_rule_model.conf"), get_examples("abac_rule_policy.csv"))
        await e.load_policy()

        sub1 = MockSub("alice", 16)
        sub2 = MockSub("bob", 20)
        sub3 = MockSub("alice", 65)

        self.assertFalse(e.enforce(sub1, "/data1", "read"))
        self.assertFalse(e.enforce(sub1, "/data2", "read"))
        self.assertFalse(e.enforce(sub1, "/data1", "write"))
        self.assertTrue(e.enforce(sub1, "/data2", "write"))

        self.assertTrue(e.enforce(sub2, "/data1", "read"))
        self.assertFalse(e.enforce(sub2, "/data2", "read"))
        self.assertFalse(e.enforce(sub2, "/data1", "write"))
        self.assertTrue(e.enforce(sub2, "/data2", "write"))

        self.assertTrue(e.enforce(sub3, "/data1", "read"))
        self.assertFalse(e.enforce(sub3, "/data2", "read"))
        self.assertFalse(e.enforce(sub3, "/data1", "write"))
        self.assertFalse(e.enforce(sub3, "/data2", "write"))

    async def test_abac_with_multiple_sub_rules(self):
        e = self.get_enforcer(
            get_examples("abac_multiple_rules_model.conf"),
            get_examples("abac_multiple_rules_policy.csv"),
        )
        await e.load_policy()

        sub1 = MockSub("alice", 16)
        sub2 = MockSub("alice", 20)
        sub3 = MockSub("bob", 65)
        sub4 = MockSub("bob", 35)

        self.assertFalse(e.enforce(sub1, "/data1", "read"))
        self.assertFalse(e.enforce(sub1, "/data2", "read"))
        self.assertFalse(e.enforce(sub1, "/data1", "write"))
        self.assertFalse(e.enforce(sub1, "/data2", "write"))

        self.assertTrue(e.enforce(sub2, "/data1", "read"))
        self.assertFalse(e.enforce(sub2, "/data2", "read"))
        self.assertFalse(e.enforce(sub2, "/data1", "write"))
        self.assertFalse(e.enforce(sub2, "/data2", "write"))

        self.assertFalse(e.enforce(sub3, "/data1", "read"))
        self.assertFalse(e.enforce(sub3, "/data2", "read"))
        self.assertFalse(e.enforce(sub3, "/data1", "write"))
        self.assertFalse(e.enforce(sub3, "/data2", "write"))

        self.assertFalse(e.enforce(sub4, "/data1", "read"))
        self.assertFalse(e.enforce(sub4, "/data2", "read"))
        self.assertFalse(e.enforce(sub4, "/data1", "write"))
        self.assertTrue(e.enforce(sub4, "/data2", "write"))

    async def test_matcher_using_in_operator_bracket(self):
        e = self.get_enforcer(
            get_examples("rbac_model_matcher_using_in_op_bracket.conf"),
            get_examples("rbac_policy.csv"),
        )
        await e.load_policy()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data3", "scribble"))
        self.assertFalse(e.enforce("alice", "data4", "scribble"))

    async def test_load_policy_rebuilds_conditional_role_links(self):
        e = self.get_enforcer(
            get_examples("rbac_with_temporal_roles_model.conf"),
            get_examples("rbac_with_temporal_roles_policy.csv"),
        )
        await e.load_policy()

        ast = e.model.model["g"]["g"]
        self.assertIsNotNone(ast.cond_rm)
        self.assertIs(ast.cond_rm, e.cond_rm_map["g"])

        e.add_named_link_condition_func("g", "alice", "data2_admin", util.time_match_func)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data2", "read"))


class TestModelDeepCopy(TestCase):
    """Assertion.__deepcopy__ must not clone the live role managers.

    They are shared, cyclic object graphs; deep-copying them races with concurrent
    add_link() calls and the copy would be thrown away by build_role_links() anyway.
    """

    def test_deepcopy_shares_role_managers(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        ast = e.model.model["g"]["g"]

        new_model = copy.deepcopy(e.model)
        new_ast = new_model.model["g"]["g"]

        self.assertIs(new_ast.rm, ast.rm)
        self.assertIs(new_ast.cond_rm, ast.cond_rm)
        # policy data is still copied, not shared
        self.assertIsNot(new_ast.policy, ast.policy)
        self.assertEqual(new_ast.policy, ast.policy)

    def test_load_policy_keeps_role_manager(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.load_policy()

        self.assertIs(e.model.model["g"]["g"].rm, e.rm_map["g"])
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_load_policy_without_auto_build_role_links(self):
        e = casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )
        e.enable_auto_build_role_links(False)
        e.load_policy()

        # the role manager must still be usable even though nothing rebuilt the links
        self.assertIsNotNone(e.model.model["g"]["g"].rm)
        self.assertTrue(e.enforce("alice", "data2", "read"))
