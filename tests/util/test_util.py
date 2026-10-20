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
from casbin import util


class TestUtil(TestCase):
    def test_remove_comments(self):
        self.assertEqual(util.remove_comments("r.act == p.act # comments"), "r.act == p.act")
        self.assertEqual(util.remove_comments("r.act == p.act#comments"), "r.act == p.act")
        self.assertEqual(util.remove_comments("r.act == p.act###"), "r.act == p.act")
        self.assertEqual(util.remove_comments("### comments"), "")
        self.assertEqual(util.remove_comments("r.act == p.act"), "r.act == p.act")

    def test_escape_assertion(self):
        self.assertEqual(
            util.escape_assertion("m = r.sub == p.sub && r.obj == p.obj && r.act == p.act"),
            "m = r_sub == p_sub && r_obj == p_obj && r_act == p_act",
        )
        self.assertEqual(
            util.escape_assertion('r.obj == "https://p.example.com" and p.sub == r.sub'),
            'r_obj == "https://p.example.com" and p_sub == r_sub',
        )
        self.assertEqual(
            util.escape_assertion("r.obj == 'a\\'p.b' or r2.obj == p2.obj"),
            "r_obj == 'a\\'p.b' or r2_obj == p2_obj",
        )

    def test_array_remove_duplicates(self):
        res = util.array_remove_duplicates(["data", "data1", "data2", "data1", "data2", "data3"])
        self.assertEqual(res, ["data", "data1", "data2", "data3"])

    def test_array_to_string(self):
        self.assertEqual(
            util.array_to_string(["data", "data1", "data2", "data3"]),
            "data, data1, data2, data3",
        )

    def test_params_to_string(self):
        self.assertEqual(
            util.params_to_string("data", "data1", "data2", "data3"),
            "data, data1, data2, data3",
        )

    def test_has_eval(self):
        self.assertTrue(util.has_eval("eval() && a && b && c"))
        self.assertTrue(util.has_eval("a && b && eval(c)"))
        self.assertFalse(util.has_eval("eval) && a && b && c"))
        self.assertFalse(util.has_eval("eval)( && a && b && c"))
        self.assertTrue(util.has_eval("eval(c * (a + b)) && a && b && c"))
        self.assertFalse(util.has_eval("xeval() && a && b && c"))
        self.assertTrue(util.has_eval("eval(a) && eval(b) && a && b && c"))

    def test_replace_eval(self):
        self.assertEqual(util.replace_eval("eval(a) && eval(b) && c", ["a", "b"]), "(a) && (b) && c")
        self.assertEqual(util.replace_eval("a && eval(b) && eval(c)", ["b", "c"]), "a && (b) && (c)")

    def test_get_eval_value(self):
        self.assertEqual(util.get_eval_value("eval(a) && a && b && c"), ["a"])
        self.assertEqual(util.get_eval_value("a && eval(a) && b && c"), ["a"])
        self.assertEqual(util.get_eval_value("eval(a) && eval(b) && a && b && c"), ["a", "b"])
        self.assertEqual(util.get_eval_value("a && eval(a) && eval(b) && b && c"), ["a", "b"])
        self.assertEqual(
            util.get_eval_value("eval(p.sub_rule) || p.obj == r.obj && eval(p.domain_rule)"),
            ["p.sub_rule", "p.domain_rule"],
        )
