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

from casbin import Model
from casbin.model.model import DEFAULT_DOMAIN


class TestModel(TestCase):
    m = Model()

    def check_hierarchy(self, policies: list, subject_hierarchy_map: dict):
        """check_hierarchy checks the hierarchy of the subject hierarchy map"""
        for policy in policies:
            if len(policy) < 2:
                raise RuntimeError("policy g expect 2 more params")
            domain = DEFAULT_DOMAIN
            if len(policy) != 2:
                domain = policy[2]
            child = self.m.get_name_with_domain(domain, policy[0])
            parent = self.m.get_name_with_domain(domain, policy[1])
            assert subject_hierarchy_map[child] < subject_hierarchy_map[parent]

    def test_get_subject_hierarchy_map(self):
        # test 1
        policies = [
            ["A1", "B1"],
            ["A1", "B2"],
            ["A2", "B3"],
        ]
        res = self.m.get_subject_hierarchy_map(policies)
        self.check_hierarchy(policies, res)
        # test 2
        policies = [
            ["A1", "B1"],
            ["B1", "B2"],
            ["B2", "B3"],
            ["B1", "B4"],
            ["A1", "B2"],
        ]
        res = self.m.get_subject_hierarchy_map(policies)
        self.check_hierarchy(policies, res)
        # test 3
        policies = [
            ["B1", "B2"],
            ["B2", "B3"],
            ["B3", "B1"],
        ]
        self.assertRaises(RuntimeError, self.m.get_subject_hierarchy_map, policies)
