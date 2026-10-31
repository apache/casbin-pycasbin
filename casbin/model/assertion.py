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

import copy
import logging

from casbin.model.policy_op import PolicyOp


class Assertion:
    def __init__(self):
        self.logger = logging.getLogger("casbin.policy")
        self.key = ""
        self.value = ""
        self.tokens = []
        self.params_tokens = []
        self.policy = []
        self.policy_version = 0
        self.rm = None
        self.cond_rm = None
        self.priority_index: int = -1
        self.policy_map: dict = {}
        self.field_index_map: dict = {}

    def build_role_links(self, rm):
        self.rm = rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError('the number of "_" in role definition should be at least 2')

        for rule in self.policy:
            if len(rule) < count:
                raise RuntimeError("grouping policy elements do not meet role definition")
            if len(rule) > count:
                rule = rule[:count]

            self.rm.add_link(*rule[:count])

        self.logger.debug(f"Role links for: {self.key}")
        self.rm.print_roles()

    def build_incremental_role_links(self, rm, op, rules):
        self.rm = rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError('the number of "_" in role definition should be at least 2')
        for rule in rules:
            if len(rule) < count:
                raise TypeError("grouping policy elements do not meet role definition")
            if len(rule) > count:
                rule = rule[:count]
            if op == PolicyOp.Policy_add:
                rm.add_link(rule[0], rule[1], *rule[2:])
            elif op == PolicyOp.Policy_remove:
                rm.delete_link(rule[0], rule[1], *rule[2:])
            else:
                raise TypeError("Invalid operation: " + str(op))

    def build_incremental_conditional_role_links(self, cond_rm, op, rules):
        self.cond_rm = cond_rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError('the number of "_" in role definition should be at least 2')

        for rule in rules:
            if len(rule) < count:
                raise TypeError("grouping policy elements do not meet role definition")
            if len(rule) > count:
                rule = rule[:count]

            domain_rule = rule[2 : len(self.tokens)]

            if op == PolicyOp.Policy_add:
                self.add_conditional_role_link(rule, domain_rule)
            elif op == PolicyOp.Policy_remove:
                self.cond_rm.delete_link(rule[0], rule[1], *rule[2:])
            else:
                raise TypeError("Invalid operation: " + str(op))

    def build_conditional_role_links(self, cond_rm):
        self.cond_rm = cond_rm
        count = self.value.count("_")
        if count < 2:
            raise RuntimeError('the number of "_" in role definition should be at least 2')
        for rule in self.policy:
            if len(rule) < count:
                raise TypeError("grouping policy elements do not meet role definition")
            if len(rule) > count:
                rule = rule[:count]

            domain_rule = rule[2 : len(self.tokens)]

            self.add_conditional_role_link(rule, domain_rule)

    def add_conditional_role_link(self, rule, domain_rule):
        if not domain_rule:
            self.cond_rm.add_link(rule[0], rule[1])
            self.cond_rm.set_link_condition_func_params(rule[0], rule[1], *rule[len(self.tokens) :])
        else:
            domain = domain_rule[0]
            self.cond_rm.add_link(rule[0], rule[1], domain)
            self.cond_rm.set_domain_link_condition_func_params(rule[0], rule[1], domain, *rule[len(self.tokens) :])

    def __deepcopy__(self, memo):
        """Custom deepcopy implementation that copies policy data only,
        sharing rm and cond_rm by reference instead of cloning them.

        The role managers are live, shared, cyclic object graphs: deep-copying them
        races with concurrent add_link() calls from another thread (as happens when a
        watcher reloads the policy), and the copy is discarded by build_role_links()
        anyway. This matches casbin-go, whose Assertion.copy() also carries RM and
        CondRM over by reference.
        """
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            if k in ("rm", "cond_rm"):
                setattr(result, k, v)
            else:
                setattr(result, k, copy.deepcopy(v, memo))
        return result
