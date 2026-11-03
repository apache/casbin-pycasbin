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

import re

from casbin import util, config
from . import Assertion
from .policy import Policy

DEFAULT_DOMAIN = ""
DEFAULT_SEPARATOR = "::"
PARAMS_REGEX = re.compile(r"\((.*?)\)")


class Model(Policy):
    section_name_map = {
        "r": "request_definition",
        "p": "policy_definition",
        "g": "role_definition",
        "e": "policy_effect",
        "m": "matchers",
    }

    def _load_assertion(self, cfg, sec, key):
        value = cfg.get(self.section_name_map[sec] + "::" + key)

        return self.add_def(sec, key, value)

    def get_params_token(self, value):
        """get_params_token Get params_token from Assertion.value"""
        # Find the matching string using the regular expression
        params_string = PARAMS_REGEX.search(value)

        if params_string is None:
            return []

        # Extract the captured group (inside parentheses) and split it by commas
        params_string = params_string.group(1)
        return [param.strip() for param in params_string.split(",")]

    def add_def(self, sec, key, value):
        if value == "":
            return

        ast = Assertion()
        ast.key = key
        ast.value = value

        if "r" == sec or "p" == sec:
            ast.tokens = ast.value.split(",")
            for i, token in enumerate(ast.tokens):
                ast.tokens[i] = key + "_" + token.strip()
        elif "g" == sec:
            ast.params_tokens = self.get_params_token(ast.value)
            ast.tokens = ast.value.split(",")
            ast.tokens = ast.tokens[: len(ast.tokens) - len(ast.params_tokens)]
        else:
            ast.value = util.remove_comments(util.escape_assertion(ast.value))

        if sec not in self.keys():
            self[sec] = {}

        self[sec][key] = ast

        return True

    def _get_key_suffix(self, i):
        if i == 1:
            return ""

        return str(i)

    def _load_section(self, cfg, sec):
        i = 1
        while True:
            if not self._load_assertion(cfg, sec, sec + self._get_key_suffix(i)):
                break
            else:
                i = i + 1

    def load_model(self, path):
        cfg = config.Config.new_config(path)

        self._load_section(cfg, "r")
        self._load_section(cfg, "p")
        self._load_section(cfg, "e")
        self._load_section(cfg, "m")

        self._load_section(cfg, "g")

    def load_model_from_text(self, text):
        cfg = config.Config.new_config_from_text(text)

        self._load_section(cfg, "r")
        self._load_section(cfg, "p")
        self._load_section(cfg, "e")
        self._load_section(cfg, "m")

        self._load_section(cfg, "g")

    def print_model(self):
        self.logger.info("Model:")
        for k, v in self.items():
            for i, j in v.items():
                self.logger.info("%s.%s: %s", k, i, j.value)

    def sort_policies_by_priority(self):
        for ptype, assertion in self["p"].items():
            for index, token in enumerate(assertion.tokens):
                if token == f"{ptype}_priority":
                    assertion.priority_index = index
                    break

            if assertion.priority_index == -1:
                continue

            assertion.policy = sorted(
                assertion.policy,
                key=lambda x: (
                    int(x[assertion.priority_index])
                    if x[assertion.priority_index].isdigit()
                    else x[assertion.priority_index]
                ),
            )

            for i, policy in enumerate(assertion.policy):
                assertion.policy_map[",".join(policy)] = i
            assertion.policy_version += 1

        return None

    def sort_policies_by_subject_hierarchy(self):
        if self["e"]["e"].value != "subjectPriority(p_eft) || deny":
            return

        sub_index = 0
        domain_index = -1
        for ptype, assertion in self["p"].items():
            for index, token in enumerate(assertion.tokens):
                if token == "{}_dom".format(ptype):
                    domain_index = index
                    break

            subject_hierarchy_map = self.get_subject_hierarchy_map(self["g"]["g"].policy)

            def compare_policy(policy):
                domain = DEFAULT_DOMAIN
                if domain_index != -1:
                    domain = policy[domain_index]
                name = self.get_name_with_domain(domain, policy[sub_index])
                return subject_hierarchy_map.get(name, 0)

            assertion.policy = sorted(assertion.policy, key=compare_policy)
            for i, policy in enumerate(assertion.policy):
                assertion.policy_map[",".join(policy)] = i
            assertion.policy_version += 1

    def get_subject_hierarchy_map(self, policies):
        """
        Get the subject hierarchy from the policy.
        Select the lowest level subject in multiple rounds until all subjects are selected.
        Return the subject hierarchy dictionary, the subject is the key, and the level is the value.
        The level starts from 0 and increases in turn. The smaller the level, the higher the priority.
        """
        # Init unsorted policy, and subject
        unsorted_policy = []
        unsorted_sub = set()
        for policy in policies:
            if len(policy) < 2:
                raise RuntimeError("policy g expect 2 more params")
            domain = DEFAULT_DOMAIN
            if len(policy) != 2:
                domain = policy[2]
            child = self.get_name_with_domain(domain, policy[0])
            parent = self.get_name_with_domain(domain, policy[1])
            unsorted_policy.append([child, parent])
            unsorted_sub.add(child)
            unsorted_sub.add(parent)
        # sort policy,and update sorted_sub_list
        sorted_sub_list = []
        while len(unsorted_policy) > 0:
            # get all parent subject
            parent_sub = {p[1] for p in unsorted_policy if p[1] != ""}
            # remove parent subject from unsorted_sub
            sorted_sub = unsorted_sub - parent_sub
            if not sorted_sub:
                raise RuntimeError("cycle dependency in subject hierarchy.subjects: {}".format(unsorted_sub))
            # update sorted_sub_list
            sorted_sub_list.append(sorted_sub)
            # remove sorted subject, and update unsorted_policy
            unsorted_policy = [p for p in unsorted_policy if p[0] not in sorted_sub]
            # update unsorted_sub
            unsorted_sub = unsorted_sub - sorted_sub
        if len(unsorted_sub) > 0:
            sorted_sub_list.append(unsorted_sub)
        # Tree structure of subject
        return {sub: i for i, subs in enumerate(sorted_sub_list) for sub in subs}

    def get_name_with_domain(self, domain, name):
        return "{}{}{}".format(domain, DEFAULT_SEPARATOR, name)

    def to_text(self):
        s = []

        def write_string(sec):
            for p_type in self[sec]:
                value = self[sec][p_type].value
                s.append("{} = {}\n".format(sec, value.replace("p_", "p.").replace("r_", "r.")))

        s.append("[request_definition]\n")
        write_string("r")
        s.append("[policy_definition]\n")
        write_string("p")
        if "g" in self.keys():
            s.append("[role_definition]\n")
            for p_type in self["g"]:
                s.append("{} = {}\n".format(p_type, self["g"][p_type].value))
        s.append("[policy_effect]\n")
        write_string("e")
        s.append("[matchers]\n")
        write_string("m")

        # remove last \n
        s[-1] = s[-1].strip()

        return "".join(s)

    def get_field_index(self, ptype, field):
        """get_field_index gets the index of the field for a ptype in a policy,
        return -1 if the field does not exist."""
        assertion = self["p"][ptype]
        if field in assertion.field_index_map:
            return assertion.field_index_map[field]

        pattern = f"{ptype}_{field}"
        index = -1
        for i, token in enumerate(assertion.tokens):
            if token == pattern:
                index = i
                break

        if index == -1:
            return index

        assertion.field_index_map[field] = index
        return index
