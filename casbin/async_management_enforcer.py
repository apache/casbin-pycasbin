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

from casbin.async_internal_enforcer import AsyncInternalEnforcer
from casbin.model.policy_op import PolicyOp
from casbin.constant.constants import ACTION_INDEX, SUBJECT_INDEX, OBJECT_INDEX


class AsyncManagementEnforcer(AsyncInternalEnforcer):
    """
    AsyncManagementEnforcer = AsyncInternalEnforcer + AsyncManagement API.
    """

    def get_all_subjects(self):
        """gets the list of subjects that show up in the current policy."""
        return self.model.get_values_for_field_in_policy_all_types_by_name("p", SUBJECT_INDEX)

    def get_all_named_subjects(self, ptype):
        """gets the list of subjects that show up in the current named policy."""
        field_index = self.model.get_field_index(ptype, SUBJECT_INDEX)
        return self.model.get_values_for_field_in_policy("p", ptype, field_index)

    def get_all_objects(self):
        """gets the list of objects that show up in the current policy."""
        return self.model.get_values_for_field_in_policy_all_types_by_name("p", OBJECT_INDEX)

    def get_all_named_objects(self, ptype):
        """gets the list of objects that show up in the current named policy."""
        field_index = self.model.get_field_index(ptype, OBJECT_INDEX)
        return self.model.get_values_for_field_in_policy("p", ptype, field_index)

    def get_all_actions(self):
        """gets the list of actions that show up in the current policy."""
        return self.model.get_values_for_field_in_policy_all_types_by_name("p", ACTION_INDEX)

    def get_all_named_actions(self, ptype):
        """gets the list of actions that show up in the current named policy."""
        field_index = self.model.get_field_index(ptype, ACTION_INDEX)
        return self.model.get_values_for_field_in_policy("p", ptype, field_index)

    def get_all_roles(self):
        """gets the list of roles that show up in the current named policy."""
        return self.get_all_named_roles("g")

    def get_all_named_roles(self, ptype):
        """gets all the authorization rules in the policy."""
        return self.model.get_values_for_field_in_policy("g", ptype, 1)

    def get_policy(self):
        """gets all the authorization rules in the policy."""
        return self.get_named_policy("p")

    def get_filtered_policy(self, field_index, *field_values):
        """gets all the authorization rules in the policy, field filters can be specified."""
        return self.get_filtered_named_policy("p", field_index, *field_values)

    def get_named_policy(self, ptype):
        """gets all the authorization rules in the named policy."""
        return self.model.get_policy("p", ptype)

    def get_filtered_named_policy(self, ptype, field_index, *field_values):
        """gets all the authorization rules in the named policy, field filters can be specified."""
        return self.model.get_filtered_policy("p", ptype, field_index, *field_values)

    def get_grouping_policy(self):
        """gets all the role inheritance rules in the policy."""
        return self.get_named_grouping_policy("g")

    def get_filtered_grouping_policy(self, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        return self.get_filtered_named_grouping_policy("g", field_index, *field_values)

    def get_named_grouping_policy(self, ptype):
        """gets all the role inheritance rules in the policy."""
        return self.model.get_policy("g", ptype)

    def get_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        return self.model.get_filtered_policy("g", ptype, field_index, *field_values)

    def has_policy(self, *params):
        """determines whether an authorization rule exists."""
        return self.has_named_policy("p", *params)

    def has_named_policy(self, ptype, *params):
        """determines whether a named authorization rule exists."""
        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            return self.model.has_policy("p", ptype, str_slice)

        return self.model.has_policy("p", ptype, list(params))

    async def add_policy(self, *params):
        """async adds an authorization rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise, the function returns true by adding the new rule.
        """
        return await self.add_named_policy("p", *params)

    async def add_policies(self, rules):
        """async adds authorization rules to the current policy.

        If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        Otherwise, the function returns true for the corresponding rule by adding the new rule.
        """
        return await self.add_named_policies("p", rules)

    async def add_named_policy(self, ptype, *params):
        """async adds an authorization rule to the current named policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise, the function returns true by adding the new rule.
        """

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_added = await self._add_policy("p", ptype, str_slice)
        else:
            rule_added = await self._add_policy("p", ptype, list(params))

        return rule_added

    async def add_named_policies(self, ptype, rules):
        """async adds authorization rules to the current named policy.

        If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        Otherwise, the function returns true for the corresponding by adding the new rule.
        """
        return await self._add_policies("p", ptype, rules)

    async def update_policy(self, old_rule, new_rule):
        """async updates an authorization rule from the current policy."""
        return await self.update_named_policy("p", old_rule, new_rule)

    async def update_policies(self, old_rules, new_rules):
        """async updates authorization rules from the current policy."""
        return await self.update_named_policies("p", old_rules, new_rules)

    async def update_named_policy(self, ptype, old_rule, new_rule):
        """async updates an authorization rule from the current named policy."""
        return await self._update_policy("p", ptype, old_rule, new_rule)

    async def update_named_policies(self, ptype, old_rules, new_rules):
        """async updates authorization rules from the current named policy."""
        return await self._update_policies("p", ptype, old_rules, new_rules)

    async def update_filtered_policies(self, new_rules, field_index, *field_values):
        """async update_filtered_policies deletes old rules and adds new rules."""
        return await self.update_filtered_named_policies("p", new_rules, field_index, *field_values)

    async def update_filtered_named_policies(self, ptype, new_rules, field_index, *field_values):
        """async update_filtered_named_policies deletes old rules and adds new rules."""
        return await self._update_filtered_policies("p", ptype, new_rules, field_index, *field_values)

    async def remove_policy(self, *params):
        """async removes an authorization rule from the current policy."""
        return await self.remove_named_policy("p", *params)

    async def remove_policies(self, rules):
        """async removes authorization rules from the current policy."""
        return await self.remove_named_policies("p", rules)

    async def remove_filtered_policy(self, field_index, *field_values):
        """async removes an authorization rule from the current policy, field filters can be specified."""
        return await self.remove_filtered_named_policy("p", field_index, *field_values)

    async def remove_named_policy(self, ptype, *params):
        """async removes an authorization rule from the current named policy."""

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_removed = await self._remove_policy("p", ptype, str_slice)
        else:
            rule_removed = await self._remove_policy("p", ptype, list(params))

        return rule_removed

    async def remove_named_policies(self, ptype, rules):
        """async removes authorization rules from the current named policy."""
        return await self._remove_policies("p", ptype, rules)

    async def remove_filtered_named_policy(self, ptype, field_index, *field_values):
        """async removes an authorization rule from the current named policy, field filters can be specified."""
        return await self._remove_filtered_policy("p", ptype, field_index, *field_values)

    def has_grouping_policy(self, *params):
        """determines whether a role inheritance rule exists."""

        return self.has_named_grouping_policy("g", *params)

    def has_named_grouping_policy(self, ptype, *params):
        """determines whether a named role inheritance rule exists."""

        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            return self.model.has_policy("g", ptype, str_slice)

        return self.model.has_policy("g", ptype, list(params))

    async def add_grouping_policy(self, *params):
        """async adds a role inheritance rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise, the function returns true by adding the new rule.
        """
        return await self.add_named_grouping_policy("g", *params)

    async def add_grouping_policies(self, rules):
        """async adds role inheritance rules to the current policy.

        If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        Otherwise, the function returns true for the corresponding policy rule by adding the new rule.
        """
        return await self.add_named_grouping_policies("g", rules)

    async def add_named_grouping_policy(self, ptype, *params):
        """async adds a named role inheritance rule to the current policy.

        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise, the function returns true by adding the new rule.
        """

        rules = []
        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_added = await self._add_policy("g", ptype, str_slice)
            rules.append(str_slice)
        else:
            rule_added = await self._add_policy("g", ptype, list(params))
            rules.append(list(params))

        if self.auto_build_role_links:
            self.model.build_incremental_role_links(self.rm_map[ptype], PolicyOp.Policy_add, "g", ptype, rules)
        return rule_added

    async def add_named_grouping_policies(self, ptype, rules):
        """async adds named role inheritance rules to the current policy.

        If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        Otherwise, the function returns true for the corresponding policy rule by adding the new rule.
        """
        rules_added = await self._add_policies("g", ptype, rules)
        if self.auto_build_role_links:
            self.model.build_incremental_role_links(self.rm_map[ptype], PolicyOp.Policy_add, "g", ptype, rules)

        return rules_added

    async def remove_grouping_policy(self, *params):
        """async removes a role inheritance rule from the current policy."""
        return await self.remove_named_grouping_policy("g", *params)

    async def remove_grouping_policies(self, rules):
        """async removes role inheritance rules from the current policy."""
        return await self.remove_named_grouping_policies("g", rules)

    async def remove_filtered_grouping_policy(self, field_index, *field_values):
        """async removes a role inheritance rule from the current policy, field filters can be specified."""
        return await self.remove_filtered_named_grouping_policy("g", field_index, *field_values)

    async def remove_named_grouping_policy(self, ptype, *params):
        """async removes a role inheritance rule from the current named policy."""

        rules = []
        if len(params) == 1 and isinstance(params[0], list):
            str_slice = params[0]
            rule_removed = await self._remove_policy("g", ptype, str_slice)
            rules.append(str_slice)
        else:
            rule_removed = await self._remove_policy("g", ptype, list(params))
            rules.append(list(params))

        if self.auto_build_role_links and rule_removed:
            self.model.build_incremental_role_links(self.rm_map[ptype], PolicyOp.Policy_remove, "g", ptype, rules)
        return rule_removed

    async def remove_named_grouping_policies(self, ptype, rules):
        """async removes role inheritance rules from the current named policy."""
        rules_removed = await self._remove_policies("g", ptype, rules)

        if self.auto_build_role_links and rules_removed:
            self.model.build_incremental_role_links(self.rm_map[ptype], PolicyOp.Policy_remove, "g", ptype, rules)

        return rules_removed

    async def remove_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """async removes a role inheritance rule from the current named policy, field filters can be specified."""
        rule_removed = await self._remove_filtered_policy_returns_effects("g", ptype, field_index, *field_values)

        if self.auto_build_role_links and rule_removed:
            self.model.build_incremental_role_links(
                self.rm_map[ptype], PolicyOp.Policy_remove, "g", ptype, rule_removed
            )
        return rule_removed

    def add_function(self, name, func):
        """adds a customized function."""
        self.fm.add_function(name, func)
