# Copyright 2023 The casbin Authors. All Rights Reserved.
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
import inspect

from casbin.core_enforcer import CoreEnforcer
from casbin.model import Model, FunctionMap
from casbin.persist.adapters.asyncio import AsyncFileAdapter, AsyncAdapter


class AsyncInternalEnforcer(CoreEnforcer):
    """
    AsyncInternalEnforcer = CoreEnforcer + Async Internal API.
    """

    def init_with_file(self, model_path, policy_path):
        """initializes an enforcer with a model file and a policy file."""
        a = AsyncFileAdapter(policy_path)
        self.init_with_adapter(model_path, a)

    def init_with_model_and_adapter(self, m, adapter=None):
        """initializes an enforcer with a model and a database adapter."""

        if not isinstance(m, Model) or adapter is not None and not isinstance(adapter, AsyncAdapter):
            raise RuntimeError("Invalid parameters for enforcer.")

        self.adapter = adapter

        self.model = m
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

        self._initialize()

    async def load_policy(self):
        """async reloads the policy from file/database."""
        need_to_rebuild = False
        new_model = copy.deepcopy(self.model)
        new_model.clear_policy()

        try:
            await self.adapter.load_policy(new_model)

            new_model.sort_policies_by_subject_hierarchy()

            new_model.sort_policies_by_priority()

            new_model.print_policy()

            if self.auto_build_role_links:
                need_to_rebuild = True
                for rm in self.rm_map.values():
                    rm.clear()
                if len(self.rm_map) != 0:
                    new_model.build_role_links(self.rm_map)

                for crm in self.cond_rm_map.values():
                    crm.clear()
                if len(self.cond_rm_map) != 0:
                    new_model.build_conditional_role_links(self.cond_rm_map)

            self.model = new_model

        except Exception as e:
            if self.auto_build_role_links and need_to_rebuild:
                self.build_role_links()

            raise e

    async def load_filtered_policy(self, filter):
        """async reloads a filtered policy from file/database."""
        self.model.clear_policy()

        if not hasattr(self.adapter, "is_filtered"):
            raise ValueError("filtered policies are not supported by this adapter")

        await self.adapter.load_filtered_policy(self.model, filter)

        self.model.sort_policies_by_priority()

        self.init_rm_map()
        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()

    async def load_increment_filtered_policy(self, filter):
        """async append a filtered policy from file/database."""
        if not hasattr(self.adapter, "is_filtered"):
            raise ValueError("filtered policies are not supported by this adapter")

        await self.adapter.load_filtered_policy(self.model, filter)
        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()

    async def save_policy(self):
        if self.is_filtered():
            raise RuntimeError("cannot save a filtered policy")

        await self.adapter.save_policy(self.model)

        if self.watcher:
            update_for_save_policy = getattr(self.watcher, "update_for_save_policy", None)
            if callable(update_for_save_policy):
                if inspect.iscoroutinefunction(update_for_save_policy):
                    await update_for_save_policy(self.model)
                else:
                    update_for_save_policy(self.model)
            else:
                if inspect.iscoroutinefunction(self.watcher.update):
                    await self.watcher.update()
                else:
                    self.watcher.update()

    async def _add_policy(self, sec, ptype, rule):
        """async adds a rule to the current policy."""
        if self.model.has_policy(sec, ptype, rule):
            return False

        if self.adapter and self.auto_save:
            result = await self.adapter.add_policy(sec, ptype, rule)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            update_for_add_policy = getattr(self.watcher, "update_for_add_policy", None)
            if callable(update_for_add_policy):
                if inspect.iscoroutinefunction(update_for_add_policy):
                    await update_for_add_policy(sec, ptype, rule)
                else:
                    update_for_add_policy(sec, ptype, rule)
            else:
                if inspect.iscoroutinefunction(self.watcher.update):
                    await self.watcher.update()
                else:
                    self.watcher.update()

        rule_added = self.model.add_policy(sec, ptype, rule)

        return rule_added

    async def _add_policies(self, sec, ptype, rules):
        """async adds rules to the current policy."""
        for rule in rules:
            if self.model.has_policy(sec, ptype, rule):
                return False

        if self.adapter and self.auto_save:
            if hasattr(self.adapter, "add_policies") is False:
                return False

            result = await self.adapter.add_policies(sec, ptype, rules)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            update_for_add_policies = getattr(self.watcher, "update_for_add_policies", None)
            if callable(update_for_add_policies):
                if inspect.iscoroutinefunction(update_for_add_policies):
                    await update_for_add_policies(sec, ptype, rules)
                else:
                    update_for_add_policies(sec, ptype, rules)
            else:
                if inspect.iscoroutinefunction(self.watcher.update):
                    await self.watcher.update()
                else:
                    self.watcher.update()

        rules_added = self.model.add_policies(sec, ptype, rules)

        return rules_added

    async def _update_policy(self, sec, ptype, old_rule, new_rule):
        """async updates a rule from the current policy."""
        rule_updated = self.model.update_policy(sec, ptype, old_rule, new_rule)

        if not rule_updated:
            return rule_updated

        if self.adapter and self.auto_save:
            result = await self.adapter.update_policy(sec, ptype, old_rule, new_rule)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if inspect.iscoroutinefunction(self.watcher.update):
                await self.watcher.update()
            else:
                self.watcher.update()

        return rule_updated

    async def _update_policies(self, sec, ptype, old_rules, new_rules):
        """async updates rules from the current policy."""
        rules_updated = self.model.update_policies(sec, ptype, old_rules, new_rules)

        if not rules_updated:
            return rules_updated

        if self.adapter and self.auto_save:
            result = await self.adapter.update_policies(sec, ptype, old_rules, new_rules)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if inspect.iscoroutinefunction(self.watcher.update):
                await self.watcher.update()
            else:
                self.watcher.update()

        return rules_updated

    async def _update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        """async deletes old rules and adds new rules."""

        old_rules = self.model.get_filtered_policy(sec, ptype, field_index, *field_values)

        if self.adapter and self.auto_save:
            try:
                old_rules = await self.adapter.update_filtered_policies(
                    sec, ptype, new_rules, field_index, *field_values
                )
            except:
                pass

        if not old_rules:
            return False

        is_rule_changed = self.model.remove_policies(sec, ptype, old_rules)
        self.model.add_policies(sec, ptype, new_rules)
        is_rule_changed = is_rule_changed and len(new_rules) != 0
        if not is_rule_changed:
            return is_rule_changed
        if sec == "g":
            self.build_role_links()
        if self.watcher and self.auto_notify_watcher:
            if inspect.iscoroutinefunction(self.watcher.update):
                await self.watcher.update()
            else:
                self.watcher.update()
        return is_rule_changed

    async def _remove_policy(self, sec, ptype, rule):
        """async removes a rule from the current policy."""
        rule_removed = self.model.remove_policy(sec, ptype, rule)
        if not rule_removed:
            return rule_removed

        if self.adapter and self.auto_save:
            result = await self.adapter.remove_policy(sec, ptype, rule)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            update_for_remove_policy = getattr(self.watcher, "update_for_remove_policy", None)
            if callable(update_for_remove_policy):
                if inspect.iscoroutinefunction(update_for_remove_policy):
                    await update_for_remove_policy(sec, ptype, rule)
                else:
                    update_for_remove_policy(sec, ptype, rule)
            else:
                if inspect.iscoroutinefunction(self.watcher.update):
                    await self.watcher.update()
                else:
                    self.watcher.update()

        return rule_removed

    async def _remove_policies(self, sec, ptype, rules):
        """async RemovePolicies removes policy rules from the model."""
        rules_removed = self.model.remove_policies(sec, ptype, rules)
        if not rules_removed:
            return rules_removed

        if self.adapter and self.auto_save:
            if hasattr(self.adapter, "remove_policies") is False:
                return False

            result = await self.adapter.remove_policies(sec, ptype, rules)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            update_for_remove_policies = getattr(self.watcher, "update_for_remove_policies", None)
            if callable(update_for_remove_policies):
                if inspect.iscoroutinefunction(update_for_remove_policies):
                    await update_for_remove_policies(sec, ptype, rules)
                else:
                    update_for_remove_policies(sec, ptype, rules)
            else:
                if inspect.iscoroutinefunction(self.watcher.update):
                    await self.watcher.update()
                else:
                    self.watcher.update()

        return rules_removed

    async def _remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """async removes rules based on field filters from the current policy."""
        rule_removed = self.model.remove_filtered_policy(sec, ptype, field_index, *field_values)
        if not rule_removed:
            return rule_removed

        if self.adapter and self.auto_save:
            result = await self.adapter.remove_filtered_policy(sec, ptype, field_index, *field_values)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            update_for_remove_filtered_policy = getattr(self.watcher, "update_for_remove_filtered_policy", None)
            if callable(update_for_remove_filtered_policy):
                if inspect.iscoroutinefunction(update_for_remove_filtered_policy):
                    await update_for_remove_filtered_policy(sec, ptype, field_index, *field_values)
                else:
                    update_for_remove_filtered_policy(sec, ptype, field_index, *field_values)
            else:
                if inspect.iscoroutinefunction(self.watcher.update):
                    await self.watcher.update()
                else:
                    self.watcher.update()

        return rule_removed

    async def _remove_filtered_policy_returns_effects(self, sec, ptype, field_index, *field_values):
        """async removes rules based on field filters from the current policy."""
        rule_removed = self.model.remove_filtered_policy_returns_effects(sec, ptype, field_index, *field_values)
        if len(rule_removed) == 0:
            return rule_removed

        if self.adapter and self.auto_save:
            result = await self.adapter.remove_filtered_policy(sec, ptype, field_index, *field_values)
            if result is False:
                return False

        if self.watcher and self.auto_notify_watcher:
            if inspect.iscoroutinefunction(self.watcher.update):
                await self.watcher.update()
            else:
                self.watcher.update()

        return rule_removed

    async def get_field_index(self, ptype, field):
        """gets the index of the field name."""
        return self.model.get_field_index(ptype, field)

    async def set_field_index(self, ptype, field, index):
        """sets the index of the field name."""
        assertion = self.model["p"][ptype]
        assertion.field_index_map[field] = index
