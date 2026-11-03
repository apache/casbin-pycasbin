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

from abc import ABCMeta, abstractmethod


class AsyncUpdateAdapter(metaclass=ABCMeta):
    """AsyncUpdateAdapter is the interface for async Casbin adapters with add update policy function."""

    @abstractmethod
    async def update_policy(self, sec, ptype, old_rule, new_policy):
        """
        update_policy updates a policy rule from storage.
        This is part of the Auto-Save feature.
        """
        pass

    @abstractmethod
    async def update_policies(self, sec, ptype, old_rules, new_rules):
        """
        UpdatePolicies updates some policy rules to storage, like db, redis.
        """
        pass

    @abstractmethod
    async def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        """
        update_filtered_policies deletes old rules and adds new rules.
        """
        pass
