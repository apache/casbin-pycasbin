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


class AsyncAdapter(metaclass=ABCMeta):
    """The interface for async Casbin adapters."""

    @abstractmethod
    async def load_policy(self, model):
        """loads all policy rules from the storage."""
        pass

    @abstractmethod
    async def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    @abstractmethod
    async def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    @abstractmethod
    async def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    @abstractmethod
    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
