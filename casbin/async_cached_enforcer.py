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

from casbin.async_enforcer import AsyncEnforcer
from casbin.cached_enforcer import CacheSupport


class AsyncCachedEnforcer(CacheSupport, AsyncEnforcer):
    """AsyncEnforcer that caches enforce() decisions.

    Only policy management is asynchronous upstream; enforce()/enforce_ex() stay
    synchronous, and so does the caching around them. The methods overridden here are
    exactly the mutating ones AsyncEnforcer defines as coroutines -- the synchronous ones
    are handled by CacheSupport, and redeclaring them as coroutines here would turn calls
    like ``e.clear_policy()`` into un-awaited no-ops.

    See CachedEnforcer for what the cache does and does not notice.
    """

    async def load_policy(self):
        try:
            return await super().load_policy()
        finally:
            self.invalidate_cache()

    async def load_filtered_policy(self, filter):
        try:
            return await super().load_filtered_policy(filter)
        finally:
            self.invalidate_cache()

    async def load_increment_filtered_policy(self, filter):
        try:
            return await super().load_increment_filtered_policy(filter)
        finally:
            self.invalidate_cache()

    async def _add_policy(self, sec, ptype, rule):
        try:
            return await super()._add_policy(sec, ptype, rule)
        finally:
            self.invalidate_cache()

    async def _add_policies(self, sec, ptype, rules):
        try:
            return await super()._add_policies(sec, ptype, rules)
        finally:
            self.invalidate_cache()

    async def _update_policy(self, sec, ptype, old_rule, new_rule):
        try:
            return await super()._update_policy(sec, ptype, old_rule, new_rule)
        finally:
            self.invalidate_cache()

    async def _update_policies(self, sec, ptype, old_rules, new_rules):
        try:
            return await super()._update_policies(sec, ptype, old_rules, new_rules)
        finally:
            self.invalidate_cache()

    async def _update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        try:
            return await super()._update_filtered_policies(sec, ptype, new_rules, field_index, *field_values)
        finally:
            self.invalidate_cache()

    async def _remove_policy(self, sec, ptype, rule):
        try:
            return await super()._remove_policy(sec, ptype, rule)
        finally:
            self.invalidate_cache()

    async def _remove_policies(self, sec, ptype, rules):
        try:
            return await super()._remove_policies(sec, ptype, rules)
        finally:
            self.invalidate_cache()

    async def _remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        try:
            return await super()._remove_filtered_policy(sec, ptype, field_index, *field_values)
        finally:
            self.invalidate_cache()

    async def _remove_filtered_policy_returns_effects(self, sec, ptype, field_index, *field_values):
        try:
            return await super()._remove_filtered_policy_returns_effects(sec, ptype, field_index, *field_values)
        finally:
            self.invalidate_cache()
