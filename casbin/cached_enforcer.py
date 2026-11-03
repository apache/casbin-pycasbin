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

import math

from casbin.cache import DefaultCache
from casbin.enforcer import Enforcer

# distinguishes "key absent" from a cached None/False without an exception on the hot path.
_MISSING = object()


class CacheSupport:
    """the caching half of CachedEnforcer, shared by the sync and async enforcers.

    Mix it in *before* an enforcer class so that ``super()`` inside it reaches the
    enforcer implementation::

        class CachedEnforcer(CacheSupport, Enforcer):
            pass

    Only enforce_ex() is intercepted. enforce() and batch_enforce() are defined in terms
    of it upstream, so they pick the cache up for free and cannot drift out of sync.
    """

    def __init__(self, *args, **kwargs):
        # these have to exist before the enforcer constructor runs: it may load a policy,
        # and the load path invalidates the cache.
        self._cache = DefaultCache()
        self._enable_cache = True
        self._expire_time = None
        self._warned_about_dynamic_model = False
        super().__init__(*args, **kwargs)

    def enable_cache(self, enable_cache):
        """turns the decision cache on or off. Turning it off also drops what is cached,
        so that turning it back on cannot resurrect stale decisions."""
        self._enable_cache = enable_cache
        if not enable_cache:
            self.invalidate_cache()

    def set_cache(self, cache):
        """replaces the cache backend with any object implementing casbin.cache.Cache."""
        self._cache = cache

    def get_cache(self):
        """returns the cache backend in use."""
        return self._cache

    def set_expire_time(self, expire_time):
        """sets how many seconds a cached decision stays valid. None means entries only
        leave the cache when a policy change invalidates them or the LRU evicts them."""
        self._expire_time = expire_time
        self.invalidate_cache()

    def invalidate_cache(self):
        """drops every cached decision."""
        self._cache.clear()

    @staticmethod
    def get_cache_key(*rvals):
        """builds a hashable key for a request, or returns None if it cannot be cached.

        Values are kept as distinct tuple elements rather than joined into one string, so
        no combination of separators in the request can make two different requests share
        a key. Strings map to themselves; numbers and None carry their type name, so that
        1, 1.0, True and "1" stay apart. Any other object has to opt in by exposing
        get_cache_key().
        """
        key = []
        for rval in rvals:
            if isinstance(rval, str):
                key.append(rval)
            elif rval is None or isinstance(rval, (bool, int, float)):
                key.append((type(rval).__name__, rval))
            else:
                get_key = getattr(rval, "get_cache_key", None)
                if not callable(get_key):
                    return None
                sub_key = get_key()
                if sub_key is None:
                    return None
                key.append((type(rval).__name__, sub_key))

        return tuple(key)

    def _cache_would_be_stale(self):
        """reports whether caching decisions is unsound for the current model.

        Conditional role managers run a link condition function on every call. Those
        functions typically close over the wall clock (a role that is valid until 18:00)
        or over parameters set later through set_named_link_condition_func_params, so a
        decision is not a pure function of the request and caching it would keep granting
        access after the role has expired.

        Setting a positive, finite expire time accepts a bounded amount of
        staleness and re-enables caching. An unbounded expiry must not do so.
        """
        if not self.cond_rm_map:
            return False
        if self._expire_time is not None and self._expire_time > 0 and math.isfinite(self._expire_time):
            return False

        if not self._warned_about_dynamic_model:
            self._warned_about_dynamic_model = True
            self.logger.warning(
                "CachedEnforcer: this model uses conditional role managers, whose link "
                "conditions are re-evaluated on every request. Caching is bypassed so that "
                "expired roles stop granting access. Call set_expire_time() to cache anyway "
                "with a bounded staleness window."
            )
        return True

    def enforce_ex(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        serving the answer from the cache when the same request was decided before.
        """
        if not self._enable_cache or self._cache_would_be_stale():
            return super().enforce_ex(*rvals)

        key = self.get_cache_key(*rvals)
        if key is None:
            return super().enforce_ex(*rvals)

        cached = self._cache.get(key, _MISSING)
        if cached is not _MISSING:
            result, explain = cached
            # Hand out a fresh explanation so callers cannot alter later cache hits.
            return result, list(explain)

        result, explain = super().enforce_ex(*rvals)
        self._cache.set(key, (result, tuple(explain)), self._expire_time)
        return result, explain

    # Everything below invalidates the cache after letting the enforcer do its work.
    #
    # Invalidating afterwards rather than before is deliberate: with a pre-invalidation, a
    # request arriving between the flush and the mutation would re-cache the pre-mutation
    # answer and keep it indefinitely.
    #
    # tests/test_cached_enforcer.py asserts this list still covers every mutating method
    # the enforcers expose, so an upstream addition cannot silently go uninvalidated.

    def clear_policy(self):
        try:
            return super().clear_policy()
        finally:
            self.invalidate_cache()

    def init_rm_map(self):
        try:
            return super().init_rm_map()
        finally:
            self.invalidate_cache()

    def build_role_links(self):
        try:
            return super().build_role_links()
        finally:
            self.invalidate_cache()

    def set_model(self, m):
        try:
            return super().set_model(m)
        finally:
            self.invalidate_cache()

    def load_model(self):
        try:
            return super().load_model()
        finally:
            self.invalidate_cache()

    def set_adapter(self, adapter):
        try:
            return super().set_adapter(adapter)
        finally:
            self.invalidate_cache()

    def set_role_manager(self, rm):
        try:
            return super().set_role_manager(rm)
        finally:
            self.invalidate_cache()

    def set_named_role_manager(self, ptype, rm):
        try:
            return super().set_named_role_manager(ptype, rm)
        finally:
            self.invalidate_cache()

    def set_effector(self, eft):
        try:
            return super().set_effector(eft)
        finally:
            self.invalidate_cache()

    def add_function(self, name, func):
        try:
            return super().add_function(name, func)
        finally:
            self.invalidate_cache()

    def enable_enforce(self, enabled=True):
        try:
            return super().enable_enforce(enabled)
        finally:
            self.invalidate_cache()

    def add_named_matching_func(self, ptype, fn):
        try:
            return super().add_named_matching_func(ptype, fn)
        finally:
            self.invalidate_cache()

    def add_named_domain_matching_func(self, ptype, fn):
        try:
            return super().add_named_domain_matching_func(ptype, fn)
        finally:
            self.invalidate_cache()

    def add_named_link_condition_func(self, ptype, user, role, fn):
        try:
            return super().add_named_link_condition_func(ptype, user, role, fn)
        finally:
            self.invalidate_cache()

    def add_named_domain_link_condition_func(self, ptype, user, role, domain, fn):
        try:
            return super().add_named_domain_link_condition_func(ptype, user, role, domain, fn)
        finally:
            self.invalidate_cache()

    def set_named_link_condition_func_params(self, ptype, user, role, *params):
        try:
            return super().set_named_link_condition_func_params(ptype, user, role, *params)
        finally:
            self.invalidate_cache()

    def set_named_domain_link_condition_func_params(self, ptype, user, role, domain, *params):
        try:
            return super().set_named_domain_link_condition_func_params(ptype, user, role, domain, *params)
        finally:
            self.invalidate_cache()


class CachedEnforcer(CacheSupport, Enforcer):
    """Enforcer that caches enforce() decisions.

    The cache is keyed on the request alone, so it is only correct as long as every change
    that could alter a decision drops it. Policy changes made through this enforcer do
    that automatically. Changes made behind its back -- a second process writing to the
    same database, or code reaching into ``e.model`` directly -- do not, so pair those with
    a call to invalidate_cache() or set_expire_time().
    """

    def load_policy(self):
        try:
            return super().load_policy()
        finally:
            self.invalidate_cache()

    def load_filtered_policy(self, filter):
        try:
            return super().load_filtered_policy(filter)
        finally:
            self.invalidate_cache()

    def load_increment_filtered_policy(self, filter):
        try:
            return super().load_increment_filtered_policy(filter)
        finally:
            self.invalidate_cache()

    def _add_policy(self, sec, ptype, rule):
        try:
            return super()._add_policy(sec, ptype, rule)
        finally:
            self.invalidate_cache()

    def _add_policies(self, sec, ptype, rules):
        try:
            return super()._add_policies(sec, ptype, rules)
        finally:
            self.invalidate_cache()

    def _add_policies_ex(self, sec, ptype, rules):
        try:
            return super()._add_policies_ex(sec, ptype, rules)
        finally:
            self.invalidate_cache()

    def _update_policy(self, sec, ptype, old_rule, new_rule):
        try:
            return super()._update_policy(sec, ptype, old_rule, new_rule)
        finally:
            self.invalidate_cache()

    def _update_policies(self, sec, ptype, old_rules, new_rules):
        try:
            return super()._update_policies(sec, ptype, old_rules, new_rules)
        finally:
            self.invalidate_cache()

    def _update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        try:
            return super()._update_filtered_policies(sec, ptype, new_rules, field_index, *field_values)
        finally:
            self.invalidate_cache()

    def _remove_policy(self, sec, ptype, rule):
        try:
            return super()._remove_policy(sec, ptype, rule)
        finally:
            self.invalidate_cache()

    def _remove_policies(self, sec, ptype, rules):
        try:
            return super()._remove_policies(sec, ptype, rules)
        finally:
            self.invalidate_cache()

    def _remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        try:
            return super()._remove_filtered_policy(sec, ptype, field_index, *field_values)
        finally:
            self.invalidate_cache()

    def _remove_filtered_policy_returns_effects(self, sec, ptype, field_index, *field_values):
        try:
            return super()._remove_filtered_policy_returns_effects(sec, ptype, field_index, *field_values)
        finally:
            self.invalidate_cache()
