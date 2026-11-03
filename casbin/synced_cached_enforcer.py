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

from casbin.cached_enforcer import CachedEnforcer
from casbin.synced_enforcer import SyncedEnforcer


class SyncedCachedEnforcer(SyncedEnforcer):
    """SyncedEnforcer whose underlying enforcer caches enforce() decisions.

    enforce() runs under the read lock, and serving it from the cache also writes to the
    cache, so several readers can be storing decisions at once. That is safe because the
    cache does its own locking -- see casbin.cache.DefaultCache. A cache installed through
    set_cache() has to offer the same guarantee.

    Policy changes take the write lock, and invalidation happens inside that same call, so
    no reader can observe a mutated policy alongside a pre-mutation cache entry.
    """

    @staticmethod
    def _new_enforcer(model, adapter):
        return CachedEnforcer(model, adapter)

    def enable_cache(self, enable_cache):
        """turns the decision cache on or off."""
        with self._wl:
            return self._e.enable_cache(enable_cache)

    def set_cache(self, cache):
        """replaces the cache backend. It must be safe to use from several threads."""
        with self._wl:
            return self._e.set_cache(cache)

    def get_cache(self):
        """returns the cache backend in use."""
        with self._rl:
            return self._e.get_cache()

    def set_expire_time(self, expire_time):
        """sets how many seconds a cached decision stays valid."""
        with self._wl:
            return self._e.set_expire_time(expire_time)

    def invalidate_cache(self):
        """drops every cached decision."""
        with self._wl:
            return self._e.invalidate_cache()

    @staticmethod
    def get_cache_key(*rvals):
        """builds a hashable key for a request, or returns None if it cannot be cached."""
        return CachedEnforcer.get_cache_key(*rvals)
