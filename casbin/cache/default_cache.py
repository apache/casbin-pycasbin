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

import threading
import time
from collections import OrderedDict

from .cache import Cache

DEFAULT_MAX_SIZE = 10000


class DefaultCache(Cache):
    """an in-memory cache with LRU eviction and optional per-entry expiry.

    The size bound matters here: cache keys are built from request values such as user
    names, so an unbounded cache in front of enforce() grows with the number of distinct
    users an application has ever seen. Once max_size entries are stored, the least
    recently used one is evicted.

    All operations hold a lock, so the cache can back an enforcer shared between threads.
    """

    def __init__(self, max_size=DEFAULT_MAX_SIZE):
        if max_size is not None and max_size <= 0:
            raise ValueError("max_size must be a positive integer or None for no bound")
        self.max_size = max_size
        self._lock = threading.Lock()
        self._store = OrderedDict()

    def get(self, key, default=None):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return default

            value, expires_at = entry
            if expires_at is not None and time.monotonic() >= expires_at:
                # only this thread can reach the delete: the lookup and the delete happen
                # under the same lock acquisition.
                del self._store[key]
                return default

            self._store.move_to_end(key)
            return value

    def set(self, key, value, ttl=None):
        expires_at = time.monotonic() + ttl if ttl is not None and ttl > 0 else None
        with self._lock:
            self._store[key] = (value, expires_at)
            self._store.move_to_end(key)
            if self.max_size is not None:
                while len(self._store) > self.max_size:
                    self._store.popitem(last=False)

    def delete(self, key):
        with self._lock:
            self._store.pop(key, None)

    def clear(self):
        with self._lock:
            self._store.clear()

    def __len__(self):
        with self._lock:
            return len(self._store)
