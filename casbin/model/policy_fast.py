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

from contextlib import contextmanager
from typing import Any, Container, Dict, Iterable, Iterator, Optional, Sequence, Set, cast


def in_cache(cache: Dict[str, Any], keys: Sequence[str]) -> Optional[Set[Sequence[str]]]:
    if keys[0] in cache:
        if len(keys) > 1:
            return in_cache(cache[keys[-0]], keys[1:])
        return cast(Set[Sequence[str]], cache[keys[0]])
    else:
        return None


class FastPolicy(Container[Sequence[str]]):
    _cache: Dict[str, Any]
    _current_filter: Optional[Set[Sequence[str]]]
    _cache_key_order: Sequence[int]

    def __init__(self, cache_key_order: Sequence[int]) -> None:
        self._cache = {}
        self._current_filter = None
        self._cache_key_order = cache_key_order

    def __iter__(self) -> Iterator[Sequence[str]]:
        yield from self.__get_policy()

    def __len__(self) -> int:
        return len(list(self.__get_policy()))

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, (list, tuple)) or len(self._cache_key_order) >= len(item):
            return False
        keys = [item[x] for x in self._cache_key_order]
        exists = in_cache(self._cache, keys)
        if not exists:
            return False
        return tuple(item) in exists

    def __getitem__(self, item: int) -> Sequence[str]:
        for i, entry in enumerate(self):
            if i == item:
                return entry
        raise KeyError("No such value exists")

    def append(self, item: Sequence[str]) -> None:
        cache = self._cache
        keys = [item[x] for x in self._cache_key_order]

        for key in keys[:-1]:
            if key not in cache:
                cache[key] = dict()
            cache = cache[key]
        if keys[-1] not in cache:
            cache[keys[-1]] = set()

        cache[keys[-1]].add(tuple(item))

    def remove(self, policy: Sequence[str]) -> bool:
        keys = [policy[x] for x in self._cache_key_order]
        exists = in_cache(self._cache, keys)
        if not exists:
            return True

        exists.remove(tuple(policy))
        return True

    def __get_policy(self) -> Iterable[Sequence[str]]:
        if self._current_filter is not None:
            return (list(x) for x in self._current_filter)
        else:
            return (list(v2) for v in self._cache.values() for v1 in v.values() for v2 in v1)

    def apply_filter(self, *keys: str) -> None:
        value = in_cache(self._cache, keys)
        self._current_filter = value or set()

    def clear_filter(self) -> None:
        self._current_filter = None


@contextmanager
def fast_policy_filter(policy: FastPolicy, *keys: str) -> Iterator[None]:
    try:
        policy.apply_filter(*keys)
        yield
    finally:
        policy.clear_filter()
