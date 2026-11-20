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

from typing import Any, Sequence

from .model import Model
from .policy_fast import FastPolicy


class FastModel(Model):
    _cache_key_order: Sequence[int]

    def __init__(self, cache_key_order: Sequence[int]) -> None:
        super().__init__()
        self._cache_key_order = cache_key_order

    def add_def(self, sec: str, key: str, value: Any) -> None:
        super().add_def(sec, key, value)
        if sec == "p" and key == "p":
            self.model[sec][key].policy = FastPolicy(self._cache_key_order)

    def clear_policy(self) -> None:
        """clears all current policy."""
        super().clear_policy()
        self.model["p"]["p"].policy = FastPolicy(self._cache_key_order)
