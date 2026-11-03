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

from abc import ABC, abstractmethod


class Cache(ABC):
    """the interface a cache backend has to implement to be usable by CachedEnforcer.

    A miss is reported by returning the ``default`` object handed to ``get``, never by
    raising. The enforcer passes a private sentinel as ``default``, so an implementation
    that returns it verbatim on a miss can cache ``False`` and ``None`` values safely.

    Implementations are expected to be safe to call from several threads at once, since
    a single enforcer may be shared between them.
    """

    @abstractmethod
    def get(self, key, default=None):
        """returns the value stored under key, or default if key is absent or expired."""

    @abstractmethod
    def set(self, key, value, ttl=None):
        """stores value under key.

        ttl is the number of seconds the entry stays valid; None means it never expires
        on its own.
        """

    @abstractmethod
    def delete(self, key):
        """drops a single key, if present."""

    @abstractmethod
    def clear(self):
        """drops every entry."""
