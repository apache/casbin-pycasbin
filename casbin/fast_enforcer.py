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

import logging
from typing import Sequence

from casbin.enforcer import Enforcer
from casbin.model import Model, FastModel, fast_policy_filter, FunctionMap
from casbin.persist.adapters import FileAdapter
from casbin.util.log import configure_logging


class FastEnforcer(Enforcer):
    _cache_key_order: Sequence[int] = None

    def __init__(
        self,
        model=None,
        adapter=None,
        enable_log=False,
        logging_config: dict = None,
        cache_key_order: Sequence[int] = None,
    ):
        self._cache_key_order = cache_key_order
        super().__init__(model, adapter, enable_log, logging_config)

    def new_model(self, path="", text=""):
        """creates a model."""
        if self._cache_key_order is None:
            m = Model()
        else:
            m = FastModel(self._cache_key_order)
        if len(path) > 0:
            m.load_model(path)
        else:
            m.load_model_from_text(text)

        return m

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        if self._cache_key_order is None:
            result, _ = self.enforce_ex(*rvals)
        else:
            keys = [rvals[x] for x in self._cache_key_order]
            with fast_policy_filter(self.model.model["p"]["p"].policy, *keys):
                result, _ = self.enforce_ex(*rvals)

        return result
