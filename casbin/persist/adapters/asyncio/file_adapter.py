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

import os

from ...adapter import load_policy_line
from .adapter import AsyncAdapter


class AsyncFileAdapter(AsyncAdapter):
    """the async file adapter for Casbin.
    It can load policy from file or save policy to file.
    """

    _file_path = ""

    def __init__(self, file_path):
        self._file_path = file_path

    async def load_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        self._load_policy_file(model)

    async def save_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        self._save_policy_file(model)

    def _load_policy_file(self, model):
        with open(self._file_path, "rb") as file:
            line = file.readline()
            while line:
                load_policy_line(line.decode().strip(), model)
                line = file.readline()

    def _save_policy_file(self, model):
        with open(self._file_path, "w") as file:
            lines = []

            if "p" in model.model.keys():
                for key, ast in model.model["p"].items():
                    for pvals in ast.policy:
                        lines.append(key + ", " + ", ".join(pvals))

            if "g" in model.model.keys():
                for key, ast in model.model["g"].items():
                    for pvals in ast.policy:
                        lines.append(key + ", " + ", ".join(pvals))

            for i, line in enumerate(lines):
                if i != len(lines) - 1:
                    lines[i] += "\n"

            file.writelines(lines)

    async def add_policy(self, sec, ptype, rule):
        pass

    async def add_policies(self, sec, ptype, rules):
        pass

    async def remove_policy(self, sec, ptype, rule):
        pass

    async def remove_policies(self, sec, ptype, rules):
        pass

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        pass
