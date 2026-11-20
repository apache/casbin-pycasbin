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

from ..adapter import Adapter, load_policy_line, policy_line_to_csv


class FileAdapter(Adapter):
    """the file adapter for Casbin.
    It can load policy from file or save policy to file.
    """

    _file_path = ""

    def __init__(self, file_path):
        self._file_path = file_path

    def load_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        self._load_policy_file(model)

    def save_policy(self, model):
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
        lines = []
        for sec in ("p", "g"):
            for key, ast in model.model.get(sec, {}).items():
                for pvals in ast.policy:
                    lines.append(policy_line_to_csv(key, pvals))

        with open(self._file_path, "w") as file:
            file.write("\n".join(lines))

    def add_policy(self, sec, ptype, rule):
        pass

    def add_policies(self, sec, ptype, rules):
        pass

    def add_policies_ex(self, sec, ptype, rules):
        pass

    def remove_policy(self, sec, ptype, rule):
        pass

    def remove_policies(self, sec, ptype, rules):
        pass
