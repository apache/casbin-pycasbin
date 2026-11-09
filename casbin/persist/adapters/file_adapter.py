# Copyright 2021 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os

from ..adapter import Adapter, load_policy_line

_NEEDS_QUOTES = frozenset(',"[]()')


def _quote_field(value):
    """Write one policy value so that load_policy_line() reads back the same value.

    A value that contains a comma, a double quote or a bracket, or that starts or
    ends with whitespace, is written as a double-quoted field ("" stands for one
    quote). Line breaks cannot be stored in a line-based file and are refused.
    """
    value = str(value)
    if "\n" in value or "\r" in value:
        raise ValueError("policy value contains a line break and cannot be saved to a file: %r" % value)
    if value != value.strip() or any(c in _NEEDS_QUOTES for c in value):
        return '"' + value.replace('"', '""') + '"'
    return value


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
            if sec in model.model.keys():
                for key, ast in model.model[sec].items():
                    for pvals in ast.policy:
                        lines.append(key + ", " + ", ".join(_quote_field(v) for v in pvals))

        for i, line in enumerate(lines):
            if i != len(lines) - 1:
                lines[i] += "\n"

        # the lines are built before the file is opened, so a value that cannot be
        # written leaves the existing file unchanged
        with open(self._file_path, "w") as file:
            file.writelines(lines)

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
