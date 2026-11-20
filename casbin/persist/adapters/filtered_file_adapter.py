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

from casbin import persist

from .file_adapter import FileAdapter
from ..adapter_filtered import FilteredAdapter


class Filter:
    # P,G are string []
    P = []
    G = []


class FilteredFileAdapter(FileAdapter, FilteredAdapter):
    filtered = False
    _file_path = ""
    filter = Filter()

    # new_filtered_adapter is the constructor for FilteredAdapter.
    def __init__(self, file_path):
        self.filtered = True
        self._file_path = file_path

    def load_policy(self, model):
        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")
        self.filtered = False
        self._load_policy_file(model)

    # load_filtered_policy loads only policy rules that match the filter.
    def load_filtered_policy(self, model, filter):
        if filter == None:
            return self.load_policy(model)

        if not os.path.isfile(self._file_path):
            raise RuntimeError("invalid file path, file path cannot be empty")

        try:
            filter_value = [filter.__dict__["P"]] + [filter.__dict__["G"]]
            is_empty_filter = all(not f for f in filter_value) or all(
                all(not x.strip() for x in f) if f else True for f in filter_value
            )
            if is_empty_filter:
                return self.load_policy(model)
        except:
            raise RuntimeError("invalid filter type")

        self.load_filtered_policy_file(model, filter_value, persist.load_policy_line)
        self.filtered = True

    def load_filtered_policy_file(self, model, filter, handler):
        with open(self._file_path, "rb") as file:
            for line in file:
                line = line.decode().strip()
                if not line or line == "\n":
                    continue

                if filter_line(line, filter):
                    continue

                handler(line, model)

    # is_filtered returns true if the loaded policy has been filtered.
    def is_filtered(self):
        return self.filtered

    def save_policy(self, model):
        if self.filtered:
            raise RuntimeError("cannot save a filtered policy")

        self._save_policy_file(model)


def filter_line(line, filter):
    if filter == None:
        return False

    p = line.split(",")
    if len(p) == 0:
        return True
    filter_slice = []

    if p[0].strip() == "g":
        if not filter[1] or all(not x.strip() for x in filter[1]):
            return False
        filter_slice = filter[1]
    elif p[0].strip() == "p":
        filter_slice = filter[0]

    return filter_words(p, filter_slice)


def filter_words(line, filter):
    if len(line) < len(filter) + 1:
        return True
    skip_line = False
    for i, v in enumerate(filter):
        if v and v.strip() and (v.strip() != line[i + 1].strip()):
            skip_line = True
            break

    return skip_line
