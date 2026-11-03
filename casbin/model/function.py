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

from casbin import util


class FunctionMap:
    fm = None

    def __init__(self):
        self.fm = dict()

    def add_function(self, name, func):
        self.fm[name] = func

    @staticmethod
    def load_function_map():
        fm = FunctionMap()
        fm.add_function("keyMatch", util.key_match_func)
        fm.add_function("keyMatch2", util.key_match2_func)
        fm.add_function("keyMatch3", util.key_match3_func)
        fm.add_function("keyMatch4", util.key_match4_func)
        fm.add_function("keyMatch5", util.key_match5_func)
        fm.add_function("regexMatch", util.regex_match_func)
        fm.add_function("ipMatch", util.ip_match_func)
        fm.add_function("globMatch", util.glob_match_func)
        fm.add_function("timeMatch", util.time_match_func)

        return fm

    def get_functions(self):
        return self.fm
