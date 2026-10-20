# Copyright 2026 The casbin Authors. All Rights Reserved.
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

import json
import os
from unittest import TestCase, skipUnless

import casbin

CONFORMANCE_DIR = os.environ.get("CASBIN_CONFORMANCE_DIR")


@skipUnless(CONFORMANCE_DIR, "CASBIN_CONFORMANCE_DIR is not set")
class TestConformance(TestCase):
    def test_conformance(self):
        cases_dir = os.path.join(CONFORMANCE_DIR, "cases")
        data_dir = os.path.join(CONFORMANCE_DIR, "data")
        case_files = sorted(name for name in os.listdir(cases_dir) if name.endswith(".json"))
        self.assertTrue(case_files, "no conformance cases found in {}".format(cases_dir))

        mismatches = []
        for case_file in case_files:
            with open(os.path.join(cases_dir, case_file), encoding="utf-8") as f:
                case = json.load(f)
            try:
                e = casbin.Enforcer(os.path.join(data_dir, case["model"]), os.path.join(data_dir, case["policy"]))
            except Exception as err:
                mismatches.append("{}: failed to load: {!r}".format(case_file, err))
                continue

            for test in case["tests"]:
                request = test["request"]
                want = (test["allow"], test["explain"])
                try:
                    allow, explain = e.enforce_ex(*request)
                    got = (allow, list(explain or []))
                except Exception as err:
                    got = repr(err)
                if got != want:
                    mismatches.append("{}: request {}: got {}, want {}".format(case_file, request, got, want))

        if mismatches:
            self.fail("{} mismatches:\n{}".format(len(mismatches), "\n".join(mismatches)))
