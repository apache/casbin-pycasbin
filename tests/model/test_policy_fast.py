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

from unittest import TestCase

from casbin.model import FastPolicy, fast_policy_filter


class TestFastPolicy(TestCase):
    def test_able_to_add_rules(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])

        assert list(policy) == [["sub", "obj", "read"]]

    def test_does_not_add_duplicates(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read"])

        assert list(policy) == [["sub", "obj", "read"]]

    def test_can_remove_rules(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.remove(["sub", "obj", "read"])

        assert list(policy) == []

    def test_returns_lengtt(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])

        assert len(policy) == 1

    def test_supports_in_keyword(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])

        assert ["sub", "obj", "read"] in policy

    def test_supports_filters(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read2"])
        policy.append(["sub", "obj2", "read2"])

        policy.apply_filter("read2", "obj2")

        assert list(policy) == [["sub", "obj2", "read2"]]

    def test_clears_filters(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read2"])
        policy.append(["sub", "obj2", "read2"])

        policy.apply_filter("read2", "obj2")
        policy.clear_filter()

        assert list(policy) == [
            ["sub", "obj", "read"],
            ["sub", "obj", "read2"],
            ["sub", "obj2", "read2"],
        ]


class TestContextManager:
    def test_fast_policy_filter(self) -> None:
        policy = FastPolicy([2, 1])

        policy.append(["sub", "obj", "read"])
        policy.append(["sub", "obj", "read2"])
        policy.append(["sub", "obj2", "read2"])

        with fast_policy_filter(policy, "read2", "obj2"):
            assert list(policy) == [["sub", "obj2", "read2"]]

        assert list(policy) == [
            ["sub", "obj", "read"],
            ["sub", "obj", "read2"],
            ["sub", "obj2", "read2"],
        ]
