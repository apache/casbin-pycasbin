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

from casbin.persist.adapter import _extract_tokens
from tests import TestCaseBase


class TestExtractTokens(TestCaseBase):
    def test_ignore_lines(self):
        self.assertIsNone(_extract_tokens(""))  # empty
        self.assertIsNone(_extract_tokens("# comment"))

    def test_simple_lines(self):
        # split on top-level commas, strip whitespace from start and end
        self.assertEqual(_extract_tokens("one"), ["one"])
        self.assertEqual(_extract_tokens("one,two"), ["one", "two"])
        self.assertEqual(_extract_tokens("   ignore  \t,\t   external, spaces  "), ["ignore", "external", "spaces"])

        self.assertEqual(_extract_tokens("internal spaces preserved"), ["internal spaces preserved"])

    def test_nested_lines(self):
        # basic nesting within a single token
        self.assertEqual(
            _extract_tokens("outside1()"),
            ["outside1()"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1())"),
            ["outside1(inside1())"],
        )

        # split on top-level commas, but not on internal ones
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2())"),
            ["outside1(inside1(), inside2())"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2(inside3(), inside4()))"),
            ["outside1(inside1(), inside2(inside3(), inside4()))"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2()), outside2(inside3(), inside4())"),
            ["outside1(inside1(), inside2())", "outside2(inside3(), inside4())"],
        )

        # different delimiters
        self.assertEqual(
            _extract_tokens(
                "all_square[inside1[], inside2[]],square_and_parens[inside1(), inside2()],parens_and_square(inside1[], inside2[])"
            ),
            [
                "all_square[inside1[], inside2[]]",
                "square_and_parens[inside1(), inside2()]",
                "parens_and_square(inside1[], inside2[])",
            ],
        )
