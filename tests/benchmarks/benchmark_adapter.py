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


def _benchmark_extract_tokens(benchmark, line):
    @benchmark
    def run_benchmark():
        _extract_tokens(line)


def test_benchmark_extract_tokens_short_simple(benchmark):
    _benchmark_extract_tokens(benchmark, "abc,def,ghi")


def test_benchmark_extract_tokens_long_simple(benchmark):
    # fixed UUIDs for length and to be similar to "real world" usage of UUIDs
    _benchmark_extract_tokens(
        benchmark,
        "00000000-0000-0000-0000-000000000000,00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002",
    )


def test_benchmark_extract_tokens_short_nested(benchmark):
    _benchmark_extract_tokens(benchmark, "abc(def,ghi),jkl(mno,pqr)")


def test_benchmark_extract_tokens_long_nested(benchmark):
    _benchmark_extract_tokens(
        benchmark,
        "00000000-0000-0000-0000-000000000000(00000000-0000-0000-0000-000000000001,00000000-0000-0000-0000-000000000002),00000000-0000-0000-0000-000000000003(00000000-0000-0000-0000-000000000004,00000000-0000-0000-0000-000000000005)",
    )
