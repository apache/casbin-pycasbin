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
import random

import casbin


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(examples_path + path)


def get_enforcer(model=None, adapter=None):
    return casbin.Enforcer(
        model,
        adapter,
    )


def _benchmark_has_policy(benchmark, user_num):
    e = get_enforcer(get_examples("basic_model.conf"))

    e.add_policies({(f"user{i}", f"data{i // 10}" "read") for i in range(user_num)})

    @benchmark
    def run_benchmark():
        e.has_policy(f"user{random.randint(0, user_num)}", f"data{random.randint(0, user_num) // 10}", "read")


def test_benchmark_has_policy_small(benchmark):
    _benchmark_has_policy(benchmark, 100)


def test_benchmark_has_policy_medium(benchmark):
    _benchmark_has_policy(benchmark, 1000)


def test_benchmark_has_policy_large(benchmark):
    _benchmark_has_policy(benchmark, 10000)


def _benchmark_add_policy(benchmark, user_num):
    e = get_enforcer(get_examples("basic_model.conf"))

    e.add_policies({(f"user{i}", f"data{i // 10}" "read") for i in range(user_num)})

    @benchmark
    def run_benchmark():
        e.add_policy(
            f"user{random.randint(0, user_num) + user_num}",
            f"data{(random.randint(0, user_num) + user_num) // 10}",
            "read",
        )


def test_benchmark_add_policy_small(benchmark):
    _benchmark_add_policy(benchmark, 100)


def test_benchmark_add_policy_medium(benchmark):
    _benchmark_add_policy(benchmark, 1000)


def test_benchmark_add_policy_large(benchmark):
    _benchmark_add_policy(benchmark, 10000)


def _benchmark_remove_policy(benchmark, user_num):
    e = get_enforcer(get_examples("basic_model.conf"))

    e.add_policies({(f"user{i}", f"data{i // 10}" "read") for i in range(user_num)})

    @benchmark
    def run_benchmark():
        e.remove_policy(f"user{random.randint(0, user_num)}", f"data{random.randint(0, user_num) // 10}", "read")


def test_benchmark_remove_policy_small(benchmark):
    _benchmark_remove_policy(benchmark, 100)


def test_benchmark_remove_policy_medium(benchmark):
    _benchmark_remove_policy(benchmark, 1000)


def test_benchmark_remove_policy_large(benchmark):
    _benchmark_remove_policy(benchmark, 10000)
