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

import casbin


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(examples_path + path)


def _policy(i):
    return [f"user{i}", f"data{i // 10}", "read"]


def _seeded_enforcer(user_num):
    e = casbin.Enforcer(get_examples("basic_model.conf"))
    e.add_policies([_policy(i) for i in range(user_num)])
    return e


def _benchmark_has_policy(benchmark, user_num):
    e = _seeded_enforcer(user_num)
    assert benchmark(e.has_policy, *_policy(user_num - 1))


def test_benchmark_has_policy_small(benchmark):
    _benchmark_has_policy(benchmark, 100)


def test_benchmark_has_policy_medium(benchmark):
    _benchmark_has_policy(benchmark, 1000)


def test_benchmark_has_policy_large(benchmark):
    _benchmark_has_policy(benchmark, 10000)


def _benchmark_add_policy(benchmark, user_num):
    e = _seeded_enforcer(user_num + 1)
    target = _policy(user_num)

    def setup():
        assert e.remove_policy(*target)

    assert benchmark.pedantic(e.add_policy, args=target, setup=setup, rounds=50)
    assert len(e.get_policy()) == user_num + 1


def test_benchmark_add_policy_small(benchmark):
    _benchmark_add_policy(benchmark, 100)


def test_benchmark_add_policy_medium(benchmark):
    _benchmark_add_policy(benchmark, 1000)


def test_benchmark_add_policy_large(benchmark):
    _benchmark_add_policy(benchmark, 10000)


def _benchmark_remove_policy(benchmark, user_num):
    e = _seeded_enforcer(user_num - 1)
    target = _policy(user_num - 1)

    def setup():
        assert e.add_policy(*target)

    assert benchmark.pedantic(e.remove_policy, args=target, setup=setup, rounds=50)
    assert len(e.get_policy()) == user_num - 1


def test_benchmark_remove_policy_small(benchmark):
    _benchmark_remove_policy(benchmark, 100)


def test_benchmark_remove_policy_medium(benchmark):
    _benchmark_remove_policy(benchmark, 1000)


def test_benchmark_remove_policy_large(benchmark):
    _benchmark_remove_policy(benchmark, 10000)
