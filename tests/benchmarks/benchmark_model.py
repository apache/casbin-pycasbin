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
from casbin import util


def raw_enforce(sub, obj, act):
    policy = [["alice", "data1", "read"], ["bob", "data2", "write"]]
    for rule in policy:
        if sub == rule[0] and obj == rule[1] and act == rule[2]:
            return True

    return False


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(examples_path + path)


def get_enforcer(model=None, adapter=None):
    return casbin.Enforcer(
        model,
        adapter,
    )


def test_benchmark_raw(benchmark):
    @benchmark
    def benchmark_raw():
        raw_enforce("alice", "data1", "read")


def test_benchmark_basic_model(benchmark):
    e = get_enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))

    @benchmark
    def benchmark_basic_model():
        e.enforce("alice", "data1", "read")


def test_benchmark_rbac_model(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))

    @benchmark
    def benchmark_rbac_model():
        e.enforce("alice", "data1", "read")


def _benchmark_rbac_model_sizes(benchmark, roles, resources, users):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies(
        {
            ("group-has-a-very-long-name-" + str(i), "data-has-a-very-long-name-" + str(i % resources), "read")
            for i in range(roles)
        }
    )
    e.add_grouping_policies(
        {
            ("user-has-a-very-long-name-" + str(i), "group-has-a-very-long-name-" + str(i % roles), "read")
            for i in range(users)
        }
    )

    requests_num = 17
    enforce_requests = []
    for i in range(requests_num):
        user_num = users // requests_num * i
        role_num = user_num % roles
        resource_num = role_num % resources
        if i % 2 == 0:
            resource_num = (resource_num + 1) % resources
        enforce_requests.append(
            (f"user-has-a-very-long-name-{user_num}", f"data-has-a-very-long-name-{resource_num}", "read")
        )

    @benchmark
    def run_benchmark():
        for request in enforce_requests:
            _ = e.enforce(*request)


def test_benchmark_rbac_model_sizes_small(benchmark):
    _benchmark_rbac_model_sizes(benchmark, 100, 10, 1000)


def test_benchmark_rbac_model_sizes_medium(benchmark):
    _benchmark_rbac_model_sizes(benchmark, 1000, 100, 10000)


def test_benchmark_rbac_model_sizes_large(benchmark):
    _benchmark_rbac_model_sizes(benchmark, 10000, 1000, 100000)


def test_benchmark_rbac_model_small(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies({("group" + str(i), "data" + str(int(i / 10)), "read") for i in range(100)})
    e.add_grouping_policies({("user" + str(i), "group" + str(int(i / 10))) for i in range(1000)})

    @benchmark
    def benchmark_rbac_model():
        e.enforce("user501", "data9", "read")


def test_benchmark_rbac_model_medium(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies({("group" + str(i), "data" + str(int(i / 10)), "read") for i in range(1000)})
    e.add_grouping_policies({("user" + str(i), "group" + str(int(i / 10))) for i in range(10000)})

    @benchmark
    def benchmark_rbac_model():
        e.enforce("user501", "data9", "read")


def test_benchmark_rbac_model_large(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))

    e.add_policies({("group" + str(i), "data" + str(int(i / 10)), "read") for i in range(10000)})
    e.add_grouping_policies({("user" + str(i), "group" + str(int(i / 10))) for i in range(100000)})

    @benchmark
    def benchmark_rbac_model():
        e.enforce("user501", "data9", "read")


def test_benchmark_rbac_model_with_resource_roles(benchmark):
    e = get_enforcer(
        get_examples("rbac_with_resource_roles_model.conf"),
        get_examples("rbac_with_resource_roles_policy.csv"),
    )

    @benchmark
    def benchmark_rbac_model_with_resource_roles():
        e.enforce("alice", "data1", "read")


def test_benchmark_rbac_model_with_domains(benchmark):
    e = get_enforcer(
        get_examples("rbac_with_domains_model.conf"),
        get_examples("rbac_with_domains_policy.csv"),
    )

    @benchmark
    def benchmark_rbac_model_with_domains():
        e.enforce("alice", "domain1", "data1", "read")


def test_benchmark_abac_model(benchmark):
    e = get_enforcer(get_examples("abac_model.conf"))
    sub = "alice"
    obj = {"Owner": "alice", "id": "data1"}

    @benchmark
    def benchmark_abac_model():
        e.enforce(sub, obj, "read")


def test_benchmark_abac_rule_model(benchmark):
    e = get_enforcer(get_examples("abac_rule_model.conf"))
    sub = {"Name": "alice", "Age": 18}
    obj = {"Owner": "alice", "id": "data1"}

    e.add_policies({("r.sub.Age > 20", f"data{i}", "read") for i in range(1000)})

    @benchmark
    def benchmark_abac_rule_model():
        ok = e.enforce(sub, obj, "read")
        assert not ok


def test_benchmark_key_match_model(benchmark):
    e = get_enforcer(get_examples("keymatch_model.conf"), get_examples("keymatch_policy.csv"))

    @benchmark
    def benchmark_keymatch():
        e.enforce("alice", "/alice_data/resource1", "GET")


def test_benchmark_rbac_with_deny(benchmark):
    e = get_enforcer(
        get_examples("rbac_with_deny_model.conf"),
        get_examples("rbac_with_deny_policy.csv"),
    )

    @benchmark
    def benchmark_rbac_with_deny():
        e.enforce("alice", "data1", "read")


def test_benchmark_priority_model(benchmark):
    e = get_enforcer(get_examples("priority_model.conf"), get_examples("priority_policy.csv"))

    @benchmark
    def benchmark_rbac_with_deny():
        e.enforce("alice", "data1", "read")


def test_benchmark_rbac_model_with_domains_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_matching_func("g", util.key_match4_func)
    e.build_role_links()

    @benchmark
    def run_benchmark():
        _ = e.enforce("staffUser1001", "/orgs/1/sites/site001", "App001.Module001.Action1001")


def test_benchmark_globmatch(benchmark):
    e = get_enforcer(get_examples("globmatch_model.conf"), get_examples("globmatch_policy.csv"))

    @benchmark
    def benchmark_globmatch():
        e.enforce("alice", "/alice_data/resource1", "GET")
