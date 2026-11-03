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
from casbin.rbac.default_role_manager import RoleManager
from casbin import util


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(os.path.join(examples_path, path))


def get_enforcer(model=None, adapter=None):
    return casbin.Enforcer(
        model,
        adapter,
    )


def test_benchmark_role_manager_small(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))
    rm: RoleManager = e.get_role_manager()

    e.enable_auto_build_role_links(False)

    p_policies = []
    for i in range(100):
        p_policies.append([f"group{i}", f"data{i}", "read"])

    _ = e.add_policies(p_policies)

    g_policies = []
    for i in range(1000):
        g_policies.append([f"user{i}", f"group{i // 10}"])

    _ = e.add_grouping_policies(g_policies)

    @benchmark
    def run_benchmark():
        for i in range(100):
            _ = rm.has_link("user501", f"group{i}")


def test_benchmark_role_manager_medium(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))
    rm: RoleManager = e.get_role_manager()

    e.enable_auto_build_role_links(False)

    p_policies = []
    for i in range(1000):
        p_policies.append([f"group{i}", f"data{i}", "read"])

    _ = e.add_policies(p_policies)

    g_policies = []
    for i in range(1000):
        g_policies.append([f"user{i}", f"group{i // 10}"])

    _ = e.add_grouping_policies(g_policies)

    e.build_role_links()

    @benchmark
    def run_benchmark():
        for i in range(1000):
            _ = rm.has_link("user501", f"group{i}")


def test_benchmark_role_manager_large(benchmark):
    e = get_enforcer(get_examples("rbac_model.conf"))
    rm: RoleManager = e.get_role_manager()

    e.enable_auto_build_role_links(False)

    p_policies = []
    for i in range(10000):
        p_policies.append([f"group{i}", f"data{i}", "read"])

    _ = e.add_policies(p_policies)

    g_policies = []
    for i in range(100000):
        g_policies.append([f"user{i}", f"group{i // 10}"])

    _ = e.add_grouping_policies(g_policies)

    @benchmark
    def run_benchmark():
        for i in range(10000):
            _ = rm.has_link("user501", f"group{i}")


def test_benchmark_build_role_links_with_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_matching_func("g", util.key_match4_func)

    @benchmark
    def run_benchmark():
        _ = e.build_role_links()


def test_benchmark_build_role_links_with_domain_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_domain_matching_func("g", util.key_match4_func)

    @benchmark
    def run_benchmark():
        _ = e.build_role_links()


def test_benchmark_build_role_links_with_pattern_and_domain_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_matching_func("g", util.key_match4_func)
    e.add_named_domain_matching_func("g", util.key_match4_func)

    @benchmark
    def run_benchmark():
        _ = e.build_role_links()


def test_benchmark_has_link_with_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_matching_func("g", util.key_match4_func)
    rm: RoleManager = e.rm_map["g"]

    @benchmark
    def run_benchmark():
        _ = rm.has_link("staffUser1001", "staff001", "/orgs/1/sites/site001")


def test_benchmark_has_link_with_domain_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_domain_matching_func("g", util.key_match4_func)
    rm: RoleManager = e.rm_map["g"]

    @benchmark
    def run_benchmark():
        _ = rm.has_link("staffUser1001", "staff001", "/orgs/1/sites/site001")


def test_benchmark_has_link_with_pattern_and_domain_pattern_large(benchmark):
    e = get_enforcer(
        get_examples("performance/rbac_with_pattern_large_scale_model.conf"),
        get_examples("performance/rbac_with_pattern_large_scale_policy.csv"),
    )

    e.add_named_matching_func("g", util.key_match4_func)
    e.add_named_domain_matching_func("g", util.key_match4_func)
    rm: RoleManager = e.rm_map["g"]

    @benchmark
    def run_benchmark():
        _ = rm.has_link("staffUser1001", "staff001", "/orgs/1/sites/site001")
