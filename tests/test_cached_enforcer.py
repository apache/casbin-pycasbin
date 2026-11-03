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

import contextlib
import logging
import os
import re
import threading
import time
from unittest import TestCase, IsolatedAsyncioTestCase

import casbin
from casbin.async_enforcer import AsyncEnforcer
from casbin.cache import Cache, DefaultCache
from casbin.cached_enforcer import CacheSupport
from casbin.core_enforcer import EnforceContext
from casbin.enforcer import Enforcer
from casbin.persist.adapters import FilteredFileAdapter
from casbin.persist.adapters.filtered_file_adapter import Filter
from casbin.util import time_match_func


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


@contextlib.contextmanager
def logging_enabled(name):
    """casbin silences its loggers unless the caller asks for them, and assertLogs()
    cannot see records from a disabled logger."""
    logger = logging.getLogger(name)
    was_disabled = logger.disabled
    logger.disabled = False
    try:
        yield
    finally:
        logger.disabled = was_disabled


class TestDefaultCache(TestCase):
    def test_set_get_delete_clear(self):
        c = DefaultCache()
        sentinel = object()

        self.assertIs(c.get("nope", sentinel), sentinel)

        c.set("k", "v")
        self.assertEqual(c.get("k", sentinel), "v")

        c.delete("k")
        self.assertIs(c.get("k", sentinel), sentinel)

        c.set("a", 1)
        c.set("b", 2)
        c.clear()
        self.assertEqual(len(c), 0)

    def test_falsy_values_are_not_confused_with_a_miss(self):
        # a denied decision is False, and reporting it as a miss would turn the cache
        # into a slow no-op for exactly the requests that matter most.
        c = DefaultCache()
        sentinel = object()

        c.set("denied", False)
        c.set("none", None)

        self.assertIs(c.get("denied", sentinel), False)
        self.assertIs(c.get("none", sentinel), None)

    def test_entries_expire(self):
        c = DefaultCache()
        sentinel = object()

        c.set("k", "v", 0.05)
        self.assertEqual(c.get("k", sentinel), "v")

        time.sleep(0.1)
        self.assertIs(c.get("k", sentinel), sentinel)
        self.assertEqual(len(c), 0)

    def test_ttl_of_none_or_zero_never_expires(self):
        c = DefaultCache()
        c.set("a", 1, None)
        c.set("b", 2, 0)
        time.sleep(0.05)
        self.assertEqual(c.get("a"), 1)
        self.assertEqual(c.get("b"), 2)

    def test_size_is_bounded(self):
        # keys are built from request values such as user names, so an unbounded cache
        # would grow with every distinct user the application has ever seen.
        c = DefaultCache(max_size=10)
        for i in range(1000):
            c.set(i, i)

        self.assertEqual(len(c), 10)
        self.assertEqual(c.get(999), 999)
        self.assertIsNone(c.get(0))

    def test_least_recently_used_entry_is_evicted(self):
        c = DefaultCache(max_size=3)
        c.set("a", 1)
        c.set("b", 2)
        c.set("c", 3)

        c.get("a")  # "b" is now the least recently used
        c.set("d", 4)

        self.assertEqual(c.get("a"), 1)
        self.assertIsNone(c.get("b"))
        self.assertEqual(c.get("c"), 3)
        self.assertEqual(c.get("d"), 4)

    def test_unbounded_is_opt_in(self):
        c = DefaultCache(max_size=None)
        for i in range(1000):
            c.set(i, i)
        self.assertEqual(len(c), 1000)

    def test_rejects_a_meaningless_bound(self):
        with self.assertRaises(ValueError):
            DefaultCache(max_size=0)
        with self.assertRaises(ValueError):
            DefaultCache(max_size=-1)

    def test_concurrent_access_is_safe(self):
        c = DefaultCache(max_size=64)
        errors = []

        def worker(n):
            try:
                for i in range(2000):
                    c.set((n, i % 128), i, 0.001)
                    c.get((n, i % 128))
            except Exception as exc:  # pragma: no cover - only runs on a real failure
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertLessEqual(len(c), 64)


class TestCacheKey(TestCase):
    def test_plain_request(self):
        self.assertEqual(
            casbin.CachedEnforcer.get_cache_key("alice", "data1", "read"),
            ("alice", "data1", "read"),
        )

    def test_separators_in_values_cannot_collide(self):
        # a key built by joining values with a separator would map both of these onto the
        # same entry, letting one request answer another.
        for sep in ("$$", ",", "|", "::", ""):
            a = casbin.CachedEnforcer.get_cache_key("x" + sep + "y", "z")
            b = casbin.CachedEnforcer.get_cache_key("x", sep + "y", "z")
            c = casbin.CachedEnforcer.get_cache_key("x", "y" + sep + "z")
            self.assertEqual(len({a, b, c}), 3, "collision with separator %r" % sep)

    def test_types_are_kept_apart(self):
        keys = [
            casbin.CachedEnforcer.get_cache_key(1),
            casbin.CachedEnforcer.get_cache_key(1.0),
            casbin.CachedEnforcer.get_cache_key(True),
            casbin.CachedEnforcer.get_cache_key("1"),
            casbin.CachedEnforcer.get_cache_key(None),
            casbin.CachedEnforcer.get_cache_key("None"),
        ]
        self.assertEqual(len(set(keys)), len(keys))

    def test_objects_have_to_opt_in(self):
        class Anonymous:
            pass

        class Keyed:
            def get_cache_key(self):
                return "keyed"

        class Refusing:
            def get_cache_key(self):
                return None

        self.assertIsNone(casbin.CachedEnforcer.get_cache_key("alice", Anonymous()))
        self.assertIsNone(casbin.CachedEnforcer.get_cache_key("alice", Refusing()))
        self.assertIsNotNone(casbin.CachedEnforcer.get_cache_key("alice", Keyed()))

    def test_enforce_context_is_part_of_the_key(self):
        a = casbin.CachedEnforcer.get_cache_key(EnforceContext("r", "p", "e", "m"), "alice")
        b = casbin.CachedEnforcer.get_cache_key(EnforceContext("r2", "p2", "e2", "m2"), "alice")
        self.assertIsNotNone(a)
        self.assertNotEqual(a, b)


class TestCachedEnforcer(TestCase):
    def get_enforcer(self, model, policy):
        return casbin.CachedEnforcer(get_examples(model), get_examples(policy))

    def test_basic(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")

        for _ in range(3):
            self.assertTrue(e.enforce("alice", "data1", "read"))
            self.assertFalse(e.enforce("alice", "data1", "write"))
            self.assertFalse(e.enforce("bob", "data1", "read"))
            self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_rbac(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")

        for _ in range(3):
            self.assertTrue(e.enforce("alice", "data1", "read"))
            self.assertTrue(e.enforce("alice", "data2", "read"))
            self.assertTrue(e.enforce("alice", "data2", "write"))
            self.assertFalse(e.enforce("bob", "data1", "read"))

    def test_a_repeated_request_is_served_from_the_cache(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertEqual(len(e.get_cache()), 0)

        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 1)

        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 1)

        e.enforce("alice", "data1", "write")
        self.assertEqual(len(e.get_cache()), 2)

    def test_batch_enforce_uses_the_cache(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        requests = [("alice", "data1", "read"), ("alice", "data1", "write")]

        self.assertEqual(e.batch_enforce(requests), [True, False])
        self.assertEqual(e.batch_enforce(requests), [True, False])
        self.assertEqual(len(e.get_cache()), 2)

    def test_enforce_ex_is_cached_and_matches_the_uncached_result(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")

        self.assertTupleEqual(e.enforce_ex("alice", "data1", "read"), (True, ["alice", "data1", "read"]))
        self.assertTupleEqual(e.enforce_ex("alice", "data1", "read"), (True, ["alice", "data1", "read"]))
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "read"), (False, []))
        self.assertTupleEqual(e.enforce_ex("alice", "data2", "read"), (False, []))

    def test_a_caller_cannot_corrupt_the_cache_through_the_explanation(self):
        # the explanation upstream is the policy row itself; handing the same list out
        # twice would let a caller rewrite both the cache and the model.
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")

        _, explain = e.enforce_ex("alice", "data1", "read")
        explain.append("tampered")

        self.assertTupleEqual(e.enforce_ex("alice", "data1", "read"), (True, ["alice", "data1", "read"]))

    def test_uncacheable_requests_still_work(self):
        # ABAC requests carry attribute bags that cannot be turned into a key, so they
        # have to fall through to a normal evaluation rather than fail or be mis-keyed.
        e = casbin.CachedEnforcer(get_examples("abac_model.conf"))

        self.assertTrue(e.enforce("alice", {"Owner": "alice", "id": "data1"}, "write"))
        self.assertFalse(e.enforce("alice", {"Owner": "bob", "id": "data1"}, "write"))
        self.assertTrue(e.enforce("alice", {"Owner": "alice", "id": "data1"}, "write"))
        self.assertEqual(len(e.get_cache()), 0)

    def test_enable_cache(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        e.enforce("alice", "data1", "read")

        e.enable_cache(False)
        self.assertEqual(len(e.get_cache()), 0)

        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 0)

        e.enable_cache(True)
        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 1)

    def test_set_cache(self):
        class CountingCache(DefaultCache):
            def __init__(self):
                super().__init__()
                self.reads = 0

            def get(self, key, default=None):
                self.reads += 1
                return super().get(key, default)

        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        cache = CountingCache()
        e.set_cache(cache)

        e.enforce("alice", "data1", "read")
        e.enforce("alice", "data1", "read")

        self.assertIs(e.get_cache(), cache)
        self.assertEqual(cache.reads, 2)

    def test_expire_time(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        e.set_expire_time(0.05)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertEqual(len(e.get_cache()), 1)

        time.sleep(0.1)
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_a_custom_cache_only_has_to_honour_the_default(self):
        # third-party backends implement Cache; the enforcer must not depend on anything
        # beyond "return the default you were given when the key is absent".
        class DictCache(Cache):
            def __init__(self):
                self.store = {}

            def get(self, key, default=None):
                return self.store.get(key, default)

            def set(self, key, value, ttl=None):
                self.store[key] = value

            def delete(self, key):
                self.store.pop(key, None)

            def clear(self):
                self.store.clear()

        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        e.set_cache(DictCache())

        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data1", "read"))

        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))


class TestCacheInvalidation(TestCase):
    """every one of these would return a stale answer if the matching hook were missing."""

    def get_enforcer(self, model, policy):
        return casbin.CachedEnforcer(get_examples(model), get_examples(policy))

    def test_add_policy(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertFalse(e.enforce("alice", "data2", "read"))
        e.add_policy("alice", "data2", "read")
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_remove_policy(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_add_policies(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertFalse(e.enforce("alice", "data2", "read"))
        e.add_policies([["alice", "data2", "read"], ["alice", "data2", "write"]])
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_add_policies_ex(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertFalse(e.enforce("alice", "data2", "read"))
        e.add_policies_ex([["alice", "data1", "read"], ["alice", "data2", "read"]])
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_remove_policies(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        e.remove_policies([["alice", "data1", "read"], ["bob", "data2", "write"]])
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

    def test_update_policy(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        e.enable_auto_save(False)  # FileAdapter cannot persist updates
        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.update_policy(["alice", "data1", "read"], ["alice", "data1", "write"])
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))

    def test_update_policies(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        e.enable_auto_save(False)  # FileAdapter cannot persist updates
        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.update_policies(
            [["alice", "data1", "read"], ["bob", "data2", "write"]],
            [["alice", "data1", "write"], ["bob", "data2", "read"]],
        )
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))

    def test_remove_filtered_policy(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.remove_filtered_policy(0, "alice")
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_add_grouping_policy(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        self.assertFalse(e.enforce("bob", "data2", "read"))
        e.add_grouping_policy("bob", "data2_admin")
        self.assertTrue(e.enforce("bob", "data2", "read"))

    def test_remove_grouping_policy(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        self.assertTrue(e.enforce("alice", "data2", "read"))
        e.remove_grouping_policy("alice", "data2_admin")
        self.assertFalse(e.enforce("alice", "data2", "read"))

    def test_rbac_api_role_changes(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        self.assertFalse(e.enforce("bob", "data2", "read"))
        e.add_role_for_user("bob", "data2_admin")
        self.assertTrue(e.enforce("bob", "data2", "read"))
        e.delete_role_for_user("bob", "data2_admin")
        self.assertFalse(e.enforce("bob", "data2", "read"))

    def test_clear_policy(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.clear_policy()
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_load_policy(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertTrue(e.enforce("alice", "data1", "read"))

        e.clear_policy()
        e.add_policy("alice", "data2", "read")
        self.assertTrue(e.enforce("alice", "data2", "read"))

        e.load_policy()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data2", "read"))

    def test_load_filtered_policy(self):
        e = casbin.CachedEnforcer(
            get_examples("rbac_with_domains_model.conf"),
            FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv")),
        )

        first = Filter()
        first.P = ["", "domain1"]
        first.G = ["", "", "domain1"]
        e.load_filtered_policy(first)
        self.assertTrue(e.enforce("alice", "domain1", "data1", "read"))

        second = Filter()
        second.P = ["", "domain2"]
        second.G = ["", "", "domain2"]
        e.load_filtered_policy(second)
        self.assertFalse(e.enforce("alice", "domain1", "data1", "read"))
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))

    def test_load_increment_filtered_policy(self):
        e = casbin.CachedEnforcer(
            get_examples("rbac_with_domains_model.conf"),
            FilteredFileAdapter(get_examples("rbac_with_domains_policy.csv")),
        )

        first = Filter()
        first.P = ["", "domain1"]
        first.G = ["", "", "domain1"]
        e.load_filtered_policy(first)
        self.assertFalse(e.enforce("bob", "domain2", "data2", "read"))

        second = Filter()
        second.P = ["", "domain2"]
        second.G = ["", "", "domain2"]
        e.load_increment_filtered_policy(second)
        self.assertTrue(e.enforce("bob", "domain2", "data2", "read"))

    def test_build_role_links(self):
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        self.assertTrue(e.enforce("alice", "data2", "read"))

        e.get_role_manager().clear()
        e.build_role_links()
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_enable_enforce(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        self.assertFalse(e.enforce("alice", "data2", "read"))

        e.enable_enforce(False)
        self.assertTrue(e.enforce("alice", "data2", "read"))

        e.enable_enforce(True)
        self.assertFalse(e.enforce("alice", "data2", "read"))

    def test_add_named_matching_func(self):
        e = casbin.CachedEnforcer(
            get_examples("rbac_with_pattern_model.conf"),
            get_examples("rbac_with_pattern_policy.csv"),
        )
        self.assertFalse(e.enforce("alice", "/book/1", "GET"))

        e.add_named_matching_func("g2", casbin.util.key_match2_func)
        e.build_role_links()
        self.assertTrue(e.enforce("alice", "/book/1", "GET"))

    def test_invalidate_cache(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")
        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 1)

        e.invalidate_cache()
        self.assertEqual(len(e.get_cache()), 0)

    def test_every_policy_mutating_method_is_intercepted(self):
        """guards the invalidation list against upstream additions.

        A mutating method that the cache layer does not wrap keeps serving decisions from
        before the change. That is how load_filtered_policy was missed, so assert the
        coverage rather than trusting a hand-maintained list.
        """
        mutating = re.compile(
            r"^(_add_polic|_update_polic|_update_filtered|_remove_polic|_remove_filtered"
            r"|load_policy|load_filtered_policy|load_increment|clear_policy)"
        )

        for cached_cls, base_cls in ((casbin.CachedEnforcer, Enforcer), (casbin.AsyncCachedEnforcer, AsyncEnforcer)):
            declared = set()
            for klass in base_cls.__mro__:
                declared |= set(vars(klass))

            expected = {name for name in declared if mutating.match(name)}
            self.assertTrue(expected, "the detection pattern matched nothing on %s" % base_cls.__name__)

            intercepted = set(vars(CacheSupport)) | set(vars(cached_cls))
            self.assertEqual(
                set(),
                expected - intercepted,
                "%s does not invalidate the cache on: %s" % (cached_cls.__name__, sorted(expected - intercepted)),
            )

    def test_synchronous_methods_are_not_redeclared_as_coroutines(self):
        # clear_policy is synchronous even on AsyncEnforcer; making it a coroutine here
        # would turn e.clear_policy() into an un-awaited no-op.
        import inspect

        for name in ("clear_policy", "build_role_links", "init_rm_map", "enable_enforce"):
            self.assertFalse(
                inspect.iscoroutinefunction(getattr(casbin.AsyncCachedEnforcer, name)),
                "%s must stay synchronous" % name,
            )


class TestConditionalRolesAreNeverCached(TestCase):
    """conditional links are re-evaluated per request, so caching them would keep
    granting access after a role expires. These are the regression tests for that."""

    def get_enforcer(self, cls=casbin.CachedEnforcer):
        e = cls(
            get_examples("rbac_with_temporal_roles_model.conf"),
            get_examples("rbac_with_temporal_roles_policy.csv"),
        )
        e.add_named_link_condition_func("g", "alice", "data2_admin", time_match_func)
        return e

    def test_changing_the_condition_parameters_takes_effect(self):
        e = self.get_enforcer()

        e.set_named_link_condition_func_params(
            "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2000-01-02 00:00:00"
        )
        self.assertFalse(e.enforce("alice", "data2", "read"))

        e.set_named_link_condition_func_params(
            "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"
        )
        self.assertTrue(e.enforce("alice", "data2", "read"))

    def test_a_role_that_expires_stops_granting_access(self):
        e = self.get_enforcer()

        now = time.time()
        e.set_named_link_condition_func_params(
            "g",
            "alice",
            "data2_admin",
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now - 1)),
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now + 1)),
        )

        self.assertTrue(e.enforce("alice", "data2", "read"))
        time.sleep(2.5)
        self.assertFalse(e.enforce("alice", "data2", "read"))

    def test_the_decision_cache_warns_and_steps_aside(self):
        e = self.get_enforcer(casbin.CachedEnforcer)
        e.set_named_link_condition_func_params(
            "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"
        )

        with logging_enabled("casbin.enforcer"), self.assertLogs("casbin.enforcer", level="WARNING") as logs:
            self.assertTrue(e.enforce("alice", "data2", "read"))

        self.assertTrue(any("conditional role managers" in line for line in logs.output))
        self.assertEqual(len(e.get_cache()), 0)

    def test_an_explicit_expire_time_opts_back_in(self):
        e = self.get_enforcer(casbin.CachedEnforcer)
        e.set_named_link_condition_func_params(
            "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"
        )
        e.set_expire_time(30)

        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertEqual(len(e.get_cache()), 1)

    def test_unbounded_expiry_does_not_cache_conditional_roles(self):
        for expiry in (0, -1, float("inf"), float("nan")):
            with self.subTest(expiry=expiry):
                e = self.get_enforcer()
                e.set_expire_time(expiry)
                e.set_named_link_condition_func_params(
                    "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2100-01-01 00:00:00"
                )
                self.assertTrue(e.enforce("alice", "data2", "read"))
                e.set_named_link_condition_func_params(
                    "g", "alice", "data2_admin", "2000-01-01 00:00:00", "2000-01-02 00:00:00"
                )
                self.assertFalse(e.enforce("alice", "data2", "read"))
                self.assertEqual(len(e.get_cache()), 0)


class TestSyncedCachedEnforcer(TestCase):
    def get_enforcer(self, model, policy):
        return casbin.SyncedCachedEnforcer(get_examples(model), get_examples(policy))

    def test_basic(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")

        for _ in range(3):
            self.assertTrue(e.enforce("alice", "data1", "read"))
            self.assertFalse(e.enforce("alice", "data2", "read"))
            self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_invalidation(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.remove_policy("alice", "data1", "read")
        self.assertFalse(e.enforce("alice", "data1", "read"))

        e.add_policy("alice", "data1", "read")
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_cache_controls(self):
        e = self.get_enforcer("basic_model.conf", "basic_policy.csv")

        e.enforce("alice", "data1", "read")
        e.invalidate_cache()
        self.assertEqual(len(e.get_cache()), 0)

        e.enable_cache(False)
        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 0)

        e.enable_cache(True)
        e.set_expire_time(30)
        e.enforce("alice", "data1", "read")
        self.assertEqual(len(e.get_cache()), 1)

    def test_readers_write_to_the_cache_concurrently(self):
        # enforce() runs under the read lock and populating the cache is a write, so
        # several readers store decisions at once. Only the cache's own lock stops that
        # from corrupting it.
        e = self.get_enforcer("rbac_model.conf", "rbac_policy.csv")
        errors = []
        stop = threading.Event()

        def reader():
            try:
                while not stop.is_set():
                    for i in range(50):
                        e.enforce("user%d" % i, "data1", "read")
                    self.assertTrue(e.enforce("alice", "data1", "read"))
            except Exception as exc:  # pragma: no cover - only runs on a real failure
                errors.append(exc)

        def writer():
            try:
                for i in range(200):
                    e.add_policy("tmp%d" % i, "data1", "read")
                    e.remove_policy("tmp%d" % i, "data1", "read")
            except Exception as exc:  # pragma: no cover - only runs on a real failure
                errors.append(exc)
            finally:
                stop.set()

        threads = [threading.Thread(target=reader) for _ in range(4)] + [threading.Thread(target=writer)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)

        self.assertEqual(errors, [])
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("tmp0", "data1", "read"))


class TestAsyncCachedEnforcer(IsolatedAsyncioTestCase):
    async def get_enforcer(self, model, policy):
        e = casbin.AsyncCachedEnforcer(get_examples(model), get_examples(policy))
        await e.load_policy()
        return e

    async def test_basic(self):
        e = await self.get_enforcer("basic_model.conf", "basic_policy.csv")

        for _ in range(3):
            self.assertTrue(e.enforce("alice", "data1", "read"))
            self.assertFalse(e.enforce("alice", "data2", "read"))
            self.assertTrue(e.enforce("bob", "data2", "write"))

        self.assertEqual(len(e.get_cache()), 3)

    async def test_add_and_remove_policy_invalidate(self):
        e = await self.get_enforcer("basic_model.conf", "basic_policy.csv")

        self.assertFalse(e.enforce("alice", "data2", "read"))
        await e.add_policy("alice", "data2", "read")
        self.assertTrue(e.enforce("alice", "data2", "read"))

        await e.remove_policy("alice", "data2", "read")
        self.assertFalse(e.enforce("alice", "data2", "read"))

    async def test_grouping_policy_invalidates(self):
        e = await self.get_enforcer("rbac_model.conf", "rbac_policy.csv")

        self.assertFalse(e.enforce("bob", "data2", "read"))
        await e.add_grouping_policy("bob", "data2_admin")
        self.assertTrue(e.enforce("bob", "data2", "read"))

    async def test_load_policy_invalidates(self):
        e = await self.get_enforcer("basic_model.conf", "basic_policy.csv")

        self.assertTrue(e.enforce("alice", "data1", "read"))
        e.clear_policy()
        self.assertFalse(e.enforce("alice", "data1", "read"))

        await e.load_policy()
        self.assertTrue(e.enforce("alice", "data1", "read"))

    async def test_clear_policy_is_synchronous(self):
        e = await self.get_enforcer("basic_model.conf", "basic_policy.csv")

        result = e.clear_policy()
        self.assertIsNone(result)
        self.assertFalse(e.enforce("alice", "data1", "read"))
