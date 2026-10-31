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

import threading

_WILDCARD_POLICY_BUCKET = 2**32 - 1
_MISSING_POLICY_BUCKET = 2**32 - 2


class PolicyIndex:
    """PolicyIndex partitions the policy rules of one policy type so that
    enforce() only evaluates the rules in the request's partition.

    request_key receives the request values, with an optional EnforceContext
    removed, and returns ``(key, True)``. Returning ``(key, False)`` disables
    the index for that request, so every rule is evaluated.

    policy_key returns the partition key for one policy rule. The key ``"*"``
    puts the rule in every partition.

    enforce() skips the matcher of a rule whose key differs from the request
    key. The caller must guarantee that such a rule can never match the
    request; otherwise the decision changes. This includes matchers that
    evaluate policy fields with eval(). Rules are still merged by the
    configured effector, so deny rules must be reachable through the request
    key or ``"*"``.
    """

    def __init__(self, request_key, policy_key):
        if not callable(request_key) or not callable(policy_key):
            raise TypeError("request_key and policy_key must be callable")

        self.request_key = request_key
        self.policy_key = policy_key
        self._lock = threading.Lock()
        self._built = False
        self._version = 0
        self._bucket_ids = []
        self._names = {}

    def ensure_built(self, assertion):
        with self._lock:
            if (
                self._built
                and self._version == assertion.policy_version
                and len(self._bucket_ids) == len(assertion.policy)
            ):
                return self._bucket_ids

            names = {}
            bucket_ids = []
            next_id = 0
            for rule in assertion.policy:
                key = self.policy_key(rule)
                if key == "*":
                    bucket_ids.append(_WILDCARD_POLICY_BUCKET)
                    continue

                bucket_id = names.get(key)
                if bucket_id is None:
                    bucket_id = next_id
                    names[key] = bucket_id
                    next_id += 1
                bucket_ids.append(bucket_id)

            self._bucket_ids = bucket_ids
            self._names = names
            self._version = assertion.policy_version
            self._built = True
            return bucket_ids

    def request_bucket(self, rvals):
        key, ok = self.request_key(rvals)
        if not ok:
            return 0, False

        with self._lock:
            bucket_id = self._names.get(key)
        if bucket_id is None:
            return _MISSING_POLICY_BUCKET, True
        return bucket_id, True

    def reset(self):
        with self._lock:
            self._built = False
            self._bucket_ids = []
            self._names = {}


def policy_matches_bucket(bucket_ids, policy_index, bucket):
    if policy_index < 0 or policy_index >= len(bucket_ids):
        return True
    bucket_id = bucket_ids[policy_index]
    return bucket_id == _WILDCARD_POLICY_BUCKET or bucket_id == bucket
