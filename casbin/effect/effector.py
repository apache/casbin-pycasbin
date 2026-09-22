# Copyright 2021 The casbin Authors. All Rights Reserved.
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


class Effector:
    """Effector is the interface for Casbin effectors."""

    ALLOW = 0

    INDETERMINATE = 1

    DENY = 2

    def intermediate_effect(self, effects):
        """returns an intermediate effect based on the matched effects of the enforcer"""
        pass

    def final_effect(self, effects):
        """returns the final effect based on the matched effects of the enforcer"""
        pass
