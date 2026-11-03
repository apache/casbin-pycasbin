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

from .watcher import Watcher
from casbin.model import Model


class WatcherEx(Watcher):
    """
    WatcherEx is the strengthened version of PyCasbin Watcher.
    """

    def update_for_add_policy(self, sec: str, ptype: str, *params: str):
        """
        update_for_add_policy calls the update callback of other instances to synchronize their policy.
        It is called after Enforcer.AddPolicy()
        """
        pass

    def update_for_remove_policy(self, sec: str, ptype: str, *params: str):
        """
        update_for_remove_policy calls the update callback of other instances to synchronize their policy.
        It is called after Enforcer.RemovePolicy()
        """
        pass

    def update_for_remove_filtered_policy(self, sec: str, ptype: str, field_index: int, *field_values: str):
        """
        update_for_remove_filtered_policy calls the update callback of other instances to synchronize their policy.
        It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
        """
        pass

    def update_for_save_policy(self, model: Model):
        """
        update_for_save_policy calls the update callback of other instances to synchronize their policy.
        It is called after Enforcer.RemoveFilteredNamedGroupingPolicy()
        """
        pass

    def update_for_add_policies(self, sec: str, ptype: str, *rules: [str]):
        """
        update_for_add_policies calls the update callback of other instances to synchronize their policy.
        It is called after Enforcer.AddPolicies()
        """
        pass

    def update_for_remove_policies(self, sec: str, ptype: str, *rules: [str]):
        """
        update_for_remove_policies calls the update callback of other instances to synchronize their policy.
        It is called after Enforcer.RemovePolicies()
        """
        pass
