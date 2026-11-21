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


class Dispatcher:
    """Dispatcher is the interface for pycasbin dispatcher"""

    def add_policies(self, sec, ptype, rules):
        """add_policies adds policies rule to all instance."""
        pass

    def remove_policies(self, sec, ptype, rules):
        """remove_policies removes policies rule from all instance."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, field_values):
        """remove_filtered_policy removes policy rules that match the filter from all instance."""
        pass

    def clear_policy(self):
        """clear_policy clears all current policy in all instances."""
        pass

    def update_policy(self, sec, ptype, old_rule, new_rule):
        """update_policy updates policy rule from all instance."""
        pass
