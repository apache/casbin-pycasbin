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


class RoleManager:
    """provides interface to define the operations for managing roles."""

    def clear(self):
        pass

    def add_link(self, name1, name2, *domain):
        pass

    def delete_link(self, name1, name2, *domain):
        pass

    def has_link(self, name1, name2, *domain):
        pass

    def get_roles(self, name, *domain):
        pass

    def get_users(self, name, *domain):
        pass

    def print_roles(self):
        pass


class ConditionalRoleManager(RoleManager):
    """
    ConditionalRoleManager provides interface to define the operations for managing roles.
    Link with conditions is supported
    """

    def add_link_condition_func(self, user_name, role_name, fn):
        """add_link_condition_func add condition function fn for Link user_name->role_name,
        when fn returns true, Link is valid, otherwise invalid"""
        pass

    def set_link_condition_func_params(self, user_name, role_name, *params):
        """set_link_condition_func_params Sets the parameters of the condition function fn for Link user_name->role_name"""
        pass

    def add_domain_link_condition_func(self, user, role, domain, fn):
        """add_domain_link_condition_func Add condition function fn for Link user_name-> {role_name, domain},
        when fn returns true, Link is valid, otherwise invalid"""
        pass

    def set_domain_link_condition_func_params(self, user, role, domain, *params):
        """set_domain_link_condition_func_params Sets the parameters of the condition function fn
        for Link user_name->{role_name, domain}"""
        pass
