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

import logging
from collections import namedtuple
from enum import Enum

from casbin.rbac import RoleManager as RM
from casbin.rbac import ConditionalRoleManager as CRM

Link = namedtuple("Link", ["user", "role"])


class MatchOrder(Enum):
    STR_PATTERN = 0
    PATTERN_STR = 1
    PATTERN_PATTERN = 2


class Role:
    def __init__(self, name):
        self.name = name
        self.roles = set()
        self.users = set()
        self.link_condition_func_map = dict()
        self.link_condition_func_params_map = dict()

    def add_role(self, role):
        self.roles.add(role)
        role._add_user(self)

    def remove_role(self, role):
        self.roles.remove(role)
        role._remove_user(self)

    def _add_user(self, user):
        self.users.add(user)

    def _remove_user(self, user):
        self.users.remove(user)

    def copy_from(self, role):
        for r in role.roles:
            self.add_role(r)
        for u in role.users:
            u.add_role(self)

    def empty(self):
        return len(self.users) + len(self.roles) == 0

    def to_string(self):
        if len(self.roles) == 0:
            return ""

        names = ", ".join(self.get_roles())

        if len(self.roles) == 1:
            return self.name + " < " + names
        else:
            return self.name + " < (" + names + ")"

    def get_roles(self):
        roles = []
        for role in self.roles:
            roles.append(role.name)

        return roles

    def add_link_condition_func(self, role, domain, fn):
        self.link_condition_func_map[(role.name, domain)] = fn

    def get_link_condition_func(self, role, domain):
        key = (role.name, domain)
        return self.link_condition_func_map.get(key)

    def set_link_condition_func_params(self, role, domain, *params):
        self.link_condition_func_params_map[(role.name, domain)] = params

    def get_link_condition_func_params(self, role, domain):
        key = (role.name, domain)
        params = self.link_condition_func_params_map.get(key)
        return list(params) if params is not None else []


class RoleManager(RM):
    """provides a default implementation for the RoleManager interface"""

    def __init__(self, max_hierarchy_level=10):
        self.logger = logging.getLogger("casbin.role")
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None
        self.domain_matching_func = None
        self.all_links = list()
        self.all_roles = dict()

    def _rebuild(self):
        self.all_roles = dict()
        links = self.all_links
        self.all_links = list()
        for link in links:
            self.add_link(link.user, link.role)

    def _matching_fn(self, str1, str2, match_order=MatchOrder.STR_PATTERN):
        if match_order == MatchOrder.PATTERN_STR:
            return match_error_handler(self.matching_func, str2, str1)
        elif match_order == MatchOrder.PATTERN_PATTERN:
            return match_error_handler(self.matching_func, str1, str2) or match_error_handler(
                self.matching_func, str2, str1
            )
        else:  # match_order == MatchOrder.STR_PATTERN
            return match_error_handler(self.matching_func, str1, str2)

    def _matching_roles(self, name, match_order=MatchOrder.STR_PATTERN):
        return [
            role
            for role_name, role in list(
                self.all_roles.items()
            )  # convert view to list to avoid RuntimeError: dictionary changed size during iteration
            if self._matching_fn(name, role_name, match_order)
        ]

    def _get_role(self, name):
        if name not in self.all_roles:
            role = Role(name)
            if self.matching_func != None:
                for pattern_role in self._matching_roles(name):
                    role.copy_from(pattern_role)
            self.all_roles[name] = role
        return self.all_roles[name]

    def add_matching_func(self, fn):
        self.matching_func = fn
        self._rebuild()

    def add_domain_matching_func(self, fn=None):
        self.domain_matching_func = fn

    def clear(self):
        self.all_roles = dict()
        self.all_links = list()

    def add_link(self, name1, name2, *domain):
        self.all_links.append(Link(name1, name2))

        user = self._get_role(name1)
        role = self._get_role(name2)

        user.add_role(role)

        if self.matching_func is not None:
            for r in self.all_roles.values():
                if r.name != user.name and self._matching_fn(user.name, r.name, MatchOrder.PATTERN_STR):
                    r.add_role(role)
                if r.name != role.name and self._matching_fn(role.name, r.name, MatchOrder.PATTERN_STR):
                    role.add_role(r)

    def delete_link(self, name1, name2, *domain):
        if Link(name1, name2) not in self.all_links:
            return
        self.all_links.remove(Link(name1, name2))

        user = self._get_role(name1)
        role = self._get_role(name2)
        user.remove_role(role)

        if self.matching_func is not None:
            for r in self.all_roles.values():
                if r.name != user.name and self._matching_fn(user.name, r.name, MatchOrder.PATTERN_STR):
                    r.remove_role(role)
                if r.name != role.name and self._matching_fn(role.name, r.name, MatchOrder.PATTERN_STR):
                    role.remove_role(r)

    def has_link(self, name1, name2, *domain):
        user = self._get_role(name1)
        role = self._get_role(name2)

        return self._has_link(name2, [user], self.max_hierarchy_level)

    def _has_link(self, name, roles, level):
        if level <= 0 or len(roles) == 0:
            return False

        next_roles = set()
        for role in roles:
            if name == role.name:
                return True
            next_roles.update(set(role.roles))

        return self._has_link(name, list(next_roles), level - 1)

    def get_roles(self, name, *domain):
        user = self._get_role(name)
        return [r.name for r in user.roles]

    def get_users(self, name, *domain):
        role = self._get_role(name)
        return [u.name for u in role.users]

    def to_string(self):
        line = []
        for role in self.all_roles.values():
            text = role.to_string()
            if text:
                line.append(text)
        return ", ".join(line)

    def print_roles(self):
        self.logger.info(self.to_string())


class DomainManagerBase(RM):
    def __init__(self, max_hierarchy_level=10):
        self.logger = logging.getLogger("casbin.role")
        self.all_links = dict()
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None
        self.domain_matching_func = None
        self.matching_func = lambda name1, name2: name1 == name2

    def add_matching_func(self, fn):
        self.matching_func = fn

    def add_domain_matching_func(self, fn=None):
        self.domain_matching_func = fn

    def _get_domain(self, *domain):
        if len(domain) > 1:
            raise RuntimeError("error: domain should be 1 parameter")
        elif len(domain) == 1:
            domain = domain[0]
        else:
            domain = ""

        return domain

    def _get_links(self, *domain):
        domain = self._get_domain(*domain)

        if domain not in self.all_links:
            self.all_links[domain] = []

        return self.all_links[domain]

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        domain_links = self.all_links.get(domain1, [])

        if self.domain_matching_func != None:
            for domain2, links in self.all_links.items():
                if domain1 != domain2 and match_error_handler(self.domain_matching_func, domain1, domain2):
                    domain_links = domain_links + links

        rm = RoleManager(max_hierarchy_level=self.max_hierarchy_level)
        rm.add_matching_func(self.matching_func)
        for link in domain_links:
            rm.add_link(link[0], link[1])
        return rm

    def clear(self):
        self.all_links = dict()

    def add_link(self, name1, name2, *domain):
        links = self._get_links(*domain)
        links.append(Link(name1, name2))

    def delete_link(self, name1, name2, *domain):
        links = self._get_links(*domain)
        if Link(name1, name2) not in links:
            raise RuntimeError(f"error: link between {name1} and {name2} does not exist")
        links.remove(Link(name1, name2))

    def has_link(self, name1, name2, *domain):
        rm = self._get_role_manager(*domain)
        return rm.has_link(name1, name2)

    def get_roles(self, name, *domain):
        rm = self._get_role_manager(*domain)
        return rm.get_roles(name)

    def get_users(self, name, *domain):
        rm = self._get_role_manager(*domain)
        return rm.get_users(name)

    def print_roles(self):
        pass


class DomainManager(DomainManagerBase):
    def __init__(self, max_hierarchy_level=10):
        super().__init__(max_hierarchy_level)
        self.rm_map = dict()  # type: dict[str, RoleManager]

    def _rebuild(self):
        self.rm_map = dict()

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        if domain1 not in self.rm_map:
            self.rm_map[domain1] = super()._get_role_manager(*domain)

        return self.rm_map[domain1]

    def _affected_role_managers(self, *domain):
        domain_pattern = self._get_domain(*domain)

        if self.domain_matching_func != None:
            return [
                self.rm_map[domain_str]
                for domain_str in self.rm_map.keys()
                if match_error_handler(self.domain_matching_func, domain_str, domain_pattern)
            ]
        else:
            return [self.rm_map[domain_pattern]] if domain_pattern in self.rm_map else []

    def add_matching_func(self, fn):
        super().add_matching_func(fn)
        for rm in self.rm_map.values():
            rm.add_matching_func(fn)

    def add_domain_matching_func(self, fn):
        super().add_domain_matching_func(fn)
        for rm in self.rm_map.values():
            rm.add_domain_matching_func(fn)
        self._rebuild()

    def clear(self):
        super().clear()
        self.rm_map = dict()

    def add_link(self, name1, name2, *domain):
        super().add_link(name1, name2, *domain)
        for rm in self._affected_role_managers(*domain):
            rm.add_link(name1, name2, *domain)

    def delete_link(self, name1, name2, *domain):
        super().delete_link(name1, name2, *domain)
        for rm in self._affected_role_managers(*domain):
            rm.delete_link(name1, name2, *domain)

    def has_link(self, name1, name2, *domain):
        return super().has_link(name1, name2, *domain)

    def get_roles(self, name, *domain):
        return super().get_roles(name, *domain)

    def get_users(self, name, *domain):
        return super().get_users(name, *domain)

    def print_roles(self):
        for domain, rm in self.rm_map.items():
            line = rm.to_string()
            self.logger.info(f"{domain}: {line}")


def match_error_handler(fn, key1, key2):
    try:
        return fn(key1, key2)
    except:
        return False


class ConditionalRoleManager(RoleManager, CRM):
    def has_link(self, name1, name2, *domains):
        """determines whether role: name1 inherits role: name2."""
        if name1 == name2 or (self.matching_func is not None and self._matching_fn(name1, name2)):
            return True

        user = self._get_role(name1)
        role = self._get_role(name2)

        return self._has_link(role.name, [user], self.max_hierarchy_level, *domains)

    def _has_link(self, target_name, roles, level, *domains):
        """use the Breadth First Search algorithm to traverse the Role tree
        Judging whether the user has a role (has link) is to judge whether the role node can be reached from the user node
        """
        if level < 0 or len(roles) == 0:
            return False

        next_roles = set()
        for role in roles:
            if target_name == role.name or (
                self.matching_func is not None and self._matching_fn(role.name, target_name)
            ):
                return True

            for next_role in role.roles:
                linked_role = self.get_next_roles(role, next_role, domains)
                next_roles.update(set(linked_role))

        return self._has_link(target_name, next_roles, level - 1, *domains)

    def get_next_roles(self, current_role, next_role, domains):
        pass_link_condition_func = True
        next_roles = list()
        if not domains:
            link_condition_func = self.get_link_condition_func(current_role.name, next_role.name)
            if link_condition_func is not None:
                params = self.get_link_condition_func_params(current_role.name, next_role.name)
                pass_link_condition_func = link_condition_func(*params)
        else:
            link_condition_func = self.get_domain_link_condition_func(current_role.name, next_role.name, domains[0])
            if link_condition_func is not None:
                params = self.get_link_condition_func_params(current_role.name, next_role.name, domains)
                pass_link_condition_func = link_condition_func(*params)

        if pass_link_condition_func:
            next_roles.append(next_role)

        return next_roles

    def get_link_condition_func(self, user_name, role_name):
        """get_link_condition_func get link_condition_func based on userName, roleName"""
        return self.get_domain_link_condition_func(user_name, role_name, "")

    def get_domain_link_condition_func(self, user_name, role_name, domain):
        """get_domain_link_condition_func get link_condition_func based on userName, roleName, domain"""
        user = self._get_role(user_name)
        role = self._get_role(role_name)

        return user.get_link_condition_func(role, domain)

    def get_link_condition_func_params(self, user_name, role_name, domains=None):
        """get_link_condition_func_params gets parameters of link_condition_func based on userName, roleName, domain"""
        if domains is None:
            domains = []

        user = self._get_role(user_name)
        role = self._get_role(role_name)

        domain_name = ""
        if len(domains) != 0:
            domain_name = domains[0]

        return user.get_link_condition_func_params(role, domain_name)

    def add_link_condition_func(self, user_name, role_name, fn):
        """add_link_condition_func is based on userName, roleName, add LinkConditionFunc"""
        self.add_domain_link_condition_func(user_name, role_name, "", fn)

    def add_domain_link_condition_func(self, user_name, role_name, domain, fn):
        """add_domain_link_condition_func is based on userName, roleName, domain, add LinkConditionFunc"""
        user = self._get_role(user_name)
        role = self._get_role(role_name)
        user.add_link_condition_func(role, domain, fn)

    def set_link_condition_func_params(self, user_name, role_name, *params):
        """set_link_condition_func_params sets parameters of LinkConditionFunc based on userName, roleName, domain"""
        self.set_domain_link_condition_func_params(user_name, role_name, "", *params)

    def set_domain_link_condition_func_params(self, user_name, role_name, domain, *params):
        """set_domain_link_condition_func_params sets parameters of LinkConditionFunc based on userName, roleName, domain"""
        user = self._get_role(user_name)
        role = self._get_role(role_name)
        user.set_link_condition_func_params(role, domain, *params)


class ConditionalDomainManager(DomainManager, ConditionalRoleManager):
    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        if domain1 not in self.rm_map:
            self.rm_map[domain1] = self._get_conditional_role_manager(*domain)

        return self.rm_map[domain1]

    def _get_conditional_role_manager(self, *domain, store=False):
        domain1 = self._get_domain(*domain)
        domain_links = self.all_links.get(domain1, [])

        rm = self.rm_map.get(domain1, None)

        if rm is None:
            rm = ConditionalRoleManager(max_hierarchy_level=self.max_hierarchy_level)
            if store:
                self.rm_map[domain1] = rm
            if self.domain_matching_func is not None:
                for domain2, links in self.all_links.items():
                    if domain1 != domain2 and match_error_handler(self.domain_matching_func, domain1, domain2):
                        domain_links = domain_links + links

            rm.add_matching_func(self.matching_func)
            for link in domain_links:
                rm.add_link(link[0], link[1])
        return rm

    def has_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        rm = self._get_conditional_role_manager(domain)
        return rm.has_link(name1, name2, domain)

    def add_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        rm = self._get_conditional_role_manager(domain, store=True)
        rm.add_link(name1, name2, domain)

    def delete_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        rm = self._get_conditional_role_manager(domain, store=True)
        rm.delete_link(name1, name2, domain)

    def add_link_condition_func(self, user_name, role_name, fn):
        for rm in self.rm_map.values():
            rm.add_link_condition_func(user_name, role_name, fn)

    def add_domain_link_condition_func(self, user_name, role_name, domain, fn):
        for rm in self.rm_map.values():
            rm.add_domain_link_condition_func(user_name, role_name, domain, fn)

    def set_link_condition_func_params(self, user_name, role_name, *params):
        for rm in self.rm_map.values():
            rm.set_link_condition_func_params(user_name, role_name, *params)

    def set_domain_link_condition_func_params(self, user_name, role_name, domain, *params):
        for rm in self.rm_map.values():
            rm.set_domain_link_condition_func_params(user_name, role_name, domain, *params)
