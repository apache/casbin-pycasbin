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

import logging
import threading
from collections import OrderedDict, namedtuple
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

    def copy_link_conditions(self, other, role_name=""):
        for key, fn in list(other.link_condition_func_map.items()):
            if role_name == "" or key[0] == role_name:
                self.link_condition_func_map[key] = fn
        for key, params in list(other.link_condition_func_params_map.items()):
            if role_name == "" or key[0] == role_name:
                self.link_condition_func_params_map[key] = params


class RoleManager(RM):
    """provides a default implementation for the RoleManager interface"""

    def __init__(self, max_hierarchy_level=10):
        self.logger = logging.getLogger("casbin.role")
        self.max_hierarchy_level = max_hierarchy_level
        self.matching_func = None
        self.domain_matching_func = None
        self.all_links = dict()
        self.all_roles = dict()
        self._query_lock = threading.RLock()

    def _rebuild(self):
        self.all_roles = dict()
        links = self.all_links
        self.all_links = dict()
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

    def _remove_role(self, name):
        """removes a role created only to answer a query, with the links copied from pattern roles."""
        role = self.all_roles.pop(name, None)
        if role is None:
            return
        for r in list(role.roles):
            r.users.discard(role)
        for u in list(role.users):
            u.roles.discard(role)

    def _query(self, names, fn):
        """calls fn with the roles of names, removing afterwards the roles that did not exist before,
        so that querying arbitrary names does not grow the role manager."""
        with self._query_lock:
            created = [name for name in dict.fromkeys(names) if name not in self.all_roles]
            try:
                return fn(*[self._get_role(name) for name in names])
            finally:
                for name in created:
                    self._remove_role(name)

    def add_matching_func(self, fn):
        self.matching_func = fn
        self._rebuild()

    def add_domain_matching_func(self, fn=None):
        self.domain_matching_func = fn

    def clear(self):
        self.all_roles = dict()
        self.all_links = dict()

    def add_link(self, name1, name2, *domain):
        self.all_links[Link(name1, name2)] = None

        user = self._get_role(name1)
        role = self._get_role(name2)

        user.add_role(role)

        if self.matching_func != None:
            for r in self.all_roles.values():
                if r.name != user.name and self._matching_fn(user.name, r.name, MatchOrder.PATTERN_STR):
                    r.add_role(role)
                if r.name != role.name and self._matching_fn(role.name, r.name, MatchOrder.PATTERN_STR):
                    role.add_role(r)

    def delete_link(self, name1, name2, *domain):
        if Link(name1, name2) not in self.all_links:
            return
        del self.all_links[Link(name1, name2)]

        user = self._get_role(name1)
        role = self._get_role(name2)
        user.remove_role(role)

        if self.matching_func != None:
            for r in self.all_roles.values():
                if r.name != user.name and self._matching_fn(user.name, r.name, MatchOrder.PATTERN_STR):
                    r.remove_role(role)
                if r.name != role.name and self._matching_fn(role.name, r.name, MatchOrder.PATTERN_STR):
                    role.remove_role(r)

    def has_link(self, name1, name2, *domain):
        return self._query([name1, name2], lambda user, role: self._has_link(name2, [user], self.max_hierarchy_level))

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
        return self._query([name], lambda user: [r.name for r in user.roles])

    def get_users(self, name, *domain):
        return self._query([name], lambda role: [u.name for u in role.users])

    def to_string(self):
        line = []
        for role in self.all_roles.values():
            text = role.to_string()
            if text:
                line.append(text)
        return ", ".join(line)

    def print_roles(self):
        self.logger.debug(self.to_string())


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
            self.all_links[domain] = dict()

        return self.all_links[domain]

    def _domain_match(self, domain, pattern):
        if domain == pattern:
            return True
        if self.domain_matching_func is None:
            return False
        return match_error_handler(self.domain_matching_func, domain, pattern)

    def _grant_domains(self, name1, name2):
        """returns the domains in which the link between name1 and name2 is still added."""
        link = Link(name1, name2)
        return [domain for domain, links in self.all_links.items() if link in links]

    def _link_granted(self, domain, grant_domains):
        return any(self._domain_match(domain, grant_domain) for grant_domain in grant_domains)

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        domain_links = list(self.all_links.get(domain1, {}))

        if self.domain_matching_func != None:
            for domain2, links in self.all_links.items():
                if domain1 != domain2 and match_error_handler(self.domain_matching_func, domain1, domain2):
                    domain_links = domain_links + list(links)

        rm = RoleManager(max_hierarchy_level=self.max_hierarchy_level)
        rm.add_matching_func(self.matching_func)
        for link in domain_links:
            rm.add_link(link[0], link[1])
        return rm

    def clear(self):
        self.all_links = dict()

    def add_link(self, name1, name2, *domain):
        links = self._get_links(*domain)
        links[Link(name1, name2)] = None

    def delete_link(self, name1, name2, *domain):
        links = self._get_links(*domain)
        if Link(name1, name2) not in links:
            raise RuntimeError(f"error: link between {name1} and {name2} does not exist")
        del links[Link(name1, name2)]

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
    def __init__(self, max_hierarchy_level=10, max_cached_role_managers=1000):
        """Caches one role manager per domain.

        max_cached_role_managers limits the cache; the least recently used role
        manager is evicted when the limit is exceeded. Pass 0 or None for no limit.
        ConditionalDomainManager does not use this limit because its link
        conditions live in the role managers.
        """
        super().__init__(max_hierarchy_level)
        self.max_cached_role_managers = max_cached_role_managers
        self.rm_map = OrderedDict()  # type: OrderedDict[str, RoleManager]

    def _rebuild(self):
        self.rm_map = OrderedDict()

    def _get_role_manager(self, *domain):
        domain1 = self._get_domain(*domain)
        rm = self.rm_map.get(domain1)
        if rm is None:
            rm = super()._get_role_manager(*domain)
            self.rm_map[domain1] = rm
            if self.max_cached_role_managers and self.max_cached_role_managers > 0:
                while len(self.rm_map) > self.max_cached_role_managers:
                    self.rm_map.popitem(last=False)
        else:
            self.rm_map.move_to_end(domain1)

        return rm

    def _affected_role_managers(self, *domain):
        domain_pattern = self._get_domain(*domain)

        if self.domain_matching_func != None:
            return [
                (domain_str, rm)
                for domain_str, rm in list(self.rm_map.items())
                if self._domain_match(domain_str, domain_pattern)
            ]
        else:
            return [(domain_pattern, self.rm_map[domain_pattern])] if domain_pattern in self.rm_map else []

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
        self.rm_map = OrderedDict()

    def add_link(self, name1, name2, *domain):
        super().add_link(name1, name2, *domain)
        for _, rm in self._affected_role_managers(*domain):
            rm.add_link(name1, name2, *domain)

    def delete_link(self, name1, name2, *domain):
        super().delete_link(name1, name2, *domain)
        grant_domains = self._grant_domains(name1, name2)
        for domain2, rm in self._affected_role_managers(*domain):
            if not self._link_granted(domain2, grant_domains):
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
            self.logger.debug(f"{domain}: {line}")


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

        return self._query(
            [name1, name2],
            lambda user, role: self._has_link(role.name, [user], self.max_hierarchy_level, *domains),
        )

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
            elif self.domain_matching_func is not None:
                pass_link_condition_func = self._check_pattern_link_condition(
                    current_role.name, next_role.name, domains[0]
                )

        if pass_link_condition_func:
            next_roles.append(next_role)

        return next_roles

    def _check_pattern_link_condition(self, name1, name2, domain):
        """checks the conditions of the links inherited from the domain patterns matching domain."""
        user = self.all_roles.get(name1)
        if user is None:
            return True

        for key, fn in list(user.link_condition_func_map.items()):
            role_name, domain_name = key
            if (
                role_name != name2
                or domain_name == domain
                or not match_error_handler(self.domain_matching_func, domain, domain_name)
            ):
                continue
            params = user.link_condition_func_params_map.get(key)
            if not fn(*(params if params is not None else [])):
                return False

        return True

    def _copy_from(self, other):
        for link in list(dict.fromkeys(other.all_links)):
            self.add_link(link.user, link.role)
            src = other.all_roles.get(link.user)
            if src is not None:
                self._get_role(link.user).copy_link_conditions(src, link.role)

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
        return self._get_conditional_role_manager(*domain)

    def _get_conditional_role_manager(self, *domain, store=False):
        domain1 = self._get_domain(*domain)
        rm = self.rm_map.get(domain1, None)

        if rm is None:
            rm = ConditionalRoleManager(max_hierarchy_level=self.max_hierarchy_level)
            rm.add_matching_func(self.matching_func)
            rm.add_domain_matching_func(self.domain_matching_func)
            if store:
                self.rm_map[domain1] = rm
            if self.domain_matching_func is not None:
                for domain2, rm2 in list(self.rm_map.items()):
                    if domain1 != domain2 and match_error_handler(self.domain_matching_func, domain1, domain2):
                        rm._copy_from(rm2)
        return rm

    def _affected_conditional_role_managers(self, domain):
        if self.domain_matching_func is None:
            return []
        return [
            (domain2, rm)
            for domain2, rm in list(self.rm_map.items())
            if domain != domain2 and match_error_handler(self.domain_matching_func, domain2, domain)
        ]

    def _link_conditional_role_managers(self, domain):
        """returns the role managers that check the links of domain: the role manager of domain
        and those of the domains matched by domain as a pattern."""
        rms = [self._get_conditional_role_manager(domain, store=True)]
        rms.extend(rm for _, rm in self._affected_conditional_role_managers(domain))
        return rms

    def _rebuild(self):
        rm_map = self.rm_map
        links = self.all_links
        self.all_links = dict()
        self.rm_map = OrderedDict()
        for domain, domain_links in links.items():
            for link in domain_links:
                self.add_link(link.user, link.role, domain)
        for domain in rm_map:
            self._get_conditional_role_manager(domain, store=True)
        for domain, old_rm in rm_map.items():
            for rm in self._link_conditional_role_managers(domain):
                for name, src in list(old_rm.all_roles.items()):
                    rm._get_role(name).copy_link_conditions(src)

    def has_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        rm = self._get_conditional_role_manager(domain)
        return rm.has_link(name1, name2, domain)

    def add_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        self._get_links(domain)[Link(name1, name2)] = None
        rm = self._get_conditional_role_manager(domain, store=True)
        rm.add_link(name1, name2, domain)

        src = rm.all_roles.get(name1)
        for _, rm2 in self._affected_conditional_role_managers(domain):
            rm2.add_link(name1, name2, domain)
            if src is not None:
                rm2._get_role(name1).copy_link_conditions(src, name2)

    def delete_link(self, name1, name2, *domain):
        domain = self._get_domain(*domain)
        self.all_links.get(domain, {}).pop(Link(name1, name2), None)
        grant_domains = self._grant_domains(name1, name2)
        rm = self._get_conditional_role_manager(domain, store=True)
        if not self._link_granted(domain, grant_domains):
            rm.delete_link(name1, name2, domain)

        for domain2, rm2 in self._affected_conditional_role_managers(domain):
            if not self._link_granted(domain2, grant_domains):
                rm2.delete_link(name1, name2, domain)

    def add_link_condition_func(self, user_name, role_name, fn):
        for rm in self.rm_map.values():
            rm.add_link_condition_func(user_name, role_name, fn)

    def add_domain_link_condition_func(self, user_name, role_name, domain, fn):
        for rm in self._link_conditional_role_managers(domain):
            rm.add_domain_link_condition_func(user_name, role_name, domain, fn)

    def set_link_condition_func_params(self, user_name, role_name, *params):
        for rm in self.rm_map.values():
            rm.set_link_condition_func_params(user_name, role_name, *params)

    def set_domain_link_condition_func_params(self, user_name, role_name, domain, *params):
        for rm in self._link_conditional_role_managers(domain):
            rm.set_domain_link_condition_func_params(user_name, role_name, domain, *params)
