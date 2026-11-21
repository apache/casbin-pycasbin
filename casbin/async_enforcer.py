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

from functools import partial

from casbin.async_management_enforcer import AsyncManagementEnforcer
from casbin.util import join_slice, array_remove_duplicates, set_subtract


class AsyncEnforcer(AsyncManagementEnforcer):
    """
    AsyncEnforcer = AsyncManagementEnforcer + RBAC_API + RBAC_WITH_DOMAIN_API
    """

    async def get_roles_for_user(self, name):
        """gets the roles that a user has."""
        return self.model.model["g"]["g"].rm.get_roles(name)

    async def get_users_for_role(self, name):
        """gets the users that have a role."""
        return self.model.model["g"]["g"].rm.get_users(name)

    async def has_role_for_user(self, name, role):
        """determines whether a user has a role."""
        roles = await self.get_roles_for_user(name)
        return any(r == role for r in roles)

    async def add_role_for_user(self, user, role):
        """
        async adds a role for a user.
        Returns false if the user already has the role (aka not affected).
        """
        return await self.add_grouping_policy(user, role)

    async def delete_role_for_user(self, user, role):
        """
        async deletes a role for a user.
        Returns false if the user does not have the role (aka not affected).
        """
        return await self.remove_grouping_policy(user, role)

    async def delete_roles_for_user(self, user):
        """
        async deletes all roles for a user.
        Returns false if the user does not have any roles (aka not affected).
        """
        return await self.remove_filtered_grouping_policy(0, user)

    async def delete_user(self, user):
        """
        async deletes a user.
        Returns false if the user does not exist (aka not affected).
        """
        res1 = await self.remove_filtered_grouping_policy(0, user)

        res2 = await self.remove_filtered_policy(0, user)
        return res1 or res2

    async def delete_role(self, role):
        """
        async deletes a role.
        Returns false if the role does not exist (aka not affected).
        """
        res1 = await self.remove_filtered_grouping_policy(1, role)

        res2 = await self.remove_filtered_policy(0, role)
        return res1 or res2

    async def delete_permission(self, *permission):
        """
        async deletes a permission.
        Returns false if the permission does not exist (aka not affected).
        """
        return await self.remove_filtered_policy(1, *permission)

    async def add_permission_for_user(self, user, *permission):
        """
        async adds a permission for a user or role.
        Returns false if the user or role already has the permission (aka not affected).
        """
        return await self.add_policy(join_slice(user, *permission))

    async def delete_permission_for_user(self, user, *permission):
        """
        async deletes a permission for a user or role.
        Returns false if the user or role does not have the permission (aka not affected).
        """
        return await self.remove_policy(join_slice(user, *permission))

    async def delete_permissions_for_user(self, user):
        """
        async deletes permissions for a user or role.
        Returns false if the user or role does not have any permissions (aka not affected).
        """
        return await self.remove_filtered_policy(0, user)

    async def get_permissions_for_user(self, user):
        """
        gets permissions for a user or role.
        """
        return self.get_filtered_policy(0, user)

    async def has_permission_for_user(self, user, *permission):
        """
        determines whether a user has a permission.
        """
        return self.has_policy(join_slice(user, *permission))

    async def get_implicit_roles_for_user(self, name, domain=""):
        """
        gets implicit roles that a user has.
        Compared to get_roles_for_user(), this function retrieves indirect roles besides direct roles.
        For example:
        g, alice, role:admin
        g, role:admin, role:user

        get_roles_for_user("alice") can only get: ["role:admin"].
        But get_implicit_roles_for_user("alice") will get: ["role:admin", "role:user"].
        """
        res = []
        queue = [name]

        while queue:
            name = queue.pop(0)

            for rm in self.rm_map.values():
                roles = rm.get_roles(name, domain)
                for r in roles:
                    if r not in res:
                        res.append(r)
                        queue.append(r)

        return res

    async def get_implicit_permissions_for_user(self, user, domain="", filter_policy_dom=True):
        """
        gets implicit permissions for a user or role.
        Compared to get_permissions_for_user(), this function retrieves permissions for inherited roles.
        For example:
        p, admin, data1, read
        p, alice, data2, read
        g, alice, admin

        get_permissions_for_user("alice") can only get: [["alice", "data2", "read"]].
        But get_implicit_permissions_for_user("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].

        For given domain policies are filtered by corresponding domain matching function of DomainManager
        Inherited roles can be matched by domain. For domain neutral policies set:
         filter_policy_dom = False

        filter_policy_dom: bool - For given *domain*, policies will be filtered by domain as well. Default = True
        """
        return await self.get_named_implicit_permissions_for_user("p", user, domain, filter_policy_dom)

    async def get_named_implicit_permissions_for_user(self, ptype, user, domain="", filter_policy_dom=True):
        """
        gets implicit permissions for a user or role by named policy.
        Compared to get_permissions_for_user(), this function retrieves permissions for inherited roles.
        For example:
        p, admin, data1, read
        p, alice, data2, read
        g, alice, admin

        get_permissions_for_user("alice") can only get: [["alice", "data2", "read"]].
        But get_implicit_permissions_for_user("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].

        For given domain policies are filtered by corresponding domain matching function of DomainManager
        Inherited roles can be matched by domain. For domain neutral policies set:
         filter_policy_dom = False

        filter_policy_dom: bool - For given *domain*, policies will be filtered by domain as well. Default = True
        """
        roles = await self.get_implicit_roles_for_user(user, domain)

        roles.insert(0, user)

        res = []

        # policy domain should be matched by domain_match_fn of DomainManager
        domain_matching_func = self.get_role_manager().domain_matching_func
        if domain and domain_matching_func != None:
            domain = partial(domain_matching_func, domain)

        for role in roles:
            permissions = await self.get_named_permissions_for_user_in_domain(
                ptype, role, domain if filter_policy_dom else ""
            )
            res.extend(permissions)

        return res

    async def get_implicit_users_for_permission(self, *permission):
        """
        gets implicit users for a permission.
        For example:
        p, admin, data1, read
        p, bob, data1, read
        g, alice, admin

        get_implicit_users_for_permission("data1", "read") will get: ["alice", "bob"].
        Note: only users will be returned, roles (2nd arg in "g") will be excluded.
        """
        p_subjects = self.get_all_subjects()
        g_inherit = self.model.get_values_for_field_in_policy("g", "g", 1)
        g_subjects = self.model.get_values_for_field_in_policy("g", "g", 0)
        subjects = array_remove_duplicates(g_subjects + p_subjects)

        res = list()
        subjects = set_subtract(subjects, g_inherit)

        for user in subjects:
            req = join_slice(user, *permission)
            allowed = self.enforce(*req)

            if allowed:
                res.append(user)

        return res

    async def get_roles_for_user_in_domain(self, name, domain):
        """gets the roles that a user has inside a domain."""
        return self.model.model["g"]["g"].rm.get_roles(name, domain)

    async def get_users_for_role_in_domain(self, name, domain):
        """gets the users that have a role inside a domain."""
        return self.model.model["g"]["g"].rm.get_users(name, domain)

    async def add_role_for_user_in_domain(self, user, role, domain):
        """async adds a role for a user inside a domain."""
        """Returns false if the user already has the role (aka not affected)."""
        return await self.add_grouping_policy(user, role, domain)

    async def delete_roles_for_user_in_domain(self, user, role, domain):
        """async deletes a role for a user inside a domain."""
        """Returns false if the user does not have any roles (aka not affected)."""
        return await self.remove_filtered_grouping_policy(0, user, role, domain)

    async def get_permissions_for_user_in_domain(self, user, domain):
        """gets permissions for a user or role inside domain."""
        return await self.get_named_permissions_for_user_in_domain("p", user, domain)

    async def get_named_permissions_for_user_in_domain(self, ptype, user, domain):
        """gets permissions for a user or role with named policy inside domain."""
        return self.get_filtered_named_policy(ptype, 0, user, domain)

    async def get_all_roles_by_domain(self, domain):
        """gets all roles associated with the domain.
        note: Not applicable to Domains with inheritance relationship  (implicit roles)"""
        g = self.model.model["g"]["g"]
        policies = g.policy
        roles = set()
        for policy in policies:
            if policy[len(policy) - 1] == domain:
                role = policy[len(policy) - 2]
                if role not in roles:
                    roles.add(role)

        return list(roles)

    async def get_implicit_users_for_resource(self, resource):
        """gets implicit user based on resource.
        for example:
            p, alice, data1, read
            p, bob, data2, write
            p, data2_admin, data2, read
            p, data2_admin, data2, write
            g, alice, data2_admin
        get_implicit_users_for_resource("data2") will return [[bob data2 write] [alice data2 read] [alice data2 write]]
        get_implicit_users_for_resource("data1") will return [[alice data1 read]]
        Note: only users will be returned, roles (2nd arg in "g") will be excluded."""
        permissions = dict()
        subject_index = await self.get_field_index("p", "sub")
        object_index = await self.get_field_index("p", "obj")
        rm = self.get_role_manager()
        roles = self.get_all_roles()

        for rule in self.get_policy():
            if rule[object_index] == resource:
                sub = rule[subject_index]
                if sub not in roles:
                    permissions[tuple(rule)] = True
                else:
                    users = rm.get_users(sub)
                    for user in users:
                        implicit_rule = rule.copy()
                        implicit_rule[subject_index] = user
                        permissions[tuple(implicit_rule)] = True

        permissions = [list(t) for t in (list(key) for key in permissions.keys())]
        return permissions

    async def get_implicit_users_for_resource_by_domain(self, resource, domain):
        """get implicit user based on resource and domain.
        Compared to GetImplicitUsersForResource, domain is supported"""
        permissions = dict()
        subject_index = await self.get_field_index("p", "sub")
        object_index = await self.get_field_index("p", "obj")
        dom_index = await self.get_field_index("p", "dom")
        rm = self.get_role_manager()
        roles = await self.get_all_roles_by_domain(domain)

        for rule in self.get_policy():
            if rule[object_index] == resource:
                sub = rule[subject_index]
                if sub not in roles:
                    permissions[tuple(rule)] = True
                else:
                    if domain != rule[dom_index]:
                        continue
                    users = rm.get_users(sub, domain)
                    for user in users:
                        implicit_rule = rule.copy()
                        implicit_rule[subject_index] = user
                        permissions[tuple(implicit_rule)] = True

        permissions = [list(t) for t in (list(key) for key in permissions.keys())]
        return permissions
