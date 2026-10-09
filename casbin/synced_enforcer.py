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

import threading
import time

from casbin.enforcer import Enforcer
from casbin.util.rwlock import RWLockWrite


class AtomicBool:
    def __init__(self, value):
        self._lock = threading.Lock()
        self._value = value

    @property
    def value(self):
        with self._lock:
            return self._value

    @value.setter
    def value(self, value):
        with self._lock:
            self._value = value


class _DeferredNotifier:
    """Queues the watcher notifications raised inside a locked section and delivers them
    once the lock has been released.

    Watchers have a lock of their own, and some of them (the redis watcher, for one) hold
    it while running the update callback, which calls back into the enforcer to reload the
    policy. Notifying from inside the enforcer lock would let the two threads take those
    two locks in opposite orders and deadlock:
    https://github.com/casbin/pycasbin/issues/408
    """

    def __init__(self):
        self._local = threading.local()

    def _stack(self):
        stack = getattr(self._local, "stack", None)
        if stack is None:
            stack = []
            self._local.stack = stack
        return stack

    def defer(self, func, args, kwargs):
        """queues a call, and returns whether it was queued. False means no lock is held
        by this thread, so the caller has to run the call itself."""
        stack = self._stack()
        if not stack:
            return False
        stack[-1].append((func, args, kwargs))
        return True

    def begin(self):
        """starts collecting, called right after the lock has been taken."""
        self._stack().append([])

    def end(self, suppress_errors=False):
        """delivers what was collected, called right after the lock has been released."""
        stack = self._stack()
        queued = stack.pop()
        if stack:
            # an outer lock is still held, so hand the calls over to it
            stack[-1].extend(queued)
            return

        for func, args, kwargs in queued:
            try:
                func(*args, **kwargs)
            except Exception:
                # the caller is already unwinding an exception of its own, and hiding it
                # behind a notification failure would only make the original harder to find
                if not suppress_errors:
                    raise


class _NotifyAfterUnlock:
    """wraps one of the enforcer locks so that _DeferredNotifier collects notifications
    for as long as the lock is held."""

    def __init__(self, lock, notifier):
        self._lock = lock
        self._notifier = notifier

    def __enter__(self):
        self._lock.__enter__()
        self._notifier.begin()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        try:
            self._lock.__exit__(exc_type, exc_value, traceback)
        finally:
            self._notifier.end(suppress_errors=exc_type is not None)
        return False


class _DeferredWatcher:
    """stands in for the user's watcher on the wrapped enforcer, and routes every call it
    makes through a _DeferredNotifier."""

    def __init__(self, watcher, notifier):
        self._watcher = watcher
        self._notifier = notifier

    def __bool__(self):
        return bool(self._watcher)

    def __getattr__(self, name):
        watcher = self.__dict__.get("_watcher")
        if watcher is None:
            raise AttributeError(name)

        attr = getattr(watcher, name)
        if not callable(attr):
            return attr

        notifier = self._notifier

        def deferred(*args, **kwargs):
            # a deferred call has no result to hand back yet, but the enforcer ignores
            # what the watcher returns anyway
            if notifier.defer(attr, args, kwargs):
                return None
            return attr(*args, **kwargs)

        return deferred


class SyncedEnforcer:
    """SyncedEnforcer wraps Enforcer and provides synchronized access.
    It's also a drop-in replacement for Enforcer"""

    def __init__(self, model=None, adapter=None):
        self._e = self._new_enforcer(model, adapter)
        self._rwlock = RWLockWrite()
        self._notifier = _DeferredNotifier()
        self._rl = _NotifyAfterUnlock(self._rwlock.gen_rlock(), self._notifier)
        self._wl = _NotifyAfterUnlock(self._rwlock.gen_wlock(), self._notifier)
        self._watcher = None
        self._auto_loading = AtomicBool(False)
        self._auto_loading_thread = None

    @staticmethod
    def _new_enforcer(model, adapter):
        """builds the enforcer this wrapper guards. Subclasses override it to wrap a
        different one without duplicating the constructor."""
        return Enforcer(model, adapter)

    def is_auto_loading_running(self):
        """check if SyncedEnforcer is auto loading policies"""
        return self._auto_loading.value

    def _auto_load_policy(self, interval):
        while self.is_auto_loading_running():
            time.sleep(interval)
            try:
                self.load_policy()
            except Exception as e:
                self._e.logger.error(repr(e))

    def start_auto_load_policy(self, interval):
        """starts a thread that will call load_policy every interval seconds"""
        if self.is_auto_loading_running():
            return
        self._auto_loading.value = True
        self._auto_loading_thread = threading.Thread(target=self._auto_load_policy, args=[interval], daemon=True)
        self._auto_loading_thread.start()

    def stop_auto_load_policy(self):
        """stops the thread started by start_auto_load_policy"""
        if self.is_auto_loading_running():
            self._auto_loading.value = False

    def get_model(self):
        """gets the current model."""
        with self._rl:
            return self._e.get_model()

    def set_model(self, m):
        """sets the current model."""
        with self._wl:
            return self._e.set_model(m)

    def load_model(self):
        """reloads the model from the model CONF file.
        Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        """
        with self._wl:
            return self._e.load_model()

    def get_role_manager(self):
        """gets the current role manager."""
        with self._rl:
            return self._e.get_role_manager()

    def set_role_manager(self, rm):
        with self._wl:
            self._e.set_role_manager(rm)

    def get_adapter(self):
        """gets the current adapter."""
        with self._rl:
            return self._e.get_adapter()

    def set_adapter(self, adapter):
        """sets the current adapter."""
        with self._wl:
            self._e.set_adapter(adapter)

    def set_watcher(self, watcher):
        """sets the current watcher.

        It is notified only once the enforcer lock has been released, so a watcher that
        holds a lock of its own while running the update callback cannot deadlock against
        the enforcer."""
        with self._wl:
            self._watcher = watcher
            self._e.set_watcher(None if watcher is None else _DeferredWatcher(watcher, self._notifier))

    def get_watcher(self):
        """gets the watcher that was passed to set_watcher()."""
        with self._rl:
            return self._watcher

    def set_effector(self, eft):
        """sets the current effector."""
        with self._wl:
            self._e.set_effector(eft)

    def clear_policy(self):
        """clears all policy."""
        with self._wl:
            return self._e.clear_policy()

    def load_policy(self):
        """reloads the policy from file/database."""
        with self._wl:
            return self._e.load_policy()

    def load_filtered_policy(self, filter):
        """ "reloads a filtered policy from file/database."""
        with self._wl:
            return self._e.load_filtered_policy(filter)

    def save_policy(self):
        with self._rl:
            return self._e.save_policy()

    def build_role_links(self):
        """manually rebuild the role inheritance relations."""
        with self._rl:
            return self._e.build_role_links()

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        with self._rl:
            return self._e.enforce(*rvals)

    def enforce_ex(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        return judge result with reason
        """
        with self._rl:
            return self._e.enforce_ex(*rvals)

    def batch_enforce(self, rvals):
        """batch_enforce enforce in batches,
        input parameters are usually: [(sub, obj, act), (sub, obj, act), ...].
        """
        with self._rl:
            return self._e.batch_enforce(rvals)

    def get_all_subjects(self):
        """gets the list of subjects that show up in the current policy."""
        with self._rl:
            return self._e.get_all_subjects()

    def get_all_named_subjects(self, ptype):
        """gets the list of subjects that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_named_subjects(ptype)

    def get_all_objects(self):
        """gets the list of objects that show up in the current policy."""
        with self._rl:
            return self._e.get_all_objects()

    def get_all_named_objects(self, ptype):
        """gets the list of objects that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_named_objects(ptype)

    def get_all_actions(self):
        """gets the list of actions that show up in the current policy."""
        with self._rl:
            return self._e.get_all_actions()

    def get_all_named_actions(self, ptype):
        """gets the list of actions that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_named_actions(ptype)

    def get_all_roles(self):
        """gets the list of roles that show up in the current named policy."""
        with self._rl:
            return self._e.get_all_roles()

    def get_all_named_roles(self, ptype):
        """gets all the authorization rules in the policy."""
        with self._rl:
            return self._e.get_all_named_roles(ptype)

    def get_policy(self):
        """gets all the authorization rules in the policy."""
        with self._rl:
            return self._e.get_policy()

    def get_filtered_policy(self, field_index, *field_values):
        """gets all the authorization rules in the policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_policy(field_index, *field_values)

    def get_named_policy(self, ptype):
        """gets all the authorization rules in the named policy."""
        with self._rl:
            return self._e.get_named_policy(ptype)

    def get_filtered_named_policy(self, ptype, field_index, *field_values):
        """gets all the authorization rules in the named policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_named_policy(ptype, field_index, *field_values)

    def get_grouping_policy(self):
        """gets all the role inheritance rules in the policy."""
        with self._rl:
            return self._e.get_grouping_policy()

    def get_filtered_grouping_policy(self, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_grouping_policy(field_index, *field_values)

    def get_named_grouping_policy(self, ptype):
        """gets all the role inheritance rules in the policy."""
        with self._rl:
            return self._e.get_named_grouping_policy(ptype)

    def get_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """gets all the role inheritance rules in the policy, field filters can be specified."""
        with self._rl:
            return self._e.get_filtered_named_grouping_policy(ptype, field_index, *field_values)

    def has_policy(self, *params):
        """determines whether an authorization rule exists."""
        with self._rl:
            return self._e.has_policy(*params)

    def has_named_policy(self, ptype, *params):
        """determines whether a named authorization rule exists."""
        with self._rl:
            return self._e.has_named_policy(ptype, *params)

    def add_policy(self, *params):
        """adds an authorization rule to the current policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_policy(*params)

    def add_named_policy(self, ptype, *params):
        """adds an authorization rule to the current named policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_named_policy(ptype, *params)

    def remove_policy(self, *params):
        """removes an authorization rule from the current policy."""
        with self._wl:
            return self._e.remove_policy(*params)

    def remove_filtered_policy(self, field_index, *field_values):
        """removes an authorization rule from the current policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_policy(field_index, *field_values)

    def remove_named_policy(self, ptype, *params):
        """removes an authorization rule from the current named policy."""
        with self._wl:
            return self._e.remove_named_policy(ptype, *params)

    def remove_filtered_named_policy(self, ptype, field_index, *field_values):
        """removes an authorization rule from the current named policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_named_policy(ptype, field_index, *field_values)

    def has_grouping_policy(self, *params):
        """determines whether a role inheritance rule exists."""
        with self._rl:
            return self._e.has_grouping_policy(*params)

    def has_named_grouping_policy(self, ptype, *params):
        """determines whether a named role inheritance rule exists."""
        with self._rl:
            return self._e.has_named_grouping_policy(ptype, *params)

    def add_grouping_policy(self, *params):
        """adds a role inheritance rule to the current policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_grouping_policy(*params)

    def add_named_grouping_policy(self, ptype, *params):
        """adds a named role inheritance rule to the current policy.
        If the rule already exists, the function returns false and the rule will not be added.
        Otherwise the function returns true by adding the new rule.
        """
        with self._wl:
            return self._e.add_named_grouping_policy(ptype, *params)

    def remove_grouping_policy(self, *params):
        """removes a role inheritance rule from the current policy."""
        with self._wl:
            return self._e.remove_grouping_policy(*params)

    def remove_filtered_grouping_policy(self, field_index, *field_values):
        """removes a role inheritance rule from the current policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_grouping_policy(field_index, *field_values)

    def remove_named_grouping_policy(self, ptype, *params):
        """removes a role inheritance rule from the current named policy."""
        with self._wl:
            return self._e.remove_named_grouping_policy(ptype, *params)

    def remove_filtered_named_grouping_policy(self, ptype, field_index, *field_values):
        """removes a role inheritance rule from the current named policy, field filters can be specified."""
        with self._wl:
            return self._e.remove_filtered_named_grouping_policy(ptype, field_index, *field_values)

    def add_function(self, name, func):
        """adds a customized function."""
        with self._wl:
            return self._e.add_function(name, func)

    # enforcer.py

    def get_roles_for_user(self, name):
        """gets the roles that a user has."""
        with self._rl:
            return self._e.get_roles_for_user(name)

    def get_users_for_role(self, name):
        """gets the users that have a role."""
        with self._rl:
            return self._e.get_users_for_role(name)

    def has_role_for_user(self, name, role):
        """determines whether a user has a role."""
        with self._rl:
            return self._e.has_role_for_user(name, role)

    def add_role_for_user(self, user, role):
        """
        adds a role for a user.
        Returns false if the user already has the role (aka not affected).
        """
        with self._wl:
            return self._e.add_role_for_user(user, role)

    def delete_role_for_user(self, user, role):
        """
        deletes a role for a user.
        Returns false if the user does not have the role (aka not affected).
        """
        with self._wl:
            return self._e.delete_role_for_user(user, role)

    def delete_roles_for_user(self, user):
        """
        deletes all roles for a user.
        Returns false if the user does not have any roles (aka not affected).
        """
        with self._wl:
            return self._e.delete_roles_for_user(user)

    def delete_user(self, user):
        """
        deletes a user.
        Returns false if the user does not exist (aka not affected).
        """
        with self._wl:
            return self._e.delete_user(user)

    def delete_role(self, role):
        """
        deletes a role.
        Returns false if the role does not exist (aka not affected).
        """
        with self._wl:
            return self._e.delete_role(role)

    def delete_permission(self, *permission):
        """
        deletes a permission.
        Returns false if the permission does not exist (aka not affected).
        """
        with self._wl:
            return self._e.delete_permission(*permission)

    def add_permission_for_user(self, user, *permission):
        """
        adds a permission for a user or role.
        Returns false if the user or role already has the permission (aka not affected).
        """
        with self._wl:
            return self._e.add_permission_for_user(user, *permission)

    def delete_permission_for_user(self, user, *permission):
        """
        deletes a permission for a user or role.
        Returns false if the user or role does not have the permission (aka not affected).
        """
        with self._wl:
            return self._e.delete_permission_for_user(user, *permission)

    def delete_permissions_for_user(self, user):
        """
        deletes permissions for a user or role.
        Returns false if the user or role does not have any permissions (aka not affected).
        """
        with self._wl:
            return self._e.delete_permissions_for_user(user)

    def get_permissions_for_user(self, user):
        """
        gets permissions for a user or role.
        """
        with self._rl:
            return self._e.get_permissions_for_user(user)

    def has_permission_for_user(self, user, *permission):
        """
        determines whether a user has a permission.
        """
        with self._rl:
            return self._e.has_permission_for_user(user, *permission)

    def get_implicit_roles_for_user(self, name, *domain):
        """
        gets implicit roles that a user has.
        Compared to get_roles_for_user(), this function retrieves indirect roles besides direct roles.
        For example:
        g, alice, role:admin
        g, role:admin, role:user

        get_roles_for_user("alice") can only get: ["role:admin"].
        But get_implicit_roles_for_user("alice") will get: ["role:admin", "role:user"].
        """
        with self._rl:
            return self._e.get_implicit_roles_for_user(name, *domain)

    def get_implicit_permissions_for_user(self, user, *domain, filter_policy_dom=True):
        """
        gets implicit permissions for a user or role.
        Compared to get_permissions_for_user(), this function retrieves permissions for inherited roles.
        For example:
        p, admin, data1, read
        p, alice, data2, read
        g, alice, admin

        get_permissions_for_user("alice") can only get: [["alice", "data2", "read"]].
        But get_implicit_permissions_for_user("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
        """
        with self._rl:
            return self._e.get_implicit_permissions_for_user(user, *domain, filter_policy_dom=filter_policy_dom)

    def get_named_implicit_permissions_for_user(self, ptype, user, *domain, filter_policy_dom=True):
        """
        gets implicit permissions for a user or role by named policy.
        Compared to get_permissions_for_user(), this function retrieves permissions for inherited roles.
        For example:
        p, admin, data1, read
        p, alice, data2, read
        g, alice, admin

        get_permissions_for_user("alice") can only get: [["alice", "data2", "read"]].
        But get_implicit_permissions_for_user("alice") will get: [["admin", "data1", "read"], ["alice", "data2", "read"]].
        """
        with self._rl:
            return self._e.get_named_implicit_permissions_for_user(
                ptype, user, *domain, filter_policy_dom=filter_policy_dom
            )

    def get_implicit_users_for_permission(self, *permission):
        """
        gets implicit users for a permission.
        For example:
        p, admin, data1, read
        p, bob, data1, read
        g, alice, admin

        get_implicit_users_for_permission("data1", "read") will get: ["alice", "bob"].
        Note: only users will be returned, roles (2nd arg in "g") will be excluded.
        """
        with self._rl:
            return self._e.get_implicit_users_for_permission(*permission)

    def get_roles_for_user_in_domain(self, name, domain):
        """gets the roles that a user has inside a domain."""
        with self._rl:
            return self._e.get_roles_for_user_in_domain(name, domain)

    def get_users_for_role_in_domain(self, name, domain):
        """gets the users that have a role inside a domain."""
        with self._rl:
            return self._e.get_users_for_role_in_domain(name, domain)

    def add_role_for_user_in_domain(self, user, role, domain):
        """adds a role for a user inside a domain."""
        """Returns false if the user already has the role (aka not affected)."""
        with self._wl:
            return self._e.add_role_for_user_in_domain(user, role, domain)

    def delete_roles_for_user_in_domain(self, user, role, domain):
        """deletes a role for a user inside a domain."""
        """Returns false if the user does not have any roles (aka not affected)."""
        with self._wl:
            return self._e.delete_roles_for_user_in_domain(user, role, domain)

    def get_permissions_for_user_in_domain(self, user, domain):
        """gets permissions for a user or role inside domain."""
        with self._rl:
            return self._e.get_permissions_for_user_in_domain(user, domain)

    def get_named_permissions_for_user_in_domain(self, ptype, user, domain):
        """gets permissions for a user or role by named policy inside domain."""
        with self._rl:
            return self._e.get_named_permissions_for_user_in_domain(ptype, user, domain)

    def enable_auto_build_role_links(self, auto_build_role_links):
        """controls whether to rebuild the role inheritance relations when a role is added or deleted."""
        with self._wl:
            return self._e.enable_auto_build_role_links(auto_build_role_links)

    def enable_auto_save(self, auto_save):
        """controls whether to save a policy rule automatically to the adapter when it is added or removed."""
        with self._wl:
            return self._e.enable_auto_save(auto_save)

    def enable_enforce(self, enabled=True):
        """changes the enforcing state of Casbin,
        when Casbin is disabled, all access will be allowed by the Enforce() function.
        """
        with self._wl:
            return self._e.enable_enforce(enabled)

    def add_named_matching_func(self, ptype, fn):
        """add_named_matching_func add MatchingFunc by ptype RoleManager"""
        with self._wl:
            self._e.add_named_matching_func(ptype, fn)

    def add_named_link_condition_func(self, ptype, user, role, fn):
        """Add condition function fn for Link userName->roleName,
        when fn returns true, Link is valid, otherwise invalid"""
        with self._wl:
            self._e.add_named_link_condition_func(ptype, user, role, fn)

    def add_named_domain_matching_func(self, ptype, fn):
        """add_named_domain_matching_func add MatchingFunc by ptype to RoleManager"""
        with self._wl:
            self._e.add_named_domain_matching_func(ptype, fn)

    def add_named_domain_link_condition_func(self, ptype, user, role, domain, fn):
        """Add condition function fn for Link userName-> {roleName, domain},
        when fn returns true, Link is valid, otherwise invalid"""
        with self._wl:
            self._e.add_named_domain_link_condition_func(ptype, user, role, domain, fn)

    def set_named_domain_link_condition_func_params(self, ptype, user, role, domain, *params):
        """Sets the parameters of the condition function fn for Link userName->{roleName, domain}"""
        with self._wl:
            self._e.set_named_domain_link_condition_func_params(ptype, user, role, domain, *params)

    def set_named_link_condition_func_params(self, ptype, user, role, *params):
        """Sets the parameters of the condition function fn for Link userName->roleName"""
        with self._wl:
            self._e.set_named_link_condition_func_params(ptype, user, role, *params)

    def is_filtered(self):
        """returns true if the loaded policy has been filtered."""
        with self._rl:
            return self._e.is_filtered()

    def add_policies(self, rules):
        """adds authorization rules to the current policy.

        If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        Otherwise the function returns true for the corresponding rule by adding the new rule.
        """
        with self._wl:
            return self._e.add_policies(rules)

    def add_policies_ex(self, rules):
        """add_policies_ex adds authorization rules to the current policy.

        If the rule already exists, the rule will not be added.
        But unlike add_policies, other non-existent rules are added instead of returning false directly.
        """
        with self._wl:
            return self._e.add_policies_ex(rules)

    def add_named_policies_ex(self, ptype, rules):
        """add_named_policies_ex adds authorization rules to the current policy.

        If the rule already exists, the rule will not be added.
        But unlike add_named_policies, other non-existent rules are added instead of returning false directly.
        """
        with self._wl:
            return self._e.add_named_policies_ex(ptype, rules)

    def add_named_policies(self, ptype, rules):
        """adds authorization rules to the current named policy.

        If the rule already exists, the function returns false for the corresponding rule and the rule will not be added.
        Otherwise the function returns true for the corresponding by adding the new rule."""
        with self._wl:
            return self._e.add_named_policies(ptype, rules)

    def remove_policies(self, rules):
        """removes authorization rules from the current policy."""
        with self._wl:
            return self._e.remove_policies(rules)

    def remove_named_policies(self, ptype, rules):
        """removes authorization rules from the current named policy."""
        with self._wl:
            return self._e.remove_named_policies(ptype, rules)

    def add_grouping_policies(self, rules):
        """adds role inheritance rules to the current policy.

        If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        Otherwise the function returns true for the corresponding policy rule by adding the new rule.
        """
        with self._wl:
            return self._e.add_grouping_policies(rules)

    def add_grouping_policies_ex(self, rules):
        """add_grouping_policies_ex adds role inheritance rules to the current policy.

        If the rule already exists, the rule will not be added.
        But unlike add_grouping_policies, other non-existent rules are added instead of returning false directly.
        """
        with self._wl:
            return self._e.add_grouping_policies_ex(rules)

    def add_named_grouping_policies(self, ptype, rules):
        """ "adds named role inheritance rules to the current policy.

        If the rule already exists, the function returns false for the corresponding policy rule and the rule will not be added.
        Otherwise the function returns true for the corresponding policy rule by adding the new rule."""
        with self._wl:
            return self._e.add_named_grouping_policies(ptype, rules)

    def add_named_grouping_policies_ex(self, ptype, rules):
        """add_named_grouping_policies_ex adds role inheritance rules to the current named policy.

        If the rule already exists, the rule will not be added.
        But unlike add_named_grouping_policies, other non-existent rules are added instead of returning false directly.
        """
        with self._wl:
            return self._e.add_named_grouping_policies_ex(ptype, rules)

    def remove_grouping_policies(self, rules):
        """removes role inheritance rules from the current policy."""
        with self._wl:
            return self._e.remove_grouping_policies(rules)

    def remove_named_grouping_policies(self, ptype, rules):
        """removes role inheritance rules from the current named policy."""
        with self._wl:
            return self._e.remove_named_grouping_policies(ptype, rules)

    def build_incremental_role_links(self, op, ptype, rules):
        self.get_model().build_incremental_role_links(self.get_role_manager(), op, "g", ptype, rules)

    def new_enforce_context(self, suffix: str) -> "EnforceContext":
        return self._e.new_enforce_context(suffix)

    def get_field_index(self, ptype, field):
        """gets the index of the field name."""
        return self._e.model.get_field_index(ptype, field)

    def set_field_index(self, ptype, field, index):
        """sets the index of the field name."""
        assertion = self._e.model["p"][ptype]
        assertion.field_index_map[field] = index

    def get_all_roles_by_domain(self, domain):
        """gets all roles associated with the domain.
        note: Not applicable to Domains with inheritance relationship  (implicit roles)"""
        with self._rl:
            return self._e.get_all_roles_by_domain(domain)

    def get_implicit_users_for_resource(self, resource):
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
        with self._rl:
            return self._e.get_implicit_users_for_resource(resource)

    def get_implicit_users_for_resource_by_domain(self, resource, domain):
        """get implicit user based on resource and domain.
        Compared to GetImplicitUsersForResource, domain is supported"""
        with self._rl:
            return self._e.get_implicit_users_for_resource_by_domain(resource, domain)
