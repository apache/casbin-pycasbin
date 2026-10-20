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

import copy
import logging
import re
from functools import lru_cache

from casbin.effect import Effector, AllowAndDenyEffector, get_effector, effect_to_bool
from casbin.model import Model, FunctionMap
from casbin.persist import Adapter
from casbin.persist.adapters import FileAdapter
from casbin.rbac import default_role_manager
from casbin.util import generate_g_function, SimpleEval, util, generate_conditional_g_function, key_match
from casbin.util.log import configure_logging, disabled_logging


class EnforceContext:
    """
    EnforceContext is used as the first element of the parameter "rvals" in method "enforce"
    """

    def __init__(self, rtype: str, ptype: str, etype: str, mtype: str):
        self.rtype: str = rtype
        self.ptype: str = ptype
        self.etype: str = etype
        self.mtype: str = mtype

    def get_cache_key(self):
        """lets CachedEnforcer key a request that carries an EnforceContext."""
        return self.rtype, self.ptype, self.etype, self.mtype


class CoreEnforcer:
    """CoreEnforcer defines the core functionality of an enforcer."""

    model_path = ""
    model = None
    fm = None
    eft = None

    adapter = None
    watcher = None
    rm_map = None
    cond_rm_map = None

    enabled = False
    auto_save = False
    auto_build_role_links = False
    auto_notify_watcher = False

    def __init__(self, model=None, adapter=None, enable_log=False, logging_config: dict = None):
        self.logger = logging.getLogger("casbin.enforcer")
        if isinstance(model, str):
            if isinstance(adapter, str):
                self.init_with_file(model, adapter)
            else:
                self.init_with_adapter(model, adapter)
                pass
        else:
            if isinstance(adapter, str):
                raise RuntimeError("Invalid parameters for enforcer.")
            else:
                self.init_with_model_and_adapter(model, adapter)

        if enable_log:
            configure_logging(logging_config)
        else:
            disabled_logging()

    def init_with_file(self, model_path, policy_path):
        """initializes an enforcer with a model file and a policy file."""
        a = FileAdapter(policy_path)
        self.init_with_adapter(model_path, a)

    def init_with_adapter(self, model_path, adapter=None):
        """initializes an enforcer with a database adapter."""
        m = self.new_model(model_path)
        self.init_with_model_and_adapter(m, adapter)

        self.model_path = model_path

    def init_with_model_and_adapter(self, m, adapter=None):
        """initializes an enforcer with a model and a database adapter."""

        if not isinstance(m, Model) or adapter is not None and not isinstance(adapter, Adapter):
            raise RuntimeError("Invalid parameters for enforcer.")

        self.adapter = adapter

        self.model = m
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

        self._initialize()

        # Do not initialize the full policy when using a filtered adapter
        if self.adapter and not self.is_filtered():
            self.load_policy()

    def _initialize(self):
        self.rm_map = dict()
        self.cond_rm_map = dict()
        self.eft = get_effector(self.model["e"]["e"].value)
        self.watcher = None

        self.enabled = True
        self.auto_save = True
        self.auto_build_role_links = True
        self.auto_notify_watcher = True

        self.init_rm_map()

    @staticmethod
    def new_model(path="", text=""):
        """creates a model."""

        m = Model()
        if len(path) > 0:
            m.load_model(path)
        else:
            m.load_model_from_text(text)

        return m

    def load_model(self):
        """reloads the model from the model CONF file.
        Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling LoadPolicy().
        """

        self.model = self.new_model()
        self.model.load_model(self.model_path)
        self.model.print_model()
        self.fm = FunctionMap.load_function_map()

    def get_model(self):
        """gets the current model."""

        return self.model

    def set_model(self, m):
        """sets the current model."""

        self.model = m
        self.fm = FunctionMap.load_function_map()

    def get_adapter(self):
        """gets the current adapter."""

        return self.adapter

    def set_adapter(self, adapter):
        """sets the current adapter."""

        self.adapter = adapter

    def set_watcher(self, watcher):
        """sets the current watcher."""

        self.watcher = watcher
        pass

    def get_role_manager(self):
        """gets the current role manager."""
        return self.rm_map["g"]

    def get_named_role_manager(self, ptype):
        if ptype in self.rm_map.keys():
            return self.rm_map.get(ptype)
        raise ValueError("ptype not found")

    def set_role_manager(self, rm):
        """sets the current role manager."""
        self.rm_map["g"] = rm

    def set_named_role_manager(self, ptype, rm):
        self.rm_map[ptype] = rm

    def set_effector(self, eft):
        """sets the current effector."""
        self.eft = eft

    def clear_policy(self):
        """clears all policy."""

        self.model.clear_policy()

    def init_rm_map(self):
        if "g" in self.model.keys():
            for ptype in self.model["g"]:
                assertion = self.model["g"][ptype]
                if ptype in self.rm_map:
                    rm = self.rm_map[ptype]
                    rm.clear()
                    continue

                if len(assertion.tokens) <= 2 and len(assertion.params_tokens) == 0:
                    assertion.rm = default_role_manager.RoleManager(10)
                    self.rm_map[ptype] = assertion.rm

                if len(assertion.tokens) <= 2 and len(assertion.params_tokens) != 0:
                    assertion.cond_rm = default_role_manager.ConditionalRoleManager(10)
                    self.cond_rm_map[ptype] = assertion.cond_rm

                if len(assertion.tokens) > 2:
                    if len(assertion.params_tokens) == 0:
                        assertion.rm = default_role_manager.DomainManager(10)
                        self.rm_map[ptype] = assertion.rm
                    else:
                        assertion.cond_rm = default_role_manager.ConditionalDomainManager(10)
                        self.cond_rm_map[ptype] = assertion.cond_rm
                    self._register_domain_matching_func(ptype)

    def _get_domain_tokens(self):
        r_domain_token = ""
        p_domain_token = ""
        r_assertion = (self.model["r"] or {}).get("r")
        if r_assertion is not None and len(r_assertion.tokens) > 1:
            r_domain_token = r_assertion.tokens[1]
        p_assertion = (self.model["p"] or {}).get("p")
        if p_assertion is not None and len(p_assertion.tokens) > 1:
            p_domain_token = p_assertion.tokens[1]
        return r_domain_token, p_domain_token

    def _register_domain_matching_func(self, ptype):
        r_domain_token, p_domain_token = self._get_domain_tokens()
        m_assertion = (self.model["m"] or {}).get("m")
        if r_domain_token == "" or p_domain_token == "" or m_assertion is None:
            return

        match_fun = "keyMatch({}, {})".format(r_domain_token, p_domain_token)
        if match_fun in m_assertion.value:
            self.add_named_domain_matching_func(ptype, key_match)

    def load_policy(self):
        """reloads the policy from file/database."""
        need_to_rebuild = False
        new_model = copy.deepcopy(self.model)
        new_model.clear_policy()

        try:
            self.adapter.load_policy(new_model)

            new_model.sort_policies_by_subject_hierarchy()

            new_model.sort_policies_by_priority()

            new_model.print_policy()

            if self.auto_build_role_links:
                need_to_rebuild = True
                for rm in self.rm_map.values():
                    rm.clear()
                if len(self.rm_map) != 0:
                    new_model.build_role_links(self.rm_map)

                for crm in self.cond_rm_map.values():
                    crm.clear()
                if len(self.cond_rm_map) != 0:
                    new_model.build_conditional_role_links(self.cond_rm_map)

            self.model = new_model

        except Exception as e:
            if self.auto_build_role_links and need_to_rebuild:
                self.build_role_links()

            raise e

    def load_filtered_policy(self, filter):
        """reloads a filtered policy from file/database."""
        self.model.clear_policy()

        if not hasattr(self.adapter, "is_filtered"):
            raise ValueError("filtered policies are not supported by this adapter")

        self.adapter.load_filtered_policy(self.model, filter)

        self.model.sort_policies_by_priority()

        self.init_rm_map()
        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()

    def load_increment_filtered_policy(self, filter):
        """LoadIncrementalFilteredPolicy append a filtered policy from file/database."""
        if not hasattr(self.adapter, "is_filtered"):
            raise ValueError("filtered policies are not supported by this adapter")

        self.adapter.load_filtered_policy(self.model, filter)
        self.model.print_policy()
        if self.auto_build_role_links:
            self.build_role_links()

    def is_filtered(self):
        """returns true if the loaded policy has been filtered."""

        return hasattr(self.adapter, "is_filtered") and self.adapter.is_filtered()

    def save_policy(self):
        if self.is_filtered():
            raise RuntimeError("cannot save a filtered policy")

        self.adapter.save_policy(self.model)

        if self.watcher:
            if callable(getattr(self.watcher, "update_for_save_policy", None)):
                self.watcher.update_for_save_policy(self.model)
            else:
                self.watcher.update()

    def enable_enforce(self, enabled=True):
        """changes the enforcing state of Casbin,
        when Casbin is disabled, all access will be allowed by the Enforce() function.
        """

        self.enabled = enabled

    def enable_auto_save(self, auto_save):
        """controls whether to save a policy rule automatically to the adapter when it is added or removed."""
        self.auto_save = auto_save

    def enable_auto_build_role_links(self, auto_build_role_links):
        """controls whether to rebuild the role inheritance relations when a role is added or deleted."""
        self.auto_build_role_links = auto_build_role_links

    def enable_auto_notify_watcher(self, auto_notify_watcher):
        """controls whether to save a policy rule automatically notify the watcher when it is added or removed."""
        self.auto_notify_watcher = auto_notify_watcher

    def build_role_links(self):
        """manually rebuild the role inheritance relations."""

        for rm in self.rm_map.values():
            rm.clear()

        self.model.build_role_links(self.rm_map)

    def add_named_matching_func(self, ptype, fn):
        """add_named_matching_func add MatchingFunc by ptype RoleManager"""
        try:
            self.rm_map[ptype].add_matching_func(fn)
            return True
        except:
            return False

    def add_named_domain_matching_func(self, ptype, fn):
        """add_named_domain_matching_func add MatchingFunc by ptype to RoleManager"""
        if ptype in self.rm_map.keys():
            self.rm_map[ptype].add_domain_matching_func(fn)
            return True
        if ptype in self.cond_rm_map.keys():
            self.cond_rm_map[ptype].add_domain_matching_func(fn)
            return True

        return False

    def add_named_link_condition_func(self, ptype, user, role, fn):
        """Add condition function fn for Link userName->roleName,
        when fn returns true, Link is valid, otherwise invalid"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.add_link_condition_func(user, role, fn)
            return True
        return False

    def add_named_domain_link_condition_func(self, ptype, user, role, domain, fn):
        """Add condition function fn for Link userName-> {roleName, domain},
        when fn returns true, Link is valid, otherwise invalid"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.add_domain_link_condition_func(user, role, domain, fn)
            return True
        return False

    def set_named_link_condition_func_params(self, ptype, user, role, *params):
        """Sets the parameters of the condition function fn for Link userName->roleName"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.set_link_condition_func_params(user, role, *params)
            return True
        return False

    def set_named_domain_link_condition_func_params(self, ptype, user, role, domain, *params):
        """Sets the parameters of the condition function fn for Link userName->{roleName, domain}"""
        if ptype in self.cond_rm_map:
            rm = self.cond_rm_map[ptype]
            rm.set_domain_link_condition_func_params(user, role, domain, *params)
            return True
        return False

    def new_enforce_context(self, suffix: str) -> EnforceContext:
        return EnforceContext(
            rtype="r" + suffix,
            ptype="p" + suffix,
            etype="e" + suffix,
            mtype="m" + suffix,
        )

    def enforce(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        """
        result, _ = self.enforce_ex(*rvals)
        return result

    def enforce_ex(self, *rvals):
        """decides whether a "subject" can access a "object" with the operation "action",
        input parameters are usually: (sub, obj, act).
        return judge result with reason
        """

        rtype = "r"
        ptype = "p"
        etype = "e"
        mtype = "m"

        if not self.enabled:
            return [True, []]

        functions = self.fm.get_functions()

        if "g" in self.model.keys():
            for key, ast in self.model["g"].items():
                if len(self.rm_map) != 0:
                    functions[key] = generate_g_function(ast.rm)
                if ast.cond_rm is not None:
                    functions[key] = generate_conditional_g_function(ast.cond_rm)

        if len(rvals) != 0:
            if isinstance(rvals[0], EnforceContext):
                enforce_context = rvals[0]
                rtype = enforce_context.rtype
                ptype = enforce_context.ptype
                etype = enforce_context.etype
                mtype = enforce_context.mtype
                rvals = rvals[1:]

        if "m" not in self.model.keys():
            raise RuntimeError("model is undefined")

        if "m" not in self.model["m"].keys():
            raise RuntimeError("model is undefined")

        r_tokens = self.model["r"][rtype].tokens
        p_tokens = self.model["p"][ptype].tokens

        if len(r_tokens) != len(rvals):
            raise RuntimeError("invalid request size")

        exp_string = self.model["m"][mtype].value
        exp_has_eval = util.has_eval(exp_string)
        expression = self._get_expression("" if exp_has_eval else exp_string, functions)
        if exp_has_eval:
            rule_names = util.get_eval_value(exp_string)

        policy_effects = set()

        r_parameters = dict(zip(r_tokens, rvals))

        policy_len = len(self.model["p"][ptype].policy)

        explain_index = -1
        allow_index = -1
        if not 0 == policy_len:
            for i, pvals in enumerate(self.model["p"][ptype].policy):
                if len(p_tokens) != len(pvals):
                    raise RuntimeError("invalid policy size")

                p_parameters = dict(zip(p_tokens, pvals))
                parameters = dict(r_parameters, **p_parameters)

                if exp_has_eval:
                    rules = tuple(p_parameters[rule_name] for rule_name in rule_names)
                    expression.set_expr(self._get_eval_expression(exp_string, rules))

                result = expression.eval(parameters)

                if isinstance(result, bool):
                    if not result:
                        policy_effects.add(Effector.INDETERMINATE)
                        continue
                elif isinstance(result, float):
                    if 0 == result:
                        policy_effects.add(Effector.INDETERMINATE)
                        continue
                else:
                    raise RuntimeError("matcher result should be bool, int or float")

                p_eft_key = ptype + "_eft"
                if p_eft_key in parameters.keys():
                    eft = parameters[p_eft_key]
                    if "allow" == eft:
                        policy_effects.add(Effector.ALLOW)
                    elif "deny" == eft:
                        policy_effects.add(Effector.DENY)
                    else:
                        policy_effects.add(Effector.INDETERMINATE)
                else:
                    policy_effects.add(Effector.ALLOW)

                if allow_index == -1 and Effector.ALLOW in policy_effects:
                    allow_index = i

                if self.eft.intermediate_effect(policy_effects) != Effector.INDETERMINATE:
                    explain_index = i
                    break

        else:
            if exp_has_eval:
                raise RuntimeError("please make sure rule exists in policy when using eval() in matcher")

            parameters = r_parameters.copy()

            for token in self.model["p"][ptype].tokens:
                parameters[token] = ""

            result = expression.eval(parameters)

            if result:
                policy_effects.add(Effector.ALLOW)
            else:
                policy_effects.add(Effector.INDETERMINATE)

        final_effect = self.eft.final_effect(policy_effects)
        result = effect_to_bool(final_effect)
        if explain_index == -1 and final_effect == Effector.ALLOW and isinstance(self.eft, AllowAndDenyEffector):
            explain_index = allow_index

        # Log request.
        if (result and self.logger.isEnabledFor(logging.INFO)) or (
            not result and self.logger.isEnabledFor(logging.WARNING)
        ):
            req_str = "Request: "
            req_str = req_str + ", ".join([str(v) for v in rvals])
            req_str = req_str + " ---> %s" % result
            if result:
                self.logger.info(req_str)
            else:
                # leaving this in warning for now, if it's very noise this can be changed to info or debug,
                # or change the log level
                self.logger.warning(req_str)

        explain_rule = []
        if explain_index != -1 and explain_index < policy_len:
            explain_rule = self.model["p"][ptype].policy[explain_index]

        return result, explain_rule

    def batch_enforce(self, rvals):
        """batch_enforce enforce in batches"""
        results = []
        for request in rvals:
            result = self.enforce(*request)
            results.append(result)
        return results

    @staticmethod
    def configure_logging(logging_config=None):
        """configure_logging configure the default logger for casbin"""
        configure_logging(logging_config)

    @staticmethod
    def _get_expression(expr, functions=None):
        return SimpleEval(CoreEnforcer._normalize_expression(expr), functions)

    @staticmethod
    @lru_cache(maxsize=8192)
    def _normalize_expression(expr):
        expr = expr.replace("&&", "and")
        expr = expr.replace("||", "or")
        return re.sub(r"!(?!=)", "not ", expr)

    @staticmethod
    @lru_cache(maxsize=8192)
    def _get_eval_expression(expr, rules):
        rules = [util.escape_assertion(rule) for rule in rules]
        return CoreEnforcer._normalize_expression(util.replace_eval(expr, rules))
