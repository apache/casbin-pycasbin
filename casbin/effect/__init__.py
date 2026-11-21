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

from .default_effectors import (
    AllowOverrideEffector,
    DenyOverrideEffector,
    AllowAndDenyEffector,
    PriorityEffector,
)
from .effector import Effector
from ..constant.constants import (
    ALLOW_OVERRIDE_EFFECT,
    SUBJECT_PRIORITY_EFFECT,
    PRIORITY_EFFECT,
    DENY_OVERRIDE_EFFECT,
    ALLOW_AND_DENY_EFFECT,
)


def get_effector(expr):
    """creates an effector based on the current policy effect expression"""

    if expr == ALLOW_OVERRIDE_EFFECT:
        return AllowOverrideEffector()
    elif expr == DENY_OVERRIDE_EFFECT:
        return DenyOverrideEffector()
    elif expr == ALLOW_AND_DENY_EFFECT:
        return AllowAndDenyEffector()
    elif expr == PRIORITY_EFFECT or expr == SUBJECT_PRIORITY_EFFECT:
        return PriorityEffector()
    else:
        raise RuntimeError("unsupported effect")


def effect_to_bool(effect):
    """ """
    if effect == Effector.ALLOW:
        return True
    if effect == Effector.DENY:
        return False
    raise RuntimeError("effect can't be converted to boolean")
