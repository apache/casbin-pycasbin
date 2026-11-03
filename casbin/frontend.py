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

import json


def casbin_js_get_permission_for_user(e, user):
    model = e.get_model()
    m = {}
    m["m"] = model.to_text()
    policies = []
    for p_type in model["p"].keys():
        policy = model.get_policy("p", p_type)
        for p in policy:
            policies.append([p_type] + p)
    m["p"] = policies
    return json.dumps(m)
