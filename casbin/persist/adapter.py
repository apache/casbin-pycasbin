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

import re

_INTERESTING_TOKENS_RE = re.compile(r"[,\[\]\(\)]")


def _extract_tokens(line):
    """Return the list of 'tokens' from the line, or None if this line has none"""

    if line == "":
        return None

    if line[:1] == "#":
        return None

    stack = []
    tokens = []

    # The tokens are separated by commas, but we support nesting so a naive `line.split(",")` is
    # wrong. E.g. `abc(def, ghi), jkl` is two tokens: `abc(def, ghi)` and `jkl`. We do this by
    # iterating over the locations of any tokens of interest, and either:
    #
    # - [](): adjust the nesting depth
    # - ,: slice the line to save the token, if the , is at the top-level, outside all []()
    #
    # `start_idx` represents the start of the current token, that we haven't seen a `,` for yet.
    start_idx = 0
    for match in _INTERESTING_TOKENS_RE.finditer(line):
        c = match.group()
        if c == "[" or c == "(":
            stack.append(c)
        elif c == "]" or c == ")":
            stack.pop()
        elif not stack:
            # must be a comma outside of any nesting: we've found the end of a top level token so
            # save that and start a new one
            tokens.append(line[start_idx : match.start()].strip())
            start_idx = match.end()

    # trailing token after the last ,
    tokens.append(line[start_idx:].strip())

    return tokens


def load_policy_line(line, model):
    """loads a text line as a policy rule to model."""

    tokens = _extract_tokens(line)
    if tokens is None:
        return

    key = tokens[0]
    sec = key[0]

    if sec not in model.model.keys():
        return

    if key not in model.model[sec].keys():
        return

    model.model[sec][key].policy.append(tokens[1:])


class Adapter:
    """the interface for Casbin adapters."""

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        pass

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
