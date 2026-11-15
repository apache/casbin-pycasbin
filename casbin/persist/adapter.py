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

import re

_INTERESTING_TOKENS_RE = re.compile(r"[,\[\]\(\)]")


def _skip_blanks(line, i):
    while i < len(line) and line[i] in " \t":
        i += 1
    return i


def _read_quoted_field(line, start):
    """Read a CSV quoted field whose opening quote is at `start`: commas and brackets inside it are
    part of the value and "" is one quote character. Return (value, end), where `end` is the index
    of the comma after the field or len(line), or None if the quotes do not form a whole field, in
    which case the field is read as a plain one."""

    chars = []
    i = start + 1
    while i < len(line):
        c = line[i]
        if c != '"':
            chars.append(c)
            i += 1
        elif line[i + 1 : i + 2] == '"':
            chars.append('"')
            i += 2
        else:
            end = _skip_blanks(line, i + 1)
            if end == len(line) or line[end] == ",":
                return "".join(chars), end
            return None
    return None


def _read_plain_field(line, start):
    """Read a field that ends at the next comma outside all []() nesting, e.g. `abc(def, ghi)`.
    Return (value, end) like _read_quoted_field()."""

    depth = 0
    for match in _INTERESTING_TOKENS_RE.finditer(line, start):
        c = match.group()
        if c == "[" or c == "(":
            depth += 1
        elif c == "]" or c == ")":
            depth = max(depth - 1, 0)
        elif depth == 0:
            return line[start : match.start()].strip(), match.start()
    return line[start:].strip(), len(line)


def _extract_tokens(line):
    """Return the list of 'tokens' from the line, or None if this line has none"""

    if line == "" or line[:1] == "#":
        return None

    tokens = []
    i = 0
    while True:
        field = None
        quote = _skip_blanks(line, i)
        if line[quote : quote + 1] == '"':
            field = _read_quoted_field(line, quote)
        if field is None:
            field = _read_plain_field(line, i)
        value, i = field
        tokens.append(value)
        if i == len(line):
            return tokens
        i += 1


def _quote_field(value):
    value = str(value)
    if "\n" in value or "\r" in value:
        raise ValueError("invalid policy field %r: line breaks are not allowed" % value)
    # an unclosed bracket would also take in the fields after it
    if "," in value or '"' in value or value != value.strip() or _read_plain_field(value + ",", 0)[0] != value:
        return '"' + value.replace('"', '""') + '"'
    return value


def policy_line_to_csv(ptype, rule):
    """Return the text line of a policy rule that load_policy_line() reads back as the same rule:
    a field containing a comma or a double quote, or with leading or trailing blanks, is written as
    a CSV quoted field."""

    return ", ".join([ptype] + [_quote_field(v) for v in rule])


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
