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

import ipaddress
import re
from datetime import datetime
import wcmatch.glob as glob

KEY_MATCH2_PATTERN = re.compile(r"(.*?):[^\/]+(.*?)")
KEY_MATCH3_PATTERN = re.compile(r"(.*?){[^\/]+?}(.*?)")
KEY_MATCH4_PATTERN = re.compile(r"{([^/]+)}")
KEY_MATCH5_PATTERN = re.compile(r"{[^/]+}")


def key_match(key1, key2):
    """determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    For example, "/foo/bar" matches "/foo/*"
    """

    i = key2.find("*")
    if i == -1:
        return key1 == key2

    if len(key1) > i:
        return key1[:i] == key2[:i]
    return key1 == key2[:i]


def key_match_func(*args):
    """The wrapper for key_match."""
    name1 = args[0]
    name2 = args[1]

    return key_match(name1, name2)


def key_get(key1, key2):
    """
    key_get returns the matched part
    For example, "/foo/bar/foo" matches "/foo/*"
    "bar/foo" will been returned
    """
    i = key2.find("*")
    if i == -1:
        return ""

    if len(key1) > i:
        if key1[:i] == key2[:i]:
            return key1[i:]
    return ""


def key_match2(key1, key2):
    """determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/:resource"
    """

    key2 = key2.replace("/*", "/.*")
    key2 = KEY_MATCH2_PATTERN.sub(r"\g<1>[^\/]+\g<2>", key2, 0)

    if key2 == "*":
        key2 = "(.*)"

    return regex_match(key1, "^" + key2 + "$")


def key_match2_func(*args):
    name1 = args[0]
    name2 = args[1]

    return key_match2(name1, name2)


def key_get2(key1, key2, path_var):
    """
    key_get2 returns value matched pattern
    For example, "/resource1" matches "/:resource"
    if the pathVar == "resource", then "resource1" will be returned
    """
    key2 = key2.replace("/*", "/.*")

    keys = re.findall(":[^/]+", key2)
    key2 = KEY_MATCH2_PATTERN.sub(r"\g<1>([^\/]+)\g<2>", key2, 0)

    if key2 == "*":
        key2 = "(.*)"

    key2 = "^" + key2 + "$"
    values = re.match(key2, key1)
    if values is None:
        return ""
    for i, key in enumerate(keys):
        if path_var == key[1:]:
            return values.groups()[i]
    return ""


def key_match3(key1, key2):
    """determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    For example, "/foo/bar" matches "/foo/*", "/resource1" matches "/{resource}"
    """

    key2 = key2.replace("/*", "/.*")
    key2 = KEY_MATCH3_PATTERN.sub(r"\g<1>[^\/]+\g<2>", key2, 0)

    return regex_match(key1, "^" + key2 + "$")


def key_match3_func(*args):
    name1 = args[0]
    name2 = args[1]

    return key_match3(name1, name2)


def key_get3(key1, key2, path_var):
    """
    key_get3 returns value matched pattern
    For example, "project/proj_project1_admin/" matches "project/proj_{project}_admin/"
    if the pathVar == "project", then "project1" will be returned
    """
    key2 = key2.replace("/*", "/.*")

    keys = re.findall(r"{[^/]+?}", key2)
    key2 = KEY_MATCH3_PATTERN.sub(r"\g<1>([^/]+?)\g<2>", key2, 0)

    if key2 == "*":
        key2 = "(.*)"

    key2 = "^" + key2 + "$"
    values = re.match(key2, key1)
    if values is None:
        return ""
    for i, key in enumerate(keys):
        if path_var == key[1 : len(key) - 1]:
            return values.groups()[i]
    return ""


def key_match4(key1: str, key2: str) -> bool:
    """
    key_match4 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
    Besides what key_match3 does, key_match4 can also match repeated patterns:
    "/parent/123/child/123" matches "/parent/{id}/child/{id}"
    "/parent/123/child/456" does not match "/parent/{id}/child/{id}"
    But key_match3 will match both.
    """
    key2 = key2.replace("/*", "/.*")

    tokens: [str] = []

    def repl(matchobj):
        tokens.append(matchobj.group(1))
        return "([^/]+)"

    key2 = KEY_MATCH4_PATTERN.sub(repl, key2)

    regexp = re.compile("^" + key2 + "$")
    matches = regexp.match(key1)

    if matches is None:
        return False
    if len(tokens) != len(matches.groups()):
        raise Exception("KeyMatch4: number of tokens is not equal to number of values")

    tokens_matches = dict()

    for i in range(len(tokens)):
        token, match = tokens[i], matches.groups()[i]

        if token not in tokens_matches.keys():
            tokens_matches[token] = match
        else:
            if tokens_matches[token] != match:
                return False
    return True


def key_match4_func(*args) -> bool:
    """
    key_match4_func is the wrapper for key_match4.
    """
    name1 = args[0]
    name2 = args[1]

    return key_match4(name1, name2)


def key_match5(key1: str, key2: str) -> bool:
    """
    key_match5 determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *
    For example,
    - "/foo/bar?status=1&type=2" matches "/foo/bar"
    - "/parent/child1" and "/parent/child1" matches "/parent/*"
    - "/parent/child1?status=1" matches "/parent/*"
    """
    i = key1.find("?")
    if i != -1:
        key1 = key1[:i]

    key2 = key2.replace("/*", "/.*")

    key2 = KEY_MATCH5_PATTERN.sub(r"[^/]+", key2, 0)

    return regex_match(key1, "^" + key2 + "$")


def key_match5_func(*args) -> bool:
    name1 = args[0]
    name2 = args[1]

    return key_match5(name1, name2)


def regex_match(key1, key2):
    """determines whether key1 matches the pattern of key2 in regular expression."""

    res = re.match(key2, key1)
    if res:
        return True
    else:
        return False


def regex_match_func(*args):
    """the wrapper for RegexMatch."""

    name1 = args[0]
    name2 = args[1]

    return regex_match(name1, name2)


def range_match(pattern, pattern_index, test):
    """check the if char `test` in string is match with the scope of [...] in pattern"""

    pattern_len = len(pattern)
    if pattern_index == pattern_len:
        return -1
    negate = pattern[pattern_index] == "!" or pattern[pattern_index] == "^"
    if negate:
        pattern_index += 1
    ok = 0
    while True:
        if pattern_index == pattern_len:
            break
        c = pattern[pattern_index]
        pattern_index += 1
        if c == "]":
            break
        if c == "\\":
            if pattern_index == pattern_len:
                return -1
            c = pattern[pattern_index]
            pattern_index += 1
        if (
            pattern_index != pattern_len
            and pattern[pattern_index] == "-"
            and pattern_index + 1 != pattern_len
            and pattern[pattern_index + 1] != "]"
        ):
            c2 = pattern[pattern_index + 1]
            pattern_index += 2
            if c2 == "\\":
                if pattern_index == pattern_len:
                    return -1
                c2 = pattern[pattern_index]
                pattern_index += 1
            if c <= test <= c2:
                ok = 1
        elif c == test:
            ok = 1

    if ok == negate:
        return -1
    else:
        return pattern_index


def glob_match(string, pattern):
    """determines whether string matches the pattern in glob expression."""

    def doublestar_to_wcmatch(pattern):
        """
        Converts glob patterns with double stars (**) to wcmatch-compatible format.
        """
        parts = pattern.split("/")
        new_parts = []
        for part in parts:
            if part == "**":
                new_parts.append("**")
            else:
                part = re.sub(r"\*{2,}", "*", part)
                new_parts.append(part)
        result_pattern = "/".join(new_parts)

        if result_pattern.endswith("/**"):
            base_pattern = result_pattern[:-3]
            result_pattern = "{" + base_pattern + "," + result_pattern + "}"

        return result_pattern

    if pattern.startswith("*/"):
        return glob_match(string, pattern[1:])

    pattern = doublestar_to_wcmatch(pattern)
    return glob.globmatch(string, pattern, flags=glob.GLOBSTAR | glob.BRACE)


def glob_match_func(*args):
    """the wrapper for globMatch."""

    string = args[0]
    pattern = args[1]

    return glob_match(string, pattern)


def ip_match(ip1, ip2):
    """IPMatch determines whether IP address ip1 matches the pattern of IP address ip2, ip2 can be an IP address or a CIDR pattern.
    For example, "192.168.2.123" matches "192.168.2.0/24"
    """
    ip1 = ipaddress.ip_address(ip1)
    try:
        network = ipaddress.ip_network(ip2, strict=False)
        return ip1 in network
    except ValueError:
        return ip1 == ip2


def ip_match_func(*args):
    """the wrapper for IPMatch."""

    ip1 = args[0]
    ip2 = args[1]

    return ip_match(ip1, ip2)


def generate_g_function(rm):
    """the factory method of the g(_, _) function."""

    def f(*args):
        name1 = args[0]
        name2 = args[1]

        if not rm:
            return name1 == name2
        elif 2 == len(args):
            return rm.has_link(name1, name2)
        else:
            domain = str(args[2])
            return rm.has_link(name1, name2, domain)

    return f


def generate_conditional_g_function(crm):
    """the factory method of the g(_, _[, _]) function with conditions."""

    def conditional_g_function(*args):
        name1, name2 = args[0], args[1]

        if crm is None:
            has_link = name1 == name2
        elif len(args) == 2:
            has_link = crm.has_link(name1, name2)
        else:
            domain = str(args[2])
            has_link = crm.has_link(name1, name2, domain)

        return has_link

    return conditional_g_function


def time_match_func(*args):
    """the wrapper for TimeMatch."""
    if len(args) != 2:
        raise RuntimeError("time_match requires 2 arguments")

    start_time, end_time = args[0], args[1]

    try:
        now = datetime.now()
        if start_time != "_":
            start = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            if not now > start:
                return False

        if end_time != "_":
            end = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            if not now < end:
                return False

        return True
    except Exception as e:
        raise RuntimeError(e)
