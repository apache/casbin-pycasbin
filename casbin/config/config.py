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

from io import StringIO


class Config:
    """represents an implementation of the ConfigInterface"""

    # DEFAULT_SECTION specifies the name of a section if no name provided
    DEFAULT_SECTION = "default"
    # DEFAULT_COMMENT defines what character(s) indicate a comment `#`
    DEFAULT_COMMENT = "#"
    # DEFAULT_COMMENT_SEM defines what alternate character(s) indicate a comment `;`
    DEFAULT_COMMENT_SEM = ";"
    # DEFAULT_MULTI_LINE_SEPARATOR defines what character indicates a multi-line content
    DEFAULT_MULTI_LINE_SEPARATOR = "\\"

    _data = dict()

    def __init__(self):
        self._data = dict()

    @staticmethod
    def new_config(conf_name):
        c = Config()
        c._parse(conf_name)
        return c

    @staticmethod
    def new_config_from_text(text):
        c = Config()
        f = StringIO(text)
        c._parse_buffer(f)
        return c

    def add_config(self, section, option, value):
        if section == "":
            section = self.DEFAULT_SECTION

        if section not in self._data.keys():
            self._data[section] = {}

        self._data[section][option] = value

    def _parse(self, fname):
        with open(fname, "r", encoding="utf-8") as f:
            self._parse_buffer(f)

    def _parse_buffer(self, f):
        section = ""
        line_num = 0
        buf = []
        can_write = False
        while True:
            if can_write:
                self._write(section, line_num, buf)
                can_write = False
            line_num = line_num + 1

            line = f.readline()

            if not line:
                if len(buf) > 0:
                    self._write(section, line_num, buf)
                break
            line = line.strip()

            if "" == line or self.DEFAULT_COMMENT == line[0:1] or self.DEFAULT_COMMENT_SEM == line[0:1]:
                can_write = True
                continue
            elif "[" == line[0:1] and "]" == line[-1]:
                if len(buf) > 0:
                    self._write(section, line_num, buf)
                    can_write = False
                section = line[1:-1]
            else:
                p = ""
                if self.DEFAULT_MULTI_LINE_SEPARATOR == line[-1]:
                    p = line[0:-1].strip()
                    p = p + " "
                else:
                    p = line
                    can_write = True

                end = len(p)
                for i, value in enumerate(p):
                    if value == self.DEFAULT_COMMENT or value == self.DEFAULT_COMMENT_SEM:
                        end = i
                        break
                buf.append(p[:end])

    def _write(self, section, line_num, b):
        buf = "".join(b)
        if len(buf) <= 0:
            return
        option_val = buf.split("=", 1)

        if len(option_val) != 2:
            raise RuntimeError("parse the content error : line {} , {} = ?".format(line_num, option_val[0]))

        option = option_val[0].strip()
        value = option_val[1].strip()

        self.add_config(section, option, value)

        del b[:]

    def get_bool(self, key):
        """looks up the value using the provided key and converts the value to a bool."""
        return self.get(key).capitalize() == "True"

    def get_int(self, key):
        """looks up the value using the provided key and converts the value to an int."""
        return int(self.get(key))

    def get_float(self, key):
        """looks up the value using the provided key and converts the value to a float."""
        return float(self.get(key))

    def get_string(self, key):
        """looks up the value using the provided key and converts the value to a string."""
        return self.get(key)

    def get_strings(self, key):
        """looks up the value using the provided key and converts the value to an array of strings."""
        value = self.get(key)
        if value == "":
            return None
        return value.split(",")

    def set(self, key, value):
        if len(key) == 0:
            raise RuntimeError("key is empty")

        keys = key.lower().split("::")
        if len(keys) >= 2:
            section = keys[0]
            option = keys[1]
        else:
            section = ""
            option = keys[0]
        self.add_config(section, option, value)

    def get(self, key):
        """section.key or key"""

        keys = key.lower().split("::")
        if len(keys) >= 2:
            section = keys[0]
            option = keys[1]
        else:
            section = self.DEFAULT_SECTION
            option = keys[0]

        if section in self._data.keys():
            if option in self._data[section].keys():
                return self._data[section][option]
        return ""
