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

from simpleeval import EvalWithCompoundTypes
import ast


class SimpleEval(EvalWithCompoundTypes):
    """Rewrite SimpleEval.
    >>> s = SimpleEval("20 + 30 - ( 10 * 5)")
    >>> s.eval()
    0
    """

    ast_parsed_value = None

    def __init__(self, expr, functions=None):
        """Create the evaluator instance.  Set up valid operators (+,-, etc)
        functions (add, random, get_val, whatever) and names."""
        super(SimpleEval, self).__init__(functions=functions)
        if expr != "":
            self.expr = expr
            self.ast_parsed_value = ast.parse(expr.strip()).body[0].value

    def eval(self, names=None):
        """evaluate an expression, using the operators, functions and
        names previously set up."""

        if names:
            self.names = names

        return self._eval(self.ast_parsed_value)
