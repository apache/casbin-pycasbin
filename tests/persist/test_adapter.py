import os
import tempfile

import casbin
from casbin.persist.adapter import _extract_tokens, policy_line_to_csv
from tests import TestCaseBase

EXAMPLES = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", "examples")


class User:
    def __init__(self, name, age):
        self.Name = name
        self.Age = age


class TestExtractTokens(TestCaseBase):
    def test_ignore_lines(self):
        self.assertIsNone(_extract_tokens(""))  # empty
        self.assertIsNone(_extract_tokens("# comment"))

    def test_simple_lines(self):
        # split on top-level commas, strip whitespace from start and end
        self.assertEqual(_extract_tokens("one"), ["one"])
        self.assertEqual(_extract_tokens("one,two"), ["one", "two"])
        self.assertEqual(_extract_tokens("   ignore  \t,\t   external, spaces  "), ["ignore", "external", "spaces"])

        self.assertEqual(_extract_tokens("internal spaces preserved"), ["internal spaces preserved"])

    def test_nested_lines(self):
        # basic nesting within a single token
        self.assertEqual(
            _extract_tokens("outside1()"),
            ["outside1()"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1())"),
            ["outside1(inside1())"],
        )

        # split on top-level commas, but not on internal ones
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2())"),
            ["outside1(inside1(), inside2())"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2(inside3(), inside4()))"),
            ["outside1(inside1(), inside2(inside3(), inside4()))"],
        )
        self.assertEqual(
            _extract_tokens("outside1(inside1(), inside2()), outside2(inside3(), inside4())"),
            ["outside1(inside1(), inside2())", "outside2(inside3(), inside4())"],
        )

        # different delimiters
        self.assertEqual(
            _extract_tokens(
                "all_square[inside1[], inside2[]],square_and_parens[inside1(), inside2()],parens_and_square(inside1[], inside2[])"
            ),
            [
                "all_square[inside1[], inside2[]]",
                "square_and_parens[inside1(), inside2()]",
                "parens_and_square(inside1[], inside2[])",
            ],
        )

    def test_quoted_fields(self):
        self.assertEqual(_extract_tokens('p, alice, "data1,data2", read'), ["p", "alice", "data1,data2", "read"])
        self.assertEqual(_extract_tokens('p, "da""ta", " x ", ""'), ["p", 'da"ta', " x ", ""])
        self.assertEqual(_extract_tokens('"p","alice" , "a(b"'), ["p", "alice", "a(b"])
        # a quote that does not form a whole field is part of the value
        self.assertEqual(_extract_tokens('p, r.sub.Name == "bob", read'), ["p", 'r.sub.Name == "bob"', "read"])
        self.assertEqual(_extract_tokens('p, "a"b, c'), ["p", '"a"b', "c"])
        self.assertEqual(_extract_tokens('p, "a, b'), ["p", '"a', "b"])
        self.assertEqual(_extract_tokens('p, keyMatch("a, b", r.obj), c'), ["p", 'keyMatch("a, b", r.obj)', "c"])

    def test_policy_line_to_csv(self):
        values = ["doc1", "a,b", '"a"', 'r.sub.Name == "bob"', " a ", "x(", "y)", "[a, b]", "f(a, b)", ""]
        for value in values:
            line = policy_line_to_csv("p", ["alice", value, "read"])
            self.assertEqual(_extract_tokens(line), ["p", "alice", value, "read"], line)
        self.assertEqual(policy_line_to_csv("p", ["alice", "data1", "read"]), "p, alice, data1, read")
        self.assertEqual(policy_line_to_csv("p", ["alice", "a,b"]), 'p, alice, "a,b"')
        with self.assertRaises(ValueError):
            policy_line_to_csv("p", ["alice", "a\np, mallory, b"])


class TestQuotedPolicyFile(TestCaseBase):
    def policy_file(self, text):
        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_quoted_abac_rule(self):
        path = self.policy_file('p, "r.sub.Age > 18", /data1, read\n')
        e = casbin.Enforcer(os.path.join(EXAMPLES, "abac_rule_model.conf"), path)
        self.assertTrue(e.enforce(User("alice", 30), "/data1", "read"))
        self.assertFalse(e.enforce(User("bob", 10), "/data1", "read"))

    def test_save_and_load_back(self):
        path = self.policy_file("p, alice, data1, read\n")
        e = casbin.Enforcer(os.path.join(EXAMPLES, "basic_model.conf"), path)
        e.add_policy("bob", "a, b", "read")
        e.add_policy("bob", '"c"', "read")
        e.save_policy()
        with open(path) as f:
            self.assertEqual(f.read(), 'p, alice, data1, read\np, bob, "a, b", read\np, bob, """c""", read')

        e = casbin.Enforcer(os.path.join(EXAMPLES, "basic_model.conf"), path)
        self.assertEqual(e.get_policy(), [["alice", "data1", "read"], ["bob", "a, b", "read"], ["bob", '"c"', "read"]])
        self.assertTrue(e.enforce("bob", "a, b", "read"))
        self.assertFalse(e.enforce("bob", "a", "read"))

        e.add_policy("bob", "d\np, mallory, data1, read", "read")
        with self.assertRaises(ValueError):
            e.save_policy()
        with open(path) as f:
            self.assertNotIn("mallory", f.read())
