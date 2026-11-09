from casbin.persist.adapter import _extract_tokens
from tests import TestCaseBase


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
        # double-quoted fields, as described on the policy storage page: the quotes are removed,
        # commas and brackets inside them do not split or nest, and "" is a literal quote
        self.assertEqual(_extract_tokens('p, alice, "data1,data2", read'), ["p", "alice", "data1,data2", "read"])
        self.assertEqual(_extract_tokens('p, alice, "da""ta", read'), ["p", "alice", 'da"ta', "read"])
        self.assertEqual(_extract_tokens('p, alice, "data1", read'), ["p", "alice", "data1", "read"])
        self.assertEqual(
            _extract_tokens('"p", "alice", "data2", "write", "deny"'), ["p", "alice", "data2", "write", "deny"]
        )
        self.assertEqual(
            _extract_tokens("p, \"r.sub.Name in ('alice', 'bob')\", /data3, read"),
            ["p", "r.sub.Name in ('alice', 'bob')", "/data3", "read"],
        )
        self.assertEqual(_extract_tokens('p, "a(b", c'), ["p", "a(b", "c"])
        self.assertEqual(_extract_tokens('p, "", c'), ["p", "", "c"])
        # a quote that does not open the field is part of the value, as before
        self.assertEqual(
            _extract_tokens('p, r.sub.Name == "bob", /data1, read'), ["p", 'r.sub.Name == "bob"', "/data1", "read"]
        )
        self.assertEqual(_extract_tokens("p, keyMatch(\"a\", r.obj), b"), ["p", 'keyMatch("a", r.obj)', "b"])


class TestQuotedPolicyDecisions(TestCaseBase):
    """A quoted field must reach the matcher without its quotes (same decision as Go casbin)."""

    def _enforcer(self, model, policy_text):
        import os
        import tempfile

        import casbin

        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w") as f:
            f.write(policy_text)
        self.addCleanup(os.remove, path)
        return casbin.Enforcer(get_examples(model), path)

    def test_quoted_abac_rule_is_evaluated(self):
        class Sub:
            def __init__(self, name, age):
                self.Name = name
                self.Age = age

        e = self._enforcer("abac_rule_model.conf", "p, \"r.sub.Name in ('alice', 'bob')\", /data3, read\n")
        self.assertTrue(e.enforce(Sub("alice", 30), "/data3", "read"))
        self.assertFalse(e.enforce(Sub("carol", 30), "/data3", "read"))

        e = self._enforcer("abac_rule_model.conf", 'p, "r.sub.Age > 18", /data1, read\n')
        self.assertTrue(e.enforce(Sub("alice", 30), "/data1", "read"))
        self.assertFalse(e.enforce(Sub("alice", 10), "/data1", "read"))

    def test_quoted_deny_rule_applies(self):
        policy = 'p, alice, data2, write, allow\np, alice, "data2", write, "deny"\n'
        e = self._enforcer("rbac_with_not_deny_model.conf", policy)
        self.assertFalse(e.enforce("alice", "data2", "write"))

        e = self._enforcer("rbac_with_not_deny_model.conf", '"p", "alice", "data2", "write", "deny"\n')
        self.assertFalse(e.enforce("alice", "data2", "write"))


    def test_saved_values_load_back_unchanged(self):
        import os
        import tempfile

        import casbin

        values = [
            "doc1",
            "secret, read",
            "secret, read, extra",
            '"secret"',
            "a(b, c)",
            'doc, "q"',
            "[secret, read]",
            "x(",
            "y)",
            " padded ",
            "r.sub.Name in ('alice', 'bob')",
        ]
        model = get_examples("basic_model.conf")
        for value in values:
            with self.subTest(value=value):
                fd, path = tempfile.mkstemp(suffix=".csv")
                with os.fdopen(fd, "w") as f:
                    f.write("p, alice, data1, read\n")
                try:
                    e = casbin.Enforcer(model, path)
                    e.add_policy("mallory", value, "read")
                    e.save_policy()
                    e2 = casbin.Enforcer(model, path)
                    self.assertEqual(e2.get_policy(), [["alice", "data1", "read"], ["mallory", value, "read"]])
                    self.assertTrue(e2.enforce("mallory", value, "read"))
                    self.assertFalse(e2.enforce("mallory", "secret", "read"))
                finally:
                    os.remove(path)

    def test_value_with_line_break_is_not_saved(self):
        import os
        import tempfile

        import casbin

        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w") as f:
            f.write("p, alice, data1, read\n")
        try:
            e = casbin.Enforcer(get_examples("basic_model.conf"), path)
            e.add_policy("mallory", "doc1\np, mallory, secret, read", "read")
            with self.assertRaises(ValueError):
                e.save_policy()
            with open(path) as f:
                self.assertEqual(f.read(), "p, alice, data1, read\n")
        finally:
            os.remove(path)

def get_examples(path):
    import os

    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../../examples/"
    return os.path.abspath(examples_path + path)
