"""Patterns: OS_Match / OS_Regex / PCRE2 to the detector's
``|re`` dialect and to RE2, and the validator that refuses every forbidden form."""

import re
import unittest

from helpers import TOOL  # noqa: F401  (puts the tool on sys.path)

from rmig.translate import patterns as P
from rmig.translate.re_dialect import problems, valid


def sigma(engine, pattern):
    f = P.to_sigma(engine, pattern)
    return f.terms, f.exact


class TestOsRegexClasses(unittest.TestCase):
    def test_w_plus(self):
        terms, exact = sigma("osregex", "^\\w+$")
        self.assertEqual(terms, [("re", ["[-A-Za-z0-9_@]+"])])
        self.assertTrue(exact)

    def test_S_plus_is_approximate(self):
        f = P.to_sigma("osregex", "\\S+")
        self.assertEqual(f.terms, [("re", [".*[!-~]+.*"])])
        self.assertFalse(f.exact)
        self.assertIn("\\S became [!-~] (no characters outside ASCII)", f.why)

    def test_d_and_D(self):
        self.assertEqual(sigma("osregex", "^\\d\\D$"), ([("re", ["[0-9][^0-9]"])], True))

    def test_backslash_dot_is_any_and_dot_is_literal(self):
        self.assertEqual(sigma("osregex", "^a\\.b.c$"), ([("re", ["[Aa].[Bb][.][Cc]"])], True))

    def test_s_is_approximate(self):
        f = P.to_sigma("osregex", "a\\sb")
        self.assertEqual(f.terms, [("re", [".*[Aa].[Bb].*"])])
        self.assertFalse(f.exact)

    def test_literal_escapes(self):
        self.assertEqual(sigma("osregex", "^\\(x\\)\\|$"), ([("re", ["[(][Xx][)][|]"])], True))

    def test_invalid_escape_is_refused(self):
        with self.assertRaises(P.PatternError):
            P.to_sigma("osregex", "\\q")


class TestOsMatch(unittest.TestCase):
    def test_letter_classes_and_anchors(self):
        self.assertEqual(sigma("osmatch", "^failed$"), ([("re", ["[Ff][Aa][Ii][Ll][Ee][Dd]"])], True))
        self.assertEqual(sigma("osmatch", "^fail"), ([("re", ["[Ff][Aa][Ii][Ll].*"])], True))
        self.assertEqual(sigma("osmatch", "fail$"), ([("re", [".*[Ff][Aa][Ii][Ll]"])], True))

    def test_alternation_is_a_list(self):
        self.assertEqual(sigma("osmatch", "illegal|invalid"),
                         ([("re", [".*[Ii][Ll][Ll][Ee][Gg][Aa][Ll].*", ".*[Ii][Nn][Vv][Aa][Ll][Ii][Dd].*"])], True))

    def test_space_and_slash_are_approximate(self):
        f = P.to_sigma("osmatch", "Invalid user")
        self.assertEqual(f.terms, [("re", [".*[Ii][Nn][Vv][Aa][Ll][Ii][Dd].[Uu][Ss][Ee][Rr].*"])])
        self.assertFalse(f.exact)
        f = P.to_sigma("osmatch", "/etc/passwd")
        self.assertEqual(f.terms, [("re", [".*.[Ee][Tt][Cc].[Pp][Aa][Ss][Ss][Ww][Dd].*"])])
        self.assertFalse(f.exact)

    def test_reserved_characters_in_a_class(self):
        self.assertEqual(sigma("osmatch", "a.b+c"), ([("re", [".*[Aa][.][Bb][+][Cc].*"])], True))


class TestPcre2(unittest.TestCase):
    def test_literal_with_anchors_becomes_modifiers(self):
        self.assertEqual(sigma("pcre2", "^abc"), ([("startswith", ["abc"])], True))
        self.assertEqual(sigma("pcre2", "abc$"), ([("endswith", ["abc"])], True))
        self.assertEqual(sigma("pcre2", "^abc$"), ([("", ["abc"])], True))
        self.assertEqual(sigma("pcre2", "a b|c d"), ([("contains", ["a b", "c d"])], True))
        self.assertEqual(sigma("pcre2", "^a|b$"), ([("startswith", ["a"]), ("endswith", ["b"])], True))
        self.assertEqual(sigma("pcre2", "^C:\\\\Windows\\.exe"), ([("startswith", ["C:\\Windows.exe"])], True))

    def test_general_regex(self):
        self.assertEqual(sigma("pcre2", "foo\\d{2,3}[a-c]+"), ([("re", [".*foo[0-9]{2,3}[a-c]+.*"])], True))
        self.assertEqual(sigma("pcre2", "(?i)ab(c|d)"), ([("re", [".*[Aa][Bb]([Cc]|[Dd]).*"])], True))

    def test_unsupported_constructs(self):
        for p in ("a(?=b)", "(a)\\1", "\\bword\\b", "a++", "(?<!x)y"):
            with self.assertRaises(P.PatternError, msg=p):
                P.to_sigma("pcre2", p)


class TestValidator(unittest.TestCase):
    def test_refuses_every_forbidden_form(self):
        for bad in ("a\\d", "abc$", "^abc", "a b", "a/b", "[a-]", "[^a-]", "[ab", "(a", "a)", "x\tb"):
            self.assertFalse(valid(bad), bad)
            self.assertTrue(problems(bad), bad)

    def test_accepts_the_emitted_forms(self):
        for good in (".*[Ii][Nn].*", "[-A-Za-z0-9_@]+", "[^-A-Za-z0-9_@]", "[!-~]+", "[^0-9]", "[-]", "([Aa]|[Bb])+"):
            self.assertTrue(valid(good), (good, problems(good)))

    def test_every_sigma_value_passes(self):
        cases = [("osregex", "\\p\\w+\\s\\S*\\t\\.x"), ("osmatch", "^a/b c$|d^e$"), ("pcre2", "[ /]x"),
                 ("osregex", "^-\\d+-$")]
        for engine, pattern in cases:
            for mod, vals in P.to_sigma(engine, pattern).terms:
                for v in vals:
                    self.assertTrue(valid(v), (engine, pattern, v, problems(v)))


class TestRe2(unittest.TestCase):
    def test_osregex_is_case_insensitive_and_lazy_except_at_the_end(self):
        f = P.to_re2("osregex", "^(\\w+) user=(\\S+)")
        self.assertEqual(f.pattern(), "(?i)^([-0-9@A-Z_a-z]+?) user=([^ ]+)")
        self.assertEqual(f.pattern(keep=2), "(?i)^(?:[-0-9@A-Z_a-z]+?) user=([^ ]+)")

    def test_compose_offsets(self):
        pre = P.to_re2("osregex", "^login ")
        rx = P.to_re2("osregex", "^id=(\\d+)")
        self.assertEqual(P.compose_re2([pre], rx, keep=1), "(?i:^login )(?i:id=([0-9]+))")
        rx2 = P.to_re2("osregex", "id=(\\d+)")
        self.assertEqual(P.compose_re2([pre], rx2, keep=1), "(?i:^login )(?i:.*?id=([0-9]+))")

    def test_every_rendering_compiles(self):
        for engine, pattern in (("osregex", "\\p+\\W\\D\\t\\.$"), ("osmatch", "a.b|^c(d)$"), ("pcre2", "(?i)x[0-9]{2}(?:y|z)")):
            re.compile(P.to_re2(engine, pattern).pattern())  # RE2 syntax used here is a subset of Python's

    def test_helper_quote(self):
        self.assertEqual(P.helper_quote("a\\.b'c"), "'a\\\\.b\\\\x27c'")


if __name__ == "__main__":
    unittest.main()
