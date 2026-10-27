"""Tests for the YAML subset reader."""

import unittest

from tests.helpers import SIGMA_FIXTURES

from coveragemap.miniyaml import MiniYamlError, load, load_all


class ScalarTests(unittest.TestCase):
    def test_plain_mapping(self):
        self.assertEqual(load("a: 1\nb: two\n"), {"a": 1, "b": "two"})

    def test_quotes_are_stripped(self):
        self.assertEqual(load("a: 'one'\nb: \"two\"\n"), {"a": "one", "b": "two"})

    def test_booleans_and_null(self):
        parsed = load("a: true\nb: no\nc: null\nd: ~\n")
        self.assertEqual(parsed, {"a": True, "b": False, "c": None, "d": None})

    def test_numbers(self):
        self.assertEqual(load("a: 42\nb: 3.5\nc: 2026/10/28\n"),
                         {"a": 42, "b": 3.5, "c": "2026/10/28"})

    def test_comment_lines_and_trailing_comments(self):
        parsed = load("# top\na: one   # trailing\nb: two\n")
        self.assertEqual(parsed, {"a": "one", "b": "two"})

    def test_hash_inside_quotes_survives(self):
        self.assertEqual(load("a: 'has # inside'\n"), {"a": "has # inside"})

    def test_value_containing_a_colon(self):
        self.assertEqual(
            load("url: https://attack.mitre.org/techniques/T1110/\n"),
            {"url": "https://attack.mitre.org/techniques/T1110/"},
        )


class CollectionTests(unittest.TestCase):
    def test_list_of_scalars(self):
        parsed = load("tags:\n  - attack.t1110\n  - attack.credential_access\n")
        self.assertEqual(parsed["tags"], ["attack.t1110", "attack.credential_access"])

    def test_nested_mapping(self):
        parsed = load("logsource:\n  product: windows\n  service: security\n")
        self.assertEqual(parsed["logsource"], {"product": "windows", "service": "security"})

    def test_deeply_nested_mapping(self):
        parsed = load(
            "detection:\n"
            "  selection:\n"
            "    EventID: 4769\n"
            "    TicketEncryptionType: '0x17'\n"
            "  condition: selection\n"
        )
        self.assertEqual(parsed["detection"]["selection"]["EventID"], 4769)
        self.assertEqual(parsed["detection"]["condition"], "selection")

    def test_list_nested_inside_a_mapping(self):
        parsed = load(
            "detection:\n"
            "  selection:\n"
            "    Image|endswith:\n"
            "      - '\\powershell.exe'\n"
            "      - '\\pwsh.exe'\n"
            "  condition: selection\n"
        )
        self.assertEqual(
            parsed["detection"]["selection"]["Image|endswith"],
            ["\\powershell.exe", "\\pwsh.exe"],
        )

    def test_key_with_no_value_and_no_children(self):
        self.assertEqual(load("a:\nb: 1\n"), {"a": None, "b": 1})


class BlockScalarTests(unittest.TestCase):
    def test_folded_scalar_joins_lines(self):
        parsed = load("description: >\n  one\n  two\n  three\nlevel: high\n")
        self.assertEqual(parsed["description"], "one two three")
        self.assertEqual(parsed["level"], "high")

    def test_folded_scalar_keeps_paragraph_breaks(self):
        parsed = load("description: >\n  one\n  two\n\n  three\n")
        self.assertEqual(parsed["description"], "one two\nthree")

    def test_literal_scalar_keeps_line_breaks(self):
        parsed = load("body: |\n  line one\n  line two\nlevel: low\n")
        self.assertEqual(parsed["body"], "line one\nline two")
        self.assertEqual(parsed["level"], "low")

    def test_chomping_indicators_are_accepted(self):
        self.assertEqual(load("a: >-\n  one\n  two\n")["a"], "one two")
        self.assertEqual(load("a: |-\n  one\n  two\n")["a"], "one\ntwo")


class DocumentTests(unittest.TestCase):
    def test_several_documents(self):
        documents = load_all("title: one\n---\ntitle: two\n---\ntitle: three\n")
        self.assertEqual([d["title"] for d in documents], ["one", "two", "three"])

    def test_leading_separator_does_not_make_an_empty_document(self):
        documents = load_all("---\ntitle: only\n")
        self.assertEqual(len(documents), 1)

    def test_load_returns_the_first_document(self):
        self.assertEqual(load("title: one\n---\ntitle: two\n")["title"], "one")

    def test_empty_input(self):
        self.assertEqual(load(""), {})
        self.assertEqual(load_all("\n\n# only a comment\n"), [])


class ErrorTests(unittest.TestCase):
    def test_flow_collection_is_rejected_rather_than_misread(self):
        with self.assertRaises(MiniYamlError):
            load("tags: [attack.t1110, attack.credential_access]\n")

    def test_tab_indentation_is_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("logsource:\n\tproduct: windows\n")

    def test_line_without_a_colon_is_rejected(self):
        with self.assertRaises(MiniYamlError):
            load("title: ok\nthis line has no colon\n")


class RealFixtureTests(unittest.TestCase):
    def test_folded_and_literal_fixture_parses_as_expected(self):
        import os

        with open(os.path.join(SIGMA_FIXTURES, "folded_and_literal.yml")) as handle:
            parsed = load(handle.read())
        self.assertEqual(parsed["title"], "Folded And Literal Scalars")
        self.assertIn("one line of text", parsed["description"])
        self.assertIn("second paragraph", parsed["description"])
        self.assertEqual(parsed["details"], "line one\nline two")
        self.assertEqual(parsed["tags"], ["attack.defense_evasion", "attack.t1562.001"])
        self.assertEqual(parsed["logsource"]["service"], "windefend")
        self.assertEqual(parsed["detection"]["selection"]["New Value|contains"], "\\Exclusions\\")
        self.assertEqual(len(parsed["falsepositives"]), 2)


if __name__ == "__main__":
    unittest.main()
