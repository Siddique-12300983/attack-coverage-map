"""Tests for the Sigma and inventory loaders."""

import json
import os
import tempfile
import unittest

from tests.helpers import BROKEN_FIXTURES, INVENTORY, SAMPLE_SIGMA, SIGMA_FIXTURES

from coveragemap.sources import (
    detection_from_sigma,
    load_inventory,
    load_sigma_dir,
    load_sigma_file,
)


class SigmaFileTests(unittest.TestCase):
    def test_minimal_rule(self):
        detections, problems = load_sigma_file(os.path.join(SIGMA_FIXTURES, "minimal.yml"))
        self.assertEqual(len(detections), 1)
        self.assertEqual(problems, [])
        detection = detections[0]
        self.assertEqual(detection.name, "Minimal Rule")
        self.assertEqual(detection.kind, "sigma")
        self.assertEqual(detection.level, "high")
        self.assertEqual(detection.techniques, ["T1110"])
        self.assertEqual(detection.tactics, ["credential-access"])
        self.assertEqual(detection.logsource, "linux/sshd")

    def test_two_documents_in_one_file_give_two_detections(self):
        detections, problems = load_sigma_file(
            os.path.join(SIGMA_FIXTURES, "two_documents.yml")
        )
        self.assertEqual(len(detections), 2)
        self.assertEqual(problems, [])
        self.assertEqual([d.name for d in detections], ["First Of Two", "Second Of Two"])
        self.assertEqual(detections[0].techniques, ["T1543.002"])
        self.assertEqual(detections[1].techniques, ["T1059.004"])

    def test_folded_description_is_collapsed_to_one_line(self):
        detections, _ = load_sigma_file(
            os.path.join(SIGMA_FIXTURES, "folded_and_literal.yml")
        )
        self.assertNotIn("\n", detections[0].description)
        self.assertIn("one line of text", detections[0].description)

    def test_rule_without_an_attack_tag_is_loaded_but_warned_about(self):
        detections, problems = load_sigma_file(
            os.path.join(SIGMA_FIXTURES, "no_attack_tag.yml")
        )
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].techniques, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("no attack.tXXXX tag", problems[0].problem)

    def test_unsupported_yaml_is_reported_not_guessed_at(self):
        detections, problems = load_sigma_file(
            os.path.join(BROKEN_FIXTURES, "flow_collection.yml")
        )
        self.assertEqual(detections, [])
        self.assertEqual(len(problems), 1)
        self.assertIn("unsupported YAML", problems[0].problem)

    def test_yaml_that_is_not_a_sigma_rule_is_skipped(self):
        detections, problems = load_sigma_file(
            os.path.join(BROKEN_FIXTURES, "not_a_rule.yml")
        )
        self.assertEqual(detections, [])
        self.assertIn("no title or detection block", problems[0].problem)

    def test_a_missing_file_is_reported_not_raised(self):
        detections, problems = load_sigma_file("/nonexistent/rule.yml")
        self.assertEqual(detections, [])
        self.assertIn("could not read", problems[0].problem)


class SigmaDocumentTests(unittest.TestCase):
    def test_tactic_and_technique_tags_are_separated(self):
        detection = detection_from_sigma(
            {
                "title": "Mixed Tags",
                "tags": [
                    "attack.credential_access",
                    "attack.t1558.003",
                    "attack.defense_evasion",
                    "attack.t1562.001",
                ],
                "level": "high",
            },
            "memory",
        )
        self.assertEqual(detection.techniques, ["T1558.003", "T1562.001"])
        self.assertEqual(detection.tactics, ["credential-access", "defense-evasion"])

    def test_duplicate_tags_are_collapsed(self):
        detection = detection_from_sigma(
            {"title": "Dupes", "tags": ["attack.t1110", "attack.T1110"]}, "memory"
        )
        self.assertEqual(detection.techniques, ["T1110"])

    def test_a_single_tag_as_a_string_is_accepted(self):
        detection = detection_from_sigma(
            {"title": "One Tag", "tags": "attack.t1110"}, "memory"
        )
        self.assertEqual(detection.techniques, ["T1110"])

    def test_an_unknown_level_becomes_unknown(self):
        detection = detection_from_sigma({"title": "X", "level": "spicy"}, "memory")
        self.assertEqual(detection.level, "unknown")

    def test_a_missing_title_falls_back_to_the_filename(self):
        detection = detection_from_sigma({"detection": {}}, "/rules/my_rule.yml")
        self.assertEqual(detection.name, "my_rule.yml")

    def test_logsource_fields_are_joined_in_a_stable_order(self):
        detection = detection_from_sigma(
            {"title": "X", "logsource": {"service": "security", "product": "windows"}},
            "memory",
        )
        self.assertEqual(detection.logsource, "windows/security")


class SigmaDirectoryTests(unittest.TestCase):
    def test_the_sample_directory_loads(self):
        detections, problems = load_sigma_dir(SAMPLE_SIGMA)
        self.assertEqual(len(detections), 3)
        self.assertEqual(problems, [])
        self.assertTrue(all(d.techniques for d in detections))

    def test_sample_rules_cover_the_techniques_their_readme_claims(self):
        detections, _ = load_sigma_dir(SAMPLE_SIGMA)
        covered = set()
        for detection in detections:
            covered.update(detection.techniques)
        self.assertEqual(
            covered, {"T1110", "T1110.001", "T1543.002", "T1059.001", "T1027"}
        )

    def test_a_single_file_path_also_works(self):
        detections, _ = load_sigma_dir(os.path.join(SIGMA_FIXTURES, "minimal.yml"))
        self.assertEqual(len(detections), 1)

    def test_non_yaml_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "README.md"), "w") as handle:
                handle.write("not a rule")
            with open(os.path.join(tmp, "r.yml"), "w") as handle:
                handle.write("title: R\ntags:\n  - attack.t1110\ndetection:\n  a: b\n")
            detections, _ = load_sigma_dir(tmp)
            self.assertEqual(len(detections), 1)

    def test_a_missing_directory_raises(self):
        with self.assertRaises(NotADirectoryError):
            load_sigma_dir("/nonexistent/rules")


class InventoryTests(unittest.TestCase):
    def test_the_bundled_inventory_loads_without_warnings(self):
        detections, problems = load_inventory(INVENTORY)
        self.assertEqual(problems, [], "the shipped inventory should be clean")
        self.assertGreater(len(detections), 10)
        for detection in detections:
            self.assertTrue(detection.name)
            self.assertTrue(detection.techniques, detection.name)
            self.assertTrue(detection.repo, detection.name)

    def test_the_bundled_inventory_only_uses_known_techniques(self):
        from coveragemap.attack import AttackData

        attack = AttackData.load()
        detections, _ = load_inventory(INVENTORY)
        for detection in detections:
            for technique in detection.techniques:
                self.assertTrue(
                    attack.is_known(technique),
                    "%s claims %s, which is not in the bundled table"
                    % (detection.name, technique),
                )

    def _write(self, tmp, payload):
        path = os.path.join(tmp, "inv.json")
        with open(path, "w") as handle:
            json.dump(payload, handle)
        return path

    def test_a_bare_list_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, [{"name": "A", "techniques": ["T1110"]}])
            detections, problems = load_inventory(path)
            self.assertEqual(len(detections), 1)
            self.assertEqual(problems, [])

    def test_a_repo_at_the_top_level_is_the_default_for_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp,
                {"repo": "shared-repo", "detections": [{"name": "A", "techniques": ["T1110"]}]},
            )
            detections, _ = load_inventory(path)
            self.assertEqual(detections[0].repo, "shared-repo")

    def test_an_entry_without_a_name_is_skipped_with_a_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"detections": [{"techniques": ["T1110"]}]})
            detections, problems = load_inventory(path)
            self.assertEqual(detections, [])
            self.assertIn("has no name", problems[0].problem)

    def test_a_bad_technique_id_is_warned_about(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(
                tmp, {"detections": [{"name": "A", "techniques": ["T1110", "banana"]}]}
            )
            detections, problems = load_inventory(path)
            self.assertEqual(detections[0].techniques, ["T1110"])
            self.assertIn("not a technique id", problems[0].problem)

    def test_an_entry_with_no_techniques_at_all_is_warned_about(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"detections": [{"name": "A"}]})
            detections, problems = load_inventory(path)
            self.assertEqual(len(detections), 1)
            self.assertIn("no usable technique id", problems[0].problem)

    def test_invalid_json_raises_with_the_path_in_the_message(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "inv.json")
            with open(path, "w") as handle:
                handle.write("{not json")
            with self.assertRaises(ValueError) as caught:
                load_inventory(path)
            self.assertIn(path, str(caught.exception))

    def test_the_wrong_shape_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._write(tmp, {"detections": "not a list"})
            with self.assertRaises(ValueError):
                load_inventory(path)


if __name__ == "__main__":
    unittest.main()
