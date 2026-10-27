"""Tests for the command line interface."""

import io
import json
import os
import tempfile
import unittest

from tests.helpers import BROKEN_FIXTURES, INVENTORY, SAMPLE_SIGMA, SIGMA_FIXTURES, TARGETS

from coveragemap.cli import EXIT_ERROR, EXIT_GAPS, EXIT_OK, main


def run_cli(*argv):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(argv), stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


class UsageTests(unittest.TestCase):
    def test_no_input_is_a_usage_error(self):
        code, _out, err = run_cli()
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("at least one --sigma path or --inventory file", err)

    def test_a_missing_sigma_directory_is_an_error(self):
        code, _out, err = run_cli("--sigma", "/nonexistent/rules")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("not a file or directory", err)

    def test_a_directory_with_nothing_loadable_is_an_error(self):
        code, _out, err = run_cli("--sigma", BROKEN_FIXTURES)
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("no detections loaded", err)

    def test_a_missing_inventory_file_is_an_error(self):
        code, _out, err = run_cli("--inventory", "/nonexistent/inv.json")
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("attack-coverage-map:", err)


class ReportTests(unittest.TestCase):
    def test_the_sample_rules_produce_a_report(self):
        code, out, _err = run_cli("--sigma", SAMPLE_SIGMA)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("ATT&CK coverage report", out)
        self.assertIn("detections   : 3  (3 Sigma rules, 0 other)", out)
        self.assertIn("T1543.002", out)

    def test_sigma_and_inventory_combine(self):
        _code, out, _err = run_cli("--sigma", SAMPLE_SIGMA, "--inventory", INVENTORY)
        self.assertIn("3 Sigma rules", out)
        self.assertIn("Kerberoasting", out)
        self.assertIn("persistwatch", out)

    def test_targets_add_the_gap_section(self):
        _code, out, _err = run_cli("--sigma", SAMPLE_SIGMA, "--targets", TARGETS)
        self.assertIn("Target techniques with no detection yet", out)
        self.assertIn("targets      :", out)

    def test_the_single_detection_section_names_the_thin_spots(self):
        _code, out, _err = run_cli("--sigma", SAMPLE_SIGMA)
        self.assertIn("Techniques resting on one detection", out)

    def test_load_warnings_reach_the_report(self):
        _code, out, _err = run_cli("--sigma", SIGMA_FIXTURES)
        self.assertIn("Load warnings", out)
        self.assertIn("no attack.tXXXX tag", out)

    def test_a_detection_with_no_technique_is_listed(self):
        _code, out, _err = run_cli("--sigma", SIGMA_FIXTURES)
        self.assertIn("Detections with no technique tag", out)
        self.assertIn("Rule Without An Attack Tag", out)

    def test_quiet_prints_nothing(self):
        code, out, _err = run_cli("--sigma", SAMPLE_SIGMA, "--quiet")
        self.assertEqual(code, EXIT_OK)
        self.assertEqual(out, "")


class JsonTests(unittest.TestCase):
    def test_json_is_valid_and_has_the_documented_keys(self):
        _code, out, _err = run_cli(
            "--sigma", SAMPLE_SIGMA, "--inventory", INVENTORY, "--targets", TARGETS, "--json"
        )
        data = json.loads(out)
        self.assertEqual(data["tool"], "attack-coverage-map")
        for key in (
            "summary",
            "by_tactic",
            "techniques",
            "gaps",
            "single_detection_techniques",
            "unknown_techniques",
            "detections",
            "load_warnings",
        ):
            self.assertIn(key, data)

    def test_json_counts_agree_with_the_lists(self):
        _code, out, _err = run_cli("--sigma", SAMPLE_SIGMA, "--inventory", INVENTORY, "--json")
        data = json.loads(out)
        self.assertEqual(data["summary"]["detections"], len(data["detections"]))
        self.assertEqual(data["summary"]["techniques_covered"], len(data["techniques"]))

    def test_every_json_technique_entry_is_complete(self):
        _code, out, _err = run_cli("--sigma", SAMPLE_SIGMA, "--json")
        for entry in json.loads(out)["techniques"]:
            self.assertEqual(
                sorted(entry),
                [
                    "depth",
                    "detections",
                    "in_local_attack_table",
                    "name",
                    "sources",
                    "tactics",
                    "technique",
                ],
            )


class OutputFileTests(unittest.TestCase):
    def test_navigator_and_html_are_written_and_announced(self):
        with tempfile.TemporaryDirectory() as tmp:
            layer = os.path.join(tmp, "layer.json")
            page = os.path.join(tmp, "map.html")
            code, out, _err = run_cli(
                "--sigma", SAMPLE_SIGMA, "--navigator", layer, "--html", page
            )
            self.assertEqual(code, EXIT_OK)
            self.assertTrue(os.path.isfile(layer))
            self.assertTrue(os.path.isfile(page))
            self.assertIn("Navigator layer written to", out)
            self.assertIn("HTML heatmap written to", out)
            with open(layer) as handle:
                self.assertEqual(json.load(handle)["versions"]["layer"], "4.5")

    def test_the_name_flag_titles_both_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            layer = os.path.join(tmp, "layer.json")
            page = os.path.join(tmp, "map.html")
            run_cli(
                "--sigma", SAMPLE_SIGMA, "--navigator", layer, "--html", page,
                "--name", "My Coverage",
            )
            with open(layer) as handle:
                self.assertEqual(json.load(handle)["name"], "My Coverage")
            with open(page) as handle:
                self.assertIn("<title>My Coverage</title>", handle.read())

    def test_an_unwritable_output_path_is_an_error_not_a_traceback(self):
        code, _out, err = run_cli(
            "--sigma", SAMPLE_SIGMA, "--navigator", "/nonexistent/dir/layer.json"
        )
        self.assertEqual(code, EXIT_ERROR)
        self.assertIn("could not write output", err)


class ExitCodeTests(unittest.TestCase):
    def test_gaps_alone_do_not_fail(self):
        code, _out, _err = run_cli("--sigma", SAMPLE_SIGMA, "--targets", TARGETS)
        self.assertEqual(code, EXIT_OK)

    def test_fail_on_gaps_exits_one_when_a_target_is_uncovered(self):
        code, _out, _err = run_cli(
            "--sigma", SAMPLE_SIGMA, "--targets", TARGETS, "--fail-on-gaps"
        )
        self.assertEqual(code, EXIT_GAPS)

    def test_fail_on_gaps_exits_zero_when_every_target_is_covered(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = os.path.join(tmp, "t.txt")
            with open(targets, "w") as handle:
                handle.write("T1543.002\nT1059.001\n")
            code, _out, _err = run_cli(
                "--sigma", SAMPLE_SIGMA, "--targets", targets, "--fail-on-gaps"
            )
            self.assertEqual(code, EXIT_OK)


class AttackDataFlagTests(unittest.TestCase):
    def test_extra_attack_data_removes_the_unknown_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            rule = os.path.join(tmp, "r.yml")
            with open(rule, "w") as handle:
                handle.write(
                    "title: Odd Technique\ntags:\n  - attack.t9999\n"
                    "detection:\n  selection:\n    a: b\n  condition: selection\n"
                )
            _code, out, _err = run_cli("--sigma", rule)
            self.assertIn("Techniques not in the bundled ATT&CK table", out)

            extra = os.path.join(tmp, "extra.json")
            with open(extra, "w") as handle:
                json.dump({"T9999": {"name": "Made Up", "tactics": ["impact"]}}, handle)
            _code, out, _err = run_cli("--sigma", rule, "--attack-data", extra)
            self.assertNotIn("Techniques not in the bundled ATT&CK table", out)
            self.assertIn("Made Up", out)


if __name__ == "__main__":
    unittest.main()
