"""Tests for the coverage engine, the Navigator layer and the heatmap."""

import json
import os
import tempfile
import unittest
from html.parser import HTMLParser

from tests.helpers import INVENTORY, SAMPLE_SIGMA, TARGETS

from coveragemap.attack import AttackData
from coveragemap.coverage import build, load_targets
from coveragemap.heatmap import build_html
from coveragemap.navigator import build_layer
from coveragemap.sources import Detection, load_inventory, load_sigma_dir

ATTACK = AttackData.load()


def detection(name, techniques, repo="r", kind="tool", level="high"):
    return Detection(
        name=name, techniques=list(techniques), repo=repo, kind=kind, level=level
    )


class GroupingTests(unittest.TestCase):
    def test_a_technique_collects_every_detection_that_claims_it(self):
        coverage = build(
            [detection("a", ["T1110"]), detection("b", ["T1110"]), detection("c", ["T1027"])],
            attack=ATTACK,
        )
        self.assertEqual(coverage.techniques["T1110"].depth, 2)
        self.assertEqual(coverage.techniques["T1027"].depth, 1)

    def test_technique_names_come_from_the_attack_table(self):
        coverage = build([detection("a", ["T1558.003"])], attack=ATTACK)
        self.assertEqual(
            coverage.techniques["T1558.003"].name,
            "Steal or Forge Kerberos Tickets: Kerberoasting",
        )

    def test_a_technique_in_several_tactics_appears_under_each(self):
        coverage = build([detection("a", ["T1543.002"])], attack=ATTACK)
        grouped = coverage.by_tactic()
        self.assertIn("persistence", grouped)
        self.assertIn("privilege-escalation", grouped)

    def test_tactics_come_back_in_kill_chain_order(self):
        coverage = build(
            [detection("a", ["T1486"]), detection("b", ["T1566"])], attack=ATTACK
        )
        self.assertEqual(list(coverage.by_tactic()), ["initial-access", "impact"])

    def test_sources_counts_distinct_repos_not_rules(self):
        coverage = build(
            [
                detection("a", ["T1110"], repo="log-analyzer"),
                detection("b", ["T1110"], repo="log-analyzer"),
                detection("c", ["T1110"], repo="sigma-rules"),
            ],
            attack=ATTACK,
        )
        entry = coverage.techniques["T1110"]
        self.assertEqual(entry.depth, 3)
        self.assertEqual(entry.sources, ["log-analyzer", "sigma-rules"])

    def test_an_unknown_technique_is_kept_and_flagged(self):
        coverage = build([detection("a", ["T9999"])], attack=ATTACK)
        self.assertIn("T9999", coverage.techniques)
        self.assertFalse(coverage.techniques["T9999"].known)
        self.assertEqual(coverage.unknown_techniques(), ["T9999"])

    def test_an_unknown_technique_falls_back_to_the_rule_tactic_tags(self):
        orphan = Detection(name="a", techniques=["T9999"], tactics=["impact"])
        coverage = build([orphan], attack=ATTACK)
        self.assertEqual(coverage.techniques["T9999"].tactics, ["impact"])

    def test_a_detection_with_no_technique_is_reported_separately(self):
        coverage = build([detection("a", [])], attack=ATTACK)
        self.assertEqual(coverage.techniques, {})
        self.assertEqual(len(coverage.detections_without_techniques()), 1)


class SummaryTests(unittest.TestCase):
    def test_counts_split_sigma_from_everything_else(self):
        coverage = build(
            [
                detection("a", ["T1110"], kind="sigma"),
                detection("b", ["T1027"], kind="tool"),
                detection("c", ["T1036"], kind="lab"),
            ],
            attack=ATTACK,
        )
        summary = coverage.summary()
        self.assertEqual(summary["detections"], 3)
        self.assertEqual(summary["sigma_rules"], 1)
        self.assertEqual(summary["other_detections"], 2)

    def test_single_detection_techniques_are_counted(self):
        coverage = build(
            [detection("a", ["T1110"]), detection("b", ["T1110"]), detection("c", ["T1027"])],
            attack=ATTACK,
        )
        self.assertEqual(coverage.summary()["techniques_with_one_detection"], 1)
        self.assertEqual([e.technique for e in coverage.single_source()], ["T1027"])

    def test_max_depth(self):
        coverage = build(
            [detection(str(i), ["T1110"]) for i in range(4)], attack=ATTACK
        )
        self.assertEqual(coverage.summary()["max_depth"], 4)

    def test_an_empty_coverage_does_not_divide_by_zero(self):
        coverage = build([], attack=ATTACK)
        summary = coverage.summary()
        self.assertEqual(summary["detections"], 0)
        self.assertEqual(summary["max_depth"], 0)
        self.assertNotIn("target_percent", summary)


class TargetTests(unittest.TestCase):
    def test_gaps_are_targets_with_no_detection(self):
        coverage = build(
            [detection("a", ["T1110"])], attack=ATTACK, targets=["T1110", "T1027", "T1036"]
        )
        self.assertEqual(coverage.gaps(), ["T1027", "T1036"])
        self.assertEqual(coverage.hit_targets(), ["T1110"])

    def test_target_percentage(self):
        coverage = build(
            [detection("a", ["T1110"])], attack=ATTACK, targets=["T1110", "T1027"]
        )
        self.assertEqual(coverage.summary()["target_percent"], 50.0)

    def test_covering_something_off_the_target_list_is_not_a_gap(self):
        coverage = build([detection("a", ["T1486"])], attack=ATTACK, targets=["T1110"])
        self.assertEqual(coverage.gaps(), ["T1110"])
        self.assertIn("T1486", coverage.techniques)


class LoadTargetsTests(unittest.TestCase):
    def test_the_bundled_target_file_parses(self):
        targets = load_targets(TARGETS)
        self.assertGreater(len(targets), 10)
        self.assertIn("T1558.003", targets)
        self.assertEqual(targets, sorted(targets))

    def test_the_bundled_target_file_only_uses_known_techniques(self):
        for technique in load_targets(TARGETS):
            self.assertTrue(
                ATTACK.is_known(technique), "%s is not in the bundled table" % technique
            )

    def test_one_per_line_with_comments(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as handle:
                handle.write("# a comment\nT1110  # trailing\n\nT1027\n")
            self.assertEqual(load_targets(path), ["T1027", "T1110"])

    def test_a_json_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.json")
            with open(path, "w") as handle:
                json.dump(["T1110", "attack.t1027"], handle)
            self.assertEqual(load_targets(path), ["T1027", "T1110"])

    def test_a_json_object_with_a_techniques_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.json")
            with open(path, "w") as handle:
                json.dump({"techniques": ["T1110"]}, handle)
            self.assertEqual(load_targets(path), ["T1110"])

    def test_duplicates_and_junk_are_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.txt")
            with open(path, "w") as handle:
                handle.write("T1110\nt1110\nbanana\n")
            self.assertEqual(load_targets(path), ["T1110"])


class NavigatorTests(unittest.TestCase):
    def setUp(self):
        self.coverage = build(
            [
                detection("a", ["T1110"], repo="log-analyzer"),
                detection("b", ["T1110"], repo="sigma", kind="sigma"),
                detection("c", ["T1543.002"], repo="persistwatch"),
            ],
            attack=ATTACK,
            targets=["T1110", "T1003.001"],
        )
        self.layer = build_layer(self.coverage)

    def test_layer_header_matches_the_navigator_schema(self):
        self.assertEqual(self.layer["versions"]["layer"], "4.5")
        self.assertEqual(self.layer["domain"], "enterprise-attack")
        self.assertIn("gradient", self.layer)
        self.assertIn("techniques", self.layer)

    def test_the_score_is_the_detection_depth(self):
        scored = {t["techniqueID"]: t["score"] for t in self.layer["techniques"] if "score" in t}
        self.assertEqual(scored["T1110"], 2)
        self.assertEqual(scored["T1543.002"], 1)

    def test_a_technique_gets_one_cell_per_tactic(self):
        cells = [t for t in self.layer["techniques"] if t["techniqueID"] == "T1543.002"]
        self.assertEqual(
            sorted(c["tactic"] for c in cells), ["persistence", "privilege-escalation"]
        )

    def test_the_comment_names_the_detections_behind_the_cell(self):
        cell = next(t for t in self.layer["techniques"] if t["techniqueID"] == "T1110")
        self.assertIn("log-analyzer", cell["comment"])
        self.assertIn("sigma", cell["comment"])

    def test_gaps_come_through_as_coloured_cells(self):
        gaps = [t for t in self.layer["techniques"] if t.get("color")]
        self.assertTrue(gaps)
        self.assertEqual({t["techniqueID"] for t in gaps}, {"T1003.001"})
        self.assertNotIn("score", gaps[0])

    def test_gaps_can_be_left_out(self):
        layer = build_layer(self.coverage, include_gaps=False)
        self.assertEqual([t for t in layer["techniques"] if t.get("color")], [])

    def test_the_gradient_maximum_matches_the_deepest_technique(self):
        self.assertEqual(self.layer["gradient"]["maxValue"], 2)

    def test_sub_techniques_are_expanded_so_the_cell_is_visible(self):
        cell = next(t for t in self.layer["techniques"] if t["techniqueID"] == "T1543.002")
        self.assertTrue(cell["showSubtechniques"])

    def test_the_layer_round_trips_through_json(self):
        self.assertEqual(json.loads(json.dumps(self.layer))["name"], self.layer["name"])


class _Balance(HTMLParser):
    VOID = {"meta", "br", "hr", "img", "input", "link", "area", "base", "col"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
            return
        self.stack.pop()


class HeatmapTests(unittest.TestCase):
    def setUp(self):
        sigma, _ = load_sigma_dir(SAMPLE_SIGMA)
        inventory, _ = load_inventory(INVENTORY)
        self.coverage = build(
            sigma + inventory, attack=ATTACK, targets=load_targets(TARGETS)
        )
        self.html = build_html(self.coverage, title="Test coverage")

    def test_the_html_is_balanced(self):
        checker = _Balance()
        checker.feed(self.html)
        checker.close()
        self.assertEqual(checker.stack, [])
        self.assertEqual(checker.errors, [])

    def test_it_is_self_contained(self):
        self.assertNotIn("<script", self.html)
        self.assertNotIn("src=", self.html)
        self.assertNotIn("@import", self.html)
        self.assertNotIn('rel="stylesheet"', self.html)

    def test_the_title_is_used(self):
        self.assertIn("<title>Test coverage</title>", self.html)

    def test_every_covered_technique_has_a_cell(self):
        for technique in self.coverage.techniques:
            self.assertIn(">%s<" % technique, self.html, technique)

    def test_every_gap_has_a_cell(self):
        for technique in self.coverage.gaps():
            self.assertIn(">%s<" % technique, self.html, technique)

    def test_gaps_are_drawn_in_the_gap_style(self):
        self.assertIn('class="cell gap"', self.html)

    def test_depth_changes_the_cell_class(self):
        self.assertIn('class="cell d1"', self.html)
        self.assertTrue('class="cell d2"' in self.html or 'class="cell d3"' in self.html)

    def test_detection_names_are_escaped_not_injected(self):
        coverage = build([detection("<script>x</script>", ["T1110"])], attack=ATTACK)
        html = build_html(coverage)
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_the_caveat_about_what_coverage_means_is_present(self):
        self.assertIn("does not mean the detection was tested", self.html)


class FilesOnDiskTests(unittest.TestCase):
    def test_both_writers_create_readable_files(self):
        from coveragemap.heatmap import write_html
        from coveragemap.navigator import write_layer

        coverage = build([detection("a", ["T1110"])], attack=ATTACK)
        with tempfile.TemporaryDirectory() as tmp:
            layer_path = os.path.join(tmp, "layer.json")
            html_path = os.path.join(tmp, "map.html")
            write_layer(coverage, layer_path)
            write_html(coverage, html_path)
            with open(layer_path) as handle:
                self.assertEqual(json.load(handle)["domain"], "enterprise-attack")
            with open(html_path) as handle:
                self.assertIn("<!doctype html>", handle.read())


if __name__ == "__main__":
    unittest.main()
