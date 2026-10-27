"""Tests for the bundled ATT&CK reference data."""

import json
import os
import tempfile
import unittest

from tests.helpers import REPO_ROOT

from coveragemap.attack import AttackData, normalise_tactic, normalise_technique

TACTIC_SHORTNAMES = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
}


class NormaliseTests(unittest.TestCase):
    def test_sigma_technique_tags(self):
        self.assertEqual(normalise_technique("attack.t1558.003"), "T1558.003")
        self.assertEqual(normalise_technique("attack.T1110"), "T1110")

    def test_bare_technique_ids(self):
        self.assertEqual(normalise_technique("T1543.002"), "T1543.002")
        self.assertEqual(normalise_technique("t1053.006"), "T1053.006")
        self.assertEqual(normalise_technique(" T1110 "), "T1110")

    def test_non_techniques_return_none(self):
        for value in ("attack.credential_access", "nonsense", "", "T11", "T110000", None):
            self.assertIsNone(normalise_technique(value), repr(value))

    def test_tactic_tags(self):
        self.assertEqual(normalise_tactic("attack.credential_access"), "credential-access")
        self.assertEqual(normalise_tactic("attack.defense_evasion"), "defense-evasion")

    def test_technique_tags_are_not_tactics(self):
        self.assertIsNone(normalise_tactic("attack.t1110"))

    def test_unrelated_tags_are_not_tactics(self):
        self.assertIsNone(normalise_tactic("detection.threat_hunting"))


class DataIntegrityTests(unittest.TestCase):
    """The bundled table is hand-maintained, so check its shape stays valid."""

    def setUp(self):
        self.attack = AttackData.load()

    def test_table_is_not_empty(self):
        self.assertGreater(len(self.attack.techniques), 50)

    def test_every_id_is_well_formed(self):
        for technique in self.attack.techniques:
            self.assertIsNotNone(
                normalise_technique(technique), "bad id in the table: %s" % technique
            )

    def test_every_entry_has_a_name_and_at_least_one_tactic(self):
        for technique, entry in self.attack.techniques.items():
            self.assertTrue(entry.get("name"), technique)
            self.assertTrue(entry.get("tactics"), technique)

    def test_every_tactic_is_a_real_navigator_shortname(self):
        for technique, entry in self.attack.techniques.items():
            for tactic in entry["tactics"]:
                self.assertIn(tactic, TACTIC_SHORTNAMES, "%s -> %s" % (technique, tactic))

    def test_every_sub_technique_has_its_parent_in_the_table(self):
        for technique in self.attack.techniques:
            if "." in technique:
                parent = technique.split(".")[0]
                self.assertIn(parent, self.attack.techniques,
                              "%s has no parent entry" % technique)

    def test_tactic_order_covers_the_whole_kill_chain(self):
        self.assertEqual(len(self.attack.tactic_order), 14)
        self.assertEqual(self.attack.tactic_order[0], "reconnaissance")
        self.assertEqual(self.attack.tactic_order[-1], "impact")


class LookupTests(unittest.TestCase):
    def setUp(self):
        self.attack = AttackData.load()

    def test_known_technique(self):
        self.assertEqual(
            self.attack.name("T1558.003"),
            "Steal or Forge Kerberos Tickets: Kerberoasting",
        )
        self.assertEqual(self.attack.tactics_for("T1558.003"), ["credential-access"])
        self.assertTrue(self.attack.is_known("T1558.003"))

    def test_unknown_sub_technique_falls_back_to_its_parent(self):
        self.assertIn("Brute Force", self.attack.name("T1110.099"))
        self.assertIn("sub-technique not in the local table", self.attack.name("T1110.099"))
        self.assertEqual(self.attack.tactics_for("T1110.099"), ["credential-access"])
        self.assertFalse(self.attack.is_known("T1110.099"))

    def test_completely_unknown_technique(self):
        self.assertEqual(self.attack.name("T9999"), "not in the local ATT&CK table")
        self.assertEqual(self.attack.tactics_for("T9999"), [])

    def test_url_uses_the_mitre_path_shape(self):
        self.assertEqual(
            self.attack.url("T1543.002"),
            "https://attack.mitre.org/techniques/T1543/002/",
        )
        self.assertEqual(
            self.attack.url("T1110"), "https://attack.mitre.org/techniques/T1110/"
        )

    def test_sort_key_follows_the_kill_chain(self):
        self.assertLess(
            self.attack.sort_key("initial-access"), self.attack.sort_key("impact")
        )
        self.assertEqual(self.attack.sort_key("not-a-tactic"), 14)


class ExtraDataTests(unittest.TestCase):
    def test_an_extra_file_extends_the_table(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "extra.json")
            with open(path, "w") as handle:
                json.dump({"T9999": {"name": "Made Up", "tactics": ["impact"]}}, handle)
            attack = AttackData.load(path)
            self.assertTrue(attack.is_known("T9999"))
            self.assertEqual(attack.name("T9999"), "Made Up")
            self.assertEqual(attack.tactics_for("T9999"), ["impact"])

    def test_an_extra_file_can_override_a_bundled_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "extra.json")
            with open(path, "w") as handle:
                json.dump({"T1110": {"name": "Renamed", "tactics": ["impact"]}}, handle)
            attack = AttackData.load(path)
            self.assertEqual(attack.name("T1110"), "Renamed")

    def test_a_list_instead_of_an_object_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "extra.json")
            with open(path, "w") as handle:
                json.dump(["T9999"], handle)
            with self.assertRaises(ValueError):
                AttackData.load(path)


if __name__ == "__main__":
    unittest.main()
