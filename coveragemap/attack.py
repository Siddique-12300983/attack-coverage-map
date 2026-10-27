"""The bundled ATT&CK reference: technique names and the tactics they sit under."""

import json
import os
import re
from typing import Dict, List, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

TECHNIQUE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")
TAG_PATTERN = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)
TACTIC_TAG_PATTERN = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)


class AttackData:
    """Technique and tactic lookups, loaded from the bundled JSON files."""

    def __init__(self, techniques: Dict[str, Dict], tactics: List[Dict]):
        self.techniques = techniques
        self.tactics = tactics
        self.tactic_names = {t["shortname"]: t["name"] for t in tactics}
        self.tactic_order = [t["shortname"] for t in tactics]

    @classmethod
    def load(cls, extra_path: Optional[str] = None) -> "AttackData":
        with open(os.path.join(DATA_DIR, "techniques.json"), encoding="utf-8") as handle:
            techniques = json.load(handle)
        with open(os.path.join(DATA_DIR, "tactics.json"), encoding="utf-8") as handle:
            tactics = json.load(handle)
        if extra_path:
            with open(extra_path, encoding="utf-8") as handle:
                extra = json.load(handle)
            if not isinstance(extra, dict):
                raise ValueError(
                    "%s should be a JSON object of technique id to "
                    '{"name": ..., "tactics": [...]}' % extra_path
                )
            techniques.update(extra)
        return cls(techniques, tactics)

    def name(self, technique: str) -> str:
        entry = self.techniques.get(technique)
        if entry:
            return entry["name"]
        parent = technique.split(".")[0]
        entry = self.techniques.get(parent)
        if entry:
            return "%s (sub-technique not in the local table)" % entry["name"]
        return "not in the local ATT&CK table"

    def tactics_for(self, technique: str) -> List[str]:
        entry = self.techniques.get(technique)
        if entry:
            return list(entry["tactics"])
        parent = self.techniques.get(technique.split(".")[0])
        if parent:
            return list(parent["tactics"])
        return []

    def is_known(self, technique: str) -> bool:
        return technique in self.techniques

    def url(self, technique: str) -> str:
        return "https://attack.mitre.org/techniques/%s/" % technique.replace(".", "/")

    def sort_key(self, tactic: str) -> int:
        try:
            return self.tactic_order.index(tactic)
        except ValueError:
            return len(self.tactic_order)


def normalise_technique(value: str) -> Optional[str]:
    """Turn any of T1110, t1110, attack.t1110.003 into a canonical technique id.

    Returns None when the value is not a technique reference, which is how
    tactic tags such as attack.credential_access get filtered out.
    """
    text = (value or "").strip()
    if not text:
        return None
    tag = TAG_PATTERN.match(text)
    if tag:
        base = "T%s" % tag.group(1)
        return "%s.%s" % (base, tag.group(2)) if tag.group(2) else base
    upper = text.upper()
    if TECHNIQUE_PATTERN.match(upper):
        return upper
    return None


def normalise_tactic(value: str) -> Optional[str]:
    """Turn attack.credential_access into the Navigator shortname."""
    match = TACTIC_TAG_PATTERN.match((value or "").strip())
    if not match:
        return None
    candidate = match.group(1).lower().replace("_", "-")
    if candidate.startswith("t") and candidate[1:].isdigit():
        return None
    return candidate
