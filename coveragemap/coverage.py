"""Aggregate detections into ATT&CK coverage."""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set

from .attack import AttackData, normalise_technique
from .sources import Detection


@dataclass
class TechniqueCoverage:
    """Every detection that claims one technique."""

    technique: str
    name: str
    tactics: List[str]
    detections: List[Detection] = field(default_factory=list)
    known: bool = True

    @property
    def depth(self) -> int:
        """How many detections cover this technique."""
        return len(self.detections)

    @property
    def sources(self) -> List[str]:
        """The distinct repos or kinds behind the coverage.

        A technique covered by both a Sigma rule and a tool is better covered
        than one covered twice by the same thing, so the report shows this
        rather than the raw count alone.
        """
        seen: List[str] = []
        for detection in self.detections:
            label = detection.repo or detection.kind
            if label not in seen:
                seen.append(label)
        return seen

    def as_dict(self) -> Dict:
        return {
            "technique": self.technique,
            "name": self.name,
            "tactics": list(self.tactics),
            "depth": self.depth,
            "sources": self.sources,
            "in_local_attack_table": self.known,
            "detections": [
                {
                    "name": d.name,
                    "kind": d.kind,
                    "repo": d.repo,
                    "level": d.level,
                    "source": d.source,
                }
                for d in self.detections
            ],
        }


@dataclass
class Coverage:
    attack: AttackData
    detections: List[Detection] = field(default_factory=list)
    techniques: Dict[str, TechniqueCoverage] = field(default_factory=dict)
    targets: List[str] = field(default_factory=list)

    # ---------------- derived views ----------------

    def by_tactic(self) -> "Dict[str, List[TechniqueCoverage]]":
        """Technique coverage grouped by tactic, in ATT&CK kill-chain order."""
        grouped: Dict[str, List[TechniqueCoverage]] = {}
        for entry in self.techniques.values():
            tactics = entry.tactics or ["unmapped"]
            for tactic in tactics:
                grouped.setdefault(tactic, []).append(entry)
        for items in grouped.values():
            items.sort(key=lambda e: (-e.depth, e.technique))
        return dict(
            sorted(grouped.items(), key=lambda kv: self.attack.sort_key(kv[0]))
        )

    def unknown_techniques(self) -> List[str]:
        return sorted(t for t, e in self.techniques.items() if not e.known)

    def detections_without_techniques(self) -> List[Detection]:
        return [d for d in self.detections if not d.techniques]

    def gaps(self) -> List[str]:
        """Target techniques with no detection behind them."""
        return sorted(t for t in self.targets if t not in self.techniques)

    def hit_targets(self) -> List[str]:
        return sorted(t for t in self.targets if t in self.techniques)

    def single_source(self) -> List[TechniqueCoverage]:
        """Techniques resting on exactly one detection."""
        return sorted(
            (e for e in self.techniques.values() if e.depth == 1),
            key=lambda e: e.technique,
        )

    def summary(self) -> Dict:
        tactics = self.by_tactic()
        data = {
            "detections": len(self.detections),
            "sigma_rules": len([d for d in self.detections if d.kind == "sigma"]),
            "other_detections": len([d for d in self.detections if d.kind != "sigma"]),
            "techniques_covered": len(self.techniques),
            "tactics_covered": len([t for t in tactics if t != "unmapped"]),
            "techniques_with_one_detection": len(self.single_source()),
            "max_depth": max((e.depth for e in self.techniques.values()), default=0),
        }
        if self.targets:
            data["targets"] = len(self.targets)
            data["targets_covered"] = len(self.hit_targets())
            data["targets_missing"] = len(self.gaps())
            data["target_percent"] = (
                round(100.0 * len(self.hit_targets()) / len(self.targets), 1)
                if self.targets
                else 0.0
            )
        return data


def build(
    detections: Sequence[Detection],
    attack: Optional[AttackData] = None,
    targets: Optional[Sequence[str]] = None,
) -> Coverage:
    """Group detections by the techniques they claim."""
    data = attack or AttackData.load()
    coverage = Coverage(attack=data, detections=list(detections))
    for detection in detections:
        for technique in detection.techniques:
            entry = coverage.techniques.get(technique)
            if entry is None:
                entry = TechniqueCoverage(
                    technique=technique,
                    name=data.name(technique),
                    tactics=data.tactics_for(technique) or list(detection.tactics),
                    known=data.is_known(technique),
                )
                coverage.techniques[technique] = entry
            entry.detections.append(detection)
    for entry in coverage.techniques.values():
        entry.detections.sort(key=lambda d: (d.kind, d.repo, d.name))
    coverage.targets = list(targets or [])
    return coverage


def load_targets(path: str) -> List[str]:
    """Read a target technique list: JSON array, {"techniques": [...]}, or one per line."""
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    stripped = text.strip()
    values: Sequence = []
    if stripped.startswith("[") or stripped.startswith("{"):
        data = json.loads(stripped)
        values = data.get("techniques", []) if isinstance(data, dict) else data
    else:
        values = [
            line.split("#")[0].strip()
            for line in text.splitlines()
            if line.split("#")[0].strip()
        ]
    targets: List[str] = []
    for value in values:
        technique = normalise_technique(str(value))
        if technique and technique not in targets:
            targets.append(technique)
    return sorted(targets)
