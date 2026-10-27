"""Render coverage as a readable report or as JSON."""

import json
from typing import Dict, List, Sequence

from .coverage import Coverage
from .sources import LoadProblem


def _rule(width: int = 74) -> str:
    return "-" * width


def _bar(depth: int, width: int = 3) -> str:
    return "#" * min(depth, width) + "." * max(0, width - depth)


def text_report(coverage: Coverage, problems: Sequence[LoadProblem] = ()) -> str:
    summary = coverage.summary()
    lines: List[str] = []
    lines.append("ATT&CK coverage report")
    lines.append(_rule())
    lines.append(
        "detections   : %d  (%d Sigma rules, %d other)"
        % (summary["detections"], summary["sigma_rules"], summary["other_detections"])
    )
    lines.append(
        "techniques   : %d covered across %d tactics"
        % (summary["techniques_covered"], summary["tactics_covered"])
    )
    lines.append(
        "depth        : %d technique(s) rest on a single detection, deepest has %d"
        % (summary["techniques_with_one_detection"], summary["max_depth"])
    )
    if coverage.targets:
        lines.append(
            "targets      : %d of %d covered (%s%%), %d gap(s)"
            % (
                summary["targets_covered"],
                summary["targets"],
                summary["target_percent"],
                summary["targets_missing"],
            )
        )
    lines.append("")

    grouped = coverage.by_tactic()
    if not grouped:
        lines.append("No techniques covered. Nothing loaded, or nothing tagged.")
        lines.append("")
        return "\n".join(lines)

    lines.append("Coverage by tactic")
    lines.append(_rule())
    for tactic, entries in grouped.items():
        label = coverage.attack.tactic_names.get(tactic, tactic.replace("-", " "))
        lines.append("%s  (%d technique%s)" % (label, len(entries), "" if len(entries) == 1 else "s"))
        for entry in entries:
            flag = " " if entry.known else "?"
            lines.append(
                "  %s %-11s %s  %-52s"
                % (flag, entry.technique, _bar(entry.depth), entry.name[:52])
            )
            for detection in entry.detections:
                lines.append(
                    "                  - %s [%s] %s"
                    % (detection.name, detection.level, detection.repo or detection.kind)
                )
        lines.append("")

    if coverage.targets:
        gaps = coverage.gaps()
        lines.append("Target techniques with no detection yet")
        lines.append(_rule())
        if not gaps:
            lines.append("  None. Every target on the list has at least one detection.")
        for technique in gaps:
            tactics = coverage.attack.tactics_for(technique)
            lines.append(
                "  %-11s %-52s %s"
                % (
                    technique,
                    coverage.attack.name(technique)[:52],
                    ", ".join(tactics) or "unmapped",
                )
            )
        lines.append("")

    thin = coverage.single_source()
    if thin:
        lines.append("Techniques resting on one detection")
        lines.append(_rule())
        lines.append("  A single rule is a single point of failure. These are the")
        lines.append("  ones to back up with a second, independent detection.")
        for entry in thin:
            lines.append(
                "  %-11s %-44s %s"
                % (entry.technique, entry.name[:44], ", ".join(entry.sources))
            )
        lines.append("")

    unknown = coverage.unknown_techniques()
    if unknown:
        lines.append("Techniques not in the bundled ATT&CK table")
        lines.append(_rule())
        lines.append("  Marked '?' above. Pass --attack-data to extend the table.")
        for technique in unknown:
            lines.append("  %s" % technique)
        lines.append("")

    orphans = coverage.detections_without_techniques()
    if orphans:
        lines.append("Detections with no technique tag")
        lines.append(_rule())
        for detection in orphans:
            lines.append("  %s  (%s)" % (detection.name, detection.source))
        lines.append("")

    if problems:
        lines.append("Load warnings")
        lines.append(_rule())
        for problem in problems:
            lines.append("  %s: %s" % (problem.source, problem.problem))
        lines.append("")

    return "\n".join(lines)


def json_report(coverage: Coverage, problems: Sequence[LoadProblem] = ()) -> Dict:
    return {
        "tool": "attack-coverage-map",
        "summary": coverage.summary(),
        "by_tactic": {
            tactic: [entry.technique for entry in entries]
            for tactic, entries in coverage.by_tactic().items()
        },
        "techniques": [
            coverage.techniques[t].as_dict() for t in sorted(coverage.techniques)
        ],
        "gaps": [
            {
                "technique": technique,
                "name": coverage.attack.name(technique),
                "tactics": coverage.attack.tactics_for(technique),
            }
            for technique in coverage.gaps()
        ],
        "single_detection_techniques": [e.technique for e in coverage.single_source()],
        "unknown_techniques": coverage.unknown_techniques(),
        "detections": [d.as_dict() for d in coverage.detections],
        "load_warnings": [
            {"source": p.source, "problem": p.problem} for p in problems
        ],
    }


def json_text(coverage: Coverage, problems: Sequence[LoadProblem] = ()) -> str:
    return json.dumps(json_report(coverage, problems), indent=2)
