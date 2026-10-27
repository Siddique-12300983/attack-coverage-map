"""Load detections from Sigma rule files and from a JSON inventory."""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence

from .attack import normalise_tactic, normalise_technique
from .miniyaml import MiniYamlError, load_all

SIGMA_EXTENSIONS = (".yml", ".yaml")
LEVELS = ("critical", "high", "medium", "low", "informational")


@dataclass
class Detection:
    """One detection: a Sigma rule, or an entry from the JSON inventory."""

    name: str
    kind: str = "sigma"
    source: str = ""
    repo: str = ""
    url: str = ""
    level: str = "unknown"
    logsource: str = ""
    description: str = ""
    techniques: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "source": self.source,
            "repo": self.repo,
            "url": self.url,
            "level": self.level,
            "logsource": self.logsource,
            "description": self.description,
            "techniques": list(self.techniques),
            "tactics": list(self.tactics),
        }


@dataclass
class LoadProblem:
    source: str
    problem: str


def _logsource_text(value) -> str:
    if not isinstance(value, dict):
        return str(value or "")
    parts = [
        str(value[key])
        for key in ("product", "category", "service", "definition")
        if value.get(key)
    ]
    return "/".join(parts)


def detection_from_sigma(document: Dict, source: str) -> Detection:
    """Build a Detection from one parsed Sigma document."""
    tags = document.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    techniques, tactics = [], []
    for tag in tags:
        technique = normalise_technique(str(tag))
        if technique:
            if technique not in techniques:
                techniques.append(technique)
            continue
        tactic = normalise_tactic(str(tag))
        if tactic and tactic not in tactics:
            tactics.append(tactic)

    level = str(document.get("level") or "unknown").strip().lower()
    description = str(document.get("description") or "").strip()
    return Detection(
        name=str(document.get("title") or os.path.basename(source)).strip(),
        kind="sigma",
        source=source,
        level=level if level in LEVELS else "unknown",
        logsource=_logsource_text(document.get("logsource")),
        description=" ".join(description.split()),
        techniques=sorted(techniques),
        tactics=tactics,
    )


def load_sigma_file(path: str) -> "tuple":
    """Parse one Sigma file. Returns (detections, problems)."""
    detections: List[Detection] = []
    problems: List[LoadProblem] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        return [], [LoadProblem(path, "could not read: %s" % exc)]
    try:
        documents = load_all(text)
    except MiniYamlError as exc:
        return [], [LoadProblem(path, "unsupported YAML: %s" % exc)]

    for document in documents:
        if not isinstance(document, dict):
            problems.append(LoadProblem(path, "a document was not a mapping"))
            continue
        if "title" not in document and "detection" not in document:
            # A Sigma correlation header or an unrelated YAML file.
            problems.append(LoadProblem(path, "no title or detection block, skipped"))
            continue
        detection = detection_from_sigma(document, path)
        if not detection.techniques:
            problems.append(
                LoadProblem(path, "'%s' has no attack.tXXXX tag" % detection.name)
            )
        detections.append(detection)
    return detections, problems


def load_sigma_dir(directory: str) -> "tuple":
    """Parse every Sigma file under a directory, or a single file path."""
    detections: List[Detection] = []
    problems: List[LoadProblem] = []
    if os.path.isfile(directory):
        return load_sigma_file(directory)
    if not os.path.isdir(directory):
        raise NotADirectoryError("not a file or directory: %s" % directory)
    for root, _dirs, files in os.walk(directory):
        for filename in sorted(files):
            if not filename.lower().endswith(SIGMA_EXTENSIONS):
                continue
            found, trouble = load_sigma_file(os.path.join(root, filename))
            detections.extend(found)
            problems.extend(trouble)
    detections.sort(key=lambda d: (d.source, d.name))
    return detections, problems


def load_inventory(path: str) -> "tuple":
    """Load non-Sigma detections from a JSON inventory file.

    The file is {"detections": [ ... ]}, or just a bare list. Each entry needs
    a name and a techniques list; everything else is optional.
    """
    detections: List[Detection] = []
    problems: List[LoadProblem] = []
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except ValueError as exc:
            raise ValueError("%s is not valid JSON: %s" % (path, exc))

    entries = data.get("detections") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError(
            '%s should be a list, or an object with a "detections" list' % path
        )

    default_repo = data.get("repo", "") if isinstance(data, dict) else ""
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problems.append(LoadProblem(path, "entry %d is not an object" % index))
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            problems.append(LoadProblem(path, "entry %d has no name" % index))
            continue
        raw = entry.get("techniques") or []
        if isinstance(raw, str):
            raw = [raw]
        techniques = []
        for value in raw:
            technique = normalise_technique(str(value))
            if technique:
                if technique not in techniques:
                    techniques.append(technique)
            else:
                problems.append(
                    LoadProblem(path, "'%s' lists %r, which is not a technique id"
                                % (name, value))
                )
        if not techniques:
            problems.append(LoadProblem(path, "'%s' has no usable technique id" % name))
        level = str(entry.get("level") or "unknown").strip().lower()
        detections.append(
            Detection(
                name=name,
                kind=str(entry.get("kind") or "tool"),
                source=path,
                repo=str(entry.get("repo") or default_repo),
                url=str(entry.get("url") or ""),
                level=level if level in LEVELS else "unknown",
                logsource=str(entry.get("logsource") or ""),
                description=" ".join(str(entry.get("description") or "").split()),
                techniques=sorted(techniques),
                tactics=[],
            )
        )
    return detections, problems
