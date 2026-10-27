"""Command line entry point."""

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .attack import AttackData
from .coverage import build, load_targets
from .heatmap import write_html
from .navigator import write_layer
from .report import json_text, text_report
from .sources import LoadProblem, load_inventory, load_sigma_dir

EXIT_OK = 0
EXIT_GAPS = 1
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="attack-coverage-map",
        description=(
            "Read Sigma rules and a detection inventory, then report which "
            "MITRE ATT&CK techniques they actually cover."
        ),
        epilog=(
            "Exit codes: 0 fine, 1 target techniques have no detection "
            "(with --fail-on-gaps), 2 an error."
        ),
    )
    parser.add_argument(
        "--sigma",
        action="append",
        default=[],
        metavar="PATH",
        help="directory of Sigma rules, or one rule file, repeatable",
    )
    parser.add_argument(
        "--inventory",
        action="append",
        default=[],
        metavar="FILE",
        help="JSON inventory of detections that are not Sigma rules, repeatable",
    )
    parser.add_argument(
        "--targets",
        metavar="FILE",
        help="technique ids you intend to cover, to report the gaps",
    )
    parser.add_argument(
        "--attack-data",
        metavar="FILE",
        help="extra technique names and tactics, merged over the bundled table",
    )
    parser.add_argument("--json", action="store_true", help="print JSON instead of a report")
    parser.add_argument(
        "--navigator",
        metavar="FILE",
        help="also write an ATT&CK Navigator layer to this path",
    )
    parser.add_argument(
        "--html", metavar="FILE", help="also write a self-contained HTML heatmap"
    )
    parser.add_argument(
        "--name",
        default="ruxchipher detection coverage",
        help="layer and heatmap title",
    )
    parser.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="exit 1 when a target technique has no detection",
    )
    parser.add_argument("--quiet", action="store_true", help="write files but print nothing")
    parser.add_argument("--version", action="version", version="attack-coverage-map %s" % __version__)
    return parser


def main(argv: Optional[Sequence[str]] = None, stdout=None, stderr=None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    if not args.sigma and not args.inventory:
        parser.print_usage(err)
        err.write(
            "attack-coverage-map: give at least one --sigma path or --inventory file\n"
        )
        return EXIT_ERROR

    detections = []
    problems: List[LoadProblem] = []
    try:
        for path in args.sigma:
            found, trouble = load_sigma_dir(path)
            detections.extend(found)
            problems.extend(trouble)
        for path in args.inventory:
            found, trouble = load_inventory(path)
            detections.extend(found)
            problems.extend(trouble)
        attack = AttackData.load(args.attack_data)
        targets = load_targets(args.targets) if args.targets else []
    except (OSError, ValueError) as exc:
        err.write("attack-coverage-map: %s\n" % exc)
        return EXIT_ERROR

    if not detections:
        err.write("attack-coverage-map: no detections loaded from the given paths\n")
        return EXIT_ERROR

    coverage = build(detections, attack=attack, targets=targets)

    try:
        if args.navigator:
            write_layer(coverage, args.navigator, name=args.name)
        if args.html:
            write_html(coverage, args.html, title=args.name)
    except OSError as exc:
        err.write("attack-coverage-map: could not write output: %s\n" % exc)
        return EXIT_ERROR

    if not args.quiet:
        if args.json:
            out.write(json_text(coverage, problems) + "\n")
        else:
            out.write(text_report(coverage, problems) + "\n")
            if args.navigator:
                out.write("Navigator layer written to %s\n" % args.navigator)
            if args.html:
                out.write("HTML heatmap written to %s\n" % args.html)

    if args.fail_on_gaps and coverage.gaps():
        return EXIT_GAPS
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
