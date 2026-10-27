# attack-coverage-map

Reads my Sigma rules and my detection tools, works out which MITRE ATT&CK
techniques they actually cover, and writes three things: a readable report, an
ATT&CK Navigator layer, and a self-contained HTML heatmap.

**Live heatmap: https://siddique-12300983.github.io/attack-coverage-map/**

Pure Python standard library. No PyYAML, no install step, no network access.

## Why I built this

I had detection rules in one repo, detection tools in several others, and lab
write-ups in a third. Each one was fine on its own, and together they answered
nothing. I could not say which part of ATT&CK I could actually see, where I was
relying on a single rule, or which of the techniques I had attacked in my own
lab I still had no detection for.

This reads all of it and answers those three questions. The report that matters
most is not the coverage, it is the gap list.

## What it does

- Loads Sigma rules straight from a rules directory, including multi-document
  files, and pulls the `attack.tXXXX` tags off each one.
- Loads non-Sigma detections from a small JSON inventory, so a Python tool or a
  lab write-up counts as a detection too.
- Groups everything by technique and tactic, in ATT&CK kill-chain order.
- Reports **depth**: how many independent detections back each technique, and
  which ones rest on exactly one. A single rule is a single point of failure.
- Reports **gaps**: techniques on my target list with nothing behind them yet.
- Writes an ATT&CK Navigator layer (v4.5) and a standalone HTML heatmap.

## Install

None. Python 3.9 or newer.

```sh
git clone https://github.com/Siddique-12300983/attack-coverage-map.git
cd attack-coverage-map
python3 -m coveragemap --sigma samples/sigma
```

## Usage

```sh
# Sigma rules only
python3 -m coveragemap --sigma samples/sigma

# my real setup: a Sigma repo, my tool inventory, and my target list
python3 -m coveragemap \
  --sigma ../sigma-detection-rules/rules \
  --inventory inventory/ruxchipher-detections.json \
  --targets inventory/lab-targets.txt

# write both visual outputs
python3 -m coveragemap \
  --sigma ../sigma-detection-rules/rules \
  --inventory inventory/ruxchipher-detections.json \
  --targets inventory/lab-targets.txt \
  --navigator docs/coverage-layer.json \
  --html docs/index.html

# fail a pipeline when a target technique has no detection
python3 -m coveragemap --sigma rules/ --targets targets.txt --fail-on-gaps
```

| Flag | What it does |
|---|---|
| `--sigma PATH` | A Sigma rules directory or one rule file. Repeatable. |
| `--inventory FILE` | JSON inventory of detections that are not Sigma rules. Repeatable. |
| `--targets FILE` | Technique ids you intend to cover, so the gaps get reported. |
| `--attack-data FILE` | Extra technique names and tactics, merged over the bundled table. |
| `--navigator FILE` | Also write an ATT&CK Navigator layer. |
| `--html FILE` | Also write a self-contained HTML heatmap. |
| `--name NAME` | Title for the layer and the heatmap. |
| `--json` | Print JSON instead of the report. |
| `--fail-on-gaps` | Exit `1` when a target technique has no detection. |
| `--quiet` | Write the output files and print nothing. |

Exit codes: `0` fine, `1` uncovered targets with `--fail-on-gaps`, `2` an error.

## Example output

Against my own Sigma repo, my tool inventory and my lab target list:

```
$ python3 -m coveragemap \
    --sigma ../sigma-detection-rules/rules \
    --inventory inventory/ruxchipher-detections.json \
    --targets inventory/lab-targets.txt

ATT&CK coverage report
--------------------------------------------------------------------------
detections   : 25  (4 Sigma rules, 21 other)
techniques   : 22 covered across 8 tactics
depth        : 16 technique(s) rest on a single detection, deepest has 4
targets      : 11 of 22 covered (50.0%), 11 gap(s)

Coverage by tactic
--------------------------------------------------------------------------
Credential Access  (4 techniques)
    T1558.003   ###  Steal or Forge Kerberos Tickets: Kerberoasting
                  - Kerberoasting confirmed in my AD lab [high] purple-team-journey
                  - Kerberoasting via RC4 Service Ticket Request [high] sigma
                  - Kerberoasting: RC4 service ticket request [high] log-analyzer
                  - Kerberoasting: SPN fan-out by one account [medium] log-analyzer
    T1110       ##.  Brute Force
                  - Brute force that ended in a successful login [high] log-analyzer
                  - Brute force: repeated failed logins from one source [high] log-analyzer
    T1557.001   ##.  Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and
                  - LLMNR and NBT-NS poisoning confirmed in my AD lab [medium] purple-team-journey
                  - LLMNR and NBT-NS Responder Traffic [medium] sigma

Target techniques with no detection yet
--------------------------------------------------------------------------
  T1003.001   OS Credential Dumping: LSASS Memory                  credential-access
  T1021.001   Remote Services: Remote Desktop Protocol             lateral-movement
  T1059.001   Command and Scripting Interpreter: PowerShell        execution
  T1069.002   Permission Groups Discovery: Domain Groups           discovery
  T1070.001   Indicator Removal: Clear Windows Event Logs          defense-evasion
  T1078.002   Valid Accounts: Domain Accounts                      defense-evasion, ...
  T1136.002   Create Account: Domain Account                       persistence
  T1543.003   Create or Modify System Process: Windows Service     persistence, ...
  T1550       Use Alternate Authentication Material                defense-evasion, ...
  T1552       Unsecured Credentials                                credential-access
  T1558.004   Steal or Forge Kerberos Tickets: AS-REP Roasting     credential-access
```

Kerberoasting is the one technique I can see four different ways. Everything in
that gap list is the honest answer to "what can you not detect yet", and it is
the roadmap for the next rules I write.

## The three outputs

### 1. The report

Shown above. Grouped by tactic, with the detections behind every technique
named, so it is clear what the coverage actually rests on.

### 2. ATT&CK Navigator layer

`--navigator FILE` writes a v4.5 layer. Open
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/), choose
**Open Existing Layer**, then **Upload from Local**. Cell score is the
detection depth, the comment on each cell names the detections, and target
techniques with no detection are coloured red.

### 3. HTML heatmap

`--html FILE` writes one self-contained file: no JavaScript, no external
requests, no CDN. Tactics run across as columns in kill-chain order, techniques
stack underneath shaded by depth, and gaps are drawn as dashed red cells. The
copy in [`docs/`](docs/) is published at
[siddique-12300983.github.io/attack-coverage-map](https://siddique-12300983.github.io/attack-coverage-map/).

## The inventory format

Sigma rules carry their own ATT&CK tags. A Python tool does not, so non-Sigma
detections go in a JSON file:

```json
{
  "detections": [
    {
      "name": "Kerberoasting: RC4 service ticket request",
      "kind": "tool",
      "repo": "log-analyzer",
      "url": "https://github.com/Siddique-12300983/log-analyzer",
      "level": "high",
      "logsource": "windows/security 4769",
      "techniques": ["T1558.003"],
      "description": "The classic 0x17 encryption indicator on a TGS-REQ."
    }
  ]
}
```

Only `name` and `techniques` are required. `kind` separates a `tool` from a
`sigma` rule or a `lab` observation, and `repo` is what the depth count groups
on, so two rules in the same repo do not look like two independent detections.

[`inventory/ruxchipher-detections.json`](inventory/ruxchipher-detections.json)
is my real one, covering
[log-analyzer](https://github.com/Siddique-12300983/log-analyzer),
[persistwatch](https://github.com/Siddique-12300983/persistwatch),
[phishing-email-analyzer](https://github.com/Siddique-12300983/phishing-email-analyzer),
[file-integrity-monitor](https://github.com/Siddique-12300983/file-integrity-monitor)
and the detections I confirmed by hand in my
[AD lab](https://github.com/Siddique-12300983/purple-team-journey).

Prevention and enrichment tools are deliberately **not** in it.
[linux-hardening-script](https://github.com/Siddique-12300983/linux-hardening-script)
stops things and
[ioc-extractor](https://github.com/Siddique-12300983/ioc-extractor) enriches
things. Neither detects anything, and counting them would inflate the map.

## About the YAML reader

Sigma rules are YAML and the standard library has no YAML parser, so
[`coveragemap/miniyaml.py`](coveragemap/miniyaml.py) reads the subset Sigma
files use: scalars, nested mappings, block lists, folded and literal block
scalars, comments, and multiple documents per file.

It does **not** do anchors, aliases or flow collections (`[a, b]`). When a rule
uses one it raises, and the loader reports that file as a load warning instead
of silently returning the wrong tags. Getting this wrong quietly is worse than
not reading the file at all, which is why the reader has 24 tests of its own.

## MITRE ATT&CK mapping

This tool does not detect an attack, so it does not map to a technique the way
the others do. What it maps is **everything else**: it reads the mappings my
other repos claim and tells me what they add up to.

The bundled table in
[`coveragemap/data/techniques.json`](coveragemap/data/techniques.json) holds
104 enterprise techniques with their names and tactics, which covers my work
and the common ones around it. It is not all of ATT&CK. A technique outside the
table still gets counted and is flagged with `?` in the report, and
`--attack-data` merges in more:

```json
{ "T1203": { "name": "Exploitation for Client Execution", "tactics": ["execution"] } }
```

Techniques currently mapped through my detections: T1027, T1036, T1036.005,
T1053.005, T1053.006, T1059.004, T1070, T1078, T1105, T1110, T1110.001,
T1204.002, T1222, T1543.002, T1557.001, T1558.003, T1562.001, T1564.001,
T1566, T1566.001, T1566.002, T1574.006.

## Tests

Standard library `unittest`, no test dependencies:

```sh
python3 -m unittest discover -s tests -t .
```

132 tests. The ones worth knowing about:

- The YAML reader is tested against folded scalars, literal scalars, nested
  lists, comments after quoted values and multi-document files. Writing these
  found two real bugs: block scalar indentation and a comment-only chunk being
  counted as a document.
- The bundled ATT&CK table is checked for shape on every run: every id well
  formed, every entry named, every tactic a real Navigator shortname, and
  every sub-technique's parent present. That last one caught four missing
  parent entries.
- The shipped inventory is checked to load with zero warnings and to only claim
  techniques that are in the table, so the repo cannot drift out of sync with
  its own data.
- The generated HTML is parsed back and checked to be balanced, to contain a
  cell for every technique and every gap, and to contain no `<script>` or
  `src=` at all. A detection named `<script>` is checked to come out escaped.

## What "coverage" does not mean

Worth being blunt about, because coverage maps are easy to misread.

- A technique is "covered" here when a detection exists and claims it. That is
  all. It does not mean the detection was tested against a live attack, that it
  catches every variant, or that the telemetry it needs is actually being
  collected.
- Three detections for one technique can all share one blind spot. Depth is a
  better signal than a tick, not a guarantee.
- The gap list is only as good as the target list. A technique missing from
  both does not show up anywhere, which is the real limitation of any map like
  this.

## Related repos

- [sigma-detection-rules](https://github.com/Siddique-12300983/sigma-detection-rules) - the Sigma rules this reads
- [log-analyzer](https://github.com/Siddique-12300983/log-analyzer) - brute force and Kerberoasting in auth logs
- [persistwatch](https://github.com/Siddique-12300983/persistwatch) - systemd persistence hunting
- [purple-team-journey](https://github.com/Siddique-12300983/purple-team-journey) - the AD lab all of it came from

## License

MIT. See [LICENSE](LICENSE).

---

Built by **ruxchipher** (Md Abu Bakar Siddique), second-year cyber security
student working toward a purple team role.
[ruxchipher.com](https://ruxchipher.com) ·
[GitHub](https://github.com/Siddique-12300983) ·
[LinkedIn](https://linkedin.com/in/siddiqueabu)
