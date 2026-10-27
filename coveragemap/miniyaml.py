"""A small YAML reader, big enough for Sigma rule metadata and nothing more.

Sigma rules are YAML, and the standard library has no YAML parser. Rather than
pull in PyYAML for a tool that otherwise needs nothing, this reads the subset
that Sigma rule files actually use:

* `key: value` scalars, with optional single or double quotes
* `key:` followed by an indented `- item` list
* nested mappings, to any depth
* block scalars, `key: >` (folded) and `key: |` (literal)
* `#` comments on their own line or after a value
* several documents in one file, separated by `---`

What it does not do: anchors, aliases, flow collections (`[a, b]`), multi-line
quoted strings, or tags. If a rule uses those, the loader raises
`MiniYamlError` rather than quietly returning the wrong thing.
"""

from typing import Any, Dict, List, Optional, Tuple


class MiniYamlError(ValueError):
    """Raised when a document uses YAML this reader does not handle."""


def _strip_comment(line: str) -> str:
    """Drop a trailing `#` comment, ignoring one inside quotes."""
    quote: Optional[str] = None
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1] in " \t"):
            return line[:index]
    return line


def _scalar(text: str) -> Any:
    """Convert a scalar to a Python value, keeping anything unclear as a string."""
    value = text.strip()
    if not value:
        return ""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        return value[1:-1]
    if value.startswith("[") or value.startswith("{"):
        raise MiniYamlError("flow collections are not supported: %s" % value)
    lowered = value.lower()
    if lowered in ("true", "yes"):
        return True
    if lowered in ("false", "no"):
        return False
    if lowered in ("null", "~"):
        return None
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


class _Reader:
    def __init__(self, lines: List[str]):
        self.lines = lines
        self.pos = 0

    def peek(self) -> Optional[Tuple[int, str]]:
        while self.pos < len(self.lines):
            raw = self.lines[self.pos]
            if "\t" in raw[: _indent_of(raw) + 1]:
                raise MiniYamlError("line %d: tab used for indentation" % (self.pos + 1))
            body = _strip_comment(raw).rstrip()
            if not body.strip():
                self.pos += 1
                continue
            return _indent_of(body), body.strip()
        return None

    def take(self) -> Tuple[int, str]:
        item = self.peek()
        if item is None:
            raise MiniYamlError("unexpected end of document")
        self.pos += 1
        return item

    def block_scalar(self, indent: int, style: str) -> str:
        """Read an indented block after `key: >` or `key: |`.

        YAML takes the block's own indentation from its first non-empty line,
        not from the parent key, so measure it rather than assuming one space.
        """
        raw_lines: List[str] = []
        while self.pos < len(self.lines):
            raw = self.lines[self.pos].rstrip("\n").rstrip("\r")
            if raw.strip() and _indent_of(raw) <= indent:
                break
            self.pos += 1
            raw_lines.append(raw)
        block_indent = None
        for raw in raw_lines:
            if raw.strip():
                block_indent = _indent_of(raw)
                break
        if block_indent is None:
            return ""
        collected = [raw[block_indent:] if len(raw) > block_indent else "" for raw in raw_lines]
        while collected and not collected[-1].strip():
            collected.pop()
        if style == "|":
            return "\n".join(collected)
        # Folded: blank lines become paragraph breaks, everything else joins.
        paragraphs: List[List[str]] = [[]]
        for line in collected:
            if line.strip():
                paragraphs[-1].append(line.strip())
            else:
                paragraphs.append([])
        return "\n".join(" ".join(p) for p in paragraphs if p)

    def parse_block(self, indent: int) -> Any:
        item = self.peek()
        if item is None or item[0] < indent:
            return {}
        if item[1].startswith("- "):
            return self.parse_list(item[0])
        return self.parse_map(item[0])

    def parse_list(self, indent: int) -> List[Any]:
        items: List[Any] = []
        while True:
            item = self.peek()
            if item is None or item[0] != indent:
                break
            level, body = item
            if not (body.startswith("- ") or body == "-"):
                break
            self.take()
            rest = body[2:].strip() if body.startswith("- ") else ""
            if not rest:
                items.append(self.parse_block(indent + 1))
                continue
            if ":" in rest and not rest.split(":", 1)[0].strip().startswith(("'", '"')):
                key, _, value = rest.partition(":")
                entry: Dict[str, Any] = {key.strip(): _scalar(value)}
                nested = self.peek()
                if nested is not None and nested[0] > indent + 1:
                    entry.update(self.parse_map(nested[0]))
                items.append(entry)
                continue
            items.append(_scalar(rest))
        return items

    def parse_map(self, indent: int) -> Dict[str, Any]:
        mapping: Dict[str, Any] = {}
        while True:
            item = self.peek()
            if item is None or item[0] != indent:
                break
            level, body = item
            if body.startswith("- "):
                break
            if ":" not in body:
                raise MiniYamlError("line %d: expected 'key: value', got %r" % (self.pos + 1, body))
            self.take()
            key, _, value = body.partition(":")
            key = key.strip().strip("'\"")
            value = value.strip()
            if value in (">", "|", ">-", "|-", ">+", "|+"):
                mapping[key] = self.block_scalar(indent, value[0])
                continue
            if value:
                mapping[key] = _scalar(value)
                continue
            nested = self.peek()
            if nested is None or nested[0] <= indent:
                mapping[key] = None
                continue
            mapping[key] = self.parse_block(nested[0])
        return mapping


def load_all(text: str) -> List[Dict[str, Any]]:
    """Parse every document in a YAML string."""
    documents: List[Dict[str, Any]] = []
    current: List[str] = []

    def flush(lines: List[str]) -> None:
        # A chunk holding only blank lines and comments is not a document.
        parsed = _load_one(lines)
        if parsed:
            documents.append(parsed)

    for line in text.splitlines():
        if line.strip() in ("---", "..."):
            flush(current)
            current = []
            continue
        current.append(line)
    flush(current)
    return documents


def _load_one(lines: List[str]) -> Dict[str, Any]:
    reader = _Reader(lines)
    item = reader.peek()
    if item is None:
        return {}
    parsed = reader.parse_block(item[0])
    if not isinstance(parsed, dict):
        raise MiniYamlError("a Sigma document must be a mapping at the top level")
    return parsed


def load(text: str) -> Dict[str, Any]:
    """Parse the first document in a YAML string."""
    documents = load_all(text)
    return documents[0] if documents else {}
