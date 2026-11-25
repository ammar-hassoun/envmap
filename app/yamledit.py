"""Surgical, line-level YAML editing.

Re-serialising a whole file with ruamel normalises formatting the author never
touched (list indent styles, quoting), which produces noisy, unreviewable
GitOps diffs. Instead we parse only to locate keys — ruamel records the exact
line/column of every key — and then patch the raw text lines in place, so a
one-key change is a one-line diff.
"""
import re

from ruamel.yaml import YAML

_probe = YAML()
_probe.preserve_quotes = True


class EditError(Exception):
    pass


def _lines(text: str) -> list[str]:
    return text.split("\n")


def _key_line(section, key) -> tuple[int, int]:
    """(line, col) of a key inside a CommentedMap, both 0-based."""
    try:
        line, col = section.lc.key(key)
        return line, col
    except Exception as exc:                      # not round-trip loaded
        raise EditError(f"cannot locate '{key}' in the file") from exc


def _render_value(old_raw: str, new: str, force_quote: bool = False) -> str:
    """Format the replacement, preserving the original quoting style.

    force_quote is for a value that parsed as a string and whose new text would
    otherwise parse as a number, a boolean or null — `tag: "1.20"` becoming
    `tag: 1.20` renders a different manifest.
    """
    s = old_raw.strip()
    quote = s[0] if s[:1] in ("'", '"') else ""
    if quote:
        body = new.replace("\\", "\\\\").replace(quote, "\\" + quote) \
            if quote == '"' else new.replace("'", "''")
        return f"{quote}{body}{quote}"
    # unquoted: quote only when the bare form would change the parsed type
    if force_quote or new == "" or re.search(r'[:#]\s|^[\s>|&*!%@`]|["\']|^\s|\s$', new):
        return '"' + new.replace('\\', '\\\\').replace('"', '\\"') + '"'
    return new


def set_value(text: str, section, key, new_value: str,
              force_quote: bool = False) -> str:
    """Replace one scalar value, touching only its line."""
    line_no, _ = _key_line(section, key)
    lines = _lines(text)
    if line_no >= len(lines):
        raise EditError(f"'{key}' is outside the file")
    m = re.match(r"^(\s*)(\S[^:]*?)(\s*:\s*)(.*)$", lines[line_no])
    if not m:
        raise EditError(f"unexpected layout on line {line_no + 1} for '{key}'")
    indent, name, sep, rest = m.groups()

    body, comment = rest, ""
    hash_at = _comment_start(rest)
    if hash_at is not None:
        body = rest[:hash_at].rstrip()
        comment = _realign(body, rest[:hash_at], rest[hash_at:], new_value)

    if body.strip() in ("|", ">", "|-", ">-", "|+", ">+"):
        raise EditError(f"'{key}' uses a block scalar — edit it in git directly")

    lines[line_no] = (f"{indent}{name}{sep}"
                      f"{_render_value(body, new_value, force_quote)}{comment}")
    return "\n".join(lines)


def _item_line(seq, idx, lines: list[str] | None = None) -> tuple[int, int]:
    """(line, dash column) of one sequence item, both 0-based.

    ruamel reports the column of the item's *value*, not of its dash. Indenting a
    new item to the value column puts it deeper than the dash, and YAML then
    folds it into the previous scalar — "- /" plus "  - /legacy" parsed as the
    single string "/ - /legacy". So the dash is found in the line itself, and the
    reported column is only a fallback for an inline list.
    """
    try:
        line, col = seq.lc.item(idx)
    except Exception as exc:                      # not round-trip loaded
        raise EditError(f"cannot locate item {idx} in the file") from exc
    if lines is not None and line < len(lines):
        dash = lines[line].find("- ")
        if dash >= 0 and lines[line][:dash].strip() == "":
            return line, dash
    return line, col


def set_item(text: str, seq, idx, new_value: str,
             force_quote: bool = False) -> str:
    """Replace one scalar item of a list, touching only its line."""
    lines = _lines(text)
    line_no, _ = _item_line(seq, idx, lines)
    if line_no >= len(lines):
        raise EditError(f"item {idx} is outside the file")
    m = re.match(r"^(\s*)(-\s+)(.*)$", lines[line_no])
    if not m:
        # a flow sequence — [a, b, c] — has no line of its own per item, and
        # rewriting one item means reformatting the line for everybody
        raise EditError("this list is written inline — edit it in git directly")
    indent, dash, rest = m.groups()
    body, comment = rest, ""
    hash_at = _comment_start(rest)
    if hash_at is not None:
        body = rest[:hash_at].rstrip()
        comment = _realign(body, rest[:hash_at], rest[hash_at:], new_value)
    lines[line_no] = (f"{indent}{dash}"
                      f"{_render_value(body, new_value, force_quote)}{comment}")
    return "\n".join(lines)


def remove_item(text: str, seq, idx) -> str:
    """Delete one list item and any lines it spans."""
    lines = _lines(text)
    line_no, col = _item_line(seq, idx, lines)
    if line_no >= len(lines):
        raise EditError(f"item {idx} is outside the file")
    end = line_no + 1
    while end < len(lines):
        ln = lines[end]
        if ln.strip() == "":
            nxt = next((x for x in lines[end + 1:] if x.strip() != ""), None)
            if nxt is None or (len(nxt) - len(nxt.lstrip())) <= col:
                break
            end += 1
            continue
        indent = len(ln) - len(ln.lstrip())
        if indent < col or (indent == col and ln.lstrip().startswith("- ")):
            break
        end += 1
    return "\n".join(lines[:line_no] + lines[end:])


def append_item(text: str, seq, value: str) -> str:
    """Add a scalar to the end of a block sequence, matching its indent."""
    if len(seq) == 0:
        raise EditError("cannot add to an empty list — add the first item in git")
    lines = _lines(text)
    last, col = _item_line(seq, len(seq) - 1, lines)
    end = last + 1
    while end < len(lines):
        ln = lines[end]
        if ln.strip() == "":
            break
        indent = len(ln) - len(ln.lstrip())
        if indent < col or (indent == col and ln.lstrip().startswith("- ")):
            break
        end += 1
    item = f"{' ' * col}- {_render_value('', value)}"
    return "\n".join(lines[:end] + [item] + lines[end:])


def _realign(body: str, before: str, comment: str, new_value: str) -> str:
    """Keep a trailing comment in the column its author chose.

    `tag: "1.20"          # pinned deliberately` losing its alignment is a
    pointless second change in the diff. The padding is preserved when the new
    value is no longer than the old one; when it is longer, the comment moves
    right by one space rather than colliding.
    """
    pad = len(before) - len(body)
    shift = len(new_value) - len(body)
    keep = pad - shift
    return (" " * keep if keep > 0 else " ") + comment


def _comment_start(s: str) -> int | None:


    """Index of a real trailing comment, ignoring # inside quotes."""
    q = None
    for i, ch in enumerate(s):
        if q:
            if ch == q:
                q = None
        elif ch in "'\"":
            q = ch
        elif ch == "#" and (i == 0 or s[i - 1] in " \t"):
            return i
    return None


def _section_bounds(text: str, section) -> tuple[int, int, str]:
    """(first_line, last_line_exclusive, indent) of a mapping's entries."""
    keys = list(section.keys())
    if not keys:
        raise EditError("cannot add a key to an empty section — add one in git first")
    lines = _lines(text)
    starts = []
    for k in keys:
        try:
            starts.append(_key_line(section, k))
        except EditError:
            pass
    if not starts:
        raise EditError("cannot locate the section in the file")
    first = min(l for l, _ in starts)
    col = starts[0][1]
    last_key_line = max(l for l, _ in starts)

    end = last_key_line + 1
    while end < len(lines):
        ln = lines[end]
        if ln.strip() == "":
            # trailing blank could belong to the next block; stop unless more follows
            nxt = next((x for x in lines[end + 1:] if x.strip() != ""), None)
            if nxt is None or (len(nxt) - len(nxt.lstrip())) <= col:
                break
            end += 1
            continue
        if (len(ln) - len(ln.lstrip())) <= col:
            break
        end += 1
    return first, end, " " * col


def add_keys(text: str, section, additions: dict,
             top_level: bool = False) -> str:
    """Append new key/value pairs at the end of a mapping, matching its indent."""
    if not additions:
        return text
    _, end, indent = _section_bounds(text, section)
    if top_level:
        # the document's own mapping ends where the text does; a new key belongs
        # after the last non-blank line rather than after the first block
        lines_now = _lines(text)
        end = max((i + 1 for i, ln in enumerate(lines_now) if ln.strip()),
                  default=len(lines_now))
        indent = ""
    lines = _lines(text)
    new = [f"{indent}{k}: {_render_value('', str(v))}" for k, v in additions.items()]
    return "\n".join(lines[:end] + new + lines[end:])


def _indent_step(text: str, section, indent: str) -> str:
    """How far this file indents one level, read from the file itself.

    Two spaces is the convention, but a chart written with four would end up
    with a block that parses as something else entirely, so it is measured
    rather than assumed: the first child deeper than the section's own keys
    says what a level is worth here.
    """
    base = len(indent)
    for line in _lines(text):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        depth = len(line) - len(line.lstrip())
        if depth > base:
            return " " * (depth - base)
    return "  "


def add_nested(text: str, section, keys: list, value: str,
               top_level: bool = False) -> str:
    """Add `keys` as a chain of new mappings under `section`, ending in `value`.

    add_keys() writes one line, so it can only add a key whose parent already
    exists. This is what makes a dotted path work end to end: asked for
    `resources.limits.cpu` on a file that has neither `resources` nor `limits`,
    it writes both, indented the way the rest of the file is.

    One edit rather than a key at a time, because the intermediate states are
    not valid documents — `resources:` with nothing under it parses as null, and
    the next step would refuse to add a key to a value.
    """
    if not keys:
        raise EditError("nothing to add")
    _, end, indent = _section_bounds(text, section)
    if top_level:
        lines_now = _lines(text)
        end = max((i + 1 for i, ln in enumerate(lines_now) if ln.strip()),
                  default=len(lines_now))
        indent = ""
    step = _indent_step(text, section, indent)
    block = []
    for depth, key in enumerate(keys[:-1]):
        block.append(f"{indent}{step * depth}{key}:")
    block.append(f"{indent}{step * (len(keys) - 1)}{keys[-1]}: "
                 + _render_value("", str(value)))
    lines = _lines(text)
    return "\n".join(lines[:end] + block + lines[end:])


def remove_key(text: str, section, key) -> str:
    """Delete one key and any lines its value spans, touching nothing else."""
    line_no, col = _key_line(section, key)
    lines = _lines(text)
    if line_no >= len(lines):
        raise EditError(f"'{key}' is outside the file")

    end = line_no + 1
    while end < len(lines):
        ln = lines[end]
        if ln.strip() == "":                       # blank line: peek ahead
            nxt = next((x for x in lines[end + 1:] if x.strip() != ""), None)
            if nxt is None or (len(nxt) - len(nxt.lstrip())) <= col:
                break
            end += 1
            continue
        if (len(ln) - len(ln.lstrip())) <= col:    # back to sibling depth
            break
        end += 1                                   # continuation of this value
    return "\n".join(lines[:line_no] + lines[end:])


def parse(text: str):
    return _probe.load(text)
