"""Every value in a values file, not only the config block.

The portal used to manage `config` / `configMap.data` and nothing else: image
tags, replica counts, resource limits, ingress hosts, probes and tolerations were
all visible but read-only, so half of a values file still had to be edited by
hand in git.

This walks the whole document and describes each leaf, so the same line-level
editing that config keys already had applies to anything in the file.

TWO DECISIONS WORTH KNOWING
    A path is a *list*, not a dotted string. Values files are full of keys like
    `app.name` and `spring.datasource.url`, and splitting a dotted path on dots
    would address the wrong node. Paths travel through forms as JSON.

    A scalar's type is preserved. `tag: 1.20` is a string in some charts and a
    float in others; rewriting it without care silently changes the type and the
    rendered manifest. The original node's type decides whether the replacement
    is quoted.
"""
from __future__ import annotations

import json

from ruamel.yaml.comments import CommentedMap, CommentedSeq

from . import yamledit

# Sections whose contents must never be offered as editable text. A sealed
# secret's value is ciphertext bound to one cluster's key: retyping it by hand
# produces something that will not decrypt, and the portal already has a proper
# sealing path for those.
PROTECTED_KEYS = ("SealedSecret", "sealedSecret", "sealed_secret")

MAX_ROWS = 4000          # a runaway file must not take the page down with it


def is_map(node) -> bool:
    return isinstance(node, (CommentedMap, dict))


def is_seq(node) -> bool:
    return isinstance(node, (CommentedSeq, list))


SEP = "\u241f"          # unit separator: not a character any YAML key holds


def chain(path: list) -> str:
    """A flat string identity for a path, for grouping rows in the page.

    Dots cannot be used — `app.name` is one key, not two — so the separator is a
    character that never appears in a key.
    """
    return SEP.join(str(s) for s in path)


def encode(path: list) -> str:
    return json.dumps(path, separators=(",", ":"))


def decode(raw: str) -> list:
    try:
        out = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("unreadable value path")
    if not isinstance(out, list) or not out:
        raise ValueError("unreadable value path")
    return out


def type_name(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    return "str"


def display(value) -> str:
    """A scalar as text for an input box, round-tripping through YAML's spelling
    of booleans and null rather than Python's."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def rows(data, protected_paths: tuple = ()) -> list[dict]:
    """Every node in the document, depth-first, in file order.

    Each row is enough for one line of UI: what to show, whether it can be
    edited, and the path to send back.
    """
    out: list[dict] = []

    def walk(node, path: list, depth: int) -> None:
        if len(out) >= MAX_ROWS:
            return
        if is_map(node):
            for key in node.keys():
                child = node[key]
                here = path + [key]
                protected = (str(key) in PROTECTED_KEYS
                             or _under(here, protected_paths))
                if is_map(child) or is_seq(child):
                    out.append({
                        "path": here, "id": encode(here), "key": str(key),
                        "chain": chain(here), "parent": chain(path),
                        "depth": depth, "kind": "map" if is_map(child) else "seq",
                        "type": "", "value": "",
                        "count": len(child), "editable": False,
                        "protected": protected})
                    if not protected:
                        walk(child, here, depth + 1)
                else:
                    out.append({
                        "path": here, "id": encode(here), "key": str(key),
                        "chain": chain(here), "parent": chain(path),
                        "depth": depth, "kind": "scalar",
                        "type": type_name(child), "value": display(child),
                        "count": 0, "editable": not protected,
                        "protected": protected})
        elif is_seq(node):
            for i, child in enumerate(node):
                here = path + [i]
                if is_map(child) or is_seq(child):
                    out.append({
                        "path": here, "id": encode(here), "key": f"[{i}]",
                        "chain": chain(here), "parent": chain(path),
                        "depth": depth,
                        "kind": "map" if is_map(child) else "seq",
                        "type": "", "value": "", "count": len(child),
                        "editable": False, "protected": False})
                    walk(child, here, depth + 1)
                else:
                    out.append({
                        "path": here, "id": encode(here), "key": f"[{i}]",
                        "chain": chain(here), "parent": chain(path),
                        "depth": depth, "kind": "scalar",
                        "type": type_name(child), "value": display(child),
                        "count": 0, "editable": True, "protected": False})

    walk(data, [], 0)
    return out


def _under(path: list, protected: tuple) -> bool:
    return any(list(p) == path[:len(p)] for p in protected)


def locate(data, path: list):
    """(parent node, last step) for a path, raising a plain-language error.

    The error matters: a path that no longer resolves usually means the file
    changed under the page, and saying so is more useful than a KeyError.
    """
    node = data
    for i, step in enumerate(path[:-1]):
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError):
            where = " → ".join(str(s) for s in path[:i + 1])
            raise ValueError(f"no longer in this file: {where}")
    last = path[-1]
    if is_map(node):
        if last not in node:
            raise ValueError(f"no longer in this file: {last}")
    elif is_seq(node):
        if not isinstance(last, int) or last >= len(node):
            raise ValueError(f"item {last} is no longer in this list")
    else:
        raise ValueError("that path does not point at a value")
    return node, last


def current(data, path: list):
    parent, last = locate(data, path)
    return parent[last]


def set_at(text: str, data, path: list, new: str) -> str:
    """Replace one scalar, touching only its line.

    A string stays a string: if the existing value parsed as text and the new
    text would parse as a number or a boolean, it is quoted. Changing
    `tag: "1.20"` into `tag: 1.20` renders a different manifest, and it should
    not happen because someone edited a box.
    """
    parent, last = locate(data, path)
    old = parent[last]
    if is_map(old) or is_seq(old):
        raise ValueError("that path is a section, not a value")
    keep_string = type_name(old) == "str" and _would_retype(new)
    value = new
    if is_seq(parent):
        return yamledit.set_item(text, parent, last, value, force_quote=keep_string)
    return yamledit.set_value(text, parent, last, value, force_quote=keep_string)


def _would_retype(new: str) -> bool:
    s = new.strip()
    if s.lower() in ("true", "false", "yes", "no", "on", "off", "null", "~", ""):
        return True
    try:
        float(s)
        return True
    except ValueError:
        return False


def delete_at(text: str, data, path: list) -> str:
    parent, last = locate(data, path)
    if is_seq(parent):
        if len(parent) == 1:
            # removing the only item leaves `paths:` with no value, which renders
            # as null and is not what anyone meant by "delete this item"
            raise ValueError("this is the only item in the list — delete the "
                             "list itself instead, or change its value")
        return yamledit.remove_item(text, parent, last)
    return yamledit.remove_key(text, parent, last)


def add_at(text: str, data, parent_path: list, key: str, value: str) -> str:
    """Add a key to a mapping, or an item to a list.

    An empty parent path means the top level of the file, which is where things
    like `replicaCount` live.
    """
    node = data
    for step in parent_path:
        try:
            node = node[step]
        except (KeyError, IndexError, TypeError):
            raise ValueError("that section is no longer in this file")
    if is_seq(node):
        return yamledit.append_item(text, node, value)
    if not is_map(node):
        raise ValueError("that path is a value, not a section")
    if key in node:
        raise ValueError(f"'{key}' already exists here")
    if not key.strip():
        raise ValueError("a key name is required")
    return yamledit.add_keys(text, node, {key: value}, top_level=not parent_path)


def split_path(raw: str) -> list:
    """`resources.limits.cpu` as ["resources", "limits", "cpu"].

    A dotted path replaced a dropdown that listed every mapping in the file and
    asked the reader to pick one. The dropdown was accurate and nobody could use
    it: it made adding `cpu` a question about the shape of a Helm chart, which is
    not what anybody opened the page to think about.

    A key with a dot in its own name is written `a\\.b` — real in Kubernetes
    annotations, so it has to be expressible even though it is rare.
    """
    out, cur, escape = [], "", False
    for ch in raw.strip():
        if escape:
            cur += ch
            escape = False
        elif ch == "\\":
            escape = True
        elif ch == ".":
            out.append(cur)
            cur = ""
        else:
            cur += ch
    out.append(cur)
    steps = [p.strip() for p in out]
    if not steps or any(not p for p in steps):
        raise ValueError("a key like replicaCount, or a path like "
                         "resources.limits.cpu")
    return steps


def add_dotted(text: str, data, raw_path: str, value: str) -> str:
    """Add a value at a dotted path, creating whatever levels are missing.

    Walks as far as the file already goes, then writes the rest in one edit. The
    error when it cannot is about the FILE, not about the path: running into a
    scalar means the person is about to bury an existing setting, and saying
    which one is the whole use of the message.
    """
    steps = split_path(raw_path)
    node, walked = data, []
    for i, step in enumerate(steps[:-1]):
        try:
            child = node[step]
        except (KeyError, IndexError, TypeError):
            child = None
        if child is None and (not is_map(node) or step not in node):
            # everything from here down has to be created
            if not is_map(node):
                raise ValueError(f"'{'.'.join(walked)}' is a value, not a "
                                 f"section — it cannot hold '{step}'")
            return yamledit.add_nested(text, node, steps[i:], value,
                                       top_level=not walked)
        if not is_map(child):
            where = ".".join(walked + [step])
            raise ValueError(f"'{where}' already holds a value — adding "
                             f"'{steps[-1]}' under it would replace it")
        node, _ = child, walked.append(step)

    if not is_map(node):
        raise ValueError(f"'{'.'.join(walked)}' is a value, not a section")
    if steps[-1] in node:
        raise ValueError(f"'{'.'.join(steps)}' already exists — edit it in the "
                         f"list instead")
    return yamledit.add_keys(text, node, {steps[-1]: value},
                             top_level=not walked)


def sections(data) -> list[dict]:
    """The top-level keys, for grouping the page: name, kind and size."""
    out = []
    if not is_map(data):
        return out
    for key in data.keys():
        child = data[key]
        kind = "map" if is_map(child) else ("seq" if is_seq(child) else "scalar")
        out.append({"key": str(key), "kind": kind,
                    "count": len(child) if kind != "scalar" else 0,
                    "protected": str(key) in PROTECTED_KEYS})
    return out
