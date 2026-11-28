"""Search and filters on the long lists: the Hypervisors page's guests and the
Server hardware page's servers.

The page filters as you type (static/listfilter.js). The server applies the
same filter to the first paint, so a shared link, a reload and the page's own
"still collecting" reloads show the right rows and counts before any script
runs, and the page still works where scripts do not. Two implementations of
one rule drift unless something holds them together:
tests/test_list_filters.py runs the script's core against the rows the server
rendered and compares every row and every count. So the rule is kept small:

- the search is words, and every word must appear somewhere in the row's
  haystack (lowercase, substring, any order);
- a facet is one value per row, compared exactly;
- an option's count is how many rows would show if it were picked with every
  OTHER filter as it is, so the number beside an option is what picking it
  gives, never a surprise empty page.
"""
from __future__ import annotations

MAX_WORDS = 8
NONE = "-"          # the facet value of "not reported", which "" cannot be:
                    # "" is "any" in the URL and in the controls


def words(q: str) -> list[str]:
    return [w for w in str(q or "").lower().split() if w][:MAX_WORDS]


def hay(*parts) -> str:
    """The text a row is searched in: every part on one line, lowercase."""
    return " ".join(" ".join(str(p).split()) for p in parts
                    if p not in (None, "")).lower()


def keep(row: dict, ws: list[str], want: dict, skip: str = "") -> bool:
    h = row["hay"]
    if any(w not in h for w in ws):
        return False
    f = row["f"]
    return all(f.get(k, "") == v for k, v in want.items() if v and k != skip)


def chosen(params, facets: dict) -> dict:
    """The facet values asked for, kept only where the page offers them. A
    link to a hypervisor since removed, or to a model no server has any more,
    shows everything rather than an empty page nobody can explain. A
    button-row facet (`fixed`) keeps a value with no rows: "the servers
    reporting a fault" being none is the answer, not a stale link."""
    out = {}
    for key, fc in facets.items():
        v = str(params.get(key) or "")
        if v and (fc.get("fixed") or any(o["v"] == v for o in fc["options"])):
            out[key] = v
    return out


def apply(rows: list[dict], q: str, want: dict, keys) -> dict:
    """Marks each row's `show` and counts every option of every facet in
    `keys`; counts[key][""] is that facet's "any" option."""
    ws = words(q)
    counts: dict = {k: {} for k in keys}
    shown = 0
    for r in rows:
        r["show"] = keep(r, ws, want)
        shown += r["show"]
        for k in keys:
            if keep(r, ws, want, skip=k):
                c = counts[k]
                c[""] = c.get("", 0) + 1
                v = r["f"].get(k, "")
                c[v] = c.get(v, 0) + 1
    return {"shown": shown, "total": len(rows), "counts": counts,
            "active": bool(ws or any(want.values()))}


def options(rows: list[dict], key: str, label=None) -> list[dict]:
    """A facet's options from the values its rows carry, A to Z, with "not
    reported" last."""
    vals = {r["f"].get(key, "") for r in rows} - {""}
    name = label or (lambda v: v)
    return sorted(({"v": v, "label": name(v)} for v in vals),
                  key=lambda o: (o["v"] == NONE, o["label"].lower()))


def bar(rows: list[dict], q: str, params, facets: dict, **more) -> dict:
    """Everything the filter bar and the list need for the first paint.
    Its keys are read as `fb.<key>` in templates, where a dict method of the
    same name wins: never `clear`, `items`, `keys`, `values` or `get`.

    `facets` maps a key to {"label", "any", "options", "fixed"?}; a facet that
    is not fixed and has fewer than two options is left out — a control with
    one choice is noise, and its filter would select every row anyway."""
    offered = {k: fc for k, fc in facets.items()
               if fc.get("fixed") or len(fc["options"]) > 1}
    want = chosen(params, offered)
    got = apply(rows, q, want, offered.keys())
    for k, fc in offered.items():
        fc["key"], fc["value"] = k, want.get(k, "")
        fc["counts"] = got["counts"][k]
    return {"q": q, "facets": offered, "want": want, **got, **more}
