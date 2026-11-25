#!/usr/bin/env python
"""Load an expense-report spreadsheet into the spend register.

WHY THIS EXISTS
    Invoices arrive as a spreadsheet long before anybody types them into a
    portal, and re-typing eleven lines by hand is how a figure ends up wrong.
    This reads the sheet and creates one register row per invoice line.

WHAT IT DELIBERATELY DOES NOT DO
    It does not invent a renewal. An invoice says what was charged and when;
    whether that thing renews, and at what price, is a separate fact that
    lives in the contract. Every imported line is a dated one-off, so the
    month totals are right and the forward forecast is not inflated by
    guesses. Add the live subscription separately if you want it forecast.

    It does not invent a number. A line the sheet could not price is imported
    at zero with a note saying so, rather than skipped quietly or estimated.

USAGE
    PORTAL_DATA_DIR=data/customer-demo .venv/bin/python \
        tools/import_expenses.py path/to/report.xlsx [--apply]

    Without --apply it prints what it would do and changes nothing.

Needs openpyxl, which the portal itself does not depend on:
    .venv/bin/pip install openpyxl
"""
from __future__ import annotations

import datetime as dt
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The sheet's own vocabulary on the left, the register's on the right. An
# unmapped category becomes "other" rather than failing the whole import.
CATEGORY = {
    "software/saas": "saas",
    "ai tools": "saas",
    "credit note": "saas",
    "web hosting": "hosting",
    "hosting": "hosting",
    "security/vpn": "security",
    "domain": "domain",
    "hardware": "other",
}
KIND = {"other": "perpetual"}          # hardware is owned, not subscribed

HEADERS = ("#", "date", "invoice number", "vendor", "category", "description",
           "currency", "amount (excl. tax)", "tax / vat",
           "total amount (incl. tax)", "payment status", "notes")


def _text(cell) -> str:
    if cell is None:
        return ""
    if hasattr(cell, "isoformat"):
        return cell.isoformat()[:10]
    return str(cell).strip()


def _date(raw: str) -> str:
    """The sheet writes dates day-first. Anything else is left empty.

    A date guessed the wrong way round puts an invoice in the wrong month,
    which is precisely the number this page exists to get right, so an
    unrecognised date is reported rather than coerced.
    """
    raw = raw.strip()
    if not raw or raw.upper() in ("N/A", "NA", "-"):
        return ""
    for fmt in ("%d/%m/%Y", "%Y-%m-%d", "%d-%m-%Y"):
        try:
            return dt.datetime.strptime(raw, fmt).date().isoformat()
        except ValueError:
            continue
    return ""


def _money(raw: str) -> tuple[float, bool]:
    """(amount, was it a number at all). Negative is kept: a credit is real."""
    raw = raw.replace(",", "").replace("$", "").strip()
    if not raw or raw.upper() in ("N/A", "NA", "-"):
        return 0.0, False
    try:
        return float(raw), True
    except ValueError:
        return 0.0, False


def _name(vendor: str, desc: str, seats: str, when: str) -> str:
    """A short label for the register list; the full text goes in the notes.

    Three Microsoft invoices in the sheet describe the same product, so the
    seat count or the charge date is carried into the name — a register with
    the same label on three rows is a register nobody can read.
    """
    head = re.split(r"\s*[(\[]|\s+[–—-]\s", desc, maxsplit=1)[0].strip(" -–—")
    head = head or desc or "expense"
    if vendor and not head.lower().startswith(vendor.lower()[:6]):
        head = f"{vendor} {head}"
    if seats and seats != "0":
        head += f" — {seats} licence{'s' if seats != '1' else ''}"
    elif when:
        head += f" — {when}"
    return head[:120]


def read(path: str) -> list[dict]:
    import openpyxl
    wb = openpyxl.load_workbook(path, data_only=True)
    ws = wb["Expense Detail"] if "Expense Detail" in wb.sheetnames else wb.active

    rows = [[_text(c) for c in r]
            for r in ws.iter_rows(values_only=True)]
    head = next((i for i, r in enumerate(rows)
                 if [c.lower() for c in r[:4]] == list(HEADERS[:4])), None)
    if head is None:
        raise SystemExit(f"{path}: no header row — expected {HEADERS[:4]}")
    col = {name: i for i, name in enumerate(c.lower() for c in rows[head])}

    def cell(r, name):
        i = col.get(name)
        return r[i] if i is not None and i < len(r) else ""

    out = []
    for r in rows[head + 1:]:
        num = cell(r, "#")
        if not num.isdigit():
            continue                      # the subtotal rows at the bottom
        desc = cell(r, "description")
        vendor = cell(r, "vendor")
        cat = CATEGORY.get(cell(r, "category").lower(), "other")
        cost, priced = _money(cell(r, "total amount (incl. tax)"))
        cur = cell(r, "currency").upper()[:3]
        when = _date(cell(r, "date"))
        inv = cell(r, "invoice number")
        seats = re.search(r"(\d+)\s+licen[cs]e", desc, re.I)
        nseats = seats.group(1) if seats else "0"
        note = " · ".join(x for x in (
            f"invoice {inv}" if inv and inv.upper() != "N/A" else "",
            desc,
            cell(r, "notes"),
            f"payment: {cell(r, 'payment status')}"
            if cell(r, "payment status") else "",
            "" if priced else "the sheet carried no amount for this line",
            "" if when else "the sheet carried no date, so this line "
                            "falls in no month",
        ) if x)
        out.append({
            "n": num, "invoice": inv, "priced": priced, "dated": bool(when),
            "row": {
                "name": _name(vendor, desc, nseats, when),
                "vendor": vendor if vendor.upper() != "N/A" else "",
                "category": cat,
                "kind": KIND.get(cat, "subscription"),
                "seats": nseats,
                "cost": f"{cost}",
                "currency": cur if cur and cur != "N/A" else "USD",
                # a dated one-off: it lands in its own month and adds nothing
                # to the forward run rate, which is what an invoice is
                "cycle": "one-off",
                "started": when, "renews": when,
                "auto_renew": "", "owner": "", "account": "", "project": "",
                "url": "", "notes": note, "status": "active",
            },
        })
    return out


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    apply = "--apply" in argv[1:]
    if not args:
        print(__doc__)
        return 2

    from app import spend
    items = read(args[0])

    have = {(r["name"], r["renews"] or "", round(r["cost"] or 0, 2))
            for r in spend.search(status="")}
    made = skipped = 0
    for it in items:
        row = it["row"]
        key = (row["name"], row["renews"], round(float(row["cost"]), 2))
        if key in have:
            print(f"  {it['n']:>2}  skip, already in the register  {row['name']}")
            skipped += 1
            continue
        flags = "".join((" [no amount]" if not it["priced"] else "",
                         " [no date]" if not it["dated"] else ""))
        print(f"  {it['n']:>2}  {row['renews'] or '          '}  "
              f"{row['currency']} {float(row['cost']):>10,.2f}  "
              f"{row['name']}{flags}")
        if apply:
            spend.create(row, actor="expense import")
            have.add(key)
        made += 1

    print(f"\n{made} line{'s' if made != 1 else ''} "
          f"{'imported' if apply else 'would be imported'}"
          f"{f', {skipped} already present' if skipped else ''}.")
    if not apply:
        print("Nothing was written. Re-run with --apply to write.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
