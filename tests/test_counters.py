"""No test may shadow its own failure counter.

WHY THIS EXISTS
    Every test here counts failures in a module global (`bad = 0`) that
    `check()` bumps with `global bad`, and prints its verdict from it. A
    function that ASSIGNS that name -- `for bad in (...)` is the natural
    spelling -- makes it a local for the whole function, and the verdict then
    reads the loop's last value instead of the count.

    That happened in test_pam.py's main(), and the last value was the empty
    string, so the file printed OK and exited 0 however many checks failed.
    CLAUDE.md had warned about exactly this in prose; a warning is not a
    guard, so this is. It walks every test file's syntax tree and refuses any
    function that assigns a module-level counter without declaring it global.
"""
import ast
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
bad = 0


def check(what: str, ok: bool) -> None:
    global bad
    if not ok:
        bad += 1
        print(f"  FAIL {what}")


def counters(tree: ast.Module) -> set:
    """Module-level names bound to 0 -- the shape of a failure counter."""
    return {t.id for n in tree.body if isinstance(n, ast.Assign)
            for t in n.targets if isinstance(t, ast.Name)
            and isinstance(n.value, ast.Constant) and n.value.value == 0}


def shadowing(src: str, name: str) -> list:
    tree = ast.parse(src)
    names, out = counters(tree), []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        declared = {n for g in ast.walk(fn) if isinstance(g, ast.Global)
                    for n in g.names}
        for node in ast.walk(fn):
            if (isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
                    and node.id in names and node.id not in declared):
                out.append(f"{name}:{node.lineno} {fn.name}() assigns "
                           f"`{node.id}`")
    return out


def main() -> int:
    print("no test shadows the counter its verdict is read from")
    found = [hit for f in sorted(HERE.glob("test_*.py"))
             for hit in shadowing(f.read_text(), f.name)]
    check("every test file keeps its failure counter global"
          + (": " + "; ".join(found) if found else ""), not found)
    # The guard must catch the exact shape that hid test_pam's failures.
    sample = ("bad = 0\ndef main():\n    for bad in ('x', ''):\n"
              "        pass\n    print('OK' if not bad else bad)\n")
    check("and it would have caught `for bad in (...)` inside main()",
          bool(shadowing(sample, "sample")))
    print("OK" if not bad else f"{bad} FAILED")
    return bad


if __name__ == "__main__":
    sys.exit(1 if main() else 0)
