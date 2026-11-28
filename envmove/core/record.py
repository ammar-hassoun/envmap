#!/usr/bin/env python3
"""Records which core.c the committed envmove-core was built from (build.sh
runs this). tests/test_vmmove.py checks the record against both files, so a
change to core.c without a rebuild, or a rebuilt binary without its source,
fails the suite."""
import hashlib
import json
import pathlib

here = pathlib.Path(__file__).resolve().parent
rec = {"core.c": hashlib.sha256((here / "core.c").read_bytes()).hexdigest(),
       "envmove-core": hashlib.sha256((here.parent / "coreimg" / "envmove-core").read_bytes()).hexdigest()}
(here.parent / "coreimg" / "BUILT-FROM.json").write_text(json.dumps(rec, indent=1) + "\n")
print("recorded", rec)
