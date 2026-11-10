#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Extract local research executables from the owner's PS2 ISO using isoinfo."""

import argparse
import hashlib
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("iso", type=Path)
parser.add_argument("--output", type=Path, default=Path("research/private"))
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
for name in ("MP.BIN", "SLUS_213.18"):
    result = subprocess.run(["isoinfo", "-i", str(args.iso), "-x", f"/{name};1"],
                            check=True, stdout=subprocess.PIPE)
    if not result.stdout.startswith(b"\x7fELF"):
        raise SystemExit(f"{name} was not found as an ELF in this disc image")
    path = args.output / name
    path.write_bytes(result.stdout)
    print(hashlib.sha256(result.stdout).hexdigest(), path)
