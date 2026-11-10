#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 codstun contributors
"""Build a VPS source bundle from an explicit source-only allowlist."""

import hashlib
from pathlib import Path
import tarfile

root = Path(__file__).resolve().parents[1]
files = [root / name for name in ("README.md", "LICENSE", "pyproject.toml", "Dockerfile", ".dockerignore", ".gitignore")]
for directory, pattern in (("codstun", "*.py"), ("scripts", "*.py"), ("scripts", "*.java"),
                           ("tests", "*.py"), ("docs", "*.md"), ("deploy", "*.service"),
                           ("deploy", "*.env.example")):
    files.extend(path for path in (root / directory).glob(pattern) if path.is_file())
output = root / "dist" / "codstun-vps.tar.gz"
output.parent.mkdir(exist_ok=True)
with tarfile.open(output, "w:gz") as archive:
    for path in sorted(set(files)):
        archive.add(path, arcname=Path("codstun") / path.relative_to(root), recursive=False)
digest = hashlib.sha256(output.read_bytes()).hexdigest()
checksum = output.with_name(output.name + ".sha256")
checksum.write_text(f"{digest}  {output.name}\n")
print(output)
print(f"{len(set(files))} source files, {output.stat().st_size} bytes")
print(digest)
