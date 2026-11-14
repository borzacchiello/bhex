#!/usr/bin/env python3
"""Check that an extracted portable build finds its bundled resources."""

import pathlib
import subprocess
import sys
import tempfile
import zipfile

with tempfile.TemporaryDirectory(prefix="bhex-portable-") as temporary:
    root = pathlib.Path(temporary)
    bundle = root / "portable"
    with zipfile.ZipFile(sys.argv[1]) as archive:
        archive.extractall(bundle)
    executable = bundle / "bhex.exe"
    executable.chmod(0o755)
    sample = root / "sample.bin"
    sample.write_bytes(bytes(range(256)) * 16)

    # Check both launching from the bundle and from an unrelated directory.
    # sh supplies the APE loader fallback on hosts without binfmt support.
    for cwd in (bundle, root):
        result = subprocess.run(
            ["sh", str(executable), "-nc", "t/l; ii/s; ii", str(sample)],
            cwd=cwd, capture_output=True, text=True, check=True, timeout=60,
        )
        output = result.stdout + result.stderr
        for expected in ("emsixbundle", "ISA identification (4096 bytes analyzed):"):
            if expected not in output:
                raise RuntimeError(f"Missing {expected!r} from portable output:\n{output}")
        if "ERROR" in output or "unable to" in output:
            raise RuntimeError(output)
    print("Portable templates and models resolved successfully")
