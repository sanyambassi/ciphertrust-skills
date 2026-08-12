#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
from pathlib import Path


def _ensure_cm_client_on_path() -> None:
    here = Path(__file__).resolve()
    candidates = [
        here.parents[1] / "lib",
        here.parents[2] / "lib",
    ]
    env_root = os.environ.get("CM_SKILLS_ROOT")
    if env_root:
        candidates.append(Path(env_root) / "lib")
    for lib in candidates:
        if (lib / "cm_client.py").is_file():
            sys.path.insert(0, str(lib))
            return
    raise SystemExit(
        "Cannot find lib/cm_client.py (expected next to this skill under lib/)."
    )


_ensure_cm_client_on_path()


def _configure_stdio_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


_configure_stdio_utf8()
from inventory.runner import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
