"""
Flask SOAR engine entrypoint. Run from `soar-engine/`:

    python app.py

Equivalent to: python -m app.main
"""
from __future__ import annotations

import runpy

if __name__ == "__main__":
    runpy.run_module("app.main", run_name="__main__")
